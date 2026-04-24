//! Transport-agnostic data-plane helpers: ingest a decrypted IPv4
//! packet into the runtime, probe an OS-side destination before
//! accepting a peer SYN, and synthesise RSTs when the probe fails.
//!
//! Lifted verbatim from `src/main.rs` during Stage 3 so the headscale
//! path (`src/hs_main.rs`) and the wg-quick path (`src/main.rs`)
//! share a single implementation. All coupling to the transport lives
//! in the caller's egress task / recv loop, not here.
//!
//! Only the public signatures are load-bearing: internal behaviour is
//! documented in the original comments preserved below.
//!
//! The data-plane's egress direction (send decrypted IP packet to peer)
//! differs per transport and is intentionally *not* in this module —
//! see `main::egress_loop` for the wg-quick single-tunnel version and
//! `hs_main::egress_loop` for the PeerTable multi-Tunn version.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::icmp::{
    build_echo_reply_for_wg_ip, send_dest_unreachable, IcmpForwarder, ICMP_CODE_HOST_UNREACHABLE,
    ICMP_CODE_NET_UNREACHABLE,
};
use crate::nat::{NatKey, NatTable};
use crate::probe::{classify_connect_error, ConnectClass};
use crate::rewrite::{self, build_tcp_rst, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::runtime::SmoltcpHandle;
use crate::udp_proxy::{extract_udp_payload, spawn_udp_proxy};

/// Per-NAT-entry UDP forwarder channel map.
///
/// Touched on every UDP packet (ingress task) and on the 10s NAT sweep.
/// `std::sync::Mutex` is the right tool: critical sections are bounded
/// `HashMap` ops with no `.await` held; `tokio::Mutex` pays for
/// park/unpark uncontended for no benefit here.
pub type UdpProxyMap = Arc<Mutex<HashMap<NatKey, mpsc::UnboundedSender<Vec<u8>>>>>;

/// Take a decrypted IPv4 packet from the transport, run NAT rewrite, and
/// dispatch by protocol: TCP into smoltcp, UDP into the per-entry
/// forwarder, ICMP into the dedicated forwarder.
#[allow(clippy::too_many_arguments)]
pub async fn ingest_tunnel_packet(
    mut packet: Vec<u8>,
    smoltcp: &SmoltcpHandle,
    nat: &Arc<NatTable>,
    udp_proxies: &UdpProxyMap,
    egress_tx: &mpsc::UnboundedSender<Vec<u8>>,
    arm_tx: &mpsc::UnboundedSender<(NatKey, TcpStream)>,
    icmp: &Arc<IcmpForwarder>,
    wg_ip: Ipv4Addr,
    dns_enabled: bool,
) {
    let view = match rewrite::parse_5tuple(&packet) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "non-IPv4 / unparseable tunnel packet, dropping");
            return;
        }
    };
    // Packets addressed to burrow's tailnet IP: smoltcp owns the TCP
    // stack (control listener, reverse-tunnel TCP, originated outbound
    // responses). UDP is handled separately — it's intercepted here
    // for reverse-tunnel forwarding without going through smoltcp.
    if view.dst_ip == wg_ip && view.proto == PROTO_TCP {
        smoltcp.enqueue_inbound(packet);
        return;
    }
    // ICMP to wg_ip: answer echo requests packet-level.
    if view.dst_ip == wg_ip && view.proto == PROTO_ICMP {
        if let Some(reply) = build_echo_reply_for_wg_ip(&packet, wg_ip) {
            let _ = egress_tx.send(reply);
        }
        return;
    }
    if view.dst_ip == wg_ip && view.proto == PROTO_UDP {
        crate::udp_reverse::dispatch_udp_to_wg_ip(&packet, &view, wg_ip, egress_tx, dns_enabled)
            .await;
        return;
    }
    match view.proto {
        PROTO_TCP => {
            let key = NatKey {
                proto: PROTO_TCP,
                peer_ip: view.src_ip,
                peer_port: view.src_port,
                original_dst_ip: view.dst_ip,
                original_dst_port: view.dst_port,
            };
            let entry = nat.get(key);
            match entry {
                Some(e) if e.smoltcp_id.is_some() => {
                    if let Err(err) = nat.rewrite_inbound(&mut packet) {
                        warn!(?key, error = %err, "nat rewrite_inbound (tcp fast path) failed");
                        return;
                    }
                    smoltcp.enqueue_inbound(packet);
                }
                Some(_) => {
                    debug!(?key, "tcp packet during connect probe — dropping");
                }
                None => {
                    use smoltcp::wire::{Ipv4Packet, TcpPacket};
                    let is_syn_only = Ipv4Packet::new_checked(&packet[..])
                        .ok()
                        .and_then(|ip| {
                            TcpPacket::new_checked(ip.payload())
                                .ok()
                                .map(|tcp| tcp.syn() && !tcp.ack())
                        })
                        .unwrap_or(false);
                    if !is_syn_only {
                        debug!(?key, "tcp packet to unknown flow (not SYN) — dropping");
                        return;
                    }
                    let smoltcp = smoltcp.clone();
                    let nat = Arc::clone(nat);
                    let arm_tx = arm_tx.clone();
                    let egress_tx = egress_tx.clone();
                    tokio::spawn(async move {
                        connect_probe(packet, key, smoltcp, nat, arm_tx, egress_tx).await;
                    });
                }
            }
        }
        PROTO_UDP => {
            let key = match nat.rewrite_inbound(&mut packet) {
                Ok((k, _, _)) => k,
                Err(e) => {
                    warn!(error = %e, "nat rewrite_inbound (udp) failed");
                    return;
                }
            };
            let payload = match extract_udp_payload(&packet) {
                Some(p) => p,
                None => {
                    debug!(?key, "malformed udp datagram");
                    return;
                }
            };
            let tx = {
                let mut map = udp_proxies.lock().unwrap();
                map.entry(key)
                    .or_insert_with(|| spawn_udp_proxy(key, egress_tx.clone()))
                    .clone()
            };
            if tx.send(payload).is_err() {
                udp_proxies.lock().unwrap().remove(&key);
            }
        }
        PROTO_ICMP => {
            icmp.handle_inbound(packet).await;
        }
        other => {
            debug!(proto = other, "unsupported proto, dropping");
        }
    }
}

/// Dial an OS-side destination before letting smoltcp answer a peer's SYN.
///
/// Outcomes classified by the kernel's `connect()` errno so the peer
/// observes the same port-state nmap would see on a direct route:
///
///   * Connect succeeds → arm the stream for the event loop, register
///     the smoltcp listener, enqueue the original SYN.
///   * ECONNREFUSED → synthesise a TCP RST and tunnel it back.
///   * EHOSTUNREACH / ENETUNREACH → synthesise ICMP Type 3 Code 1 / 0.
///   * ETIMEDOUT / other → drop silently (peer's own SYN retries time out).
pub async fn connect_probe(
    mut packet: Vec<u8>,
    key: NatKey,
    smoltcp: SmoltcpHandle,
    nat: Arc<NatTable>,
    arm_tx: mpsc::UnboundedSender<(NatKey, TcpStream)>,
    egress_tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 8 {
        debug!(?key, "probe: malformed SYN, dropping");
        return;
    }
    let peer_seq = u32::from_be_bytes([
        packet[ihl + 4],
        packet[ihl + 5],
        packet[ihl + 6],
        packet[ihl + 7],
    ]);

    match nat.try_reserve_pending(key) {
        Ok(Some(_)) => {}
        Ok(None) => {
            debug!(?key, "probe: another probe already in flight; dropping");
            return;
        }
        Err(e) => {
            warn!(?key, error = %e, "probe: cannot reserve NAT slot");
            return;
        }
    };

    let dst = (key.original_dst_ip, key.original_dst_port);
    let stream = match TcpStream::connect(dst).await {
        Ok(s) => s,
        Err(e) => {
            let class = classify_connect_error(&e);
            debug!(?key, ?class, error = %e, "probe: OS connect failed");
            match class {
                ConnectClass::Refused => send_rst(&egress_tx, key, peer_seq),
                ConnectClass::HostUnreachable => {
                    send_dest_unreachable(&egress_tx, &packet, ICMP_CODE_HOST_UNREACHABLE);
                }
                ConnectClass::NetUnreachable => {
                    send_dest_unreachable(&egress_tx, &packet, ICMP_CODE_NET_UNREACHABLE);
                }
                ConnectClass::Filtered => {}
            }
            nat.evict_key(key);
            return;
        }
    };

    if arm_tx.send((key, stream)).is_err() {
        warn!(?key, "probe: event loop receiver gone; aborting");
        nat.evict_key(key);
        return;
    }

    let (virtual_ip, gateway_port) = match nat.rewrite_inbound(&mut packet) {
        Ok((_, vip, gw)) => (vip, gw),
        Err(e) => {
            warn!(?key, error = %e, "probe: rewrite_inbound failed post-connect");
            nat.evict_key(key);
            return;
        }
    };
    if smoltcp
        .ensure_listener(virtual_ip, gateway_port, key)
        .await
        .is_err()
    {
        error!(?key, "probe: smoltcp dropped ensure_listener reply");
        nat.evict_key(key);
        return;
    }
    smoltcp.enqueue_inbound(packet);
}

fn send_rst(egress_tx: &mpsc::UnboundedSender<Vec<u8>>, key: NatKey, peer_seq: u32) {
    let rst = build_tcp_rst(
        key.original_dst_ip,
        key.peer_ip,
        key.original_dst_port,
        key.peer_port,
        peer_seq.wrapping_add(1),
    );
    let _ = egress_tx.send(rst);
}
