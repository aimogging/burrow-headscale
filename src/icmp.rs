//! ICMP forwarding with graceful fallback. Two operating modes:
//!
//!   * **Raw**: a real raw ICMP socket (cross-platform via `socket2` →
//!     `tokio::net::UdpSocket::from_std`) — peer echo requests are
//!     forwarded to the original destination, replies are demuxed by
//!     (id, seq) and tunneled back.
//!   * **Fallback**: when raw socket creation fails (no admin / no
//!     `CAP_NET_RAW`), every echo request gets ICMP Type 3 / Code 13
//!     (Communication Administratively Prohibited). This is semantically
//!     accurate — policy/privilege blocked the forward.
//!
//! The cross-platform `from_std` trick: tokio's `UdpSocket::from_std`
//! takes any `std::net::UdpSocket`, which is just a handle wrapper —
//! the underlying mio I/O calls (`WSARecvFrom`/`WSASendTo` on Windows,
//! `recvfrom`/`sendto` on Unix) work fine on raw sockets. So a raw
//! socket created with `WSASocketW` (via socket2) can be driven by
//! tokio's runtime as if it were a UDP socket.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::rewrite::{parse_5tuple, PROTO_ICMP};
use crate::udp_proxy::PacketSink;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_DEST_UNREACHABLE: u8 = 3;
/// RFC 792 Type 3 codes used by the probe-failure path (Phase 11 fix #1)
/// and the raw-socket fallback.
pub const ICMP_CODE_NET_UNREACHABLE: u8 = 0;
pub const ICMP_CODE_HOST_UNREACHABLE: u8 = 1;
pub const ICMP_CODE_ADMIN_PROHIBITED: u8 = 13;

/// Inbound echo requests that we've forwarded; reply lookup is by (id, seq).
const ECHO_PENDING_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
struct PendingEcho {
    peer_ip: Ipv4Addr,
    original_dst_ip: Ipv4Addr,
    sent_at: Instant,
}

type PendingMap = Arc<Mutex<HashMap<(u16, u16), PendingEcho>>>;

/// Top-level handle the main loop calls into for each inbound ICMP packet.
pub enum IcmpForwarder {
    Raw(RawForwarder),
    Fallback(FallbackForwarder),
}

pub struct RawForwarder {
    socket: Arc<UdpSocket>,
    pending: PendingMap,
    sink: PacketSink,
}

pub struct FallbackForwarder {
    sink: PacketSink,
}

impl IcmpForwarder {
    /// Probe at startup. Tries to bind a raw ICMP socket; on success returns
    /// `Raw` and spawns a reader task. On failure returns `Fallback`.
    pub fn probe(sink: PacketSink) -> Self {
        match build_raw_socket() {
            Ok(socket) => {
                tracing::info!("ICMP raw socket available — echo will be forwarded");
                let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
                spawn_raw_reader(Arc::clone(&socket), Arc::clone(&pending), sink.clone());
                spawn_pending_sweeper(Arc::clone(&pending));
                IcmpForwarder::Raw(RawForwarder {
                    socket,
                    pending,
                    sink,
                })
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "ICMP raw socket unavailable — echo requests will get Type 3/Code 13 (admin prohibited)"
                );
                IcmpForwarder::Fallback(FallbackForwarder { sink })
            }
        }
    }

    /// Handle one inbound ICMP IPv4 packet from a peer.
    pub async fn handle_inbound(&self, packet: Vec<u8>) {
        match self {
            IcmpForwarder::Raw(r) => r.handle(packet).await,
            IcmpForwarder::Fallback(f) => f.handle(packet),
        }
    }
}

impl RawForwarder {
    async fn handle(&self, packet: Vec<u8>) {
        let view = match parse_5tuple(&packet) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "icmp: drop unparseable");
                return;
            }
        };
        if view.proto != PROTO_ICMP {
            return;
        }
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        if packet.len() < ihl + 8 {
            tracing::debug!("icmp: truncated header");
            return;
        }
        let icmp = &packet[ihl..];
        if icmp[0] != ICMP_ECHO_REQUEST {
            tracing::debug!(ty = icmp[0], "icmp: non-echo, dropping");
            return;
        }
        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
        // Register pending so the reply can be matched.
        self.pending.lock().unwrap().insert(
            (id, seq),
            PendingEcho {
                peer_ip: view.src_ip,
                original_dst_ip: view.dst_ip,
                sent_at: Instant::now(),
            },
        );
        // Send just the ICMP bytes (kernel adds the IP header).
        let dst: SocketAddr = SocketAddrV4::new(view.dst_ip, 0).into();
        if let Err(e) = self.socket.send_to(icmp, dst).await {
            tracing::warn!(error = %e, "icmp: raw send failed; falling back to admin-prohibited");
            self.pending.lock().unwrap().remove(&(id, seq));
            send_admin_prohibited(&self.sink, &packet);
        }
    }
}

impl FallbackForwarder {
    fn handle(&self, packet: Vec<u8>) {
        let view = match parse_5tuple(&packet) {
            Ok(v) => v,
            Err(_) => return,
        };
        if view.proto != PROTO_ICMP {
            return;
        }
        send_admin_prohibited(&self.sink, &packet);
    }
}

fn build_raw_socket() -> Result<Arc<UdpSocket>> {
    let s = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .context("socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)")?;
    s.set_nonblocking(true).context("set_nonblocking")?;
    // Cross-platform fd/handle handoff: socket2 → std → tokio.
    #[cfg(unix)]
    let std_sock: std::net::UdpSocket = {
        use std::os::fd::{FromRawFd, IntoRawFd};
        unsafe { std::net::UdpSocket::from_raw_fd(s.into_raw_fd()) }
    };
    #[cfg(windows)]
    let std_sock: std::net::UdpSocket = {
        use std::os::windows::io::{FromRawSocket, IntoRawSocket};
        unsafe { std::net::UdpSocket::from_raw_socket(s.into_raw_socket()) }
    };
    let tok = UdpSocket::from_std(std_sock).context("tokio::UdpSocket::from_std on raw socket")?;
    Ok(Arc::new(tok))
}

fn spawn_raw_reader(socket: Arc<UdpSocket>, pending: PendingMap, sink: PacketSink) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, _src)) => {
                    if let Err(e) = handle_raw_recv(&buf[..n], &pending, &sink) {
                        tracing::debug!(error = %e, "icmp: raw recv handling");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "icmp: raw recv error; ending reader");
                    return;
                }
            }
        }
    });
}

/// Both Linux and Windows raw IP sockets deliver the full IP packet
/// (header + payload) on `recvfrom`. Strip the IP header to get to the ICMP.
fn handle_raw_recv(buf: &[u8], pending: &PendingMap, sink: &PacketSink) -> Result<()> {
    if buf.len() < 28 {
        return Ok(());
    }
    let view = parse_5tuple(buf)?;
    if view.proto != PROTO_ICMP {
        return Ok(());
    }
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    if buf.len() < ihl + 8 {
        return Ok(());
    }
    let icmp = &buf[ihl..];
    if icmp[0] != ICMP_ECHO_REPLY {
        // Could be other ICMP (unreachable, time exceeded). For phase 6 we
        // only relay echo replies; other types would need richer demux.
        return Ok(());
    }
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let pe = match pending.lock().unwrap().remove(&(id, seq)) {
        Some(p) => p,
        None => {
            tracing::debug!(id, seq, "icmp: reply with no pending request, dropping");
            return Ok(());
        }
    };
    // Build response packet: src=original_dst_ip (the responder), dst=peer_ip.
    let pkt = build_icmp_packet(pe.original_dst_ip, pe.peer_ip, icmp);
    let _ = sink.send(pkt);
    Ok(())
}

fn spawn_pending_sweeper(pending: PendingMap) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let now = Instant::now();
            pending
                .lock()
                .unwrap()
                .retain(|_, v| now.duration_since(v.sent_at) < ECHO_PENDING_TTL);
        }
    });
}

/// Build an ICMP Type 3 reply with the given code (RFC 792), wrap it in an
/// IPv4 header whose src is the intended destination (we're speaking for it)
/// and dst is the peer, and push it onto the sink.
///
/// Used both by the ICMP fallback path (code 13 — administratively prohibited)
/// and by the TCP connect-probe failure classifier (codes 0 / 1 — net /
/// host unreachable).
pub fn send_dest_unreachable(sink: &PacketSink, original: &[u8], code: u8) {
    let view = match parse_5tuple(original) {
        Ok(v) => v,
        Err(_) => return,
    };
    let ihl = ((original[0] & 0x0F) as usize) * 4;
    // ICMP body: 4 bytes unused + (IP header + first 8 bytes of payload).
    // We embed up to ihl + 8 bytes of the original packet (RFC 792).
    let embed_len = (ihl + 8).min(original.len());
    let mut icmp = Vec::with_capacity(8 + embed_len);
    icmp.push(ICMP_DEST_UNREACHABLE);
    icmp.push(code);
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&[0, 0, 0, 0]); // unused
    icmp.extend_from_slice(&original[..embed_len]);
    let csum = icmp_checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    // IP wrapper: src = the host they were trying to reach (we're speaking
    // for it), dst = peer.
    let pkt = build_icmp_packet(view.dst_ip, view.src_ip, &icmp);
    let _ = sink.send(pkt);
}

/// Convenience wrapper: the ICMP fallback path's Type 3 / Code 13.
fn send_admin_prohibited(sink: &PacketSink, original: &[u8]) {
    send_dest_unreachable(sink, original, ICMP_CODE_ADMIN_PROHIBITED);
}

/// If `packet` is an ICMP echo request addressed to `wg_ip`, build and
/// return the corresponding echo reply (type 0) with `src = wg_ip`,
/// `dst = peer`. Returns `None` for anything else.
///
/// Used by `ingest_tunnel_packet` so peers can `ping wg_ip` for
/// reachability checks without burrow needing a raw socket bound to an
/// address Windows doesn't own. Pings to LAN hosts still go through
/// `IcmpForwarder::handle_inbound`.
pub fn build_echo_reply_for_wg_ip(packet: &[u8], wg_ip: Ipv4Addr) -> Option<Vec<u8>> {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, Ipv4Packet};

    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if u8::from(ip.next_header()) != PROTO_ICMP || ip.dst_addr() != wg_ip {
        return None;
    }
    let checksum = ChecksumCapabilities::default();
    let icmp = Icmpv4Packet::new_checked(ip.payload()).ok()?;
    let (ident, seq_no, data) = match Icmpv4Repr::parse(&icmp, &checksum).ok()? {
        Icmpv4Repr::EchoRequest {
            ident,
            seq_no,
            data,
        } => (ident, seq_no, data),
        _ => return None,
    };
    let reply = Icmpv4Repr::EchoReply {
        ident,
        seq_no,
        data,
    };
    let mut icmp_bytes = vec![0u8; reply.buffer_len()];
    reply.emit(&mut Icmpv4Packet::new_unchecked(&mut icmp_bytes), &checksum);
    Some(build_icmp_packet(wg_ip, ip.src_addr().into(), &icmp_bytes))
}

/// Build an IPv4 header around `icmp_payload` and return a complete packet.
fn build_icmp_packet(src: Ipv4Addr, dst: Ipv4Addr, icmp_payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + icmp_payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_ICMP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let csum = ip_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    pkt[20..].copy_from_slice(icmp_payload);
    pkt
}

fn icmp_checksum(buf: &[u8]) -> u16 {
    ones_complement(buf)
}

fn ip_checksum(buf: &[u8]) -> u16 {
    ones_complement(buf)
}

fn ones_complement(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn build_echo_request(
        peer: Ipv4Addr,
        dst: Ipv4Addr,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let icmp_len = 8 + payload.len();
        let total = 20 + icmp_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = PROTO_ICMP;
        pkt[12..16].copy_from_slice(&peer.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        let csum = ip_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        // ICMP
        pkt[20] = ICMP_ECHO_REQUEST;
        pkt[21] = 0;
        pkt[24..26].copy_from_slice(&id.to_be_bytes());
        pkt[26..28].copy_from_slice(&seq.to_be_bytes());
        pkt[28..28 + payload.len()].copy_from_slice(payload);
        let csum = icmp_checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    #[test]
    fn admin_prohibited_packet_shape() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let req = build_echo_request(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            0x1234,
            7,
            b"hello",
        );
        send_admin_prohibited(&tx, &req);
        let pkt = rx.try_recv().unwrap();
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.proto, PROTO_ICMP);
        // Source is the host they tried to reach; destination is the peer.
        assert_eq!(view.src_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
        let icmp = &pkt[20..];
        assert_eq!(icmp[0], ICMP_DEST_UNREACHABLE);
        assert_eq!(icmp[1], ICMP_CODE_ADMIN_PROHIBITED);
        // Embedded original IP header must be present (first byte is 0x45).
        assert_eq!(icmp[8], 0x45);
        // ICMP checksum should now sum to zero.
        assert_eq!(ones_complement(icmp), 0);
        // IP checksum likewise.
        assert_eq!(ones_complement(&pkt[..20]), 0);
    }

    #[tokio::test]
    async fn fallback_forwarder_emits_admin_prohibited() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let f = FallbackForwarder { sink: tx };
        let req = build_echo_request(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            0xABCD,
            42,
            b"x",
        );
        f.handle(req);
        let pkt = rx.try_recv().unwrap();
        let icmp = &pkt[20..];
        assert_eq!(icmp[0], ICMP_DEST_UNREACHABLE);
        assert_eq!(icmp[1], ICMP_CODE_ADMIN_PROHIBITED);
    }

    #[tokio::test]
    async fn fallback_forwarder_ignores_non_icmp() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let f = FallbackForwarder { sink: tx };
        // Hand-build a TCP packet (proto=6) — fallback should ignore.
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 50]);
        let csum = ip_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        f.handle(pkt);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn probe_is_callable() {
        // Just verify probe() returns *something* (Raw or Fallback) without
        // panicking. Whether raw works depends on test runner privileges.
        // (`from_std` needs a tokio runtime, hence #[tokio::test].)
        let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let _ = IcmpForwarder::probe(tx);
    }
}
