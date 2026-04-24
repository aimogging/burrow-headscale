//! UDP ingress dispatch for datagrams whose dst is `wg_ip`.
//!
//! Reverse UDP tunnels no longer live on the WG ingress path — they
//! bind real OS `UdpSocket`s on the burrow host's network interfaces.
//! This module only serves the built-in DNS resolver now: datagrams
//! to `(wg_ip, 53)` are answered using the host's system resolver
//! when `dns_enabled` is true.

use std::net::Ipv4Addr;

use tokio::sync::mpsc;

use crate::dns_service::{handle_query, DNS_PORT};
use crate::rewrite::{build_udp_packet, PacketView};
use crate::udp_proxy::extract_udp_payload;

/// Dispatch a UDP datagram whose dst is `wg_ip`. If `dns_enabled` and
/// the port is 53, synthesize a DNS answer and push the reply packet
/// onto `egress_tx`. Everything else drops silently — it is not a NAT
/// miss, just traffic with no handler on the WG-facing side.
pub async fn dispatch_udp_to_wg_ip(
    packet: &[u8],
    view: &PacketView,
    wg_ip: Ipv4Addr,
    egress_tx: &mpsc::UnboundedSender<Vec<u8>>,
    dns_enabled: bool,
) {
    let Some(payload) = extract_udp_payload(packet) else {
        tracing::debug!(?view, "malformed UDP to wg_ip — dropping");
        return;
    };
    if dns_enabled && view.dst_port == DNS_PORT {
        if let Some(resp) = handle_query(&payload).await {
            let out = build_udp_packet(wg_ip, view.src_ip, DNS_PORT, view.src_port, &resp.payload);
            let _ = egress_tx.send(out);
            return;
        }
    }
    tracing::debug!(?view, "UDP to wg_ip matched no handler — dropping");
}
