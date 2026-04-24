//! Test-only helpers for hand-crafting IP/TCP packets. Uses smoltcp's
//! wire accessors so checksums are computed correctly — including
//! odd-length payloads, which the hand-rolled loops this replaces used
//! to silently mangle.
//!
//! Public module because both unit tests (inside `src/`) and integration
//! tests (in `tests/`) need it, and integration tests can't see
//! `#[cfg(test)]` items. `#[doc(hidden)]` keeps the helpers out of the
//! public API surface.

#![doc(hidden)]

use std::net::Ipv4Addr;

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber};

/// Bitmask constants matching the TCP flags wire layout.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// Build a fully-checksummed IPv4 + TCP packet. Uses smoltcp's
/// `fill_checksum` for both layers, so odd-length payloads are handled
/// per RFC 793 (pad with a zero byte for the checksum computation).
pub fn build_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 20 + payload.len();
    let mut pkt = vec![0u8; total_len];
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut pkt[..]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(total_len as u16);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(src_ip);
        ip.set_dst_addr(dst_ip);
        ip.set_dont_frag(false);
        ip.fill_checksum();
    }
    {
        let mut tcp = TcpPacket::new_unchecked(&mut pkt[20..]);
        tcp.set_src_port(src_port);
        tcp.set_dst_port(dst_port);
        tcp.set_seq_number(TcpSeqNumber(seq as i32));
        tcp.set_ack_number(TcpSeqNumber(ack as i32));
        tcp.set_header_len(20);
        tcp.set_fin(flags & FIN != 0);
        tcp.set_syn(flags & SYN != 0);
        tcp.set_rst(flags & RST != 0);
        tcp.set_psh(flags & PSH != 0);
        tcp.set_ack(flags & ACK != 0);
        tcp.set_window_len(65535);
        tcp.set_urgent_at(0);
        tcp.payload_mut().copy_from_slice(payload);
        tcp.fill_checksum(&IpAddress::Ipv4(src_ip), &IpAddress::Ipv4(dst_ip));
    }
    pkt
}

/// Convenience: SYN-only packet with seq=1000 (matches the value the
/// pre-refactor hand-rolled helpers used). No payload, ack=0.
pub fn build_tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    build_tcp(src, dst, src_port, dst_port, 1000, 0, SYN, &[])
}

/// Convenience: SYN-only packet with an explicit seq — used by the
/// smoltcp-iface direct-poll test that asserts a specific seq survives
/// through the pipeline.
pub fn build_tcp_syn_seq(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    build_tcp(src, dst, src_port, dst_port, seq, 0, SYN, &[])
}
