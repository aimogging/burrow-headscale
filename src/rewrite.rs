//! Low-level packet rewrite primitives. The actual stateful destination
//! tracking lives in `crate::nat::NatTable`; this module only provides
//! parsing and in-place IP/transport rewrites built on smoltcp's wire
//! parsers — the same crate that owns the userspace TCP/IP stack we feed.

use std::net::Ipv4Addr;

use anyhow::{anyhow, bail, Result};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber, UdpPacket};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy)]
pub struct PacketView {
    pub proto: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Validate that `packet` is a well-formed IPv4 packet according to smoltcp's
/// own length checks AND has version=4. Once this returns Ok, callers may
/// build `Ipv4Packet::new_unchecked(packet)` without further checks.
fn require_ipv4(packet: &[u8]) -> Result<()> {
    if packet.is_empty() {
        bail!("packet too short for IPv4 header");
    }
    if Ipv4Packet::new_unchecked(packet).version() != 4 {
        bail!("not an IPv4 packet");
    }
    Ipv4Packet::new_checked(packet).map_err(|_| anyhow!("packet too short for IPv4 header"))?;
    Ok(())
}

/// Parse the 5-tuple from a raw IPv4 packet. Only TCP/UDP populate ports —
/// ICMP and other protocols return `(0, 0)` and are handled separately.
pub fn parse_5tuple(packet: &[u8]) -> Result<PacketView> {
    require_ipv4(packet)?;
    let ip = Ipv4Packet::new_unchecked(packet);
    let proto: u8 = ip.next_header().into();
    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();
    let (src_port, dst_port) = match ip.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(ip.payload())
                .map_err(|_| anyhow!("transport header truncated"))?;
            (tcp.src_port(), tcp.dst_port())
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(ip.payload())
                .map_err(|_| anyhow!("transport header truncated"))?;
            (udp.src_port(), udp.dst_port())
        }
        _ => (0, 0),
    };
    Ok(PacketView {
        proto,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}

/// Rewrite the destination IP and recompute affected checksums in place.
/// Returns the previous destination address.
pub fn rewrite_dst_ip(packet: &mut [u8], new_dst: Ipv4Addr) -> Result<Ipv4Addr> {
    require_ipv4(packet)?;
    let mut ip = Ipv4Packet::new_unchecked(packet);
    let old_dst = ip.dst_addr();
    if old_dst == new_dst {
        return Ok(old_dst);
    }
    let src = ip.src_addr();
    let proto = ip.next_header();
    ip.set_dst_addr(new_dst);
    ip.fill_checksum();
    refill_transport_checksum(ip.payload_mut(), proto, src, new_dst)?;
    Ok(old_dst)
}

/// Rewrite the source IP and recompute affected checksums in place.
/// Returns the previous source address.
pub fn rewrite_src_ip(packet: &mut [u8], new_src: Ipv4Addr) -> Result<Ipv4Addr> {
    require_ipv4(packet)?;
    let mut ip = Ipv4Packet::new_unchecked(packet);
    let old_src = ip.src_addr();
    if old_src == new_src {
        return Ok(old_src);
    }
    let dst = ip.dst_addr();
    let proto = ip.next_header();
    ip.set_src_addr(new_src);
    ip.fill_checksum();
    refill_transport_checksum(ip.payload_mut(), proto, new_src, dst)?;
    Ok(old_src)
}

/// Rewrite the TCP/UDP destination port and patch the transport checksum.
/// Returns the previous destination port.
pub fn rewrite_dst_port(packet: &mut [u8], new_port: u16) -> Result<u16> {
    require_ipv4(packet)?;
    let mut ip = Ipv4Packet::new_unchecked(packet);
    let proto = ip.next_header();
    if proto != IpProtocol::Tcp && proto != IpProtocol::Udp {
        bail!("rewrite_dst_port: unsupported proto {}", u8::from(proto));
    }
    let src = ip.src_addr();
    let dst = ip.dst_addr();
    rewrite_transport_port(ip.payload_mut(), proto, src, dst, PortEnd::Dst, new_port)
}

/// Rewrite the TCP/UDP source port and patch the transport checksum.
/// Returns the previous source port.
pub fn rewrite_src_port(packet: &mut [u8], new_port: u16) -> Result<u16> {
    require_ipv4(packet)?;
    let mut ip = Ipv4Packet::new_unchecked(packet);
    let proto = ip.next_header();
    if proto != IpProtocol::Tcp && proto != IpProtocol::Udp {
        bail!("rewrite_src_port: unsupported proto {}", u8::from(proto));
    }
    let src = ip.src_addr();
    let dst = ip.dst_addr();
    rewrite_transport_port(ip.payload_mut(), proto, src, dst, PortEnd::Src, new_port)
}

#[derive(Copy, Clone)]
enum PortEnd {
    Src,
    Dst,
}

fn rewrite_transport_port(
    payload: &mut [u8],
    proto: IpProtocol,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    end: PortEnd,
    new_port: u16,
) -> Result<u16> {
    let src_addr = IpAddress::Ipv4(src);
    let dst_addr = IpAddress::Ipv4(dst);
    match proto {
        IpProtocol::Tcp => {
            let mut tcp = TcpPacket::new_checked(payload)
                .map_err(|_| anyhow!("transport header truncated"))?;
            let old = match end {
                PortEnd::Src => tcp.src_port(),
                PortEnd::Dst => tcp.dst_port(),
            };
            if old == new_port {
                return Ok(old);
            }
            match end {
                PortEnd::Src => tcp.set_src_port(new_port),
                PortEnd::Dst => tcp.set_dst_port(new_port),
            }
            tcp.fill_checksum(&src_addr, &dst_addr);
            Ok(old)
        }
        IpProtocol::Udp => {
            let mut udp = UdpPacket::new_checked(payload)
                .map_err(|_| anyhow!("transport header truncated"))?;
            let old = match end {
                PortEnd::Src => udp.src_port(),
                PortEnd::Dst => udp.dst_port(),
            };
            if old == new_port {
                return Ok(old);
            }
            match end {
                PortEnd::Src => udp.set_src_port(new_port),
                PortEnd::Dst => udp.set_dst_port(new_port),
            }
            // RFC 768: UDP checksum 0 means "unchecked" — leave alone.
            if udp.checksum() != 0 {
                udp.fill_checksum(&src_addr, &dst_addr);
            }
            Ok(old)
        }
        _ => unreachable!("caller verified proto is TCP or UDP"),
    }
}

fn refill_transport_checksum(
    payload: &mut [u8],
    proto: IpProtocol,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Result<()> {
    let src_addr = IpAddress::Ipv4(src);
    let dst_addr = IpAddress::Ipv4(dst);
    match proto {
        IpProtocol::Tcp => {
            let mut tcp = TcpPacket::new_checked(payload)
                .map_err(|_| anyhow!("transport header truncated"))?;
            tcp.fill_checksum(&src_addr, &dst_addr);
        }
        IpProtocol::Udp => {
            let mut udp = UdpPacket::new_checked(payload)
                .map_err(|_| anyhow!("transport header truncated"))?;
            // RFC 768: UDP checksum 0 means "unchecked" — leave alone.
            if udp.checksum() != 0 {
                udp.fill_checksum(&src_addr, &dst_addr);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Build an IPv4+TCP RST|ACK packet from scratch. Used to synthesize a
/// connection refusal when the OS-side connect probe (`Phase 9 fix #1`)
/// fails — the peer must see the same thing it would see if the closed port
/// answered directly.
pub fn build_tcp_rst(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ack_seq: u32,
) -> Vec<u8> {
    let total_len = 40usize; // 20 IP + 20 TCP, no payload, no options
    let mut pkt = vec![0u8; total_len];
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut pkt[..]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_len(total_len as u16);
        ip.set_ident(0);
        ip.set_dont_frag(false);
        ip.set_more_frags(false);
        ip.set_frag_offset(0);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(src_ip);
        ip.set_dst_addr(dst_ip);
        ip.fill_checksum();
    }
    {
        let mut tcp = TcpPacket::new_unchecked(&mut pkt[20..]);
        tcp.set_src_port(src_port);
        tcp.set_dst_port(dst_port);
        tcp.set_seq_number(TcpSeqNumber(0));
        tcp.set_ack_number(TcpSeqNumber(ack_seq as i32));
        tcp.set_header_len(20);
        tcp.clear_flags();
        tcp.set_rst(true);
        tcp.set_ack(true);
        tcp.set_window_len(0);
        tcp.set_urgent_at(0);
        tcp.fill_checksum(&IpAddress::Ipv4(src_ip), &IpAddress::Ipv4(dst_ip));
    }
    pkt
}

/// Build a fully-checksummed IPv4 + UDP datagram from scratch. Used by the
/// UDP proxy to construct response packets injected back into the tunnel.
pub fn build_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut pkt[..]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_len(total_len as u16);
        ip.set_ident(0);
        ip.set_dont_frag(false);
        ip.set_more_frags(false);
        ip.set_frag_offset(0);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(src_ip);
        ip.set_dst_addr(dst_ip);
        ip.fill_checksum();
    }
    {
        let mut udp = UdpPacket::new_unchecked(&mut pkt[20..]);
        udp.set_src_port(src_port);
        udp.set_dst_port(dst_port);
        udp.set_len((8 + payload.len()) as u16);
        udp.payload_mut().copy_from_slice(payload);
        // smoltcp's fill_checksum already implements RFC 768's "0 → 0xFFFF"
        // when the computed checksum lands on zero.
        udp.fill_checksum(&IpAddress::Ipv4(src_ip), &IpAddress::Ipv4(dst_ip));
    }
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_tcp_syn;

    fn ip_checksum_ok(pkt: &[u8]) -> bool {
        Ipv4Packet::new_checked(pkt)
            .map(|p| p.verify_checksum())
            .unwrap_or(false)
    }

    fn tcp_checksum_ok(pkt: &[u8]) -> bool {
        let ip = Ipv4Packet::new_checked(pkt).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        tcp.verify_checksum(
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr()),
        )
    }

    #[test]
    fn parses_tcp_5tuple() {
        let pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.proto, PROTO_TCP);
        assert_eq!(view.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(view.dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view.src_port, 54321);
        assert_eq!(view.dst_port, 80);
    }

    #[test]
    fn dst_rewrite_updates_ip_and_tcp_checksums() {
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));

        let old = rewrite_dst_ip(&mut pkt, Ipv4Addr::new(10, 0, 0, 2)).unwrap();
        assert_eq!(old, Ipv4Addr::new(192, 168, 1, 50));

        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));

        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(view.src_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn src_rewrite_updates_ip_and_tcp_checksums() {
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            80,
            54321,
        );
        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));

        rewrite_src_ip(&mut pkt, Ipv4Addr::new(192, 168, 1, 50)).unwrap();

        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.src_ip, Ipv4Addr::new(192, 168, 1, 50));
    }

    #[test]
    fn udp_checksum_zero_left_unchecked() {
        // Build a UDP packet with checksum=0 and verify rewrite does NOT touch it.
        let total_len = 28usize; // 20 IP + 8 UDP
        let mut pkt = vec![0u8; total_len];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut pkt[..]);
            ip.set_version(4);
            ip.set_header_len(20);
            ip.set_total_len(total_len as u16);
            ip.set_hop_limit(64);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(Ipv4Addr::new(10, 0, 0, 1));
            ip.set_dst_addr(Ipv4Addr::new(192, 168, 1, 50));
            ip.fill_checksum();
        }
        {
            let mut udp = UdpPacket::new_unchecked(&mut pkt[20..]);
            udp.set_src_port(53);
            udp.set_dst_port(53);
            udp.set_len(8);
            // checksum left at 0,0 (valid for IPv4 UDP — means no checksum)
        }

        rewrite_dst_ip(&mut pkt, Ipv4Addr::new(10, 0, 0, 2)).unwrap();
        let udp_after = UdpPacket::new_checked(&pkt[20..]).unwrap();
        assert_eq!(udp_after.checksum(), 0, "UDP checksum 0 must remain 0");
        assert!(ip_checksum_ok(&pkt));
    }

    #[test]
    fn build_udp_roundtrips_through_parse() {
        let payload = b"hello";
        let pkt = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(10, 0, 0, 1),
            53,
            33333,
            payload,
        );
        assert!(ip_checksum_ok(&pkt));
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.proto, PROTO_UDP);
        assert_eq!(view.src_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(view.src_port, 53);
        assert_eq!(view.dst_port, 33333);
        assert_eq!(&pkt[28..], payload);

        let ip = Ipv4Packet::new_checked(&pkt[..]).unwrap();
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_ne!(udp.checksum(), 0);
        assert!(udp.verify_checksum(
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr())
        ));
    }

    #[test]
    fn dst_port_rewrite_updates_tcp_checksum() {
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));

        let old = rewrite_dst_port(&mut pkt, 8080).unwrap();
        assert_eq!(old, 80);

        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.dst_port, 8080);
        assert_eq!(view.src_port, 54321);
    }

    #[test]
    fn src_port_rewrite_updates_tcp_checksum() {
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            45678,
            54321,
        );
        assert!(tcp_checksum_ok(&pkt));

        rewrite_src_port(&mut pkt, 80).unwrap();

        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.src_port, 80);
        assert_eq!(view.dst_port, 54321);
    }

    #[test]
    fn dst_port_rewrite_combined_with_dst_ip() {
        // The realistic path: NAT inbound rewrite changes BOTH dst_ip
        // (peer-visible → smoltcp's interface IP) AND dst_port (original
        // → per-flow gateway port). Both checksum patches must compose.
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));

        rewrite_dst_ip(&mut pkt, Ipv4Addr::new(10, 0, 0, 2)).unwrap();
        rewrite_dst_port(&mut pkt, 32801).unwrap();

        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(view.dst_port, 32801);
    }

    #[test]
    fn build_tcp_rst_is_well_formed() {
        let pkt = build_tcp_rst(
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(10, 0, 0, 1),
            80,
            54321,
            1001,
        );
        assert_eq!(pkt.len(), 40);
        assert!(ip_checksum_ok(&pkt));
        assert!(tcp_checksum_ok(&pkt));
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.proto, PROTO_TCP);
        assert_eq!(view.src_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(view.src_port, 80);
        assert_eq!(view.dst_port, 54321);

        let ip = Ipv4Packet::new_checked(&pkt[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.rst() && tcp.ack(), "RST|ACK expected");
        assert!(!tcp.syn() && !tcp.fin());
        assert_eq!(tcp.ack_number(), TcpSeqNumber(1001));
        assert_eq!(tcp.seq_number(), TcpSeqNumber(0));
    }

    #[test]
    fn rejects_non_ipv4() {
        let pkt = vec![0x60u8; 40]; // IPv6 first nibble
        let err = parse_5tuple(&pkt).unwrap_err();
        assert!(err.to_string().contains("not an IPv4"));
    }

    #[test]
    fn rejects_truncated() {
        let pkt = vec![0x45u8, 0, 0, 10];
        let err = parse_5tuple(&pkt).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }
}
