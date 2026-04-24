//! smoltcp `Device` implementation backed by tokio mpsc channels. Inbound
//! packets (from the WireGuard tunnel after destination rewrite) are pushed
//! into the rx sender; outbound packets emitted by smoltcp are forwarded out
//! the tx sender for src-IP rewrite + WireGuard encapsulation.
//!
//! smoltcp's `Interface::poll` is single-threaded and pull-based — the
//! `SmoltcpRuntime` (Phase 4) wraps everything in a dedicated thread plus a
//! command channel. For Phase 2 we expose the building blocks so tests can
//! drive `Interface::poll` directly.
//!
//! Tokio `UnboundedSender::send` is sync; `UnboundedReceiver::try_recv` is
//! sync. That's exactly the shape smoltcp's blocking poll loop needs, while
//! still letting tokio tasks consume the receiver asynchronously.

use smoltcp::iface::{Config as IfaceConfig, Interface};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Cidr};
use tokio::sync::mpsc::{self, error::TryRecvError};

/// MTU presented to smoltcp. WireGuard adds 32 bytes of overhead to a 1500
/// byte underlying MTU; we round to a safe 1420.
pub const MTU: usize = 1420;

pub type PacketSender = mpsc::UnboundedSender<Vec<u8>>;
pub type PacketReceiver = mpsc::UnboundedReceiver<Vec<u8>>;

/// `Device` implementation that reads inbound packets from `rx` (a receiver
/// owned by the smoltcp thread) and emits outbound packets via `tx` (a
/// sender shared with the egress task).
pub struct ChannelDevice {
    rx: PacketReceiver,
    tx: PacketSender,
    mtu: usize,
}

impl ChannelDevice {
    pub fn new(rx: PacketReceiver, tx: PacketSender) -> Self {
        Self { rx, tx, mtu: MTU }
    }
}

pub struct ChannelRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for ChannelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct ChannelTxToken {
    tx: PacketSender,
}

impl phy::TxToken for ChannelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // Receiver hangs up only on shutdown; failure here is harmless.
        let _ = self.tx.send(buf);
        r
    }
}

impl phy::Device for ChannelDevice {
    type RxToken<'a>
        = ChannelRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = ChannelTxToken
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self.rx.try_recv() {
            Ok(buf) => Some((
                ChannelRxToken { buffer: buf },
                ChannelTxToken {
                    tx: self.tx.clone(),
                },
            )),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ChannelTxToken {
            tx: self.tx.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Build a smoltcp `Interface` for IP medium with the given gateway address.
pub fn build_interface(addr: &Ipv4Cidr, device: &mut ChannelDevice) -> Interface {
    let config = IfaceConfig::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::Ipv4(*addr))
            .expect("IP address vec full — should hold at least one");
    });
    iface
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::SocketSet;
    use smoltcp::socket::tcp;
    use std::net::Ipv4Addr;

    use crate::nat::NatTable;
    use crate::rewrite;
    use crate::test_helpers::build_tcp_syn_seq as build_tcp_syn;

    /// Functional test for Phase 2 / Phase 11: synthetic TCP SYN through the
    /// rewrite shim + smoltcp produces a SYN-ACK at the device tx queue,
    /// which after the outbound rewrite has src restored to the original
    /// destination. Post-Phase-11 the rewrite picks a (virtual_ip,
    /// gateway_port) from the 198.18.0.0/15 pool; smoltcp's interface uses
    /// the lowest address of the pool plus `set_any_ip(true)` so any
    /// virtual_ip in the /15 is accepted.
    #[test]
    fn syn_through_pipeline_yields_synack() {
        use smoltcp::wire::{IpAddress, IpListenEndpoint};

        let cidr = Ipv4Cidr::new(
            crate::nat::VIRTUAL_IFACE_ADDR,
            crate::nat::VIRTUAL_CIDR_PREFIX,
        );

        let (rx_tx, rx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx_tx, mut tx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut device = ChannelDevice::new(rx_rx, tx_tx);
        let mut iface = build_interface(&cidr, &mut device);
        iface.set_any_ip(true);

        let mut sockets = SocketSet::new(vec![]);

        let table = NatTable::new();

        // Build a SYN from peer 10.0.0.1:54321 → 192.168.1.50:80 (original dst).
        let mut syn = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
            1000,
        );
        let (key, virtual_ip, gateway_port) = table.rewrite_inbound(&mut syn).unwrap();
        assert_eq!(key.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(key.original_dst_port, 80);

        // Bind the listener on (virtual_ip, gateway_port) — that's where
        // smoltcp will see the rewritten SYN arrive.
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let mut listener = tcp::Socket::new(rx_buf, tx_buf);
        listener
            .listen(IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(virtual_ip)),
                port: gateway_port,
            })
            .expect("listen ok");
        let _handle = sockets.add(listener);

        rx_tx.send(syn).unwrap();

        // Poll smoltcp until it produces output.
        let mut produced = None;
        for _ in 0..16 {
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);
            if let Ok(p) = tx_rx.try_recv() {
                produced = Some(p);
                break;
            }
        }
        let mut out = produced.expect("smoltcp should have produced a SYN-ACK");

        // Must be a SYN-ACK (flags = 0x12) before the rewrite pass.
        let view = rewrite::parse_5tuple(&out).unwrap();
        assert_eq!(view.proto, rewrite::PROTO_TCP);
        assert_eq!(view.src_ip, virtual_ip);
        assert_eq!(view.src_port, gateway_port);
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(view.dst_port, 54321);
        let ihl = ((out[0] & 0x0F) as usize) * 4;
        let flags = out[ihl + 13];
        assert_eq!(flags & 0x12, 0x12, "SYN+ACK flags must be set");

        // Outbound rewrite restores the peer's view: src = original dst.
        let restored = table.rewrite_outbound(&mut out).unwrap();
        assert_eq!(restored.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        let view_after = rewrite::parse_5tuple(&out).unwrap();
        assert_eq!(view_after.src_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view_after.src_port, 80);
    }
}
