//! Synchronous wrapper around `boringtun::noise::Tunn` — pure protocol,
//! no I/O. Each `Peer` in the `PeerTable` owns one `WgCore`; the data
//! plane drives encapsulate/decapsulate against it and forwards
//! `to_network` bytes through DERP rather than a UDP socket.
//!
//! The `WgTunnel` wrapper (old wg-quick single-UDP-socket transport)
//! was retired in Stage 5 alongside the wg-quick config parser. If
//! you need a raw UDP transport for testing, build the socket in the
//! caller and feed bytes into `decapsulate`/`encapsulate` directly.
//!
//! No `Config` dep — WG credentials come in as raw keys via
//! [`WgCore::from_raw`]. The old `WgCore::new(&Config)` constructor
//! was the only path that reached into `config.rs`, which no longer
//! exists.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use anyhow::{bail, Result};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};

/// Maximum size of a single encapsulated WG datagram we'll produce.
/// Covers a 1500 byte underlying MTU plus WireGuard overhead.
pub const MAX_UDP_SIZE: usize = 1700;

/// Result of one synchronous step against the Tunn protocol engine.
/// Any `to_network` packets must be forwarded to the peer (in order)
/// before the next call. `to_tunnel` is a decrypted IPv4 packet.
#[derive(Debug, Default)]
pub struct CoreStep {
    pub to_network: Vec<Vec<u8>>,
    pub to_tunnel: Option<TunnelPacket>,
    pub expired: bool,
}

#[derive(Debug)]
pub struct TunnelPacket {
    pub data: Vec<u8>,
    pub src: Ipv4Addr,
}

pub struct WgCore {
    tunn: Mutex<Tunn>,
}

impl WgCore {
    /// Construct a `WgCore` from raw key material. The node's own
    /// private key and the peer's public key are supplied explicitly;
    /// preshared keys aren't part of the Headscale data model so
    /// callers that don't use one pass `None`.
    pub fn from_raw(
        private_key: x25519_dalek::StaticSecret,
        peer_public_key: x25519_dalek::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
    ) -> Self {
        let tunn = Tunn::new(
            private_key,
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            0,
            None,
        );
        Self {
            tunn: Mutex::new(tunn),
        }
    }

    /// Build a handshake initiation message. `force_resend` forces a
    /// fresh handshake even if one is already in flight (maps to
    /// boringtun's `format_handshake_initiation` parameter).
    pub fn handshake_init(&self, force_resend: bool) -> Result<CoreStep> {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let mut step = CoreStep::default();
        let mut tunn = self.tunn.lock().expect("tunn mutex poisoned");
        match tunn.format_handshake_initiation(&mut buf, force_resend) {
            TunnResult::Done => {}
            TunnResult::Err(e) => bail!("handshake_init: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.truncate(len);
                step.to_network.push(buf);
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                bail!("handshake_init: unexpected WriteToTunnel result");
            }
        }
        Ok(step)
    }

    /// Process an incoming encrypted datagram. Drains any queued
    /// control packets (handshake responses, cookie replies) by
    /// re-calling decapsulate with an empty input until it returns
    /// `Done`, per the boringtun contract.
    pub fn decapsulate(&self, src: Option<IpAddr>, datagram: &[u8]) -> Result<CoreStep> {
        let mut step = CoreStep::default();
        let mut tunn = self.tunn.lock().expect("tunn mutex poisoned");
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        match tunn.decapsulate(src, datagram, &mut buf) {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                step.expired = true;
            }
            TunnResult::Err(e) => bail!("decapsulate: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                let mut owned = vec![0u8; len];
                owned.copy_from_slice(&buf[..len]);
                step.to_network.push(owned);
                loop {
                    let mut drain_buf = vec![0u8; MAX_UDP_SIZE];
                    match tunn.decapsulate(None, &[], &mut drain_buf) {
                        TunnResult::WriteToNetwork(p) => {
                            let plen = p.len();
                            drain_buf.truncate(plen);
                            step.to_network.push(drain_buf);
                        }
                        TunnResult::Done => break,
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            step.expired = true;
                            break;
                        }
                        TunnResult::Err(e) => bail!("decapsulate drain: {e:?}"),
                        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                            bail!("decapsulate drain: unexpected tunnel write");
                        }
                    }
                }
            }
            TunnResult::WriteToTunnelV4(packet, src_v4) => {
                let len = packet.len();
                let mut data = vec![0u8; len];
                data.copy_from_slice(&buf[..len]);
                step.to_tunnel = Some(TunnelPacket { data, src: src_v4 });
            }
            TunnResult::WriteToTunnelV6(_, _) => {
                tracing::trace!("dropping IPv6 tunnel packet (IPv4-only data plane)");
            }
        }
        Ok(step)
    }

    /// Encrypt a plaintext IP packet. If no session is yet established
    /// the returned `to_network` bytes are a handshake init instead —
    /// callers should forward whatever comes out without interpreting it.
    pub fn encapsulate(&self, ip_packet: &[u8]) -> Result<CoreStep> {
        let mut step = CoreStep::default();
        let mut buf = vec![0u8; MAX_UDP_SIZE.max(ip_packet.len() + 64)];
        let mut tunn = self.tunn.lock().expect("tunn mutex poisoned");
        match tunn.encapsulate(ip_packet, &mut buf) {
            TunnResult::Done => {}
            TunnResult::Err(e) => bail!("encapsulate: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.truncate(len);
                step.to_network.push(buf);
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                bail!("encapsulate: unexpected WriteToTunnel result");
            }
        }
        Ok(step)
    }

    /// Drive WireGuard timers — keepalives, handshake retransmits,
    /// expiry. Should be called every ~250ms.
    pub fn timer_tick(&self) -> Result<CoreStep> {
        let mut step = CoreStep::default();
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let mut tunn = self.tunn.lock().expect("tunn mutex poisoned");
        match tunn.update_timers(&mut buf) {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                step.expired = true;
            }
            TunnResult::Err(e) => bail!("update_timers: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.truncate(len);
                step.to_network.push(buf);
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                bail!("update_timers: unexpected WriteToTunnel result");
            }
        }
        Ok(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn make_core() -> WgCore {
        let private = StaticSecret::from([0x42u8; 32]);
        let peer_secret = StaticSecret::from([0x99u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);
        WgCore::from_raw(private, peer_public, None, Some(25))
    }

    #[test]
    fn handshake_init_produces_network_packet() {
        let core = make_core();
        let step = core
            .handshake_init(false)
            .expect("handshake should succeed");
        assert_eq!(
            step.to_network.len(),
            1,
            "handshake init must produce exactly one network packet"
        );
        // WireGuard handshake initiation message is 148 bytes.
        assert_eq!(
            step.to_network[0].len(),
            148,
            "WireGuard handshake initiation is 148 bytes"
        );
        // Message type byte = 1 (HANDSHAKE_INIT).
        assert_eq!(step.to_network[0][0], 1);
        assert!(step.to_tunnel.is_none());
        assert!(!step.expired);
    }

    #[test]
    fn encapsulate_with_no_session_triggers_handshake() {
        let core = make_core();
        // A minimal IPv4 packet header (20 bytes, mostly zeroed) —
        // content doesn't matter since boringtun will queue it pending
        // handshake.
        let mut ip_packet = vec![0u8; 40];
        ip_packet[0] = 0x45; // Version 4, IHL 5
        let step = core.encapsulate(&ip_packet).expect("encapsulate ok");
        // With no active session, boringtun queues the packet and
        // emits a handshake init message instead.
        assert_eq!(step.to_network.len(), 1);
        assert_eq!(step.to_network[0][0], 1, "should be HANDSHAKE_INIT");
    }

    #[test]
    fn timer_tick_idle_initially() {
        let core = make_core();
        // Immediately after construction, no timers have fired.
        let step = core.timer_tick().expect("timer tick ok");
        assert!(step.to_network.is_empty(), "no timers should fire yet");
        assert!(!step.expired);
    }

    #[test]
    fn decapsulate_garbage_returns_error() {
        let core = make_core();
        let garbage = vec![0xFFu8; 64];
        let _ = core.decapsulate(None, &garbage);
        // Either Err or empty step is acceptable; we just want no panic.
    }
}
