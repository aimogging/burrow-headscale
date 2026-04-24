//! Reverse-tunnel registry. Each entry records the tunnel metadata plus
//! a handle to the owning client's yamux connection, so that when a
//! peer hits the tunnel's listen port burrow can open an outbound
//! yamux substream to that client.
//!
//! Port-collision: first start on a `(proto, listen_port, bind)` combo
//! wins. Stops on the exact same key; tunnels auto-release when the
//! owning client's yamux connection closes (the control task evicts
//! them).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::sync::{mpsc, oneshot};
use yamux::Stream;

use crate::wire::{BindAddr, Proto, ReverseEntry, TunnelId};

/// Request handed to the owning yamux connection's driver task. The
/// driver polls `poll_new_outbound` and sends the resulting stream
/// back through `reply`. The driver task is the only owner of the
/// `Connection<T>`; anybody who wants to open a substream must go
/// through this channel.
pub type SubstreamOpener = mpsc::UnboundedSender<OpenRequest>;

pub struct OpenRequest {
    pub reply: oneshot::Sender<Result<Stream, String>>,
}

#[derive(Clone)]
pub struct RegEntry {
    pub tunnel_id: TunnelId,
    pub proto: Proto,
    pub listen_port: u16,
    pub bind: BindAddr,
    pub forward_to: String,
    /// Channel to request a new outbound substream on the owning
    /// client's yamux connection.
    pub opener: SubstreamOpener,
}

impl From<&RegEntry> for ReverseEntry {
    fn from(e: &RegEntry) -> Self {
        ReverseEntry {
            tunnel_id: e.tunnel_id,
            proto: e.proto,
            listen_port: e.listen_port,
            forward_to: e.forward_to.clone(),
            bind: e.bind,
        }
    }
}

pub struct ReverseRegistry {
    next_id: AtomicU64,
    inner: Mutex<Inner>,
}

struct Inner {
    /// Primary index: `(proto, listen_port, bind)` → entry. `bind` is
    /// part of the key because two tunnels CAN share a listen_port if
    /// their bind addresses differ (e.g. one on wg_ip:8080, another
    /// on 10.2.10.50:8080) — smoltcp's per-endpoint listener dispatch
    /// disambiguates at the TCP layer.
    by_key: HashMap<(Proto, u16, BindAddr), RegEntry>,
    /// tunnel_id → key, for O(1) stop.
    by_id: HashMap<TunnelId, (Proto, u16, BindAddr)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartError {
    PortInUse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StopError {
    UnknownTunnel,
}

impl ReverseRegistry {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            inner: Mutex::new(Inner {
                by_key: HashMap::new(),
                by_id: HashMap::new(),
            }),
        }
    }

    pub fn start(
        &self,
        proto: Proto,
        listen_port: u16,
        bind: BindAddr,
        forward_to: String,
        opener: SubstreamOpener,
    ) -> Result<TunnelId, StartError> {
        let mut inner = self.inner.lock().unwrap();
        let key = (proto, listen_port, bind);
        if inner.by_key.contains_key(&key) {
            return Err(StartError::PortInUse);
        }
        let tunnel_id = TunnelId(self.next_id.fetch_add(1, Ordering::Relaxed));
        inner.by_key.insert(
            key,
            RegEntry {
                tunnel_id,
                proto,
                listen_port,
                bind,
                forward_to,
                opener,
            },
        );
        inner.by_id.insert(tunnel_id, key);
        Ok(tunnel_id)
    }

    pub fn stop(&self, tunnel_id: TunnelId) -> Result<RegEntry, StopError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(key) = inner.by_id.remove(&tunnel_id) else {
            return Err(StopError::UnknownTunnel);
        };
        // Return the removed entry so the caller can tear down its
        // smoltcp listener.
        inner.by_key.remove(&key).ok_or(StopError::UnknownTunnel)
    }

    /// Find a tunnel that matches an incoming packet. `dst_ip` is the
    /// packet's destination; `wg_ip` is the node's WG address (for
    /// resolving `BindAddr::Default`). Returns the entry if any of the
    /// registered binds accepts `dst_ip`:
    /// - `Default` accepts `dst_ip == wg_ip`
    /// - `Any` accepts any `dst_ip`
    /// - `Ipv4(x)` accepts `dst_ip == x`
    pub fn lookup(
        &self,
        proto: Proto,
        dst_ip: Ipv4Addr,
        listen_port: u16,
        wg_ip: Ipv4Addr,
    ) -> Option<RegEntry> {
        let inner = self.inner.lock().unwrap();
        // Try Default (resolved to wg_ip) first, then Any, then
        // explicit Ipv4 match.
        for candidate_bind in [BindAddr::Default, BindAddr::Any, BindAddr::Ipv4(dst_ip)] {
            if let Some(entry) = inner.by_key.get(&(proto, listen_port, candidate_bind)) {
                let matches = match candidate_bind {
                    BindAddr::Default => dst_ip == wg_ip,
                    BindAddr::Any => true,
                    BindAddr::Ipv4(x) => dst_ip == x,
                };
                if matches {
                    return Some(entry.clone());
                }
            }
        }
        None
    }

    pub fn list(&self) -> Vec<ReverseEntry> {
        self.inner
            .lock()
            .unwrap()
            .by_key
            .values()
            .map(ReverseEntry::from)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ReverseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_opener() -> SubstreamOpener {
        let (tx, _rx) = mpsc::unbounded_channel();
        tx
    }

    #[test]
    fn start_and_lookup_roundtrip() {
        let reg = ReverseRegistry::new();
        let id = reg
            .start(
                Proto::Tcp,
                8080,
                BindAddr::Default,
                "host:9000".into(),
                dummy_opener(),
            )
            .unwrap();
        let wg_ip = Ipv4Addr::new(10, 0, 0, 2);
        let entry = reg.lookup(Proto::Tcp, wg_ip, 8080, wg_ip).unwrap();
        assert_eq!(entry.tunnel_id, id);
        assert_eq!(entry.forward_to, "host:9000");
    }

    #[test]
    fn default_bind_only_matches_wg_ip() {
        let reg = ReverseRegistry::new();
        reg.start(
            Proto::Tcp,
            22,
            BindAddr::Default,
            "h:22".into(),
            dummy_opener(),
        )
        .unwrap();
        let wg_ip = Ipv4Addr::new(10, 0, 0, 2);
        assert!(reg.lookup(Proto::Tcp, wg_ip, 22, wg_ip).is_some());
        // Different dst → no match.
        let other = Ipv4Addr::new(10, 0, 0, 99);
        assert!(reg.lookup(Proto::Tcp, other, 22, wg_ip).is_none());
    }

    #[test]
    fn any_bind_matches_any_dst() {
        let reg = ReverseRegistry::new();
        reg.start(Proto::Tcp, 80, BindAddr::Any, "h:80".into(), dummy_opener())
            .unwrap();
        let wg_ip = Ipv4Addr::new(10, 0, 0, 2);
        assert!(reg.lookup(Proto::Tcp, wg_ip, 80, wg_ip).is_some());
        assert!(reg
            .lookup(Proto::Tcp, Ipv4Addr::new(203, 0, 113, 7), 80, wg_ip)
            .is_some());
    }

    #[test]
    fn explicit_bind_matches_only_that_ip() {
        let reg = ReverseRegistry::new();
        let pinned = Ipv4Addr::new(10, 2, 10, 50);
        reg.start(
            Proto::Tcp,
            80,
            BindAddr::Ipv4(pinned),
            "h:80".into(),
            dummy_opener(),
        )
        .unwrap();
        let wg_ip = Ipv4Addr::new(10, 0, 0, 2);
        assert!(reg.lookup(Proto::Tcp, pinned, 80, wg_ip).is_some());
        assert!(reg.lookup(Proto::Tcp, wg_ip, 80, wg_ip).is_none());
    }

    #[test]
    fn port_collision_rejected() {
        let reg = ReverseRegistry::new();
        reg.start(
            Proto::Tcp,
            443,
            BindAddr::Default,
            "h:443".into(),
            dummy_opener(),
        )
        .unwrap();
        let err = reg.start(
            Proto::Tcp,
            443,
            BindAddr::Default,
            "other:8443".into(),
            dummy_opener(),
        );
        assert_eq!(err, Err(StartError::PortInUse));
    }

    #[test]
    fn same_port_different_bind_coexist() {
        let reg = ReverseRegistry::new();
        let a = reg
            .start(
                Proto::Tcp,
                443,
                BindAddr::Default,
                "h:443".into(),
                dummy_opener(),
            )
            .unwrap();
        let b = reg
            .start(
                Proto::Tcp,
                443,
                BindAddr::Ipv4(Ipv4Addr::new(10, 2, 10, 50)),
                "other:443".into(),
                dummy_opener(),
            )
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn stop_frees_port() {
        let reg = ReverseRegistry::new();
        let id = reg
            .start(
                Proto::Tcp,
                8080,
                BindAddr::Default,
                "h:9000".into(),
                dummy_opener(),
            )
            .unwrap();
        let entry = reg.stop(id).unwrap();
        assert_eq!(entry.tunnel_id, id);
        reg.start(
            Proto::Tcp,
            8080,
            BindAddr::Default,
            "h:9001".into(),
            dummy_opener(),
        )
        .unwrap();
    }

    #[test]
    fn stop_unknown_errors() {
        let reg = ReverseRegistry::new();
        let err = reg.stop(TunnelId(999));
        assert!(matches!(err, Err(StopError::UnknownTunnel)));
    }

    #[test]
    fn tunnel_ids_unique() {
        let reg = ReverseRegistry::new();
        let a = reg
            .start(
                Proto::Tcp,
                1,
                BindAddr::Default,
                "h:1".into(),
                dummy_opener(),
            )
            .unwrap();
        let b = reg
            .start(
                Proto::Tcp,
                2,
                BindAddr::Default,
                "h:2".into(),
                dummy_opener(),
            )
            .unwrap();
        assert_ne!(a, b);
    }
}
