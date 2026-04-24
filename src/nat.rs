//! Connection tracking + destination/source IP rewrite. The NAT table is the
//! single source of truth for an in-flight connection: it owns the 5-tuple →
//! gateway-side `(virtual_ip, gateway_port)` mapping (so the egress rewrite
//! can restore the peer-visible src), the smoltcp ConnectionId, and the
//! lifecycle state.
//!
//! ## Two-index design
//!
//! * `entries`: full 5-tuple (`NatKey`) → `NatEntry`. `NatEntry` carries the
//!   per-flow `(virtual_ip, gateway_port)` pair.
//! * `by_gateway`: post-rewrite 4-tuple `(proto, peer_ip, peer_port,
//!   virtual_ip, gateway_port)` → 5-tuple `NatKey`, used on egress when both
//!   the original `dst_ip` AND `dst_port` have been replaced with smoltcp-side
//!   values.
//!
//! ## Why per-flow virtual_ip + gateway_port (Phase 11)
//!
//! Phase 9 fixed the SYN-scan eviction problem by allocating a per-flow
//! `gateway_port` from `32768..=65535`. That gave us 32K identifier slots —
//! enough to stop one peer's nmap from stomping its own flows, but tight
//! under sustained concurrent scan workloads from multiple peers (5 peers ×
//! 1500 pps × 127s kernel SYN-retry budget ≈ 950K concurrent in-flight).
//!
//! Phase 11 reframes the identifier: `gateway_port` is not protocol-meaningful
//! — it's just an opaque tag, present on the packet only between WG ingress
//! and the egress rewrite (both internal to burrow). The smoltcp interface IP
//! is similarly opaque. So we expand the identifier to `(virtual_ip,
//! gateway_port)` drawn from `198.18.0.0/15` (RFC 2544 benchmark range,
//! never on the public internet) × `1..=65535`. That's ~131070 virtual_ips
//! × 65535 ports = ~8.6 billion identifier slots per protocol. The bottleneck
//! moves entirely from identifier space to smoltcp socket-buffer memory.
//!
//! On egress, the lookup `(proto, peer_ip, peer_port, virtual_ip,
//! gateway_port)` is unique by construction and no flow can stomp another.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};

use crate::rewrite::{
    parse_5tuple, rewrite_dst_ip, rewrite_dst_port, rewrite_src_ip, rewrite_src_port, PROTO_TCP,
    PROTO_UDP,
};
use crate::runtime::ConnectionId;

/// Grace period after a TCP connection's smoltcp socket reports closed
/// before the entry is swept.
pub const DEFAULT_TCP_GRACE: Duration = Duration::from_secs(60);
/// Idle timeout for UDP entries (no smoltcp state to observe).
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(30);

/// 198.18.0.0/15 — RFC 2544 benchmark range. Used purely as an internal
/// identifier space; the addresses never appear on any wire outside burrow
/// (the egress rewrite restores the original_dst_ip before the packet
/// leaves the smoltcp side, and inbound packets are never sourced from
/// these addresses). Recognizable as synthetic in debug logs.
pub const VIRTUAL_CIDR_BASE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
pub const VIRTUAL_CIDR_BCAST: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 255);
pub const VIRTUAL_CIDR_PREFIX: u8 = 15;
/// Address assigned to the smoltcp `Interface`. Any non-network/broadcast
/// address inside the /15 works; we pick the lowest. With `set_any_ip(true)`
/// the interface accepts packets to any address in the /15.
pub const VIRTUAL_IFACE_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);

/// Inclusive lower / upper bounds of the virtual_ip pool (skip network and
/// broadcast addresses for hygiene).
const VIP_MIN_U32: u32 = 0xC612_0001; // 198.18.0.1
const VIP_MAX_U32: u32 = 0xC613_FFFE; // 198.19.255.254

/// Inclusive bounds of the per-vip port pool. We avoid 0 because it
/// collides with smoltcp's wildcard listen-endpoint semantics.
const PORT_MIN: u16 = 1;
const PORT_MAX: u16 = 65535;

/// Natural 5-tuple identifying a peer-initiated flow. Derivable purely from
/// the inbound packet — NO gateway-side state in here. The (virtual_ip,
/// gateway_port) pair that disambiguates the egress side lives on `NatEntry`.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct NatKey {
    pub proto: u8,
    pub peer_ip: Ipv4Addr,
    pub peer_port: u16,
    pub original_dst_ip: Ipv4Addr,
    pub original_dst_port: u16,
}

/// Egress-side index key. The peer's view of the smoltcp endpoint is
/// `(virtual_ip, gateway_port)`, so when an outbound packet from smoltcp
/// arrives carrying `(src=virtual_ip, src_port=gateway_port,
/// dst=peer_ip, dst_port=peer_port)`, we recover the full 5-tuple via this
/// index.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct KeyGw {
    proto: u8,
    peer_ip: Ipv4Addr,
    peer_port: u16,
    virtual_ip: Ipv4Addr,
    gateway_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Pending,
    Established,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy)]
pub struct NatEntry {
    /// Per-flow virtual address allocated on the smoltcp side. Inbound
    /// rewrite changes `dst_ip` to this value; smoltcp listens on
    /// `(virtual_ip, gateway_port)`.
    pub virtual_ip: Ipv4Addr,
    /// Per-flow port allocated on the smoltcp side. Inbound rewrite changes
    /// `dst_port` to this value; egress rewrite uses the (virtual_ip, port)
    /// pair to recover the `NatKey`.
    pub gateway_port: u16,
    /// Set once the smoltcp thread has issued a `ConnectionId` for this NAT
    /// entry. `None` until the first `EnsureTcpListener` reply lands (or for
    /// UDP entries, where smoltcp isn't involved).
    pub smoltcp_id: Option<ConnectionId>,
    pub state: ConnectionState,
    pub created: Instant,
    pub last_activity: Instant,
    pub expiry: Option<Instant>,
}

pub struct NatTable {
    inner: Mutex<NatInner>,
}

struct NatInner {
    entries: HashMap<NatKey, NatEntry>,
    by_gateway: HashMap<KeyGw, NatKey>,
    /// Set of (virtual_ip, gateway_port) pairs in current use.
    allocated: HashSet<(Ipv4Addr, u16)>,
    /// Round-robin allocator cursor.
    next_vip: u32,
    next_port: u16,
}

impl Default for NatInner {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            by_gateway: HashMap::new(),
            allocated: HashSet::new(),
            next_vip: VIP_MIN_U32,
            next_port: PORT_MIN,
        }
    }
}

impl NatTable {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NatInner::default()),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().entries.is_empty()
    }

    /// Inbound rewrite (peer → smoltcp). Registers or refreshes the entry,
    /// allocates a per-flow `(virtual_ip, gateway_port)` on first sight, and
    /// rewrites BOTH `dst_ip` → virtual_ip AND `dst_port` → gateway_port.
    /// Returns the (5-tuple, virtual_ip, gateway_port) so the caller can
    /// immediately register the matching smoltcp listener without a
    /// follow-up lookup.
    pub fn rewrite_inbound(&self, packet: &mut [u8]) -> Result<(NatKey, Ipv4Addr, u16)> {
        let view = parse_5tuple(packet)?;
        if view.proto != PROTO_TCP && view.proto != PROTO_UDP {
            bail!("rewrite_inbound: unsupported proto {}", view.proto);
        }
        let key = NatKey {
            proto: view.proto,
            peer_ip: view.src_ip,
            peer_port: view.src_port,
            original_dst_ip: view.dst_ip,
            original_dst_port: view.dst_port,
        };
        let now = Instant::now();
        let (virtual_ip, gateway_port) = {
            let mut inner = self.inner.lock().unwrap();
            // Hit on the existing 5-tuple → reuse its endpoint.
            if let Some(entry) = inner.entries.get_mut(&key) {
                entry.last_activity = now;
                (entry.virtual_ip, entry.gateway_port)
            } else {
                // New flow → allocate a fresh (virtual_ip, gateway_port).
                let (vip, gw) = allocate_virtual_endpoint(&mut inner)?;
                inner.entries.insert(
                    key,
                    NatEntry {
                        virtual_ip: vip,
                        gateway_port: gw,
                        smoltcp_id: None,
                        state: ConnectionState::Pending,
                        created: now,
                        last_activity: now,
                        expiry: None,
                    },
                );
                inner.by_gateway.insert(
                    KeyGw {
                        proto: key.proto,
                        peer_ip: key.peer_ip,
                        peer_port: key.peer_port,
                        virtual_ip: vip,
                        gateway_port: gw,
                    },
                    key,
                );
                (vip, gw)
            }
        };
        rewrite_dst_ip(packet, virtual_ip)?;
        rewrite_dst_port(packet, gateway_port)?;
        Ok((key, virtual_ip, gateway_port))
    }

    /// Outbound rewrite (smoltcp → peer). Looks up the entry by the
    /// gateway-side 5-tuple (because `dst_ip` is now the virtual_ip and
    /// `src_port` is the per-flow gateway_port) and restores BOTH `src_ip` →
    /// original_dst_ip AND `src_port` → original_dst_port so the peer sees a
    /// coherent return path.
    pub fn rewrite_outbound(&self, packet: &mut [u8]) -> Result<NatKey> {
        let view = parse_5tuple(packet)?;
        let key_gw = KeyGw {
            proto: view.proto,
            peer_ip: view.dst_ip,
            peer_port: view.dst_port,
            virtual_ip: view.src_ip,
            gateway_port: view.src_port,
        };
        let (key, original_dst_ip, original_dst_port) = {
            let mut inner = self.inner.lock().unwrap();
            let key = inner
                .by_gateway
                .get(&key_gw)
                .copied()
                .ok_or_else(|| anyhow!("rewrite_outbound: no NAT entry for {:?}", key_gw))?;
            let entry = inner
                .entries
                .get_mut(&key)
                .ok_or_else(|| anyhow!("rewrite_outbound: entry vanished for {:?}", key))?;
            entry.last_activity = Instant::now();
            (key, key.original_dst_ip, key.original_dst_port)
        };
        rewrite_src_ip(packet, original_dst_ip)?;
        rewrite_src_port(packet, original_dst_port)?;
        Ok(key)
    }

    /// Insert a `Pending` entry directly without touching the packet. Used by
    /// the connect-probe path (Phase 9 fix #1) to claim the NAT slot BEFORE
    /// any rewrite happens, so SYN retransmits arriving while the OS-side
    /// connect is in flight see an existing entry and short-circuit. Returns
    /// `None` if an entry already exists for this 5-tuple, leaving it in
    /// place. Returns `Some((virtual_ip, gateway_port))` on a fresh insertion.
    pub fn try_reserve_pending(&self, key: NatKey) -> Result<Option<(Ipv4Addr, u16)>> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        if inner.entries.contains_key(&key) {
            return Ok(None);
        }
        let (vip, gw) = allocate_virtual_endpoint(&mut inner)?;
        inner.entries.insert(
            key,
            NatEntry {
                virtual_ip: vip,
                gateway_port: gw,
                smoltcp_id: None,
                state: ConnectionState::Pending,
                created: now,
                last_activity: now,
                expiry: None,
            },
        );
        inner.by_gateway.insert(
            KeyGw {
                proto: key.proto,
                peer_ip: key.peer_ip,
                peer_port: key.peer_port,
                virtual_ip: vip,
                gateway_port: gw,
            },
            key,
        );
        Ok(Some((vip, gw)))
    }

    /// Remove an entry — used by the probe-failure path to roll back a
    /// `try_reserve_pending` that didn't lead to a real connection.
    pub fn evict_key(&self, key: NatKey) {
        let mut inner = self.inner.lock().unwrap();
        evict(&mut inner, key);
    }

    pub fn set_id(&self, key: NatKey, id: ConnectionId) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.smoltcp_id = Some(id);
        }
    }

    pub fn set_state(&self, key: NatKey, state: ConnectionState) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.state = state;
        }
    }

    /// Begin the close grace period. Subsequent `sweep_expired(now)` calls
    /// will remove the entry once `now >= now_at_call + grace`.
    pub fn mark_closing(&self, key: NatKey, grace: Duration) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.state = ConnectionState::Closing;
            entry.expiry = Some(Instant::now() + grace);
        }
    }

    /// Force the entry to expire on the next sweep.
    pub fn mark_closed(&self, key: NatKey) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.state = ConnectionState::Closed;
            entry.expiry = Some(Instant::now());
        }
    }

    /// Update `last_activity` to now.
    pub fn touch(&self, key: NatKey) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.last_activity = Instant::now();
        }
    }

    /// Remove entries whose `expiry` has passed. Returns the removed keys.
    pub fn sweep_expired(&self, now: Instant) -> Vec<NatKey> {
        let mut inner = self.inner.lock().unwrap();
        let to_remove: Vec<NatKey> = inner
            .entries
            .iter()
            .filter_map(|(k, e)| match e.expiry {
                Some(exp) if exp <= now => Some(*k),
                _ => None,
            })
            .collect();
        for key in &to_remove {
            evict(&mut inner, *key);
        }
        to_remove
    }

    /// Remove UDP entries idle longer than `idle_timeout`.
    pub fn sweep_udp_idle(&self, now: Instant, idle_timeout: Duration) -> Vec<NatKey> {
        let mut inner = self.inner.lock().unwrap();
        let to_remove: Vec<NatKey> = inner
            .entries
            .iter()
            .filter_map(|(k, e)| {
                if k.proto == PROTO_UDP && now.duration_since(e.last_activity) >= idle_timeout {
                    Some(*k)
                } else {
                    None
                }
            })
            .collect();
        for key in &to_remove {
            evict(&mut inner, *key);
        }
        to_remove
    }

    pub fn get(&self, key: NatKey) -> Option<NatEntry> {
        self.inner.lock().unwrap().entries.get(&key).copied()
    }

    /// Visit every entry (for diagnostics or bulk operations on the smoltcp
    /// thread). Holds the lock for the duration of the call.
    pub fn for_each<F: FnMut(&NatKey, &NatEntry)>(&self, mut f: F) {
        let inner = self.inner.lock().unwrap();
        for (k, e) in inner.entries.iter() {
            f(k, e);
        }
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Round-robin allocator over the (virtual_ip, gateway_port) cartesian
/// product within `198.18.0.0/15` × `1..=65535`. Walks ports first within
/// the current vip, then advances vip — keeps a single hot vip's pool
/// dense before scattering, which improves locality for inspecting
/// debug output.
///
/// Errors only on full exhaustion — ~8.6 billion slots, orders of
/// magnitude beyond realistic load.
fn allocate_virtual_endpoint(inner: &mut NatInner) -> Result<(Ipv4Addr, u16)> {
    let start_vip = clamp_vip(inner.next_vip);
    let start_port = clamp_port(inner.next_port);
    let mut vip = start_vip;
    let mut port = start_port;
    loop {
        let candidate = (Ipv4Addr::from(vip), port);
        if !inner.allocated.contains(&candidate) {
            inner.allocated.insert(candidate);
            // Advance cursor past this slot so the next allocation tries the
            // following one first.
            let (next_vip, next_port) = advance(vip, port);
            inner.next_vip = next_vip;
            inner.next_port = next_port;
            return Ok(candidate);
        }
        let (nv, np) = advance(vip, port);
        vip = nv;
        port = np;
        if vip == start_vip && port == start_port {
            bail!("virtual_endpoint pool exhausted");
        }
    }
}

fn clamp_vip(v: u32) -> u32 {
    if (VIP_MIN_U32..=VIP_MAX_U32).contains(&v) {
        v
    } else {
        VIP_MIN_U32
    }
}

fn clamp_port(p: u16) -> u16 {
    if (PORT_MIN..=PORT_MAX).contains(&p) {
        p
    } else {
        PORT_MIN
    }
}

/// Advance (vip, port) by one slot, wrapping at the pool boundaries.
fn advance(vip: u32, port: u16) -> (u32, u16) {
    if port == PORT_MAX {
        let next_vip = if vip == VIP_MAX_U32 {
            VIP_MIN_U32
        } else {
            vip + 1
        };
        (next_vip, PORT_MIN)
    } else {
        (vip, port + 1)
    }
}

fn evict(inner: &mut NatInner, key: NatKey) {
    if let Some(entry) = inner.entries.remove(&key) {
        let kgw = KeyGw {
            proto: key.proto,
            peer_ip: key.peer_ip,
            peer_port: key.peer_port,
            virtual_ip: entry.virtual_ip,
            gateway_port: entry.gateway_port,
        };
        if inner.by_gateway.get(&kgw) == Some(&key) {
            inner.by_gateway.remove(&kgw);
        }
        inner
            .allocated
            .remove(&(entry.virtual_ip, entry.gateway_port));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::PROTO_TCP;
    use crate::test_helpers::build_tcp_syn;
    use std::thread::sleep;

    fn vip_in_pool(addr: Ipv4Addr) -> bool {
        let v: u32 = addr.into();
        (VIP_MIN_U32..=VIP_MAX_U32).contains(&v)
    }

    #[test]
    fn ingress_creates_entry_and_rewrites_dst() {
        let table = NatTable::new();
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let (key, vip, gw) = table.rewrite_inbound(&mut pkt).unwrap();
        assert_eq!(key.peer_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(key.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(key.original_dst_port, 80);
        assert!(vip_in_pool(vip), "vip {vip} must be in the synthetic pool");
        assert!((PORT_MIN..=PORT_MAX).contains(&gw));
        assert_eq!(table.len(), 1);

        // packet's dst should now be (virtual_ip, gateway_port).
        let view = crate::rewrite::parse_5tuple(&pkt).unwrap();
        assert_eq!(view.dst_ip, vip);
        assert_eq!(view.dst_port, gw);

        let entry = table.get(key).unwrap();
        assert_eq!(entry.state, ConnectionState::Pending);
        assert!(entry.smoltcp_id.is_none());
        assert_eq!(entry.virtual_ip, vip);
        assert_eq!(entry.gateway_port, gw);
    }

    #[test]
    fn egress_restores_src_after_ingress() {
        let table = NatTable::new();
        let mut ing = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let (_, vip, gw) = table.rewrite_inbound(&mut ing).unwrap();

        // smoltcp would emit (src=vip:gw, dst=10.0.0.1:54321)
        let mut eg = build_tcp_syn(vip, Ipv4Addr::new(10, 0, 0, 1), gw, 54321);
        let key = table.rewrite_outbound(&mut eg).unwrap();
        assert_eq!(key.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(key.original_dst_port, 80);

        let view = crate::rewrite::parse_5tuple(&eg).unwrap();
        assert_eq!(view.src_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view.src_port, 80);
    }

    #[test]
    fn same_4tuple_different_dst_ip_coexist() {
        // The whole reason for per-flow endpoint allocation: nmap-style
        // workloads where one (peer_ip, peer_port) reaches many distinct
        // (dst_ip) on the same dst_port. Both flows must coexist with
        // distinct (virtual_ip, gateway_port) pairs so neither stomps the
        // other.
        let table = NatTable::new();
        let mut a = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let mut b = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 99),
            54321,
            80,
        );
        let (ka, vipa, gwa) = table.rewrite_inbound(&mut a).unwrap();
        let (kb, vipb, gwb) = table.rewrite_inbound(&mut b).unwrap();
        assert_ne!(ka, kb);
        assert_ne!(
            (vipa, gwa),
            (vipb, gwb),
            "distinct flows must get distinct endpoints"
        );
        assert_eq!(table.len(), 2, "both entries must coexist");
        assert!(table.get(ka).is_some());
        assert!(table.get(kb).is_some());
    }

    #[test]
    fn state_transitions_persist() {
        let table = NatTable::new();
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let (key, _, _) = table.rewrite_inbound(&mut pkt).unwrap();

        table.set_state(key, ConnectionState::Established);
        assert_eq!(table.get(key).unwrap().state, ConnectionState::Established);

        table.mark_closing(key, Duration::from_millis(50));
        let entry = table.get(key).unwrap();
        assert_eq!(entry.state, ConnectionState::Closing);
        assert!(entry.expiry.is_some());

        // sweep before expiry → no removal
        let removed = table.sweep_expired(Instant::now());
        assert!(removed.is_empty());
        assert_eq!(table.len(), 1);

        sleep(Duration::from_millis(60));
        let removed = table.sweep_expired(Instant::now());
        assert_eq!(removed, vec![key]);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn evict_releases_endpoint() {
        // After eviction, the (virtual_ip, gateway_port) returns to the pool.
        let table = NatTable::new();
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let (key, vip, gw) = table.rewrite_inbound(&mut pkt).unwrap();
        table.evict_key(key);
        assert!(table.get(key).is_none());
        assert!(
            !table.inner.lock().unwrap().allocated.contains(&(vip, gw)),
            "evicted endpoint must be released"
        );
    }

    #[test]
    fn try_reserve_pending_idempotent() {
        let table = NatTable::new();
        let key = NatKey {
            proto: PROTO_TCP,
            peer_ip: Ipv4Addr::new(10, 0, 0, 1),
            peer_port: 54321,
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 50),
            original_dst_port: 80,
        };
        let (vip, gw) = table
            .try_reserve_pending(key)
            .unwrap()
            .expect("first reserve");
        assert!(vip_in_pool(vip));
        assert!((PORT_MIN..=PORT_MAX).contains(&gw));
        let second = table.try_reserve_pending(key).unwrap();
        assert!(
            second.is_none(),
            "second reserve on same key must be a no-op"
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn udp_idle_sweep() {
        let table = NatTable::new();
        // Build a minimal UDP packet so we can register a UDP entry.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = PROTO_UDP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 50]);
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let csum = !(sum as u16);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt[20..22].copy_from_slice(&53u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes());

        let (key, _, _) = table.rewrite_inbound(&mut pkt).unwrap();
        assert_eq!(key.proto, PROTO_UDP);

        // Idle of 0 from "now in the future" sweeps everything immediately.
        let future = Instant::now() + Duration::from_secs(60);
        let removed = table.sweep_udp_idle(future, Duration::from_secs(30));
        assert_eq!(removed, vec![key]);
    }

    #[test]
    fn outbound_without_entry_errors() {
        let table = NatTable::new();
        let mut eg = build_tcp_syn(VIRTUAL_IFACE_ADDR, Ipv4Addr::new(10, 0, 0, 1), 80, 54321);
        let err = table.rewrite_outbound(&mut eg).unwrap_err();
        assert!(err.to_string().contains("no NAT entry"));
    }

    #[test]
    fn icmp_inbound_rejected() {
        // ICMP is handled by the dedicated path in proxy/icmp.rs (Phase 6),
        // not by NAT. rewrite_inbound should bail.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 50]);
        let table = NatTable::new();
        let err = table.rewrite_inbound(&mut pkt).unwrap_err();
        assert!(err.to_string().contains("unsupported proto"));
    }

    #[test]
    fn allocator_walks_port_then_vip() {
        // Two consecutive allocations should differ by exactly one slot in
        // the (vip, port) ordering: same vip, port+1 (until port wraps).
        let table = NatTable::new();
        let key1 = NatKey {
            proto: PROTO_TCP,
            peer_ip: Ipv4Addr::new(10, 0, 0, 1),
            peer_port: 1,
            original_dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            original_dst_port: 80,
        };
        let key2 = NatKey {
            proto: PROTO_TCP,
            peer_ip: Ipv4Addr::new(10, 0, 0, 1),
            peer_port: 2,
            original_dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            original_dst_port: 80,
        };
        let (v1, p1) = table.try_reserve_pending(key1).unwrap().unwrap();
        let (v2, p2) = table.try_reserve_pending(key2).unwrap().unwrap();
        assert_eq!(v1, v2, "consecutive allocs should stay on same vip");
        assert_eq!(p2, p1 + 1, "consecutive allocs should advance port by 1");
    }
}
