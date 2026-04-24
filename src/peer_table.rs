//! Multi-peer Tunn table for the Headscale fork.
//!
//! Replaces the single-`WgCore` transport assumption in `src/tunnel.rs`.
//! Each `Peer` owns its own `Tunn` instance, keyed by DERP routing
//! identity (`NodePublicKey`) and tailnet IPv4.
//!
//! Stage 1a skeleton: struct + basic CRUD. Dispatch integration lands
//! in Stage 3 when the netmap reconciler drives `reconcile()`.

use std::net::Ipv4Addr;
use std::sync::Arc;

use dashmap::DashMap;
use ts_keys::NodePublicKey;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tunnel::WgCore;

pub struct Peer {
    /// DERP routing address. Tailscale-rs's DERP layer authenticates
    /// peers to the relay by node key; the disco key (a separate
    /// Curve25519 key used by the disco protocol for direct-connection
    /// negotiation) is not used by Stage 1-3 burrow.
    pub node_key: NodePublicKey,

    /// boringtun peer public key. Fed to `Tunn::new` and otherwise
    /// opaque here. In real Tailscale this is the same key material as
    /// `node_key`; we keep them separate because `WgCore::from_raw`
    /// wants an `x25519_dalek::PublicKey` while the DERP layer works
    /// in `NodePublicKey`, and the conversion boundary lives at the
    /// `Peer` constructor.
    pub wg_pub: PublicKey,

    /// IPv4 this peer occupies on the tailnet. Assigned by Headscale
    /// in the `MapResponse.Node.addresses` field; static for the
    /// lifetime of the `Peer`.
    pub tailnet_ip: Ipv4Addr,

    pub core: WgCore,
}

impl Peer {
    pub fn new(
        node_key: NodePublicKey,
        wg_pub: PublicKey,
        tailnet_ip: Ipv4Addr,
        our_private: StaticSecret,
        persistent_keepalive: Option<u16>,
    ) -> Self {
        let core = WgCore::from_raw(our_private, wg_pub, None, persistent_keepalive);
        Self {
            node_key,
            wg_pub,
            tailnet_ip,
            core,
        }
    }
}

pub struct PeerTable {
    /// DERP ingress path: on each inbound frame we look up the sender's
    /// `NodePublicKey` to find which `Tunn` should decapsulate it.
    by_node_key: DashMap<NodePublicKey, Arc<Peer>>,

    /// Egress path: smoltcp emits an IPv4 packet with an arbitrary dst;
    /// we look up the matching `Peer` by that IP and hand the packet
    /// to its `Tunn` for encapsulation + DERP send.
    by_tnet_ip: DashMap<Ipv4Addr, Arc<Peer>>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            by_node_key: DashMap::new(),
            by_tnet_ip: DashMap::new(),
        }
    }

    /// Insert or replace. If a peer with the same `node_key` already
    /// exists, its old `tailnet_ip` entry is removed so the reverse
    /// index doesn't go stale. Returns the replaced `Arc<Peer>` if one
    /// was evicted.
    pub fn insert(&self, peer: Peer) -> Option<Arc<Peer>> {
        let peer = Arc::new(peer);
        let old = self.by_node_key.insert(peer.node_key, Arc::clone(&peer));
        if let Some(ref old_peer) = old {
            if old_peer.tailnet_ip != peer.tailnet_ip {
                self.by_tnet_ip.remove(&old_peer.tailnet_ip);
            }
        }
        self.by_tnet_ip.insert(peer.tailnet_ip, peer);
        old
    }

    /// Remove a peer and both of its indices. Returns the evicted
    /// `Arc<Peer>` if it was present. Dropping the returned Arc frees
    /// the `Tunn`'s internal queues.
    pub fn remove(&self, node_key: &NodePublicKey) -> Option<Arc<Peer>> {
        let (_, peer) = self.by_node_key.remove(node_key)?;
        self.by_tnet_ip.remove(&peer.tailnet_ip);
        Some(peer)
    }

    pub fn by_node_key(&self, node_key: &NodePublicKey) -> Option<Arc<Peer>> {
        self.by_node_key.get(node_key).map(|e| Arc::clone(&e))
    }

    pub fn by_tailnet_ip(&self, ip: &Ipv4Addr) -> Option<Arc<Peer>> {
        self.by_tnet_ip.get(ip).map(|e| Arc::clone(&e))
    }

    pub fn len(&self) -> usize {
        self.by_node_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_node_key.is_empty()
    }

    /// Bring the table in line with a desired peer set, typically drawn
    /// from [`crate::headscale::ControlState::peers`].
    ///
    /// - peers in `want` that aren't in the table are constructed via
    ///   [`Peer::new`] with a clone of the node's own WG private key
    ///   and inserted.
    /// - peers in the table whose node key is absent from `want` are
    ///   removed. Dropping the evicted `Arc<Peer>` frees that `Tunn`'s
    ///   pending encrypt/decrypt queues; no explicit teardown needed
    ///   because boringtun holds no I/O resources.
    /// - peers whose tailnet IPv4 changed in `want` are replaced in
    ///   full (a new `Peer`, which means a fresh `Tunn`). The previous
    ///   encryption session is discarded, which forces a re-handshake
    ///   on the next data packet. This is the rare path — Tailscale
    ///   does not normally re-address nodes.
    ///
    /// The `keepalive` argument is forwarded to every newly-constructed
    /// `Peer`. `None` means "no persistent keepalive" — a typical
    /// Headscale deployment doesn't need one because DERP itself keeps
    /// the TCP connection warm.
    pub fn reconcile(
        &self,
        want: &[crate::headscale::PeerInfo],
        ident: &crate::node_identity::NodeIdentity,
        keepalive: Option<u16>,
    ) {
        use std::collections::HashSet;

        // Build the desired key set once.
        let want_keys: HashSet<NodePublicKey> = want.iter().map(|p| p.node_key).collect();

        // Step 1: evict peers that are no longer wanted.
        let doomed: Vec<NodePublicKey> = self
            .by_node_key
            .iter()
            .filter_map(|entry| {
                let k = *entry.key();
                (!want_keys.contains(&k)).then_some(k)
            })
            .collect();
        for k in doomed {
            self.remove(&k);
        }

        // Step 2: upsert the wanted set. `insert` is idempotent on the
        // node_key path; we only pay the `Peer::new` cost when we
        // actually need a new Tunn.
        for info in want {
            let existing = self.by_node_key.get(&info.node_key).map(|e| Arc::clone(&e));
            match existing {
                Some(prev) if prev.tailnet_ip == info.tailnet_ipv4 => {
                    // Same identity, same IP — nothing to do.
                }
                _ => {
                    let wg_pub = x25519_dalek::PublicKey::from(info.node_key.to_bytes());
                    self.insert(Peer::new(
                        info.node_key,
                        wg_pub,
                        info.tailnet_ipv4,
                        ident.wg_private(),
                        keepalive,
                    ));
                }
            }
        }
    }

    /// Iterate all peers. Used by the 250ms timer tick to drive each
    /// `Tunn`'s keepalive/retransmit state. The `DashMap` shard locks
    /// are released between invocations of `f` so concurrent ingress
    /// paths don't stall.
    pub fn for_each<F: FnMut(&Arc<Peer>)>(&self, mut f: F) {
        for entry in self.by_node_key.iter() {
            f(entry.value());
        }
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_node_key(byte: u8) -> NodePublicKey {
        NodePublicKey::from([byte; 32])
    }

    fn mk_peer(node_byte: u8, wg_byte: u8, ip: [u8; 4]) -> Peer {
        let priv_key = StaticSecret::from([0x11u8; 32]);
        Peer::new(
            mk_node_key(node_byte),
            PublicKey::from([wg_byte; 32]),
            Ipv4Addr::from(ip),
            priv_key,
            Some(25),
        )
    }

    #[test]
    fn insert_and_lookup_by_both_indices() {
        let table = PeerTable::new();
        let peer = mk_peer(0x01, 0x02, [100, 64, 0, 1]);
        let node_key = peer.node_key;
        let ip = peer.tailnet_ip;
        assert!(table.insert(peer).is_none());
        assert!(table.by_node_key(&node_key).is_some());
        assert!(table.by_tailnet_ip(&ip).is_some());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn remove_clears_both_indices() {
        let table = PeerTable::new();
        let peer = mk_peer(0x03, 0x04, [100, 64, 0, 2]);
        let node_key = peer.node_key;
        let ip = peer.tailnet_ip;
        table.insert(peer);
        assert!(table.remove(&node_key).is_some());
        assert!(table.by_node_key(&node_key).is_none());
        assert!(table.by_tailnet_ip(&ip).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn reinsert_updates_tailnet_ip_index() {
        let table = PeerTable::new();
        let first = mk_peer(0x05, 0x06, [100, 64, 0, 3]);
        let node_key = first.node_key;
        let first_ip = first.tailnet_ip;
        table.insert(first);

        // Same node_key, new tailnet_ip — the stale ip→peer mapping must go.
        let second = mk_peer(0x05, 0x06, [100, 64, 0, 99]);
        let second_ip = second.tailnet_ip;
        let evicted = table.insert(second);
        assert!(evicted.is_some());
        assert!(table.by_tailnet_ip(&first_ip).is_none());
        assert!(table.by_tailnet_ip(&second_ip).is_some());
        assert_eq!(table.len(), 1);
        assert_eq!(table.by_node_key(&node_key).unwrap().tailnet_ip, second_ip);
    }

    #[test]
    fn for_each_visits_every_peer() {
        let table = PeerTable::new();
        for i in 0..5u8 {
            table.insert(mk_peer(0x10 + i, 0x20 + i, [100, 64, 0, 10 + i]));
        }
        let mut count = 0;
        table.for_each(|_| count += 1);
        assert_eq!(count, 5);
    }

    fn mk_info(byte: u8, ip: [u8; 4]) -> crate::headscale::PeerInfo {
        crate::headscale::PeerInfo {
            node_id: byte as i64,
            node_key: mk_node_key(byte),
            disco_key: None,
            tailnet_ipv4: Ipv4Addr::from(ip),
            hostname: format!("peer-{byte}"),
            home_region: None,
        }
    }

    #[test]
    fn reconcile_adds_missing_peers() {
        let table = PeerTable::new();
        let ident = crate::node_identity::NodeIdentity::generate();
        table.reconcile(
            &[
                mk_info(0xa0, [100, 64, 0, 10]),
                mk_info(0xa1, [100, 64, 0, 11]),
            ],
            &ident,
            None,
        );
        assert_eq!(table.len(), 2);
        assert!(table.by_node_key(&mk_node_key(0xa0)).is_some());
        assert!(table
            .by_tailnet_ip(&"100.64.0.11".parse().unwrap())
            .is_some());
    }

    #[test]
    fn reconcile_evicts_peers_absent_from_desired_set() {
        let table = PeerTable::new();
        let ident = crate::node_identity::NodeIdentity::generate();
        // Seed with three peers.
        table.reconcile(
            &[
                mk_info(0xb0, [100, 64, 0, 20]),
                mk_info(0xb1, [100, 64, 0, 21]),
                mk_info(0xb2, [100, 64, 0, 22]),
            ],
            &ident,
            None,
        );
        assert_eq!(table.len(), 3);
        // Reconcile down to one.
        table.reconcile(&[mk_info(0xb1, [100, 64, 0, 21])], &ident, None);
        assert_eq!(table.len(), 1);
        assert!(table.by_node_key(&mk_node_key(0xb0)).is_none());
        assert!(table.by_node_key(&mk_node_key(0xb1)).is_some());
        assert!(table.by_node_key(&mk_node_key(0xb2)).is_none());
    }

    #[test]
    fn reconcile_replaces_peer_whose_tailnet_ip_changed() {
        let table = PeerTable::new();
        let ident = crate::node_identity::NodeIdentity::generate();
        table.reconcile(&[mk_info(0xc0, [100, 64, 0, 30])], &ident, None);
        let original = table.by_node_key(&mk_node_key(0xc0)).unwrap();

        table.reconcile(&[mk_info(0xc0, [100, 64, 0, 99])], &ident, None);
        assert!(table
            .by_tailnet_ip(&"100.64.0.30".parse().unwrap())
            .is_none());
        let replaced = table.by_node_key(&mk_node_key(0xc0)).unwrap();
        assert_eq!(
            replaced.tailnet_ip,
            "100.64.0.99".parse::<Ipv4Addr>().unwrap()
        );
        // The new Peer is a fresh construction (not the same Arc).
        assert!(!Arc::ptr_eq(&original, &replaced));
    }

    #[test]
    fn reconcile_is_stable_on_identical_repeats() {
        let table = PeerTable::new();
        let ident = crate::node_identity::NodeIdentity::generate();
        let set = vec![mk_info(0xd0, [100, 64, 0, 40])];
        table.reconcile(&set, &ident, None);
        let first = table.by_node_key(&mk_node_key(0xd0)).unwrap();

        // Second reconcile with an identical set must not rebuild the
        // Peer — if it did, we'd throw away an established Tunn
        // session on every netmap delta. Arc pointer equality is the
        // strongest signal that no replacement happened.
        table.reconcile(&set, &ident, None);
        let second = table.by_node_key(&mk_node_key(0xd0)).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }
}
