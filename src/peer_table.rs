//! Multi-peer Tunn table for the Headscale fork.
//!
//! Replaces the single-`WgCore` transport assumption in `src/tunnel.rs`.
//! Each `Peer` owns its own `Tunn` instance, keyed by DERP routing
//! identity (`NodePublicKey`) and tailnet IPv4.
//!
//! Stage 1a skeleton: struct + basic CRUD. Dispatch integration lands
//! in Stage 3 when the netmap reconciler drives `reconcile()`.

#![cfg(feature = "headscale")]

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
}
