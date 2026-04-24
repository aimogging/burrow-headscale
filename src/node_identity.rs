//! Per-process cryptographic identity for the headscale data plane.
//!
//! Structurally a thin wrapper over [`ts_keys::NodeState`], which already
//! bundles the four X25519 keypairs Tailscale uses (machine, node, disco,
//! network lock). Burrow only needs three of those in play:
//!
//! - `node_keys` — authenticates the control channel to Headscale (Noise
//!   IK handshake) AND the DERP handshake AND identifies us as a WG peer.
//!   Tailscale's on-wire protocol treats the node public key *as* the
//!   WireGuard peer public key. Our `boringtun::Tunn` therefore uses
//!   `node_keys.private` as its local static secret, and peer_table's
//!   `wg_pub` for a given remote is that peer's `node_keys.public`.
//! - `disco_keys` — reserved for the Tailscale disco protocol (peer
//!   endpoint discovery for direct connections). Stage 1-3 burrow does
//!   not exchange disco packets, but the key is materialised here so
//!   registration with Headscale can advertise it.
//! - `machine_keys` — hardware identity, used by the control-plane Noise
//!   IK handshake. `ts_control::AsyncControlClient::connect` reads this
//!   via the shared `NodeState`.
//!
//! Nothing persists to disk (design constraint): `generate()` draws fresh
//! material each boot.

#![cfg(feature = "headscale")]

use ts_keys::NodeState;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct NodeIdentity {
    pub state: NodeState,
}

impl NodeIdentity {
    /// Generate a fresh identity. Each of the four keypairs inside
    /// `NodeState` draws independently from the OS RNG; nothing is
    /// derived, nothing is persisted.
    pub fn generate() -> Self {
        Self {
            state: NodeState::generate(),
        }
    }

    /// The WireGuard private key for this node. Callers typically clone
    /// this per-peer since `boringtun::Tunn::new` takes ownership.
    ///
    /// Identical to `state.node_keys.private` — the distinction is for
    /// documentation at call sites that reason in boringtun terms rather
    /// than tailcfg terms.
    ///
    /// Going through `to_bytes()` is deliberate: boringtun and the
    /// vendored `ts_keys` sit on different `x25519-dalek` versions
    /// (2.x vs 3.0-pre), so the blanket `From<NodePrivateKey>` impl
    /// wouldn't resolve to our `StaticSecret`. The raw scalar is the
    /// same in both versions so the round-trip is lossless.
    pub fn wg_private(&self) -> StaticSecret {
        StaticSecret::from(self.state.node_keys.private.to_bytes())
    }

    /// Our WireGuard public key (= Tailscale node public key). Remote
    /// peers addressing us in the tailnet use this same 32-byte value.
    pub fn wg_public(&self) -> PublicKey {
        PublicKey::from(&self.wg_private())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `wg_public` must match the derived public of `node_keys.private`
    /// — same key material by design. Separately, the disco key must
    /// be independent of the node key; conflating them would let anyone
    /// who observed a disco-protocol payload also forge WG traffic.
    #[test]
    fn generate_binds_wg_to_node_and_keeps_disco_distinct() {
        let ident = NodeIdentity::generate();

        let wg_pub = ident.wg_public().to_bytes();
        let node_pub: [u8; 32] = ident.state.node_keys.public.into();
        let disco_pub: [u8; 32] = ident.state.disco_keys.public.into();

        assert_eq!(
            wg_pub, node_pub,
            "wg pubkey equals node pubkey (Tailscale invariant)"
        );
        assert_ne!(disco_pub, node_pub, "disco key is independent of node key");
    }

    /// Two successive invocations must produce independent identities.
    /// Deterministic output would signal a seeded RNG or a cache bug.
    #[test]
    fn generate_is_non_deterministic() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();

        let a_node: [u8; 32] = a.state.node_keys.public.into();
        let b_node: [u8; 32] = b.state.node_keys.public.into();
        assert_ne!(a_node, b_node, "two generates produced the same node key");

        let a_disco: [u8; 32] = a.state.disco_keys.public.into();
        let b_disco: [u8; 32] = b.state.disco_keys.public.into();
        assert_ne!(
            a_disco, b_disco,
            "two generates produced the same disco key"
        );

        let a_machine: [u8; 32] = a.state.machine_keys.public.into();
        let b_machine: [u8; 32] = b.state.machine_keys.public.into();
        assert_ne!(
            a_machine, b_machine,
            "two generates produced the same machine key"
        );
    }
}
