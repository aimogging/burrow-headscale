//! Per-process cryptographic identity for the headscale data plane.
//!
//! Three distinct X25519 keypairs are needed at once:
//!
//! - `wg_private` feeds `boringtun::noise::Tunn::new` on our side of every
//!   peer relationship. It is identical across all `Peer`s we maintain in
//!   `peer_table.rs`.
//! - `disco_key` is kept for the Tailscale disco protocol (peer endpoint
//!   negotiation). Stage 1-3 burrow doesn't use it on the wire, but we
//!   materialise the key now so the shape of `NodeIdentity` is stable
//!   across stages.
//! - `node_key` authenticates us both to Headscale (Noise IK handshake in
//!   `headscale.rs`) and to the DERP relay (handshake in
//!   `ts_transport_derp::Client::handshake`).
//!
//! Per the project constraint that nothing persists to disk, a fresh
//! identity is minted on every process start. Callers are expected to
//! treat `NodeIdentity` as owned state that lives for the lifetime of the
//! runtime; clone the sub-fields if individual tasks need their own
//! copies (e.g. each `Peer` takes a `StaticSecret::clone()` of the WG
//! private).

#![cfg(feature = "headscale")]

use ts_keys::{DiscoKeyPair, NodeKeyPair};
use x25519_dalek::StaticSecret;

pub struct NodeIdentity {
    pub wg_private: StaticSecret,
    pub disco_key: DiscoKeyPair,
    pub node_key: NodeKeyPair,
}

impl NodeIdentity {
    /// Generate a fresh identity. Each of the three keypairs is drawn
    /// independently from the OS RNG via its own constructor; there is no
    /// shared seed or derivation, so recovering one from another is not
    /// possible.
    pub fn generate() -> Self {
        Self {
            wg_private: StaticSecret::random(),
            disco_key: DiscoKeyPair::new(),
            node_key: NodeKeyPair::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::PublicKey;

    /// Each of the three key materials must be byte-distinct from the
    /// others within a single identity. If any two happen to match it
    /// signals a construction bug — e.g. all three secretly sharing one
    /// underlying key — far more than it signals a 2^-256 RNG collision.
    #[test]
    fn generate_produces_three_distinct_public_keys() {
        let ident = NodeIdentity::generate();

        let wg_pub = PublicKey::from(&ident.wg_private).to_bytes();
        let disco_pub: [u8; 32] = ident.disco_key.public.into();
        let node_pub: [u8; 32] = ident.node_key.public.into();

        assert_ne!(
            wg_pub, disco_pub,
            "wg_private derives to same public as disco_key"
        );
        assert_ne!(
            wg_pub, node_pub,
            "wg_private derives to same public as node_key"
        );
        assert_ne!(disco_pub, node_pub, "disco_key and node_key share a public");
    }

    /// Two successive invocations must produce independent identities.
    /// If they match, either the RNG is seeded deterministically or
    /// `generate` is caching — both are bugs.
    #[test]
    fn generate_is_non_deterministic() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();

        let a_wg = PublicKey::from(&a.wg_private).to_bytes();
        let b_wg = PublicKey::from(&b.wg_private).to_bytes();
        assert_ne!(a_wg, b_wg, "two calls produced the same wg_private");

        let a_disco: [u8; 32] = a.disco_key.public.into();
        let b_disco: [u8; 32] = b.disco_key.public.into();
        assert_ne!(a_disco, b_disco, "two calls produced the same disco_key");

        let a_node: [u8; 32] = a.node_key.public.into();
        let b_node: [u8; 32] = b.node_key.public.into();
        assert_ne!(a_node, b_node, "two calls produced the same node_key");
    }
}
