//! Stage 0 stub. Real implementation lands in Stage 1a.
//!
//! Target: a table of `Peer`s keyed by Curve25519 disco key (for DERP
//! addressing) and by tailnet IPv4 (for egress routing). Each `Peer`
//! owns a `boringtun::Tunn` via the transport-agnostic `WgCore`
//! wrapper in `src/tunnel.rs`.

#![cfg(feature = "headscale")]

pub struct PeerTable {
    _unimplemented: (),
}

impl PeerTable {
    pub fn new() -> Self {
        todo!("stage 1a")
    }
}
