//! Stage 0 stub. Real implementation lands in Stage 2a.
//!
//! Target: control-plane client. Noise IK register against Headscale,
//! netmap long-poll, publishes a `watch<ControlState>` that carries
//! our tailnet IP, DERP region assignment, and current peer list.

#![cfg(feature = "headscale")]

pub struct HeadscaleClient {
    _unimplemented: (),
}

impl HeadscaleClient {
    pub fn todo() -> Self {
        todo!("stage 2a")
    }
}
