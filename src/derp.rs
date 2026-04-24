//! Stage 0 stub. Real implementation lands in Stage 1b.
//!
//! Target: thin wrapper over `ts_transport_derp`. Exposes
//! `send(disco_key, bytes)` / `subscribe() -> recv<DerpInbound>`
//! so the rest of burrow never imports tailscale-rs directly.

#![cfg(feature = "headscale")]

pub struct DerpClient {
    _unimplemented: (),
}

impl DerpClient {
    pub fn todo() -> Self {
        todo!("stage 1b")
    }
}
