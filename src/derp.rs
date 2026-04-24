//! Thin wrapper over `ts_transport_derp::Client`.
//!
//! Owns the DERP connection + a tokio supervisor task that drives the
//! single `recv_one()` loop and pushes decoded peer packets onto an
//! mpsc channel. Sends go straight to the underlying client (which
//! internally serialises writes through its own `Mutex<FramedWrite>`).
//!
//! Scope limits for Stage 1b:
//! - No auto-reconnect. If the DERP stream dies the supervisor task
//!   exits; subsequent `send()` calls will fail with the upstream
//!   error. The caller is expected to drop the `DerpClient` and build
//!   a fresh one. Reconnect-with-backoff moves into Stage 2 when the
//!   Headscale netmap loop picks a new DERP region on disconnect.
//! - Single-consumer mpsc receiver. The data plane has exactly one
//!   consumer of inbound packets (the dispatch task that routes to
//!   `PeerTable`), so a broadcast channel would add overhead without
//!   a use case.

#![cfg(feature = "headscale")]

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_transport_derp::{frame::SendPacket, DefaultClient, ServerConnInfo};

#[derive(Debug)]
pub struct DerpInbound {
    pub sender: NodePublicKey,
    pub bytes: Bytes,
}

pub struct DerpClient {
    inner: Arc<DefaultClient>,
    supervisor: JoinHandle<()>,
}

impl DerpClient {
    /// Dial the first reachable server in `servers`, complete the DERP
    /// handshake with `node_keypair`, and spawn the recv supervisor.
    /// Returns the client plus the receiver end of the inbound stream —
    /// holding onto the `DerpClient` keeps the supervisor alive.
    pub async fn connect(
        servers: &[ServerConnInfo],
        node_keypair: &NodeKeyPair,
    ) -> Result<(Self, mpsc::UnboundedReceiver<DerpInbound>)> {
        let client = DefaultClient::connect(servers.iter(), node_keypair)
            .await
            .context("derp connect")?;
        let inner = Arc::new(client);

        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<DerpInbound>();
        let supervisor = tokio::spawn(supervise_recv(Arc::clone(&inner), inbound_tx));

        Ok((Self { inner, supervisor }, inbound_rx))
    }

    /// Send `payload` to the peer with node key `dst` via the DERP
    /// server. Bypasses the `UnderlayTransport` trait to avoid a direct
    /// dep on `ts_transport`: the trait's batch shape would force us
    /// to allocate an outer iterator on every packet for no benefit,
    /// since burrow's egress loop sends one packet at a time.
    pub async fn send(&self, dst: NodePublicKey, payload: &[u8]) -> Result<()> {
        self.inner
            .send_frame_with_extra(&SendPacket { dest: dst }, payload)
            .await
            .context("derp send")
    }
}

impl Drop for DerpClient {
    fn drop(&mut self) {
        self.supervisor.abort();
    }
}

async fn supervise_recv(
    client: Arc<DefaultClient>,
    inbound_tx: mpsc::UnboundedSender<DerpInbound>,
) {
    loop {
        match client.recv_one().await {
            Ok((sender, packet)) => {
                let bytes = packet_to_bytes(packet);
                if inbound_tx.send(DerpInbound { sender, bytes }).is_err() {
                    debug!("derp inbound receiver dropped; supervisor exiting");
                    break;
                }
            }
            Err(e) => {
                warn!(error = %e, "derp recv_one failed; supervisor exiting");
                break;
            }
        }
    }
}

fn packet_to_bytes(packet: PacketMut) -> Bytes {
    // PacketMut doesn't expose a zero-copy `into_bytes()`; `as_ref()` +
    // `Bytes::copy_from_slice` is fine for the per-packet path — WG
    // packets are <= 1500 bytes.
    Bytes::copy_from_slice(packet.as_ref())
}

/// Convenience: build a `ServerConnInfo` from a plain HTTPS URL using
/// the upstream helper's heuristic defaults. Intended for the spike
/// binary and tests; production code should construct `ServerConnInfo`
/// from Headscale's `DerpMap` with full TLS-validation settings.
pub fn server_conn_info_from_url(url: &str) -> Result<ServerConnInfo> {
    let parsed = url::Url::parse(url).with_context(|| format!("parse derp url {url}"))?;
    ServerConnInfo::default_from_url(&parsed)
        .context("URL doesn't match ts_transport_derp's default-from-URL heuristics (must be https)")
}
