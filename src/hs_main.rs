//! Stage 2b/c (MVP): headscale-path binary entry.
//!
//! Parses `--server-url` / `--authkey` / `--hostname`, generates a
//! fresh `NodeIdentity`, connects to Headscale via [`HeadscaleClient`],
//! waits for the first netmap snapshot that carries our assigned
//! tailnet IPv4, then blocks on ctrl-c.
//!
//! This is the *minimum* runnable headscale-path entry point. It is
//! already enough to register a node (it appears in
//! `headscale nodes list`) and to observe the netmap stream staying
//! open. The data plane (DERP + PeerTable + smoltcp wiring) lands in
//! Stage 3, which expands `run()` below with the ingress/egress loops
//! that mirror `src/main.rs` for the wg-quick transport.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;

use crate::headscale::HeadscaleClient;
use crate::node_identity::NodeIdentity;

/// CLI options understood by the headscale path. Mirrors the shape
/// the `Cli` struct in `main.rs` exposes; broken out here so the
/// wg-quick path doesn't pull headscale-only types when the feature
/// is off.
#[derive(Debug, Clone)]
pub struct HeadscaleArgs {
    pub server_url: Url,
    pub authkey: String,
    pub hostname: Option<String>,
}

pub async fn run(args: HeadscaleArgs) -> Result<()> {
    // Tracing is initialised here instead of in `main` because the
    // wg-quick path has its own init block. Using `try_init` so a
    // second call (e.g. from tests) doesn't panic.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,burrow=debug,ts_control=info")),
        )
        .try_init();

    info!(server_url = %args.server_url, "connecting to Headscale");
    let ident = NodeIdentity::generate();
    let client = HeadscaleClient::connect(args.server_url, &ident, &args.authkey, args.hostname)
        .await
        .context("HeadscaleClient::connect")?;

    // Wait for the first netmap delta that gives us a tailnet IPv4.
    // Headscale typically sends this within a few ms of register; we
    // fail loudly if it doesn't arrive so deployment scripts notice
    // misconfigured prefixes or policies early.
    let mut rx = client.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let tailnet_ip = loop {
        if let Some(ip) = client.snapshot().my_tailnet_ipv4 {
            break ip;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(anyhow!(
                "timed out waiting for Headscale to assign a tailnet IP"
            ));
        }
        tokio::time::timeout(deadline - now, rx.changed())
            .await
            .map_err(|_| anyhow!("netmap stream produced no state change inside 10s"))?
            .context("netmap watch channel closed")?;
    };
    info!(%tailnet_ip, "registered with Headscale");

    // Stage 2b/c MVP: no data plane yet. Report and idle until
    // shutdown so operators can confirm the registration looks sane
    // from `headscale nodes list` before the reconciler lands in
    // Stage 3.
    warn!("data plane not yet wired up (Stage 3); idling until ctrl-c");
    signal::ctrl_c().await.context("ctrl-c handler")?;
    info!("shutting down");
    Ok(())
}
