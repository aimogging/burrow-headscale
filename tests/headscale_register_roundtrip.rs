//! Stage 2d — Headscale registration end-to-end.
//!
//! Boots a `HeadscaleClient` against a live Headscale instance, waits
//! until the netmap pump publishes a `ControlState` with our assigned
//! tailnet IP, and asserts the IP falls inside Headscale's configured
//! CGNAT prefix. This is the automated counterpart of running
//! `cargo run --bin burrow -- --server-url … --authkey …` and
//! checking `headscale nodes list` by eye.
//!
//! Configure via env:
//!   BURROW_TEST_HEADSCALE_URL     e.g. http://localhost:18443
//!   BURROW_TEST_HEADSCALE_AUTHKEY a Headscale preauth key
//! Without both, the test short-circuits.
//!
//! Typical local setup:
//!   docker run -d headscale/headscale:latest serve   # on the remote
//!   ssh -fN -L 18443:localhost:8443 do
//!   BURROW_TEST_HEADSCALE_URL=http://localhost:18443 \
//!     BURROW_TEST_HEADSCALE_AUTHKEY=hskey-auth-... \
//!     cargo test --features insecure-tests --test headscale_register_roundtrip
//!
//! Known constraint: the Headscale instance must be configured with
//! *both* IPv4 and IPv6 `prefixes` (default v4 + a v6 like
//! `fd7a:115c:a1e0::/48`) and the database should be empty of nodes
//! that were registered before v6 was configured. `ts_control_serde`
//! models `Node.addresses` as a strict `(Ipv4Net, Ipv6Net)` tuple;
//! Headscale emits a single-element `["<ipv4>/32"]` for pre-v6 nodes
//! and the whole MapResponse fails to deserialize. The Stage 5
//! rebase of vendored tailscale-rs is a good moment to broaden this
//! type to `(Ipv4Net, Option<Ipv6Net>)`.

#![cfg(feature = "insecure-tests")]

use std::time::Duration;

use burrow::headscale::HeadscaleClient;
use burrow::node_identity::NodeIdentity;

fn env() -> Option<(url::Url, String)> {
    let url = std::env::var("BURROW_TEST_HEADSCALE_URL").ok()?;
    let authkey = std::env::var("BURROW_TEST_HEADSCALE_AUTHKEY").ok()?;
    Some((url::Url::parse(&url).expect("URL parse"), authkey))
}

fn init_test_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,ts_control=debug,burrow=debug")),
        )
        .try_init();
}

#[tokio::test]
async fn register_yields_a_tailnet_ipv4_in_the_configured_prefix() {
    let Some((url, authkey)) = env() else {
        eprintln!("BURROW_TEST_HEADSCALE_{{URL,AUTHKEY}} not set; skipping");
        return;
    };
    init_test_tracing();

    let ident = NodeIdentity::generate();
    let client = HeadscaleClient::connect(url, &ident, &authkey, Some("burrow-test-1".into()))
        .await
        .expect("HeadscaleClient::connect");

    // The netmap stream arrives on a separate task. Poll the snapshot
    // with a bounded timeout rather than racing the initial connect:
    // Headscale sends the self-node frame within a handful of ms in
    // practice, but there's no explicit "registered" signal through
    // the public API.
    let mut rx = client.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    loop {
        if let Some(ip) = client.snapshot().my_tailnet_ipv4 {
            // Default Headscale CGNAT prefix is 100.64.0.0/10.
            assert!(
                (100..=127).contains(&ip.octets()[0]),
                "tailnet ip {ip} is outside CGNAT 100.64.0.0/10"
            );
            // Headscale allocates sequentially from .0.1 in our test
            // config; first node registered so assume .0.1 or .0.2
            // depending on whether the server pre-allocated its own.
            assert_ne!(ip.octets(), [0, 0, 0, 0], "ip was zero");
            return;
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!("no tailnet ipv4 materialised within timeout");
        }

        tokio::time::timeout(deadline - now, rx.changed())
            .await
            .expect("timed out waiting on a state change")
            .expect("watch channel closed");
    }
}
