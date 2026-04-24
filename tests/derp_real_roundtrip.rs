//! Stage 1e — real-DERP transport validation.
//!
//! Runs the same shape of handshake round-trip as
//! `tests/derp_stub_roundtrip.rs`, but against an actual Headscale DERP
//! server (via a self-signed cert, so the `insecure-for-tests` feature
//! in `ts_transport_derp` bypasses cert validation).
//!
//! The Stage 1d/3e in-memory stub already covers the correctness of our
//! own code (Peer + PeerTable + WgCore::from_raw composition). This
//! test covers the transport layer that lives entirely in the vendored
//! crate: TLS handshake, HTTP upgrade, WebSocket framing, control-frame
//! handling (KeepAlive/Ping/Pong), `SendPacket`/`RecvPacket` routing
//! keyed by node public key.
//!
//! Opt in at runtime via the `BURROW_TEST_DERP_URL` environment variable
//! pointing at `https://<host>:<port>` of a reachable Headscale (or bare
//! derper). Without that variable the test short-circuits, so the
//! broader test suite stays hermetic on machines without the tunnel
//! up.
//!
//! Typical local setup (see session notes):
//!   ssh -fN -L 18443:localhost:8443 do
//!   BURROW_TEST_DERP_URL=https://localhost:18443 \
//!     cargo test --features insecure-tests --test derp_real_roundtrip

#![cfg(feature = "insecure-tests")]

use std::net::Ipv4Addr;
use std::time::Duration;

use ts_keys::NodeKeyPair;
use ts_transport_derp::{IpUsage, ServerConnInfo, TlsValidationConfig};

use burrow::derp::DerpClient;

/// Build a `ServerConnInfo` pointing at `url` with TLS verification
/// disabled. `IpUsage::FixedAddr(127.0.0.1)` avoids a DNS lookup for
/// `localhost` (some resolvers return both v4 and v6 addresses and the
/// v6 path in the dialer fails with a connection error on machines
/// without ::1 configured, masking the real test failure).
fn test_server(url: &url::Url) -> ServerConnInfo {
    let hostname = url.host_str().expect("url has host").to_owned();
    let https_port = url.port().unwrap_or(443);
    ServerConnInfo {
        hostname: hostname.clone(),
        ipv4: IpUsage::FixedAddr(Ipv4Addr::new(127, 0, 0, 1)),
        ipv6: IpUsage::Disable,
        tls_validation_config: TlsValidationConfig::InsecureForTests,
        https_port,
        stun_port: None,
        stun_only: false,
        supports_port_80: false,
    }
}

fn derp_url() -> Option<url::Url> {
    let raw = std::env::var("BURROW_TEST_DERP_URL").ok()?;
    Some(url::Url::parse(&raw).expect("BURROW_TEST_DERP_URL must parse as a URL"))
}

#[tokio::test]
async fn two_clients_round_trip_a_small_payload() {
    let Some(url) = derp_url() else {
        eprintln!("BURROW_TEST_DERP_URL not set; skipping");
        return;
    };
    let server = test_server(&url);

    // Two independent identities — both connect to the same DERP region
    // but identify themselves with distinct NodeKeyPairs. The DERP relay
    // indexes connected clients by node public key and routes
    // `SendPacket` frames between them.
    let a = NodeKeyPair::new();
    let b = NodeKeyPair::new();

    let (a_client, mut a_rx) = DerpClient::connect(std::slice::from_ref(&server), &a)
        .await
        .expect("A failed to connect to DERP");
    let (_b_client, mut b_rx) = DerpClient::connect(std::slice::from_ref(&server), &b)
        .await
        .expect("B failed to connect to DERP");

    // The DERP server must observe B's presence before it can route A's
    // frame. In practice this is "already done by the time handshake
    // returned", but there is no explicit sync point in the client so
    // we settle for a short timeout on the recv side.
    let payload = b"burrow-headscale stage 1e".to_vec();
    a_client
        .send(b.public, &payload)
        .await
        .expect("A failed to send");

    let got = tokio::time::timeout(Duration::from_secs(5), b_rx.recv())
        .await
        .expect("B timed out waiting for A's frame")
        .expect("B's DerpClient supervisor exited before the frame arrived");

    assert_eq!(got.sender, a.public, "sender key tags match");
    assert_eq!(
        got.bytes.as_ref(),
        payload.as_slice(),
        "payload survived round trip"
    );

    // Nothing should have landed on A's own channel.
    match tokio::time::timeout(Duration::from_millis(100), a_rx.recv()).await {
        Err(_) => {}
        Ok(frame) => panic!("unexpected frame arrived on A's inbox: {frame:?}"),
    }
}

#[tokio::test]
async fn wireguard_handshake_init_round_trips_over_real_derp() {
    let Some(url) = derp_url() else {
        eprintln!("BURROW_TEST_DERP_URL not set; skipping");
        return;
    };
    let server = test_server(&url);

    let a = NodeKeyPair::new();
    let b = NodeKeyPair::new();

    let (a_client, mut _a_rx) = DerpClient::connect(std::slice::from_ref(&server), &a)
        .await
        .expect("A failed to connect");
    let (_b_client, mut b_rx) = DerpClient::connect(std::slice::from_ref(&server), &b)
        .await
        .expect("B failed to connect");

    // Build a WG handshake init packet from A to B using the same
    // machinery the data plane uses. B's side doesn't have a matching
    // `Peer` on this test — we only assert that the bytes survive the
    // DERP transport, not that B accepts them. (Matching decapsulation
    // is already exercised by `derp_stub_roundtrip`.)
    use burrow::node_identity::NodeIdentity;
    use burrow::peer_table::Peer;
    use x25519_dalek::PublicKey;

    let a_ident = NodeIdentity::generate();
    let b_ident = NodeIdentity::generate();
    let peer_of_b = Peer::new(
        b.public,
        PublicKey::from(&b_ident.wg_private()),
        "100.64.0.2".parse().unwrap(),
        a_ident.wg_private(),
        None,
    );

    let step = peer_of_b
        .core
        .handshake_init(false)
        .expect("handshake_init should always succeed");
    assert_eq!(step.to_network.len(), 1);
    let init_bytes = step.to_network.into_iter().next().unwrap();
    let init_len = init_bytes.len();

    a_client
        .send(b.public, &init_bytes)
        .await
        .expect("A failed to send handshake over derp");

    let got = tokio::time::timeout(Duration::from_secs(5), b_rx.recv())
        .await
        .expect("B timed out")
        .expect("B supervisor exited");

    assert_eq!(got.sender, a.public);
    assert_eq!(
        got.bytes.len(),
        init_len,
        "handshake bytes survived the transport intact (length match)"
    );
    assert_eq!(
        got.bytes.as_ref(),
        init_bytes.as_slice(),
        "handshake byte content unchanged"
    );
    assert_eq!(
        got.bytes[0], 1,
        "first byte is WireGuard type=HANDSHAKE_INIT"
    );
}
