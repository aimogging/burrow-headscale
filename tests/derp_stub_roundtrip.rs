//! Stage 1 end-to-end validation: prove that [`Peer`], [`PeerTable`], and
//! [`WgCore::from_raw`] compose correctly for a full WireGuard handshake
//! + data exchange between two nodes — without needing a real DERP
//! server.
//!
//! We stand up an in-process substitute for the DERP relay: a `HashMap`
//! keyed by `NodePublicKey` holding one mpsc sender per registered node.
//! `send(from, to, bytes)` looks up the recipient and pushes an inbound
//! frame onto their channel. That is all a DERP relay does semantically;
//! the real client adds TLS + WebSocket framing + authenticated handshake
//! on top. The stage-1 question is whether the *protocol layer above*
//! the transport is wired up correctly, and for that a byte-pipe is
//! sufficient.
//!
//! Stage 1e will re-run this shape against a real derper to cover the
//! transport itself.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use ts_keys::NodePublicKey;
use x25519_dalek::PublicKey;

use burrow::node_identity::NodeIdentity;
use burrow::peer_table::{Peer, PeerTable};

#[derive(Debug)]
struct MemFrame {
    sender: NodePublicKey,
    bytes: Vec<u8>,
}

#[derive(Default, Clone)]
struct MemDerp {
    inboxes: Arc<Mutex<HashMap<NodePublicKey, mpsc::UnboundedSender<MemFrame>>>>,
}

impl MemDerp {
    fn new() -> Self {
        Self::default()
    }

    async fn register(&self, key: NodePublicKey) -> mpsc::UnboundedReceiver<MemFrame> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inboxes.lock().await.insert(key, tx);
        rx
    }

    async fn send(&self, from: NodePublicKey, to: NodePublicKey, bytes: Vec<u8>) {
        let inbox = self.inboxes.lock().await.get(&to).cloned();
        if let Some(tx) = inbox {
            let _ = tx.send(MemFrame {
                sender: from,
                bytes,
            });
        }
    }
}

/// Helper — relay every entry of `step.to_network` from `from_peer`'s
/// owner to the other side and return the other side's next inbound
/// frame (panics if there is nothing to relay or no response arrives).
async fn relay_and_recv(
    derp: &MemDerp,
    from: NodePublicKey,
    to: NodePublicKey,
    packets: Vec<Vec<u8>>,
    recv_rx: &mut mpsc::UnboundedReceiver<MemFrame>,
) -> MemFrame {
    assert!(
        !packets.is_empty(),
        "caller expected outbound packets to exist"
    );
    for pkt in packets {
        derp.send(from, to, pkt).await;
    }
    recv_rx
        .recv()
        .await
        .expect("sender dropped before recipient saw the relayed frame")
}

#[tokio::test]
async fn handshake_and_ipv4_data_round_trip_over_mem_derp() {
    // Two independent identities. Each treats the other as a known peer
    // (tailnet_ip + WG pubkey supplied out of band — in production this
    // comes from Headscale's MapResponse, which Stage 3 wires up).
    let a = NodeIdentity::generate();
    let b = NodeIdentity::generate();

    let a_tailnet: Ipv4Addr = "100.64.0.1".parse().unwrap();
    let b_tailnet: Ipv4Addr = "100.64.0.2".parse().unwrap();

    let a_wg_pub = PublicKey::from(&a.wg_private());
    let b_wg_pub = PublicKey::from(&b.wg_private());

    // PeerTable on each side — small test but exercises the DashMap
    // path that Stage 3's ingress/egress dispatch will use.
    let a_peers = PeerTable::new();
    a_peers.insert(Peer::new(
        b.state.node_keys.public,
        b_wg_pub,
        b_tailnet,
        a.wg_private(),
        None,
    ));
    let b_peers = PeerTable::new();
    b_peers.insert(Peer::new(
        a.state.node_keys.public,
        a_wg_pub,
        a_tailnet,
        b.wg_private(),
        None,
    ));

    let derp = MemDerp::new();
    let mut a_rx = derp.register(a.state.node_keys.public).await;
    let mut b_rx = derp.register(b.state.node_keys.public).await;

    // --- Handshake init: A -> B ---
    let a_peer_b = a_peers
        .by_node_key(&b.state.node_keys.public)
        .expect("a sees b");
    let init_step = a_peer_b.core.handshake_init(false).expect("handshake init");
    assert_eq!(
        init_step.to_network.len(),
        1,
        "handshake init always produces exactly one packet"
    );
    let init_frame = relay_and_recv(
        &derp,
        a.state.node_keys.public,
        b.state.node_keys.public,
        init_step.to_network,
        &mut b_rx,
    )
    .await;
    assert_eq!(init_frame.sender, a.state.node_keys.public);

    // --- Handshake response: B -> A ---
    let b_peer_a = b_peers
        .by_node_key(&a.state.node_keys.public)
        .expect("b sees a");
    let resp_step = b_peer_a
        .core
        .decapsulate(None, &init_frame.bytes)
        .expect("b decapsulates handshake init");
    assert!(
        !resp_step.to_network.is_empty(),
        "boringtun emits a handshake response upon receiving init"
    );
    assert!(
        resp_step.to_tunnel.is_none(),
        "handshake-only exchange yields no plaintext yet"
    );
    let resp_frame = relay_and_recv(
        &derp,
        b.state.node_keys.public,
        a.state.node_keys.public,
        resp_step.to_network,
        &mut a_rx,
    )
    .await;
    assert_eq!(resp_frame.sender, b.state.node_keys.public);

    let settle = a_peer_b
        .core
        .decapsulate(None, &resp_frame.bytes)
        .expect("a decapsulates handshake response");
    assert!(
        settle.to_tunnel.is_none(),
        "settling the session yields no plaintext"
    );

    // --- Data: A -> B, decrypted to the same bytes A encapsulated ---
    let plaintext = build_ipv4_stub(a_tailnet, b_tailnet);
    let enc_step = a_peer_b
        .core
        .encapsulate(&plaintext)
        .expect("encapsulate with established session");
    assert_eq!(
        enc_step.to_network.len(),
        1,
        "established session encapsulates to one packet"
    );
    let data_frame = relay_and_recv(
        &derp,
        a.state.node_keys.public,
        b.state.node_keys.public,
        enc_step.to_network,
        &mut b_rx,
    )
    .await;

    let dec_step = b_peer_a
        .core
        .decapsulate(None, &data_frame.bytes)
        .expect("b decapsulates data");
    let tunnel_pkt = dec_step
        .to_tunnel
        .expect("decrypted data surfaces as a tunnel packet");
    assert_eq!(
        tunnel_pkt.data, plaintext,
        "plaintext survived the encrypt -> mem-derp -> decrypt round trip"
    );
}

#[tokio::test]
async fn frame_to_unregistered_node_is_dropped_silently() {
    // The stub does what a real DERP relay would do for an unknown dst:
    // discard the frame rather than error. A future change to the real
    // DerpClient wrapper must preserve this behaviour so Stage 3's
    // reconciler can drop a peer without coordinating with every
    // concurrent send site.
    let derp = MemDerp::new();
    let a = NodeIdentity::generate();
    let b = NodeIdentity::generate();
    let mut a_rx = derp.register(a.state.node_keys.public).await;

    derp.send(
        a.state.node_keys.public,
        b.state.node_keys.public,
        vec![1, 2, 3],
    )
    .await;

    // `a` should not see `b`'s traffic and there is no `b` inbox, so
    // `a`'s channel stays empty.
    match tokio::time::timeout(std::time::Duration::from_millis(50), a_rx.recv()).await {
        Err(_) => {} // expected: nothing arrived
        Ok(frame) => panic!("unexpected frame on unrelated inbox: {frame:?}"),
    }
}

/// Hand-build a minimal IPv4 packet (no options, no payload) so we have
/// a byte pattern to compare before/after the tunnel. boringtun does
/// not care about the IPv4 contents; we just need something non-trivial
/// with the right src/dst to sanity-check the round trip.
fn build_ipv4_stub(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45; // IPv4 + IHL 5 (no options)
    pkt[2] = 0x00;
    pkt[3] = 0x14; // total length = 20
    pkt[8] = 64; // TTL
    pkt[9] = 0xfd; // protocol = experimental-0xfd (doesn't matter here)
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt
}
