//! Stage 2a: Headscale control-plane client wrapper.
//!
//! Wraps `ts_control::AsyncControlClient` (Noise IK + register +
//! long-polled netmap stream) and reduces the upstream `StateUpdate`
//! stream into a single `ControlState` snapshot that the rest of
//! burrow consumes. Exposes:
//!
//! - [`HeadscaleClient::connect`] — register with Headscale using an
//!   authkey, start the netmap stream, spawn a pump task that keeps
//!   the snapshot current.
//! - [`HeadscaleClient::snapshot`] — cheap read of the latest state.
//! - [`HeadscaleClient::subscribe`] — `tokio::sync::watch` receiver,
//!   fires on every netmap delta.
//!
//! Design notes:
//! - `watch` (latest-only) is the right channel shape: consumers like
//!   the peer reconciler in Stage 3 only care about the current peer
//!   set, not the transitive deltas. Missing an update because a
//!   slower update landed on top is fine.
//! - The inner `AsyncControlClient` already handles reconnect with
//!   exp backoff via its own `run()` loop; we don't wrap that.
//! - Peer list lives as `Vec<PeerInfo>`. Stage 3 builds a
//!   `DashMap<NodePublicKey, Arc<Peer>>` on top of it via
//!   `PeerTable::reconcile`.

#![cfg(feature = "headscale")]

use std::net::Ipv4Addr;
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use ts_control::{
    AsyncControlClient, Config as TsConfig, DerpMap, Node as TsNode, PeerUpdate, StateUpdate,
};
use ts_keys::{DiscoPublicKey, NodePublicKey};
use ts_transport_derp::RegionId;
use url::Url;

use crate::node_identity::NodeIdentity;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("control-plane connect/register failed: {0}")]
    Connect(#[from] ts_control::Error),
}

/// Snapshot of everything burrow cares about from Headscale at a given
/// point in time. Replaces itself on each netmap delta.
#[derive(Debug, Default, Clone)]
pub struct ControlState {
    /// The IPv4 address Headscale assigned to this node in the
    /// tailnet. `None` until the first `StateUpdate` that carries a
    /// self-node.
    pub my_tailnet_ipv4: Option<Ipv4Addr>,

    /// The DERP region Headscale told us to call home. `None` until
    /// control sends a DerpMap *and* designates a home region.
    pub my_home_region: Option<RegionId>,

    /// The full DERP map from the most recent update (may arrive
    /// before `my_home_region` is populated).
    pub derp_map: Option<DerpMap>,

    /// Current peer set. Replaced wholesale on a `PeerUpdate::Full`
    /// and mutated in place on `PeerUpdate::Delta`.
    pub peers: Vec<PeerInfo>,
}

/// Burrow's view of a single tailnet peer. Mirrors the subset of
/// `ts_control::Node` that downstream code (Stage 3 reconciler) needs.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: ts_control::NodeId,
    pub node_key: NodePublicKey,
    pub disco_key: Option<DiscoPublicKey>,
    pub tailnet_ipv4: Ipv4Addr,
    pub hostname: String,
    pub home_region: Option<RegionId>,
}

impl PeerInfo {
    /// Best-effort conversion. Returns `None` if the node lacks fields
    /// burrow requires (only the IPv4 is actually mandatory today;
    /// disco + region are optional on the wire).
    fn from_ts_node(node: &TsNode) -> Option<Self> {
        Some(Self {
            node_id: node.id,
            node_key: node.node_key,
            disco_key: node.disco_key,
            tailnet_ipv4: node.tailnet_address.ipv4.addr(),
            hostname: node.hostname.clone(),
            home_region: node.derp_region,
        })
    }
}

pub struct HeadscaleClient {
    // Keep the inner client alive for its lifetime — dropping it ends
    // the netmap stream task internally.
    _inner: Arc<AsyncControlClient>,
    state_tx: watch::Sender<Arc<ControlState>>,
    _pump: JoinHandle<()>,
}

impl HeadscaleClient {
    /// Register with Headscale and start pumping netmap updates into
    /// the shared snapshot.
    ///
    /// `authkey` must be a valid Headscale preauth key. OIDC browser-
    /// flow auth isn't wired up (Stage 2a scope); pass a preauth key.
    pub async fn connect(
        server_url: Url,
        ident: &NodeIdentity,
        authkey: &str,
        hostname: Option<String>,
    ) -> Result<Self, Error> {
        let config = TsConfig {
            server_url,
            hostname,
            client_name: Some("burrow-headscale".to_owned()),
            tags: vec![],
        };

        let (inner, stream) = AsyncControlClient::connect(&config, &ident.state, Some(authkey))
            .await
            .map_err(ts_control::Error::from)?;
        let inner = Arc::new(inner);

        let (state_tx, _state_rx) = watch::channel(Arc::new(ControlState::default()));

        // `AsyncControlClient`'s netmap stream isn't `Unpin`; pin it
        // on the heap before passing to the pump (which is generic
        // over any `Stream + Unpin` so unit tests can feed a cheap
        // mpsc-backed stream without allocating).
        let pinned = Box::pin(stream);
        let pump = {
            let state_tx = state_tx.clone();
            tokio::spawn(async move {
                pump_state_updates(pinned, state_tx).await;
            })
        };

        Ok(Self {
            _inner: inner,
            state_tx,
            _pump: pump,
        })
    }

    /// Latest snapshot. Cheap (clones an `Arc`).
    pub fn snapshot(&self) -> Arc<ControlState> {
        Arc::clone(&self.state_tx.borrow())
    }

    /// Fires every time the netmap produces a delta.
    pub fn subscribe(&self) -> watch::Receiver<Arc<ControlState>> {
        self.state_tx.subscribe()
    }
}

async fn pump_state_updates<S>(stream: S, state_tx: watch::Sender<Arc<ControlState>>)
where
    S: futures::Stream<Item = Arc<StateUpdate>> + Unpin,
{
    let mut stream = stream;
    let mut state = ControlState::default();
    while let Some(update) = stream.next().await {
        let changed = reduce_state_update(&mut state, update.as_ref());
        if changed {
            if state_tx.send(Arc::new(state.clone())).is_err() {
                debug!("netmap pump: all subscribers dropped, exiting");
                return;
            }
        } else {
            debug!("netmap update produced no observable change");
        }
    }
    warn!("netmap stream ended unexpectedly");
}

/// Pure reduction of a single `StateUpdate` into the cumulative
/// `ControlState`. Returns `true` iff the state changed observably.
/// Split out for unit testing — all I/O and locking happens above
/// this function.
fn reduce_state_update(state: &mut ControlState, update: &StateUpdate) -> bool {
    let mut changed = false;

    if let Some(node) = &update.node {
        let new_ip = Some(node.tailnet_address.ipv4.addr());
        if state.my_tailnet_ipv4 != new_ip {
            state.my_tailnet_ipv4 = new_ip;
            changed = true;
        }
        if state.my_home_region != node.derp_region {
            state.my_home_region = node.derp_region;
            changed = true;
        }
    }

    if let Some(derp) = &update.derp {
        // DerpMap doesn't impl PartialEq, so we assume any fresh map
        // is a meaningful update. The pump logs upstream if this
        // fires too often in practice.
        state.derp_map = Some(derp.clone());
        changed = true;
    }

    if let Some(peer_update) = &update.peer_update {
        apply_peer_update(&mut state.peers, peer_update);
        changed = true;
    }

    changed
}

fn apply_peer_update(peers: &mut Vec<PeerInfo>, update: &PeerUpdate) {
    match update {
        PeerUpdate::Full(nodes) => {
            peers.clear();
            peers.extend(nodes.iter().filter_map(PeerInfo::from_ts_node));
        }
        PeerUpdate::Delta { upsert, remove } => {
            // Remove first: if a peer is both removed and upserted in
            // the same delta the net effect is "upsert wins".
            peers.retain(|p| !remove.contains(&p.node_id));
            for node in upsert {
                let Some(new) = PeerInfo::from_ts_node(node) else {
                    continue;
                };
                match peers.iter_mut().find(|p| p.node_id == new.node_id) {
                    Some(slot) => *slot = new,
                    None => peers.push(new),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::{Ipv4Net, Ipv6Net};
    use ts_control::{StableNodeId, TailnetAddress};
    use ts_keys::NodeKeyPair;

    fn mk_node(id: ts_control::NodeId, ipv4: Ipv4Addr, hostname: &str) -> TsNode {
        let node_key = NodeKeyPair::new().public;
        TsNode {
            id,
            stable_id: StableNodeId(format!("stable-{id}")),
            hostname: hostname.to_owned(),
            tailnet: Some("test".to_owned()),
            tags: vec![],
            tailnet_address: TailnetAddress {
                ipv4: Ipv4Net::new(ipv4, 32).unwrap(),
                ipv6: Ipv6Net::new("fd7a::1".parse().unwrap(), 128).unwrap(),
            },
            node_key,
            node_key_expiry: None,
            machine_key: None,
            disco_key: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
        }
    }

    fn mk_state_update() -> StateUpdate {
        StateUpdate {
            derp: None,
            node: None,
            peer_update: None,
            ping: None,
            packetfilter: None,
            pop_browser_url: None,
            dial_plan: None,
        }
    }

    #[test]
    fn reduce_sets_tailnet_ipv4_from_self_node() {
        let mut state = ControlState::default();
        let mut update = mk_state_update();
        update.node = Some(mk_node(1, "100.64.0.7".parse().unwrap(), "me"));

        let changed = reduce_state_update(&mut state, &update);
        assert!(changed);
        assert_eq!(state.my_tailnet_ipv4, Some("100.64.0.7".parse().unwrap()));
    }

    #[test]
    fn reduce_no_change_when_ipv4_already_matches() {
        let mut state = ControlState {
            my_tailnet_ipv4: Some("100.64.0.7".parse().unwrap()),
            ..Default::default()
        };
        let mut update = mk_state_update();
        update.node = Some(mk_node(1, "100.64.0.7".parse().unwrap(), "me"));

        let changed = reduce_state_update(&mut state, &update);
        assert!(!changed, "identical update should be a no-op");
    }

    #[test]
    fn peer_update_full_replaces_peers() {
        let mut peers = vec![];
        let full = vec![
            mk_node(10, "100.64.0.10".parse().unwrap(), "a"),
            mk_node(11, "100.64.0.11".parse().unwrap(), "b"),
        ];

        apply_peer_update(&mut peers, &PeerUpdate::Full(full));

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].hostname, "a");
        assert_eq!(
            peers[0].tailnet_ipv4,
            "100.64.0.10".parse::<Ipv4Addr>().unwrap()
        );

        // A second Full wipes the previous set.
        apply_peer_update(
            &mut peers,
            &PeerUpdate::Full(vec![mk_node(20, "100.64.0.20".parse().unwrap(), "c")]),
        );
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].hostname, "c");
    }

    #[test]
    fn peer_update_delta_upsert_and_remove_both_apply() {
        let mut peers = vec![];
        apply_peer_update(
            &mut peers,
            &PeerUpdate::Full(vec![
                mk_node(1, "100.64.0.1".parse().unwrap(), "a"),
                mk_node(2, "100.64.0.2".parse().unwrap(), "b"),
                mk_node(3, "100.64.0.3".parse().unwrap(), "c"),
            ]),
        );

        apply_peer_update(
            &mut peers,
            &PeerUpdate::Delta {
                // Upsert an existing one (rename) and a new one.
                upsert: vec![
                    mk_node(2, "100.64.0.2".parse().unwrap(), "b-renamed"),
                    mk_node(4, "100.64.0.4".parse().unwrap(), "d"),
                ],
                remove: vec![1],
            },
        );

        let by_id: std::collections::BTreeMap<_, _> = peers
            .iter()
            .map(|p| (p.node_id, p.hostname.as_str()))
            .collect();
        assert_eq!(by_id.get(&1), None, "node 1 removed");
        assert_eq!(by_id.get(&2).copied(), Some("b-renamed"));
        assert_eq!(by_id.get(&3).copied(), Some("c"));
        assert_eq!(by_id.get(&4).copied(), Some("d"));
    }

    #[test]
    fn delta_with_same_id_in_upsert_and_remove_lets_upsert_win() {
        // Tailscale's protocol has no documented constraint on this;
        // our convention is upsert wins so `remove.then(upsert)` =
        // "replace". Codify the choice.
        let mut peers = vec![];
        apply_peer_update(
            &mut peers,
            &PeerUpdate::Full(vec![mk_node(1, "100.64.0.1".parse().unwrap(), "orig")]),
        );
        apply_peer_update(
            &mut peers,
            &PeerUpdate::Delta {
                upsert: vec![mk_node(1, "100.64.0.9".parse().unwrap(), "replaced")],
                remove: vec![1],
            },
        );
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].hostname, "replaced");
        assert_eq!(
            peers[0].tailnet_ipv4,
            "100.64.0.9".parse::<Ipv4Addr>().unwrap()
        );
    }
}
