//! Reconciler loop: drain [`HeadscaleClient`]'s netmap watch channel
//! and push each new snapshot into a [`PeerTable`] via
//! [`PeerTable::reconcile`].
//!
//! Isolated from `HeadscaleClient` itself so tests can feed a synthetic
//! `watch::Receiver<Arc<ControlState>>` without constructing a real
//! control-plane session.
//!
//! The reconciler applies the initial snapshot immediately (so a
//! MapResponse that's already landed before the task starts is not
//! missed) then suspends on `rx.changed().await`. It exits when the
//! sender drops — which happens when `HeadscaleClient` is dropped, so
//! no explicit shutdown signal is needed.

use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, trace};

use crate::headscale::ControlState;
use crate::node_identity::NodeIdentity;
use crate::peer_table::PeerTable;

/// Spawn the reconciler. Returns the task handle; dropping it does
/// not abort (spawned with `tokio::spawn`, not structured), but
/// aborting it is safe.
pub fn spawn_reconciler(
    mut rx: watch::Receiver<Arc<ControlState>>,
    peers: Arc<PeerTable>,
    ident: Arc<NodeIdentity>,
    keepalive: Option<u16>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Borrow the current state and apply it before we start
        // waiting. `borrow_and_update` marks this value as seen so
        // the next `changed().await` waits for a genuinely newer
        // snapshot, not this one.
        let snap = rx.borrow_and_update().clone();
        trace!(
            peers = snap.peers.len(),
            "reconciler applying initial snapshot"
        );
        peers.reconcile(&snap.peers, &ident, keepalive);
        trace!(
            peer_table_len = peers.len(),
            "reconciler: initial snapshot applied"
        );

        loop {
            if rx.changed().await.is_err() {
                debug!("reconciler: control-state sender dropped, exiting");
                return;
            }
            let snap = rx.borrow_and_update().clone();
            trace!(peers = snap.peers.len(), "reconciler applying delta");
            peers.reconcile(&snap.peers, &ident, keepalive);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::time::timeout;
    use ts_keys::NodePublicKey;

    use crate::headscale::PeerInfo;

    fn mk_info(byte: u8, ip: [u8; 4]) -> PeerInfo {
        PeerInfo {
            node_id: byte as i64,
            node_key: NodePublicKey::from([byte; 32]),
            disco_key: None,
            tailnet_ipv4: Ipv4Addr::from(ip),
            hostname: format!("peer-{byte}"),
            home_region: None,
        }
    }

    /// Helper — spin until `cond(&PeerTable)` returns true, up to a
    /// 500ms deadline. Necessary because `spawn_reconciler` runs on a
    /// separate task and the watch-channel delivery has a small
    /// scheduling delay.
    async fn wait_until<F: Fn(&PeerTable) -> bool>(peers: &PeerTable, cond: F) {
        timeout(Duration::from_millis(500), async {
            loop {
                if cond(peers) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reconciler didn't produce the expected state inside 500ms");
    }

    #[tokio::test]
    async fn initial_snapshot_is_applied_before_first_change() {
        let initial = ControlState {
            peers: vec![mk_info(0xe0, [100, 64, 0, 50])],
            ..Default::default()
        };
        let (tx, rx) = watch::channel(Arc::new(initial));

        let peers = Arc::new(PeerTable::new());
        let ident = Arc::new(NodeIdentity::generate());
        let _handle = spawn_reconciler(rx, Arc::clone(&peers), ident, None);

        wait_until(&peers, |t| t.len() == 1).await;
        assert!(peers
            .by_node_key(&NodePublicKey::from([0xe0; 32]))
            .is_some());

        // Keep tx alive until we've finished asserting so the pump
        // doesn't exit before we look.
        drop(tx);
    }

    #[tokio::test]
    async fn subsequent_updates_reconcile_into_the_table() {
        let (tx, rx) = watch::channel(Arc::new(ControlState::default()));
        let peers = Arc::new(PeerTable::new());
        let ident = Arc::new(NodeIdentity::generate());
        let _handle = spawn_reconciler(rx, Arc::clone(&peers), ident, None);

        // Start empty, push two peers.
        tx.send(Arc::new(ControlState {
            peers: vec![
                mk_info(0xf0, [100, 64, 0, 60]),
                mk_info(0xf1, [100, 64, 0, 61]),
            ],
            ..Default::default()
        }))
        .unwrap();
        wait_until(&peers, |t| t.len() == 2).await;

        // Drop one.
        tx.send(Arc::new(ControlState {
            peers: vec![mk_info(0xf1, [100, 64, 0, 61])],
            ..Default::default()
        }))
        .unwrap();
        wait_until(&peers, |t| t.len() == 1).await;
        assert!(peers
            .by_node_key(&NodePublicKey::from([0xf0; 32]))
            .is_none());
    }
}
