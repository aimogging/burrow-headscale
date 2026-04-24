//! Peer delta update tracking.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_control::{Node, NodeId};
use ts_keys::NodePublicKey;

use crate::{Error, env::Env};

/// Actor that tracks peer delta updates and emits new states.
pub struct PeerTracker {
    peers: HashMap<NodePublicKey, Node>,
    id_to_nodekey: HashMap<NodeId, NodePublicKey>,
    env: Env,
}

impl kameo::Actor for PeerTracker {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        Ok(Self {
            peers: Default::default(),
            id_to_nodekey: Default::default(),
            env,
        })
    }
}

// For messages with arguments, a struct is generated with the args as fields. They aren't
// documented, and we can't apply attributes directly to the fields. Hence, wrap in a module where
// docs are turned off everywhere.
#[allow(missing_docs)]
mod msg_impl {
    use super::*;

    #[kameo::messages]
    impl PeerTracker {
        /// Lookup a peer by name.
        #[message]
        pub fn peer_by_name(&self, name: String) -> Option<Node> {
            self.peers
                .values()
                .find(|&peer| peer.matches_name(&name))
                .cloned()
        }
    }
}

pub use msg_impl::*;

#[derive(Debug, Clone)]
pub(crate) struct PeerState {
    #[allow(unused)]
    pub deletions: HashSet<NodePublicKey>,
    #[allow(unused)]
    pub upserts: HashSet<NodePublicKey>,
    pub peers: Arc<HashMap<NodePublicKey, Node>>,
}

// TODO: rpds

impl Message<Arc<ts_control::StateUpdate>> for PeerTracker {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(peer_update) = &msg.peer_update else {
            return;
        };

        let mut upserts = HashSet::default();
        let mut deletions = HashSet::default();

        match peer_update {
            ts_control::PeerUpdate::Full(nodes) => {
                tracing::trace!("full peer update");

                deletions = self.peers.keys().copied().collect();

                self.peers.clear();
                self.id_to_nodekey.clear();

                for node in nodes {
                    upserts.insert(node.node_key);
                    deletions.remove(&node.node_key);

                    self.id_to_nodekey.insert(node.id, node.node_key);
                    self.peers.insert(node.node_key, node.clone());
                }
            }

            ts_control::PeerUpdate::Delta { remove, upsert } => {
                tracing::trace!("delta peer update");

                for peer in upsert {
                    self.id_to_nodekey.insert(peer.id, peer.node_key);
                    self.peers.insert(peer.node_key, peer.clone());

                    upserts.insert(peer.node_key);
                }

                for peer in remove {
                    let node_key = self.id_to_nodekey.remove(peer);

                    if let Some(node_key) = node_key {
                        self.peers.remove(&node_key);
                        deletions.insert(node_key);
                    }
                }
            }
        }

        tracing::debug!(
            n_upsert = upserts.len(),
            n_delete = deletions.len(),
            peer_count = self.peers.len(),
            "new peer state"
        );

        if let Err(e) = self
            .env
            .publish(PeerState {
                upserts,
                deletions,
                peers: Arc::new(self.peers.clone()),
            })
            .await
        {
            tracing::error!(error = %e, "publishing peer state update");
        }
    }
}
