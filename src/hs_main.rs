//! Headscale-path binary entry. Owns the full data-plane lifetime
//! end-to-end: register with Headscale, connect to the assigned DERP
//! region, start the peer reconciler, stand up the smoltcp runtime +
//! NAT + reverse-tunnel machinery, and run the ingress/egress loops
//! that mirror `src/main.rs::run` for the PeerTable transport.
//!
//! Two transport-specific loops live here (everything else is shared
//! with the wg-quick path via [`crate::dataplane`]):
//!
//! - [`peer_egress_loop`] drains smoltcp's TX channel and sends each
//!   plaintext IP packet into the right peer's `Tunn` for
//!   encapsulation, then forwards the encrypted bytes over DERP. Also
//!   handles src rewriting (the synthetic `198.18.0.0/15` → original
//!   tailnet src) by calling `NatTable::rewrite_outbound`.
//! - [`tick_all_peers`] walks `PeerTable` every 250ms and drives
//!   `WgCore::timer_tick` on each `Tunn`. Any handshake retransmits
//!   or keepalives go out through DERP keyed by the peer's node key.
//!
//! Inbound DERP frames are dispatched inline in the main `run` loop:
//! look up the sender's peer, decapsulate, forward handshake response
//! bytes back to the peer, and hand decrypted IP packets to
//! [`ingest_tunnel_packet`].

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::net::TcpStream;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use ts_keys::NodePublicKey;
use ts_transport_derp::RegionId;
use url::Url;

use crate::control::{listener_key, spawn_control_handler, DEFAULT_CONTROL_PORT};
use crate::dataplane::{ingest_tunnel_packet, UdpProxyMap};
use crate::derp::DerpClient;
use crate::headscale::{ControlState, HeadscaleClient};
use crate::icmp::IcmpForwarder;
use crate::nat::{self, NatKey, NatTable};
use crate::node_identity::NodeIdentity;
use crate::peer_reconciler::spawn_reconciler;
use crate::peer_table::PeerTable;
use crate::proxy::{spawn_tcp_proxy_with_stream, ProxyMsg};
use crate::reverse_registry::ReverseRegistry;
use crate::rewrite;
use crate::runtime::{spawn_smoltcp, ConnectionId, SmoltcpEvent};

#[derive(Debug, Clone)]
pub struct HeadscaleArgs {
    pub server_url: Url,
    pub authkey: String,
    pub hostname: Option<String>,
}

pub async fn run(args: HeadscaleArgs) -> Result<()> {
    init_tracing();

    info!(server_url = %args.server_url, "connecting to Headscale");
    let ident = Arc::new(NodeIdentity::generate());
    let client = Arc::new(
        HeadscaleClient::connect(args.server_url, &ident, &args.authkey, args.hostname)
            .await
            .context("HeadscaleClient::connect")?,
    );

    // Wait for the first netmap snapshot that carries (a) our tailnet
    // IP, and (b) a DERP region we can connect to. Headscale sends
    // both in the first MapResponse in practice; we poll with a
    // bounded deadline instead of awaiting a specific sentinel event.
    let (tailnet_ip, derp_servers) = wait_for_initial_state(&client).await?;
    info!(%tailnet_ip, regions = derp_servers.len(), "registered with Headscale");

    let (derp_client, mut derp_rx) = DerpClient::connect(&derp_servers, &ident.state.node_keys)
        .await
        .context("DERP connect")?;
    let derp_client = Arc::new(derp_client);
    info!("DERP client connected");

    let peers = Arc::new(PeerTable::new());
    let reconciler = spawn_reconciler(
        client.subscribe(),
        Arc::clone(&peers),
        Arc::clone(&ident),
        None,
    );

    // Shared state for the data plane — identical shape to
    // src/main.rs.
    let nat = Arc::new(NatTable::new());
    let (smoltcp, mut events, smoltcp_tx_rx) = spawn_smoltcp(Arc::clone(&nat), tailnet_ip);
    info!("smoltcp runtime spawned");

    let udp_proxies: UdpProxyMap = Arc::new(Mutex::new(HashMap::new()));
    let (egress_tx, mut egress_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Originated responses (UDP replies, ICMP replies, RSTs from
    // connect_probe). Ship them to peers via DERP.
    let direct_egress = tokio::spawn({
        let peers = Arc::clone(&peers);
        let derp = Arc::clone(&derp_client);
        async move {
            while let Some(pkt) = egress_rx.recv().await {
                send_plaintext_to_peer(&pkt, &peers, &derp, tailnet_ip).await;
            }
        }
    });

    let icmp = Arc::new(IcmpForwarder::probe(egress_tx.clone()));

    // smoltcp egress → src-rewrite → peer encapsulate → DERP send.
    let egress = tokio::spawn({
        let peers = Arc::clone(&peers);
        let derp = Arc::clone(&derp_client);
        let nat = Arc::clone(&nat);
        async move {
            peer_egress_loop(smoltcp_tx_rx, nat, peers, derp, tailnet_ip).await;
        }
    });

    let (arm_tx, mut arm_rx) = mpsc::unbounded_channel::<(NatKey, TcpStream)>();
    let reverse_registry = Arc::new(ReverseRegistry::new());
    let control_port = DEFAULT_CONTROL_PORT;
    let _ = smoltcp
        .ensure_listener(
            tailnet_ip,
            control_port,
            listener_key(tailnet_ip, control_port),
        )
        .await
        .context("initial control listener")?;
    info!(%tailnet_ip, control_port, "control listener active");

    let event_loop = tokio::spawn({
        let smoltcp = smoltcp.clone();
        let nat = Arc::clone(&nat);
        let reverse_registry = Arc::clone(&reverse_registry);
        async move {
            let mut proxies: HashMap<ConnectionId, mpsc::UnboundedSender<ProxyMsg>> =
                HashMap::new();
            let mut armed: HashMap<NatKey, TcpStream> = HashMap::new();
            loop {
                tokio::select! {
                    Some((key, stream)) = arm_rx.recv() => {
                        if armed.insert(key, stream).is_some() {
                            warn!(?key, "armed stream replaced — duplicate probe");
                        }
                    }
                    Some(evt) = events.evt_rx.recv() => match evt {
                        SmoltcpEvent::TcpConnected { key, id } => {
                            debug!(?key, ?id, "tcp connected");
                            if key.original_dst_ip == tailnet_ip
                                && key.original_dst_port == control_port
                            {
                                let next_key = listener_key(tailnet_ip, control_port);
                                let _ = smoltcp
                                    .ensure_listener(tailnet_ip, control_port, next_key)
                                    .await;
                                let tx = spawn_control_handler(
                                    id,
                                    smoltcp.clone(),
                                    Arc::clone(&reverse_registry),
                                );
                                proxies.insert(id, tx);
                            } else if key.original_dst_ip == tailnet_ip {
                                warn!(?key, ?id, "TCP to unregistered tailnet_ip port — aborting");
                                smoltcp.abort_tcp(id);
                            } else {
                                let Some(stream) = armed.remove(&key) else {
                                    error!(?key, ?id, "TcpConnected with no armed stream; aborting");
                                    smoltcp.abort_tcp(id);
                                    continue;
                                };
                                let tx = spawn_tcp_proxy_with_stream(
                                    key,
                                    id,
                                    smoltcp.clone(),
                                    Arc::clone(&nat),
                                    stream,
                                );
                                proxies.insert(id, tx);
                            }
                        }
                        SmoltcpEvent::TcpData { id, data, .. } => {
                            if let Some(tx) = proxies.get(&id) {
                                let _ = tx.send(ProxyMsg::Data(data));
                            }
                        }
                        SmoltcpEvent::TcpFinFromPeer { id, .. } => {
                            if let Some(tx) = proxies.get(&id) {
                                let _ = tx.send(ProxyMsg::PeerFin);
                            }
                        }
                        SmoltcpEvent::TcpClosed { key, id } => {
                            if let Some(tx) = proxies.remove(&id) {
                                let _ = tx.send(ProxyMsg::Closed);
                            }
                            armed.remove(&key);
                        }
                        SmoltcpEvent::TcpAborted { key, id } => {
                            debug!(?key, ?id, "tcp aborted before establishment");
                            if let Some(tx) = proxies.remove(&id) {
                                let _ = tx.send(ProxyMsg::Closed);
                            }
                            armed.remove(&key);
                            if key.peer_ip == Ipv4Addr::UNSPECIFIED
                                && key.original_dst_ip == tailnet_ip
                                && key.original_dst_port == control_port
                            {
                                let next = listener_key(tailnet_ip, control_port);
                                let _ = smoltcp
                                    .ensure_listener(tailnet_ip, control_port, next)
                                    .await;
                            }
                        }
                    },
                    else => break,
                }
            }
        }
    });

    let sweep = tokio::spawn({
        let nat = Arc::clone(&nat);
        let udp_proxies = Arc::clone(&udp_proxies);
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                let removed = nat.sweep_expired(now);
                if !removed.is_empty() {
                    debug!(count = removed.len(), "NAT entries swept (expired)");
                }
                let removed_udp = nat.sweep_udp_idle(now, nat::DEFAULT_UDP_IDLE);
                if !removed_udp.is_empty() {
                    let mut map = udp_proxies.lock().unwrap();
                    for k in &removed_udp {
                        map.remove(k);
                    }
                    debug!(count = removed_udp.len(), "NAT entries swept (udp idle)");
                }
            }
        }
    });

    // Main loop: drive per-peer timers + dispatch inbound DERP frames.
    // Burrow's DNS service is always on for the headscale path (there
    // is no wg-quick config to toggle it). Stage 5 removes the
    // `dns_enabled` plumbing entirely.
    let dns_enabled = true;
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let result: Result<()> = loop {
        tokio::select! {
            biased;
            _ = signal::ctrl_c() => {
                info!("ctrl-c received, shutting down");
                break Ok(());
            }
            _ = timer.tick() => {
                tick_all_peers(&peers, &derp_client).await;
            }
            Some(frame) = derp_rx.recv() => {
                handle_derp_inbound(
                    frame,
                    &peers,
                    &derp_client,
                    &smoltcp,
                    &nat,
                    &udp_proxies,
                    &egress_tx,
                    &arm_tx,
                    &icmp,
                    tailnet_ip,
                    dns_enabled,
                )
                .await;
            }
        }
    };

    egress.abort();
    event_loop.abort();
    sweep.abort();
    direct_egress.abort();
    reconciler.abort();
    result
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,burrow=debug,ts_control=info")),
        )
        .try_init();
}

/// Poll the control-state watch channel until a single snapshot has
/// both a tailnet IPv4 and a resolvable home DERP region. Fails if
/// that doesn't happen inside 10 seconds — registration usually
/// completes inside a few hundred ms.
async fn wait_for_initial_state(
    client: &HeadscaleClient,
) -> Result<(Ipv4Addr, Vec<ts_transport_derp::ServerConnInfo>)> {
    let mut rx = client.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(ready) = extract_ready_state(&client.snapshot()) {
            return Ok(ready);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(anyhow!(
                "timed out waiting for Headscale to deliver tailnet IP + DERP region"
            ));
        }
        tokio::time::timeout(deadline - now, rx.changed())
            .await
            .map_err(|_| anyhow!("netmap stream produced no state change inside 10s"))?
            .context("netmap watch channel closed")?;
    }
}

fn extract_ready_state(
    state: &ControlState,
) -> Option<(Ipv4Addr, Vec<ts_transport_derp::ServerConnInfo>)> {
    let ip = state.my_tailnet_ipv4?;
    let region = pick_home_region(state)?;
    let map = state.derp_map.as_ref()?;
    let servers = map.get(&region)?.servers.clone();
    Some((ip, servers))
}

/// Choose the DERP region to connect to. Prefer the explicit
/// `my_home_region` assignment when set; otherwise fall back to the
/// single region the derp_map advertises (test setups with one
/// embedded derper). Returns `None` if neither path pins a region.
fn pick_home_region(state: &ControlState) -> Option<RegionId> {
    if let Some(r) = state.my_home_region {
        return Some(r);
    }
    let map = state.derp_map.as_ref()?;
    if map.len() == 1 {
        map.keys().next().copied()
    } else {
        None
    }
}

/// Handle a single DERP frame: find its sender's `Peer`, decrypt,
/// forward any handshake-response bytes back over DERP, and hand
/// decrypted IP packets to the shared ingest helper.
#[allow(clippy::too_many_arguments)]
async fn handle_derp_inbound(
    frame: crate::derp::DerpInbound,
    peers: &Arc<PeerTable>,
    derp: &Arc<DerpClient>,
    smoltcp: &crate::runtime::SmoltcpHandle,
    nat: &Arc<NatTable>,
    udp_proxies: &UdpProxyMap,
    egress_tx: &mpsc::UnboundedSender<Vec<u8>>,
    arm_tx: &mpsc::UnboundedSender<(NatKey, TcpStream)>,
    icmp: &Arc<IcmpForwarder>,
    tailnet_ip: Ipv4Addr,
    dns_enabled: bool,
) {
    let peer = match peers.by_node_key(&frame.sender) {
        Some(p) => p,
        None => {
            debug!(
                sender = ?frame.sender,
                "DERP inbound from unknown peer — dropping"
            );
            return;
        }
    };
    let step = match peer.core.decapsulate(None, &frame.bytes) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "decapsulate from peer");
            return;
        }
    };
    for pkt in step.to_network {
        if let Err(e) = derp.send(peer.node_key, &pkt).await {
            warn!(error = %e, "derp send (handshake/ctrl) failed");
        }
    }
    if step.expired {
        warn!("peer session expired; will rehandshake on next data");
    }
    if let Some(tp) = step.to_tunnel {
        ingest_tunnel_packet(
            tp.data,
            smoltcp,
            nat,
            udp_proxies,
            egress_tx,
            arm_tx,
            icmp,
            tailnet_ip,
            dns_enabled,
        )
        .await;
    }
}

/// Drive every peer's WG timer. Handshake retransmits + keepalives
/// emit packets that have to reach the correct peer over DERP;
/// collect-then-send so the DashMap shard locks are released before
/// any await.
async fn tick_all_peers(peers: &PeerTable, derp: &DerpClient) {
    let mut work: Vec<(NodePublicKey, Vec<u8>)> = Vec::new();
    peers.for_each(|peer| match peer.core.timer_tick() {
        Ok(step) => {
            for pkt in step.to_network {
                work.push((peer.node_key, pkt));
            }
            if step.expired {
                warn!(?peer.node_key, "peer timer reports expired session");
            }
        }
        Err(e) => warn!(error = %e, "peer timer tick"),
    });
    for (dst, pkt) in work {
        if let Err(e) = derp.send(dst, &pkt).await {
            debug!(error = %e, "derp send (timer) failed");
        }
    }
}

/// Egress from smoltcp: source-rewrite 198.18.x.x back to the
/// original tailnet address, then route the plaintext IPv4 packet
/// to the matching peer and send the encrypted bytes over DERP.
async fn peer_egress_loop(
    mut tx_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    nat: Arc<NatTable>,
    peers: Arc<PeerTable>,
    derp: Arc<DerpClient>,
    tailnet_ip: Ipv4Addr,
) {
    while let Some(mut pkt) = tx_rx.recv().await {
        // Originated flows (reverse tunnels, DNS, control channel)
        // already have src=tailnet_ip — they bypass NAT rewrite.
        // Everything else comes from the synthetic 198.18.0.0/15
        // identifier pool and needs src restored to original_dst_ip
        // before the peer sees it.
        let src_is_tnet = matches!(
            rewrite::parse_5tuple(&pkt),
            Ok(v) if v.src_ip == tailnet_ip
        );
        if !src_is_tnet {
            if let Err(e) = nat.rewrite_outbound(&mut pkt) {
                debug!(
                    error = %e,
                    "egress rewrite (no NAT entry — likely RST for unknown flow)"
                );
                continue;
            }
        }
        send_plaintext_to_peer(&pkt, &peers, &derp, tailnet_ip).await;
    }
}

/// Route a plaintext IPv4 packet to the peer that owns its dst
/// address. Silently drops if the dst doesn't correspond to a known
/// peer (Headscale should cover every in-tailnet dst; anything else
/// is stale traffic).
async fn send_plaintext_to_peer(
    pkt: &[u8],
    peers: &PeerTable,
    derp: &DerpClient,
    tailnet_ip: Ipv4Addr,
) {
    let dst = match rewrite::parse_5tuple(pkt) {
        Ok(view) => view.dst_ip,
        Err(e) => {
            debug!(error = %e, "outbound packet failed 5-tuple parse, dropping");
            return;
        }
    };
    if dst == tailnet_ip {
        // Loopback to ourselves should never reach this path in
        // normal operation; smoltcp handles local delivery directly.
        debug!(%dst, "outbound packet addressed to self, dropping");
        return;
    }
    let Some(peer) = peers.by_tailnet_ip(&dst) else {
        debug!(%dst, "outbound to unknown tailnet ip, dropping");
        return;
    };
    let step = match peer.core.encapsulate(pkt) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "encapsulate for peer");
            return;
        }
    };
    for bytes in step.to_network {
        if let Err(e) = derp.send(peer.node_key, &bytes).await {
            warn!(error = %e, "derp send (data) failed");
        }
    }
}
