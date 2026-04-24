//! Per-invocation client dataplane for `burrow-client`.
//!
//! Registers with Headscale, connects to the assigned DERP region, and
//! exposes [`ClientSession::open_tcp`] — an outbound TCP dial to a
//! tailnet peer IP that returns a [`DerpTcpStream`] (tokio
//! `AsyncRead + AsyncWrite`) in place of what used to be a direct
//! `tokio::net::TcpStream`.
//!
//! ## Why a separate module from `hs_main`
//!
//! `hs_main` is the full server-side data plane: NAT rewrite, reverse
//! tunnel listeners, DNS, control channel, ICMP. `burrow-client` only
//! originates outbound TCP flows from its own tailnet IP, so none of
//! that machinery applies. Extracting a third "dataplane bootstrap"
//! helper that both could share would obscure the difference — the
//! client path is a strict subset and it's short enough to stand alone.
//!
//! ## Task topology
//!
//! The session owns five background tasks, all abortable on `Drop`:
//!
//! - reconciler: netmap → `PeerTable::reconcile`
//! - egress: smoltcp TX → `peer.encapsulate` → DERP
//! - ingress: DERP recv → `peer.decapsulate` → smoltcp enqueue
//! - wg-timer: 250ms tick → `peer.timer_tick` → DERP
//! - dispatcher: `SmoltcpEvent` fan-out → per-stream channel
//!
//! The dispatcher exists because `SmoltcpEvents::evt_rx` is a single
//! consumer; multiple concurrent `DerpTcpStream`s each need their own
//! view of `TcpData`/`TcpClosed`/... events keyed by `ConnectionId`.

use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};
use url::Url;

use crate::derp::DerpClient;
use crate::headscale::HeadscaleClient;
use crate::nat::NatTable;
use crate::node_identity::NodeIdentity;
use crate::peer_reconciler::spawn_reconciler;
use crate::peer_table::PeerTable;
use crate::rewrite::{self, PROTO_UDP};
use crate::runtime::{spawn_smoltcp, ConnectionId, SmoltcpEvent, SmoltcpHandle};
use crate::udp_proxy::extract_udp_payload;

/// How long `open_tcp` waits for the target peer to show up in the
/// Headscale netmap before failing. Typical Headscale delivers the
/// full peer list inside a few hundred ms of registration.
const PEER_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `open_tcp` waits for the TCP 3-way handshake to complete
/// once smoltcp has been asked to dial. Generous: the first packet
/// kicks off the WG handshake as a side-effect, adding ~1 DERP RTT on
/// top of the usual TCP RTT.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Lowest ephemeral port we hand out for outbound sockets. smoltcp
/// 0.13 rejects port 0 on `connect()` (despite docs — see the comment
/// in `tests/originated_outbound_tcp.rs`), so `ClientSession` runs its
/// own monotonic allocator starting here and wrapping at 65535.
const EPHEMERAL_PORT_FLOOR: u16 = 49152;

/// Per-stream event forwarded by the dispatcher task to its
/// `DerpTcpStream`.
#[derive(Debug)]
enum StreamEvent {
    Connected,
    Data(Vec<u8>),
    PeerFin,
    Closed,
    Aborted,
}

type StreamRegistry = Arc<Mutex<HashMap<ConnectionId, mpsc::UnboundedSender<StreamEvent>>>>;

/// One datagram dispatched to a `UdpReceiver`: sender tailnet IP,
/// sender port, payload.
pub type UdpDatagram = (Ipv4Addr, u16, Vec<u8>);

/// Per-local-port UDP listener registry. Ingress looks up by the
/// packet's *destination* port (our ephemeral) and pushes the
/// datagram to the matching listener.
type UdpDispatchMap = Arc<Mutex<HashMap<u16, mpsc::UnboundedSender<UdpDatagram>>>>;

pub struct ClientSession {
    tailnet_ip: Ipv4Addr,
    peers: Arc<PeerTable>,
    smoltcp: SmoltcpHandle,
    derp: Arc<DerpClient>,
    headscale: HeadscaleClient,
    streams: StreamRegistry,
    udp_listeners: UdpDispatchMap,
    tasks: Vec<JoinHandle<()>>,
    /// Monotonic ephemeral-port allocator for outbound TCP connects
    /// and UDP binds. Both protocols share the range since local
    /// bookkeeping only cares about (proto, port) collisions and we
    /// never overlap within a single protocol — `fetch_add` wraps at
    /// `u16::MAX` and we remap into
    /// [`EPHEMERAL_PORT_FLOOR`..=65535].
    next_ephemeral: Arc<AtomicU16>,
}

/// Receiver handle for UDP datagrams dispatched to a bound port.
/// Dropping this unregisters the listener from the session's
/// dispatch table — subsequent datagrams on that port are dropped
/// silently.
pub struct UdpReceiver {
    port: u16,
    rx: mpsc::UnboundedReceiver<UdpDatagram>,
    listeners: UdpDispatchMap,
}

impl UdpReceiver {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Next datagram for this bound port. Returns `None` once the
    /// dispatcher task exits (i.e. the session is shutting down).
    pub async fn recv(&mut self) -> Option<UdpDatagram> {
        self.rx.recv().await
    }
}

impl Drop for UdpReceiver {
    fn drop(&mut self) {
        self.listeners.lock().unwrap().remove(&self.port);
    }
}

impl ClientSession {
    /// Register with Headscale, connect DERP, and start the client
    /// dataplane. Returns once both the tailnet IP and home DERP
    /// region are populated — typically a few hundred ms after the
    /// TLS handshake to Headscale completes.
    pub async fn connect(server_url: Url, authkey: &str, hostname: Option<String>) -> Result<Self> {
        let ident = Arc::new(NodeIdentity::generate());
        let headscale = HeadscaleClient::connect(server_url, &ident, authkey, hostname)
            .await
            .context("HeadscaleClient::connect")?;

        let (tailnet_ip, derp_servers) = wait_for_initial_state(&headscale).await?;
        tracing::info!(
            %tailnet_ip,
            regions = derp_servers.len(),
            "burrow-client registered with Headscale",
        );

        let (derp, derp_rx) = DerpClient::connect(&derp_servers, &ident.state.node_keys)
            .await
            .context("DERP connect")?;
        let derp = Arc::new(derp);

        let peers = Arc::new(PeerTable::new());
        let reconciler = spawn_reconciler(
            headscale.subscribe(),
            Arc::clone(&peers),
            Arc::clone(&ident),
            None,
        );

        // `NatTable` is required by `spawn_smoltcp` but unused here —
        // we never ingest NAT'd traffic on the client side (no peers
        // initiate connections to *us*). `set_state`/`mark_closing`
        // silently no-op on unknown keys, so the synthetic NatKeys
        // that outbound sockets carry are harmless.
        let nat = Arc::new(NatTable::new());
        let (smoltcp, events, smoltcp_tx_rx) = spawn_smoltcp(Arc::clone(&nat), tailnet_ip);

        let egress = tokio::spawn({
            let peers = Arc::clone(&peers);
            let derp = Arc::clone(&derp);
            async move {
                egress_loop(smoltcp_tx_rx, peers, derp).await;
            }
        });

        let udp_listeners: UdpDispatchMap = Arc::new(Mutex::new(HashMap::new()));
        let ingress = tokio::spawn({
            let peers = Arc::clone(&peers);
            let derp = Arc::clone(&derp);
            let smoltcp = smoltcp.clone();
            let udp_listeners = Arc::clone(&udp_listeners);
            async move {
                ingress_loop(derp_rx, peers, derp, smoltcp, tailnet_ip, udp_listeners).await;
            }
        });

        let timer = tokio::spawn({
            let peers = Arc::clone(&peers);
            let derp = Arc::clone(&derp);
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(250));
                loop {
                    interval.tick().await;
                    tick_all_peers(&peers, &derp).await;
                }
            }
        });

        let streams: StreamRegistry = Arc::new(Mutex::new(HashMap::new()));
        let dispatcher = tokio::spawn({
            let streams = Arc::clone(&streams);
            dispatcher_loop(events, streams)
        });

        let tasks = vec![reconciler, egress, ingress, timer, dispatcher];
        Ok(Self {
            tailnet_ip,
            peers,
            smoltcp,
            derp,
            headscale,
            streams,
            udp_listeners,
            tasks,
            next_ephemeral: Arc::new(AtomicU16::new(0)),
        })
    }

    fn alloc_ephemeral_port(&self) -> u16 {
        // fetch_add wraps at u16::MAX; remap into the [49152..=65535]
        // range (16384 slots). Collisions inside the process are
        // possible after 16k connects — smoltcp surfaces them as
        // `tcp connect: Unaddressable`, which we'd see on open_tcp.
        // At a CLI's scale (<10 outbound flows per session) it's a
        // non-issue.
        let n = self.next_ephemeral.fetch_add(1, Ordering::Relaxed);
        EPHEMERAL_PORT_FLOOR + (n % (u16::MAX - EPHEMERAL_PORT_FLOOR + 1))
    }

    pub fn tailnet_ip(&self) -> Ipv4Addr {
        self.tailnet_ip
    }

    /// Open a TCP connection from our tailnet IP to `(dst, port)`. The
    /// destination must be another tailnet node — the peer has to be
    /// present in Headscale's netmap. Waits up to
    /// [`PEER_WAIT_TIMEOUT`] for the peer to arrive and
    /// [`CONNECT_TIMEOUT`] for the handshake to complete.
    pub async fn open_tcp(&self, dst: Ipv4Addr, port: u16) -> Result<DerpTcpStream> {
        self.wait_for_peer(dst).await?;

        // Nudge the WG handshake in parallel with smoltcp's SYN so the
        // peer's Tunn is usually established by the time boringtun
        // encapsulates the first payload packet. Best-effort: any
        // error here is non-fatal — boringtun will initiate a
        // handshake on the first encapsulate call otherwise, at the
        // cost of one smoltcp SYN retransmit.
        if let Some(peer) = self.peers.by_tailnet_ip(&dst) {
            if let Ok(step) = peer.core.handshake_init(false) {
                for pkt in step.to_network {
                    let _ = self.derp.send(peer.node_key, &pkt).await;
                }
            }
        }

        let (evt_tx, mut evt_rx) = mpsc::unbounded_channel::<StreamEvent>();
        let local = SocketAddrV4::new(self.tailnet_ip, self.alloc_ephemeral_port());
        let remote = SocketAddrV4::new(dst, port);
        let id = self
            .smoltcp
            .open_outbound_tcp(local, remote)
            .await
            .context("smoltcp open_outbound_tcp")?;

        // Register BEFORE the smoltcp thread next polls so we can't
        // miss the TcpConnected event. Commands-then-poll ordering in
        // `run_smoltcp_thread` guarantees the connect command runs on
        // poll cycle N and the earliest event emit is cycle N+1.
        self.streams.lock().unwrap().insert(id, evt_tx);

        match tokio::time::timeout(CONNECT_TIMEOUT, await_connected(&mut evt_rx)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                self.streams.lock().unwrap().remove(&id);
                self.smoltcp.abort_tcp(id);
                return Err(e.context(format!("connect to {remote}")));
            }
            Err(_) => {
                self.streams.lock().unwrap().remove(&id);
                self.smoltcp.abort_tcp(id);
                return Err(anyhow!(
                    "timed out after {CONNECT_TIMEOUT:?} waiting for TCP handshake to {remote}"
                ));
            }
        }

        Ok(DerpTcpStream::new(
            id,
            self.smoltcp.clone(),
            evt_rx,
            Arc::clone(&self.streams),
        ))
    }

    /// Poll `PeerTable` (populated by the reconciler) for a peer at
    /// `dst`. Polling — not a watch-channel await — because PeerTable
    /// updates are downstream of netmap updates + the reconciler task,
    /// and there's a race where `watch::Receiver::changed()` returns
    /// *before* the reconciler has finished processing the same
    /// snapshot. A fixed-interval poll catches the peer once the
    /// reconciler's insert lands in the DashMap, independent of the
    /// netmap-to-reconciler ordering.
    /// Bind a UDP listener on a fresh ephemeral port. Returned
    /// [`UdpReceiver`] deregisters the listener on drop. Use the
    /// returned port as the `src_port` when calling
    /// [`ClientSession::send_udp`]; datagrams whose dst port matches
    /// will be dispatched to the receiver.
    pub fn bind_udp(&self) -> UdpReceiver {
        let port = self.alloc_ephemeral_port();
        let (tx, rx) = mpsc::unbounded_channel::<UdpDatagram>();
        self.udp_listeners.lock().unwrap().insert(port, tx);
        UdpReceiver {
            port,
            rx,
            listeners: Arc::clone(&self.udp_listeners),
        }
    }

    /// Send a UDP datagram from `(our_tailnet_ip, src_port)` to
    /// `(dst, dst_port)`. Waits for the peer to appear in the netmap
    /// + triggers a WG handshake-init side-effect on the first call
    /// so subsequent requests pay only 1 RTT.
    pub async fn send_udp(
        &self,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        self.wait_for_peer(dst).await?;
        let peer = self
            .peers
            .by_tailnet_ip(&dst)
            .ok_or_else(|| anyhow!("peer {dst} disappeared between wait and send"))?;
        let packet = rewrite::build_udp_packet(self.tailnet_ip, dst, src_port, dst_port, payload);
        let step = peer
            .core
            .encapsulate(&packet)
            .context("encapsulating UDP datagram")?;
        for bytes in step.to_network {
            self.derp
                .send(peer.node_key, &bytes)
                .await
                .context("DERP send (UDP)")?;
        }
        Ok(())
    }

    /// Fire-and-await-response convenience wrapper: binds a UDP
    /// listener, sends a datagram, awaits the first reply (regardless
    /// of source), and drops the listener. Suitable for request-reply
    /// protocols like DNS. For multi-reply flows, use
    /// [`ClientSession::bind_udp`] + [`ClientSession::send_udp`]
    /// directly.
    pub async fn query_udp(
        &self,
        dst: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let mut recv = self.bind_udp();
        self.send_udp(recv.port(), dst, dst_port, payload).await?;
        let (_src, _from_port, reply) = tokio::time::timeout(timeout, recv.recv())
            .await
            .map_err(|_| anyhow!("UDP query to {dst}:{dst_port} timed out after {timeout:?}"))?
            .ok_or_else(|| anyhow!("UDP listener channel closed"))?;
        Ok(reply)
    }

    async fn wait_for_peer(&self, dst: Ipv4Addr) -> Result<()> {
        let deadline = tokio::time::Instant::now() + PEER_WAIT_TIMEOUT;
        let mut logged = false;
        while tokio::time::Instant::now() < deadline {
            if self.peers.by_tailnet_ip(&dst).is_some() {
                return Ok(());
            }
            if !logged {
                let snap = self.headscale.snapshot();
                tracing::debug!(
                    %dst,
                    peer_table_len = self.peers.len(),
                    netmap_peers = snap.peers.len(),
                    netmap_ips = ?snap.peers.iter().map(|p| p.tailnet_ipv4).collect::<Vec<_>>(),
                    "wait_for_peer: dst not yet in peer table, polling",
                );
                logged = true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let snap = self.headscale.snapshot();
        let known: Vec<Ipv4Addr> = snap.peers.iter().map(|p| p.tailnet_ipv4).collect();
        Err(anyhow!(
            "peer {dst} not present in PeerTable after {PEER_WAIT_TIMEOUT:?} \
             (peer_table_len={}, netmap_peers={:?})",
            self.peers.len(),
            known,
        ))
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
        }
    }
}

async fn await_connected(rx: &mut mpsc::UnboundedReceiver<StreamEvent>) -> Result<()> {
    loop {
        match rx.recv().await {
            Some(StreamEvent::Connected) => return Ok(()),
            Some(StreamEvent::Aborted) => return Err(anyhow!("peer aborted before establish")),
            Some(StreamEvent::Closed) => return Err(anyhow!("connection closed before establish")),
            // Pre-connect data or half-closes shouldn't happen, but
            // drain defensively rather than error out.
            Some(_) => continue,
            None => return Err(anyhow!("dispatcher channel closed")),
        }
    }
}

async fn dispatcher_loop(mut events: crate::runtime::SmoltcpEvents, streams: StreamRegistry) {
    while let Some(evt) = events.evt_rx.recv().await {
        let (id, kind) = match evt {
            SmoltcpEvent::TcpConnected { id, .. } => (id, StreamEvent::Connected),
            SmoltcpEvent::TcpData { id, data, .. } => (id, StreamEvent::Data(data)),
            SmoltcpEvent::TcpFinFromPeer { id, .. } => (id, StreamEvent::PeerFin),
            SmoltcpEvent::TcpClosed { id, .. } => (id, StreamEvent::Closed),
            SmoltcpEvent::TcpAborted { id, .. } => (id, StreamEvent::Aborted),
        };
        let is_terminal = matches!(kind, StreamEvent::Closed | StreamEvent::Aborted);
        let tx = streams.lock().unwrap().get(&id).cloned();
        match tx {
            Some(tx) => {
                let _ = tx.send(kind);
            }
            None => {
                trace!(?id, "smoltcp event for unregistered stream — dropping");
            }
        }
        if is_terminal {
            streams.lock().unwrap().remove(&id);
        }
    }
}

async fn egress_loop(
    mut tx_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    peers: Arc<PeerTable>,
    derp: Arc<DerpClient>,
) {
    while let Some(pkt) = tx_rx.recv().await {
        let view = match rewrite::parse_5tuple(&pkt) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "egress: non-IPv4 / unparseable packet, dropping");
                continue;
            }
        };
        let Some(peer) = peers.by_tailnet_ip(&view.dst_ip) else {
            debug!(dst = %view.dst_ip, "egress: no peer for dst ip, dropping");
            continue;
        };
        let step = match peer.core.encapsulate(&pkt) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "egress: encapsulate failed");
                continue;
            }
        };
        for bytes in step.to_network {
            if let Err(e) = derp.send(peer.node_key, &bytes).await {
                warn!(error = %e, "egress: DERP send failed");
            }
        }
    }
}

async fn ingress_loop(
    mut derp_rx: mpsc::UnboundedReceiver<crate::derp::DerpInbound>,
    peers: Arc<PeerTable>,
    derp: Arc<DerpClient>,
    smoltcp: SmoltcpHandle,
    tailnet_ip: Ipv4Addr,
    udp_listeners: UdpDispatchMap,
) {
    while let Some(frame) = derp_rx.recv().await {
        let Some(peer) = peers.by_node_key(&frame.sender) else {
            debug!(sender = ?frame.sender, "ingress: inbound from unknown peer");
            continue;
        };
        let step = match peer.core.decapsulate(None, &frame.bytes) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "ingress: decapsulate failed");
                continue;
            }
        };
        for pkt in step.to_network {
            if let Err(e) = derp.send(peer.node_key, &pkt).await {
                warn!(error = %e, "ingress: DERP send (handshake reply) failed");
            }
        }
        if step.expired {
            warn!("ingress: peer session expired");
        }
        if let Some(tp) = step.to_tunnel {
            // UDP datagrams addressed to one of our bound ports go to
            // the matching listener. Everything else falls through to
            // smoltcp (TCP flows + anything unbound — dropped there).
            if let Ok(view) = rewrite::parse_5tuple(&tp.data) {
                if view.proto == PROTO_UDP && view.dst_ip == tailnet_ip {
                    let listener = udp_listeners.lock().unwrap().get(&view.dst_port).cloned();
                    if let Some(tx) = listener {
                        if let Some(payload) = extract_udp_payload(&tp.data) {
                            let _ = tx.send((view.src_ip, view.src_port, payload));
                            continue;
                        }
                        debug!(?view, "ingress: malformed UDP payload, dropping");
                        continue;
                    }
                    debug!(
                        dst_port = view.dst_port,
                        "ingress: UDP to unbound port, dropping"
                    );
                    continue;
                }
            }
            smoltcp.enqueue_inbound(tp.data);
        }
    }
}

async fn tick_all_peers(peers: &PeerTable, derp: &DerpClient) {
    use ts_keys::NodePublicKey;
    let mut work: Vec<(NodePublicKey, Vec<u8>)> = Vec::new();
    peers.for_each(|peer| match peer.core.timer_tick() {
        Ok(step) => {
            for pkt in step.to_network {
                work.push((peer.node_key, pkt));
            }
        }
        Err(e) => warn!(error = %e, "timer tick failed"),
    });
    for (dst, pkt) in work {
        if let Err(e) = derp.send(dst, &pkt).await {
            debug!(error = %e, "timer: DERP send failed");
        }
    }
}

async fn wait_for_initial_state(
    client: &HeadscaleClient,
) -> Result<(Ipv4Addr, Vec<ts_transport_derp::ServerConnInfo>)> {
    let mut rx = client.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let snap = client.snapshot();
        if let (Some(ip), Some(region)) = (snap.my_tailnet_ipv4, pick_home_region(&snap)) {
            if let Some(map) = snap.derp_map.as_ref() {
                if let Some(region_info) = map.get(&region) {
                    return Ok((ip, region_info.servers.clone()));
                }
            }
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(anyhow!(
                "Headscale did not deliver tailnet IP + DERP region inside 10s"
            ));
        }
        tokio::time::timeout(deadline - now, rx.changed())
            .await
            .map_err(|_| anyhow!("netmap stream produced no state change inside 10s"))?
            .map_err(|_| anyhow!("netmap watch channel closed"))?;
    }
}

fn pick_home_region(state: &crate::headscale::ControlState) -> Option<ts_transport_derp::RegionId> {
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

/// Tokio-io duplex stream over a smoltcp `ConnectionId`. Reads drain
/// from a `SmoltcpEvent::TcpData` channel; writes push into a pump
/// task that calls [`SmoltcpHandle::write_tcp`] with retry on
/// backpressure (matching the pattern used by `crate::proxy`).
pub struct DerpTcpStream {
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    streams: StreamRegistry,

    // Read path.
    evt_rx: mpsc::UnboundedReceiver<StreamEvent>,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,

    // Write path: feed the pump; pump drives write_tcp with retries.
    write_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    pump: Option<JoinHandle<()>>,
}

impl DerpTcpStream {
    fn new(
        id: ConnectionId,
        smoltcp: SmoltcpHandle,
        evt_rx: mpsc::UnboundedReceiver<StreamEvent>,
        streams: StreamRegistry,
    ) -> Self {
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let pump = tokio::spawn(write_pump(write_rx, id, smoltcp.clone()));
        Self {
            id,
            smoltcp,
            streams,
            evt_rx,
            read_buf: Vec::new(),
            read_pos: 0,
            eof: false,
            write_tx: Some(write_tx),
            pump: Some(pump),
        }
    }
}

impl Drop for DerpTcpStream {
    fn drop(&mut self) {
        // Detach the dispatcher entry; pending per-stream events are
        // then dropped silently instead of queuing unread.
        self.streams.lock().unwrap().remove(&self.id);
        // Best-effort: close the smoltcp socket if it hasn't already
        // gone through the pump's shutdown path.
        self.smoltcp.close_tcp(self.id);
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

async fn write_pump(
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
) {
    while let Some(data) = write_rx.recv().await {
        let mut remaining = data;
        while !remaining.is_empty() {
            match smoltcp.write_tcp(id, remaining.clone()).await {
                Ok(0) => {
                    // smoltcp tx buffer full or socket not yet in a
                    // sendable state — same backoff as crate::proxy.
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Ok(n) => {
                    remaining.drain(..n);
                }
                Err(e) => {
                    debug!(?id, error = %e, "write_pump: smoltcp gone");
                    return;
                }
            }
        }
    }
    // Sender dropped (poll_shutdown / Drop) — emit FIN.
    smoltcp.close_tcp(id);
}

impl AsyncRead for DerpTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.read_pos < self.read_buf.len() {
                let remaining = &self.read_buf[self.read_pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                self.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match self.evt_rx.poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(data))) => {
                    self.read_buf = data;
                    self.read_pos = 0;
                    // Loop to drain the new chunk into `buf`.
                    continue;
                }
                Poll::Ready(Some(StreamEvent::PeerFin))
                | Poll::Ready(Some(StreamEvent::Closed))
                | Poll::Ready(Some(StreamEvent::Aborted)) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(StreamEvent::Connected)) => {
                    // Duplicate Connected (shouldn't happen post-open).
                    continue;
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for DerpTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let Some(tx) = self.write_tx.as_ref() else {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream already shut down",
            )));
        };
        match tx.send(data.to_vec()) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "write pump terminated",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // No application-level flush signal: the write pump processes
        // queued chunks in order, and smoltcp buffers outbound bytes
        // until the next poll tick. Callers that need "everything is
        // on the wire" semantics should wait on the peer's ack.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Drop the write sender so the pump exits after draining any
        // queued chunks, then emits the smoltcp CloseTcp (FIN).
        self.write_tx.take();
        if let Some(pump) = self.pump.as_mut() {
            match Pin::new(pump).poll(cx) {
                Poll::Ready(_) => {
                    self.pump.take();
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::NatTable;
    use crate::runtime::{spawn_smoltcp, SmoltcpEvents};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn smoltcp_for_test() -> SmoltcpHandle {
        let nat = Arc::new(NatTable::new());
        let (handle, _events, _tx_rx) = spawn_smoltcp(nat, Ipv4Addr::new(100, 64, 0, 1));
        handle
    }

    #[tokio::test]
    async fn dispatcher_routes_events_by_id_and_removes_on_terminal() {
        let (evt_tx, evt_rx) = mpsc::unbounded_channel::<SmoltcpEvent>();
        let events = SmoltcpEvents { evt_rx };
        let streams: StreamRegistry = Arc::new(Mutex::new(HashMap::new()));

        let (a_tx, mut a_rx) = mpsc::unbounded_channel::<StreamEvent>();
        let (b_tx, mut b_rx) = mpsc::unbounded_channel::<StreamEvent>();
        let id_a = ConnectionId::for_test(1);
        let id_b = ConnectionId::for_test(2);
        streams.lock().unwrap().insert(id_a, a_tx);
        streams.lock().unwrap().insert(id_b, b_tx);

        let task = tokio::spawn(dispatcher_loop(events, Arc::clone(&streams)));

        // Fake key to stuff into SmoltcpEvent — only `id` matters to
        // the dispatcher; it never inspects `key`.
        let fake_key = crate::nat::NatKey {
            proto: 6,
            peer_ip: Ipv4Addr::new(0, 0, 0, 0),
            peer_port: 0,
            original_dst_ip: Ipv4Addr::new(0, 0, 0, 0),
            original_dst_port: 0,
        };

        evt_tx
            .send(SmoltcpEvent::TcpConnected {
                key: fake_key,
                id: id_a,
            })
            .unwrap();
        evt_tx
            .send(SmoltcpEvent::TcpData {
                key: fake_key,
                id: id_b,
                data: b"hello".to_vec(),
            })
            .unwrap();
        evt_tx
            .send(SmoltcpEvent::TcpClosed {
                key: fake_key,
                id: id_a,
            })
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(1), a_rx.recv()).await {
            Ok(Some(StreamEvent::Connected)) => {}
            other => panic!("expected Connected on a, got {other:?}"),
        }
        match tokio::time::timeout(Duration::from_secs(1), a_rx.recv()).await {
            Ok(Some(StreamEvent::Closed)) => {}
            other => panic!("expected Closed on a, got {other:?}"),
        }
        match tokio::time::timeout(Duration::from_secs(1), b_rx.recv()).await {
            Ok(Some(StreamEvent::Data(d))) if d == b"hello" => {}
            other => panic!("expected Data(hello) on b, got {other:?}"),
        }

        // Terminal event must evict id_a; id_b still live.
        // Give the dispatcher a tick to process the remove.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let map = streams.lock().unwrap();
        assert!(!map.contains_key(&id_a), "id_a must be removed on Closed");
        assert!(map.contains_key(&id_b), "id_b stays until its own terminal");

        drop(map);
        drop(evt_tx);
        let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
    }

    #[tokio::test]
    async fn stream_drains_data_events_and_reports_eof_on_peer_fin() {
        let smoltcp = smoltcp_for_test();
        let streams: StreamRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (evt_tx, evt_rx) = mpsc::unbounded_channel::<StreamEvent>();
        let id = ConnectionId::for_test(0x9999);

        let mut stream = DerpTcpStream::new(id, smoltcp, evt_rx, streams);

        evt_tx.send(StreamEvent::Data(b"hello ".to_vec())).unwrap();
        evt_tx.send(StreamEvent::Data(b"world".to_vec())).unwrap();
        evt_tx.send(StreamEvent::PeerFin).unwrap();

        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut out))
            .await
            .expect("read_to_end didn't complete within 1s")
            .expect("read_to_end returned error");
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn stream_drop_removes_registry_entry() {
        let smoltcp = smoltcp_for_test();
        let streams: StreamRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (_evt_tx, evt_rx) = mpsc::unbounded_channel::<StreamEvent>();
        let id = ConnectionId::for_test(0x9999);
        // Plant a stream-side tx so Drop has something to evict.
        let (plant_tx, _plant_rx) = mpsc::unbounded_channel::<StreamEvent>();
        streams.lock().unwrap().insert(id, plant_tx);

        let stream = DerpTcpStream::new(id, smoltcp, evt_rx, Arc::clone(&streams));
        drop(stream);
        assert!(
            !streams.lock().unwrap().contains_key(&id),
            "Drop must evict the stream from the registry"
        );
    }

    #[tokio::test]
    async fn stream_write_buffers_into_pump_channel_and_reports_full_len() {
        let smoltcp = smoltcp_for_test();
        let streams: StreamRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (_evt_tx, evt_rx) = mpsc::unbounded_channel::<StreamEvent>();
        let id = ConnectionId::for_test(0x9999);
        let mut stream = DerpTcpStream::new(id, smoltcp, evt_rx, streams);

        // poll_write always returns Ready(Ok(data.len())): it pushes
        // into an unbounded channel that the pump drains.
        let n = stream.write(b"ping").await.expect("write");
        assert_eq!(n, 4);
    }
}
