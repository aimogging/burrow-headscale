//! Dedicated thread that owns the smoltcp `Interface`, `SocketSet`, and
//! `ChannelDevice`. smoltcp's API is single-threaded and pull-based, so all
//! manipulation funnels through this thread via a command channel. State
//! changes and inbound data flow back to the tokio runtime through an event
//! channel.
//!
//! ## Why `ConnectionId`, not `SocketHandle`
//!
//! `smoltcp::iface::SocketHandle` is a bare `pub struct SocketHandle(usize)`
//! — an index into a slot table with no generation counter. When the smoltcp
//! thread evicts a closed socket via `sockets.remove(handle)`, the slot is
//! freed and may be reused on the next `sockets.add(...)`. But cross-thread
//! commands (`WriteTcp`, `CloseTcp`, ...) sit in the cmd channel after their
//! socket is gone — at best smoltcp panics on `get_mut` on the freed slot,
//! at worst a brand new connection silently receives stale writes.
//!
//! The fix: bare `SocketHandle`s never leave this thread. Every connection
//! is also issued a monotonically increasing `ConnectionId(u64)` — the
//! opaque token that crosses the channel. `handle_command` resolves
//! `ConnectionId → SocketHandle` against an internal map; if the id is gone
//! (because we already emitted `TcpClosed` and tore down the entry), the
//! command is silently no-op'd. Slot reuse is harmless because the new
//! socket gets a fresh `ConnectionId`.
//!
//! This module is the *plumbing* for the smoltcp side. The actual proxying
//! (open OS TcpStream, shuffle bytes both ways) lives in `crate::proxy`.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Cidr};
use tokio::sync::{mpsc, oneshot};

use crate::rewrite::PROTO_TCP;

use crate::nat::{
    ConnectionState, NatKey, NatTable, DEFAULT_TCP_GRACE, VIRTUAL_CIDR_PREFIX, VIRTUAL_IFACE_ADDR,
};
use crate::smoltcp_iface::{build_interface, ChannelDevice, PacketReceiver, PacketSender};

/// Per-socket smoltcp buffer size. Phase 11 Option A: pick a small fixed
/// value so a large concurrent-listener pool (post-virtual_ip allocator the
/// identifier space holds ~8.6 billion slots) stays memory-bounded. 4 KiB
/// each direction keeps 1 M idle listeners at ~8 GiB of socket buffers —
/// still generous vs Phase 11's expected workload. Established flows pay
/// the same small window, trading single-stream throughput for concurrency
/// headroom. See the Phase 11 plan for the Option A/B tradeoff.
const TCP_BUF_SIZE: usize = 4096;

/// Maximum bytes drained from a single socket per poll cycle. Keeps any one
/// flow from monopolising the smoltcp thread under heavy load.
const RECV_CHUNK: usize = 16 * 1024;

/// Loop sleep when the thread is idle. Sets the worst-case latency for new
/// packets / commands. Small enough to feel snappy, large enough to keep
/// CPU at idle low.
const IDLE_SLEEP: Duration = Duration::from_millis(2);

/// Opaque token identifying a single smoltcp connection across thread
/// boundaries. Never reused — even if smoltcp recycles the underlying
/// `SocketHandle` slot, a new connection gets a new `ConnectionId`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ConnectionId(u64);

pub enum SmoltcpCmd {
    /// Idempotently create a TCP listener bound to `(virtual_ip, port)` and
    /// tag it with `key` so the runtime can route the eventual ESTABLISHED
    /// event to the right NAT entry. Replies once with the issued
    /// `ConnectionId`. Two listeners on the same `port` but different
    /// `virtual_ip` coexist — smoltcp dispatches on the full
    /// `IpListenEndpoint`.
    EnsureTcpListener {
        virtual_ip: Ipv4Addr,
        port: u16,
        key: NatKey,
        ready: oneshot::Sender<ConnectionId>,
    },
    /// Open an outbound TCP connection originated by burrow itself (reverse
    /// tunnels, future DNS/control flows). smoltcp binds the socket on
    /// `local` (which should be `(wg_ip, ephemeral_port)`) and calls
    /// `connect` to `remote`. Replies once the SYN has been dispatched with
    /// the `ConnectionId`; the caller then awaits `SmoltcpEvent::TcpConnected`
    /// on the same id to know the remote completed the handshake.
    ///
    /// The stored `NatKey` is synthetic — it carries `remote` in the
    /// peer-side fields and `local` in the original_dst-side fields — and
    /// is NOT inserted into the NAT table. It's only used for event routing
    /// and diagnostics. Egress packets from this socket have src==wg_ip and
    /// MUST bypass `rewrite_outbound` in the egress loop.
    OpenOutboundTcp {
        local: SocketAddrV4,
        remote: SocketAddrV4,
        ready: oneshot::Sender<Result<ConnectionId>>,
    },
    /// Append `data` to the smoltcp socket's tx buffer. Replies with the
    /// number of bytes accepted (0 if the buffer is full or the socket is
    /// not in a sendable state — caller should retry). Replies with 0 if
    /// the connection has already been torn down.
    WriteTcp {
        id: ConnectionId,
        data: Vec<u8>,
        ack: oneshot::Sender<usize>,
    },
    /// Initiate a graceful close (FIN). Returns when the command is
    /// dispatched, not when the close completes. Silently no-op if the
    /// connection has already been torn down.
    CloseTcp { id: ConnectionId },
    /// Send RST. Silently no-op if the connection has already been torn down.
    AbortTcp { id: ConnectionId },
}

#[derive(Debug)]
pub enum SmoltcpEvent {
    /// Socket transitioned to ESTABLISHED. Spawn a proxy task here.
    TcpConnected { key: NatKey, id: ConnectionId },
    /// Bytes were received on a socket. May arrive in many small chunks.
    TcpData {
        key: NatKey,
        id: ConnectionId,
        data: Vec<u8>,
    },
    /// Socket entered a closing state (FIN from peer). Caller should
    /// half-close the OS-side stream's write half.
    TcpFinFromPeer { key: NatKey, id: ConnectionId },
    /// Socket reached terminal CLOSED state. The `ConnectionId` is no longer
    /// valid after this event; subsequent commands referencing it no-op.
    TcpClosed { key: NatKey, id: ConnectionId },
    /// Phase 10: connection attempt was aborted before reaching ESTABLISHED
    /// (peer sent RST after SYN-ACK, or the listener went directly to
    /// CLOSED without ever transitioning through ESTABLISHED). The smoltcp
    /// socket and ConnectionId are torn down by the time this event fires;
    /// callers should drop any armed OS-side stream and forget the entry.
    /// `ConnectionId` is invalid after this event.
    TcpAborted { key: NatKey, id: ConnectionId },
}

/// Cheap-to-clone handle for issuing commands and feeding inbound packets to
/// the smoltcp thread.
#[derive(Clone)]
pub struct SmoltcpHandle {
    cmd_tx: mpsc::UnboundedSender<SmoltcpCmd>,
    rx_tx: PacketSender,
}

impl SmoltcpHandle {
    /// Push an inbound packet (already dst-rewritten by the NAT table) into
    /// the smoltcp Device's rx queue.
    pub fn enqueue_inbound(&self, packet: Vec<u8>) {
        // If the smoltcp thread has gone, drop silently — the rest of the
        // system will surface that elsewhere.
        let _ = self.rx_tx.send(packet);
    }

    pub fn ensure_listener(
        &self,
        virtual_ip: Ipv4Addr,
        port: u16,
        key: NatKey,
    ) -> oneshot::Receiver<ConnectionId> {
        let (tx, rx) = oneshot::channel();
        let _ = self.cmd_tx.send(SmoltcpCmd::EnsureTcpListener {
            virtual_ip,
            port,
            key,
            ready: tx,
        });
        rx
    }

    /// Originate an outbound TCP connection. `local` should typically be
    /// `(wg_ip, 0)` — the runtime picks an ephemeral local port if the
    /// port is 0. Returns the `ConnectionId` once the socket is registered;
    /// the caller awaits `SmoltcpEvent::TcpConnected { id, .. }` to know the
    /// handshake completed. The synthetic `NatKey` attached to events has
    /// `peer_* = remote`, `original_dst_* = local` — useful for debug
    /// output; NOT a real NAT-table entry.
    pub async fn open_outbound_tcp(
        &self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> Result<ConnectionId> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SmoltcpCmd::OpenOutboundTcp {
                local,
                remote,
                ready: tx,
            })
            .map_err(|_| anyhow!("smoltcp thread terminated"))?;
        rx.await
            .map_err(|_| anyhow!("smoltcp thread dropped reply"))?
    }

    pub async fn write_tcp(&self, id: ConnectionId, data: Vec<u8>) -> Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SmoltcpCmd::WriteTcp { id, data, ack: tx })
            .map_err(|_| anyhow!("smoltcp thread terminated"))?;
        rx.await
            .map_err(|_| anyhow!("smoltcp thread dropped reply"))
    }

    pub fn close_tcp(&self, id: ConnectionId) {
        let _ = self.cmd_tx.send(SmoltcpCmd::CloseTcp { id });
    }

    pub fn abort_tcp(&self, id: ConnectionId) {
        let _ = self.cmd_tx.send(SmoltcpCmd::AbortTcp { id });
    }
}

pub struct SmoltcpEvents {
    pub evt_rx: mpsc::UnboundedReceiver<SmoltcpEvent>,
}

/// Spawn the smoltcp poll thread. Returns the cmd handle, an event stream,
/// and the receiver end of the device's tx queue (drained by the egress
/// task to encapsulate and send through the WG tunnel). The smoltcp
/// interface is configured with the synthetic `198.18.0.0/15` range (see
/// `nat::VIRTUAL_*`) plus `wg_ip/32` — the WG IP is required for
/// originated outbound flows (reverse tunnels, DNS, control channel) so
/// smoltcp can produce packets with the right src address and accept
/// responses to it. `set_any_ip(true)` makes the interface accept packets
/// to any address in that pool.
pub fn spawn_smoltcp(
    nat: Arc<NatTable>,
    wg_ip: Ipv4Addr,
) -> (SmoltcpHandle, SmoltcpEvents, PacketReceiver) {
    let (rx_tx, rx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (tx_tx, tx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel();

    let nat_thread = Arc::clone(&nat);

    thread::Builder::new()
        .name("burrow-smoltcp".into())
        .spawn(move || run_smoltcp_thread(rx_rx, tx_tx, cmd_rx, evt_tx, nat_thread, wg_ip))
        .expect("spawn smoltcp thread");

    (
        SmoltcpHandle { cmd_tx, rx_tx },
        SmoltcpEvents { evt_rx },
        tx_rx,
    )
}

/// The smoltcp thread's view of an open connection. Owned exclusively by
/// the smoltcp thread; never crosses a channel.
struct ConnState {
    handle: SocketHandle,
    key: NatKey,
}

fn run_smoltcp_thread(
    rx_queue: PacketReceiver,
    tx_queue: PacketSender,
    mut cmd_rx: mpsc::UnboundedReceiver<SmoltcpCmd>,
    evt_tx: mpsc::UnboundedSender<SmoltcpEvent>,
    nat: Arc<NatTable>,
    wg_ip: Ipv4Addr,
) {
    let addr = Ipv4Cidr::new(VIRTUAL_IFACE_ADDR, VIRTUAL_CIDR_PREFIX);
    let mut device = ChannelDevice::new(rx_queue, tx_queue);
    let mut iface = build_interface(&addr, &mut device);
    // Add wg_ip as a second interface address so originated outbound sockets
    // can bind src=wg_ip and smoltcp accepts the replies. /32 keeps it a
    // host route — we don't want to accidentally shadow the virtual /15.
    iface.update_ip_addrs(|addrs| {
        let wg_cidr = Ipv4Cidr::new(wg_ip, 32);
        addrs
            .push(IpCidr::Ipv4(wg_cidr))
            .expect("interface address vec full — should hold wg_ip alongside virtual CIDR");
    });
    // `any_ip=true` makes `has_ip_addr` return true unconditionally, so the
    // interface accepts packets addressed to any virtual_ip in the pool
    // without needing to enumerate 131K addresses on the interface vec.
    iface.set_any_ip(true);
    tracing::debug!(?wg_ip, "smoltcp interface bound with wg_ip");
    let mut sockets: SocketSet<'static> = SocketSet::new(vec![]);

    let mut conns: HashMap<ConnectionId, ConnState> = HashMap::new();
    let mut by_handle: HashMap<SocketHandle, ConnectionId> = HashMap::new();
    let mut last_states: HashMap<ConnectionId, tcp::State> = HashMap::new();
    // Phase 10: track which conns ever reached ESTABLISHED so we can
    // distinguish "aborted before establishment" (drop everything, no proxy
    // exists) from "closed after establishment" (signal proxy to wind down,
    // mark NAT entry for grace-period sweep).
    let mut ever_established: HashSet<ConnectionId> = HashSet::new();
    let mut next_id: u64 = 0;

    // Fix #3 observability: emit a single ERROR the first time the event
    // consumer disappears, then stay quiet. A flapping consumer doesn't
    // produce log spam but also doesn't get silently swallowed forever.
    let consumer_alive = AtomicBool::new(true);
    let send_evt = |evt: SmoltcpEvent| {
        if evt_tx.send(evt).is_err() && consumer_alive.swap(false, Ordering::Relaxed) {
            tracing::error!("smoltcp event consumer task gone — TCP path is dead");
        }
    };

    let mut last_cardinality_log = Instant::now();
    const CARDINALITY_LOG_INTERVAL: Duration = Duration::from_secs(30);

    tracing::info!(addr = ?addr, "smoltcp thread started");

    loop {
        // 1. Drain commands first so a freshly registered listener is in place
        //    before its triggering SYN reaches `iface.poll`.
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_command(
                cmd,
                &mut iface,
                &mut sockets,
                &mut conns,
                &mut by_handle,
                &mut next_id,
                &nat,
            );
        }

        // 2. Drive the stack. `poll` returns whether anything changed —
        //    purely advisory, ignore.
        let _changed = iface.poll(SmolInstant::now(), &mut device, &mut sockets);

        // 3. Inspect each socket; emit events on transitions / data.
        let mut to_drop: Vec<ConnectionId> = Vec::new();
        // Phase 10: aborted connections — never reached ESTABLISHED. Tear
        // down the smoltcp socket AND evict the NAT entry (no grace
        // period — there's no proxy/peer state to wind down).
        let mut to_abort: Vec<(ConnectionId, NatKey)> = Vec::new();
        for (handle, socket) in sockets.iter_mut() {
            let smoltcp::socket::Socket::Tcp(tcp_sock) = socket else {
                continue;
            };
            let Some(&id) = by_handle.get(&handle) else {
                continue;
            };
            let Some(state) = conns.get(&id) else {
                continue;
            };
            let key = state.key;

            let new_state = tcp_sock.state();
            let prev = last_states.get(&id).copied();

            // Phase 10: detect "aborted before establishment". smoltcp
            // explicitly sends a SYN-RECEIVED listener back to LISTEN on
            // RST (smoltcp 0.13 socket/tcp.rs:1818-1826), so SYN-scan
            // workloads (`nmap -sS`) leave listeners stuck in LISTEN
            // forever — never reaching CLOSED, never firing TcpClosed.
            // Treat any backwards transition (toward LISTEN, or directly
            // to CLOSED) without a prior ESTABLISHED as an abort.
            let mut is_aborting = false;

            if prev != Some(new_state) {
                last_states.insert(id, new_state);
                tracing::trace!(?id, ?key, ?prev, ?new_state, "tcp state change");

                // Detect establishment via any post-SYN_RECEIVED state.
                // smoltcp can transition Established → CloseWait (or
                // further) inside a single `Interface::poll` call; our
                // outer sampling then sees the later state without ever
                // observing Established. Any of these states implies the
                // 3-way handshake completed, so mark `ever_established`
                // and fire `TcpConnected` if we haven't already.
                let is_post_handshake = matches!(
                    new_state,
                    tcp::State::Established
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::CloseWait
                        | tcp::State::Closing
                        | tcp::State::LastAck
                        | tcp::State::TimeWait
                );
                if is_post_handshake && !ever_established.contains(&id) {
                    ever_established.insert(id);
                    nat.set_state(key, ConnectionState::Established);
                    send_evt(SmoltcpEvent::TcpConnected { key, id });
                }

                // CLOSE_WAIT means peer has FIN'd us. Half-close signal.
                if matches!(new_state, tcp::State::CloseWait)
                    && !matches!(prev, Some(tcp::State::CloseWait))
                {
                    send_evt(SmoltcpEvent::TcpFinFromPeer { key, id });
                }

                let went_back_to_listen =
                    matches!(prev, Some(tcp::State::SynReceived | tcp::State::SynSent))
                        && matches!(new_state, tcp::State::Listen);
                let closed_now = matches!(new_state, tcp::State::Closed);
                if (went_back_to_listen || closed_now) && !ever_established.contains(&id) {
                    tracing::debug!(
                        ?id,
                        ?key,
                        ?prev,
                        ?new_state,
                        "tcp aborted before establishment"
                    );
                    send_evt(SmoltcpEvent::TcpAborted { key, id });
                    to_abort.push((id, key));
                    is_aborting = true;
                }
            }

            if !is_aborting && tcp_sock.can_recv() {
                let mut buf = vec![0u8; RECV_CHUNK];
                if let Ok(n) = tcp_sock.recv_slice(&mut buf) {
                    if n > 0 {
                        buf.truncate(n);
                        send_evt(SmoltcpEvent::TcpData { key, id, data: buf });
                    }
                }
            }

            if matches!(new_state, tcp::State::Closed) && !is_aborting {
                send_evt(SmoltcpEvent::TcpClosed { key, id });
                nat.mark_closing(key, DEFAULT_TCP_GRACE);
                to_drop.push(id);
            }
        }

        for (id, key) in to_abort {
            if let Some(state) = conns.remove(&id) {
                sockets.remove(state.handle);
                by_handle.remove(&state.handle);
            }
            last_states.remove(&id);
            ever_established.remove(&id);
            // Aborted entries skip the TCP grace window — there's no
            // half-open state to keep alive and the gateway_port should
            // return to the pool immediately.
            nat.evict_key(key);
        }

        for id in to_drop {
            if let Some(state) = conns.remove(&id) {
                sockets.remove(state.handle);
                by_handle.remove(&state.handle);
            }
            last_states.remove(&id);
            ever_established.remove(&id);
        }

        // 4. Periodic cardinality log — tracks live socket count vs
        //    connection-id count. Steady-state should hover near zero
        //    plus open flows; monotonic growth is a leak signal.
        if last_cardinality_log.elapsed() >= CARDINALITY_LOG_INTERVAL {
            last_cardinality_log = Instant::now();
            tracing::debug!(
                sockets = sockets.iter().count(),
                conns = conns.len(),
                by_handle = by_handle.len(),
                "smoltcp cardinality"
            );
        }

        thread::sleep(IDLE_SLEEP);
    }
}

fn handle_command(
    cmd: SmoltcpCmd,
    iface: &mut smoltcp::iface::Interface,
    sockets: &mut SocketSet<'static>,
    conns: &mut HashMap<ConnectionId, ConnState>,
    by_handle: &mut HashMap<SocketHandle, ConnectionId>,
    next_id: &mut u64,
    nat: &NatTable,
) {
    match cmd {
        SmoltcpCmd::EnsureTcpListener {
            virtual_ip,
            port,
            key,
            ready,
        } => {
            // If we already have a listener for this key, hand back the same
            // id. Idempotent: callers can fire this on every inbound packet
            // without growing the socket set.
            if let Some(existing) = conns
                .iter()
                .find_map(|(id, st)| (st.key == key).then_some(*id))
            {
                let _ = ready.send(existing);
                return;
            }
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let mut sock = tcp::Socket::new(rx_buf, tx_buf);
            // Bind the listener to the specific (virtual_ip, gateway_port).
            // Smoltcp matches per-socket on the full `IpListenEndpoint`, so
            // two listeners sharing a port but on different virtual_ips
            // dispatch correctly.
            let endpoint = IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(virtual_ip)),
                port,
            };
            if let Err(e) = sock.listen(endpoint) {
                tracing::warn!(?virtual_ip, port, ?e, "tcp listen failed");
                // Drop `ready` so the caller's await wakes up with an error.
                drop(ready);
                return;
            }
            let handle = sockets.add(sock);
            let id = ConnectionId(*next_id);
            *next_id += 1;
            conns.insert(id, ConnState { handle, key });
            by_handle.insert(handle, id);
            nat.set_id(key, id);
            let _ = ready.send(id);
        }
        SmoltcpCmd::OpenOutboundTcp {
            local,
            remote,
            ready,
        } => {
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let sock = tcp::Socket::new(rx_buf, tx_buf);
            let handle = sockets.add(sock);
            // Grab a mutable ref back out so we can call connect with
            // iface.context(). This mirrors how listeners are set up — add
            // first, configure after.
            let connect_result = {
                let sock_mut = sockets.get_mut::<tcp::Socket>(handle);
                let local_ep = IpListenEndpoint {
                    addr: Some(IpAddress::Ipv4(*local.ip())),
                    port: local.port(),
                };
                let remote_ep = IpEndpoint {
                    addr: IpAddress::Ipv4(*remote.ip()),
                    port: remote.port(),
                };
                sock_mut.connect(iface.context(), remote_ep, local_ep)
            };
            if let Err(e) = connect_result {
                sockets.remove(handle);
                let _ = ready.send(Err(anyhow!("tcp connect: {e:?}")));
                return;
            }
            let id = ConnectionId(*next_id);
            *next_id += 1;
            // Synthetic NatKey: carries remote in peer_* and local in
            // original_dst_*. Never inserted into the NAT table; used only
            // for event routing + tracing output.
            let synth_key = NatKey {
                proto: PROTO_TCP,
                peer_ip: *remote.ip(),
                peer_port: remote.port(),
                original_dst_ip: *local.ip(),
                original_dst_port: local.port(),
            };
            conns.insert(
                id,
                ConnState {
                    handle,
                    key: synth_key,
                },
            );
            by_handle.insert(handle, id);
            let _ = ready.send(Ok(id));
        }
        SmoltcpCmd::WriteTcp { id, data, ack } => {
            // Stale id (already torn down). No-op with 0 bytes accepted —
            // the proxy task's pump will treat it as backpressure and exit
            // its loop on the next channel error.
            let Some(state) = conns.get(&id) else {
                let _ = ack.send(0);
                return;
            };
            let sock = sockets.get_mut::<tcp::Socket>(state.handle);
            let n = sock.send_slice(&data).unwrap_or(0);
            let _ = ack.send(n);
        }
        SmoltcpCmd::CloseTcp { id } => {
            let Some(state) = conns.get(&id) else { return };
            let sock = sockets.get_mut::<tcp::Socket>(state.handle);
            sock.close();
        }
        SmoltcpCmd::AbortTcp { id } => {
            let Some(state) = conns.get(&id) else { return };
            let sock = sockets.get_mut::<tcp::Socket>(state.handle);
            sock.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::NatTable;
    use crate::test_helpers::build_tcp_syn;
    use std::net::Ipv4Addr;
    use std::time::Duration as StdDuration;

    #[tokio::test]
    async fn runtime_emits_synack_for_listened_port() {
        let nat = Arc::new(NatTable::new());
        let (handle, _events, mut tx_rx) =
            spawn_smoltcp(Arc::clone(&nat), Ipv4Addr::new(10, 0, 0, 2));

        let mut syn = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            8080,
        );
        let (key, virtual_ip, gateway_port) = nat.rewrite_inbound(&mut syn).unwrap();

        // Set up listener BEFORE enqueueing the packet so the SYN finds it.
        // Listener binds the (virtual_ip, gateway_port) where smoltcp
        // actually sees the rewritten SYN.
        let id = handle
            .ensure_listener(virtual_ip, gateway_port, key)
            .await
            .unwrap();
        assert_eq!(nat.get(key).unwrap().smoltcp_id, Some(id));

        handle.enqueue_inbound(syn);

        // Spin until smoltcp emits a SYN-ACK.
        let mut found = None;
        for _ in 0..200 {
            tokio::time::sleep(StdDuration::from_millis(5)).await;
            if let Ok(p) = tx_rx.try_recv() {
                found = Some(p);
                break;
            }
        }
        let mut out = found.expect("expected SYN-ACK from smoltcp runtime");
        let ihl = ((out[0] & 0x0F) as usize) * 4;
        let flags = out[ihl + 13];
        assert_eq!(flags & 0x12, 0x12, "must be SYN-ACK");

        // After egress rewrite, src should be the original dst.
        let restored = nat.rewrite_outbound(&mut out).unwrap();
        assert_eq!(restored.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
    }
}
