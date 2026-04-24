//! Control-channel handler. Runs per accepted TCP flow on
//! `(wg_ip, CONTROL_PORT)`. Reads one `ClientReq`, routes based on kind:
//!
//! * `StopReverse` / `ListReverse` — synchronous response, close.
//! * `RequestShell { Interactive }` — hand the flow to the framed stdio
//!   pump in `shell_handler::run_interactive`.
//! * `RequestShell { Oneshot | FireAndForget }` — synchronous response
//!   with the captured output / pid, close.
//! * `StartTcpTunnel` / `StartUdpTunnel` — bind a real OS listener on
//!   the burrow host's OS interface(s), write `ServerResp::Started`,
//!   then upgrade the flow to yamux. For each peer that connects to
//!   the listener, the server opens an outbound yamux substream to
//!   the owning client; the client dials `forward_to` locally and
//!   pipes bytes. UDP uses one substream for the tunnel with
//!   framed datagrams.
//!
//! `BindAddr` maps to an OS interface:
//!   * `Default` / `Any` → `0.0.0.0` (INADDR_ANY, all OS interfaces)
//!   * `Ipv4(x)` → bind to that specific interface address
//!
//! The host has to actually own the requested address for the bind to
//! succeed (same rule as any other program).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// Default TCP port the control listener binds on — 57821. Burrow
/// listens on `(tailnet_ip, DEFAULT_CONTROL_PORT)`; `burrow-client
/// tunnel`/`shell` targets this port unless `--control-port` is set.
pub const DEFAULT_CONTROL_PORT: u16 = 57821;

use crate::nat::NatKey;
use crate::proxy::ProxyMsg;
use crate::reverse_registry::{
    OpenRequest, ReverseRegistry, StartError, StopError, SubstreamOpener,
};
use crate::rewrite::PROTO_TCP;
use crate::runtime::{ConnectionId, SmoltcpHandle};
use crate::shell_handler::{handle_shell_request, run_interactive};
use crate::wire::{
    BindAddr, ClientReq, ErrorKind, Proto, ServerResp, ShellMode, TunnelSpec, MAX_FRAME_LEN,
};
use crate::yamux_bridge::{drive_connection, smoltcp_as_duplex, udp_frame};

/// Build a unique synthetic `NatKey` for the control-port listener
/// (which does live on smoltcp, since that's how WG peers reach the
/// burrow host's `wg_ip`). The counter-suffixed peer_port lets main.rs
/// re-arm the listener after each accept without key collisions.
pub fn listener_key(wg_ip: Ipv4Addr, port: u16) -> NatKey {
    static COUNTER: AtomicU16 = AtomicU16::new(1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    NatKey {
        proto: PROTO_TCP,
        peer_ip: Ipv4Addr::UNSPECIFIED,
        peer_port: seq,
        original_dst_ip: wg_ip,
        original_dst_port: port,
    }
}

/// Spawn the per-flow handler. Returns the `ProxyMsg` sender that the
/// event loop feeds with `TcpData` / `PeerFin` / `Closed`.
pub fn spawn_control_handler(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    registry: Arc<ReverseRegistry>,
) -> mpsc::UnboundedSender<ProxyMsg> {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run_once(id, smoltcp, msg_rx, registry).await {
            tracing::debug!(?id, error = %e, "control handler exited");
        }
    });
    msg_tx
}

async fn run_once(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    mut msg_rx: mpsc::UnboundedReceiver<ProxyMsg>,
    registry: Arc<ReverseRegistry>,
) -> anyhow::Result<()> {
    let mut leftover: Vec<u8> = Vec::new();

    let len_bytes = read_n(&mut msg_rx, &mut leftover, 4).await?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    if len > MAX_FRAME_LEN {
        send_error(
            &smoltcp,
            id,
            ErrorKind::InvalidRequest,
            format!("frame {len} exceeds cap {MAX_FRAME_LEN}"),
        )
        .await;
        smoltcp.close_tcp(id);
        return Ok(());
    }
    let frame = read_n(&mut msg_rx, &mut leftover, len as usize).await?;

    let req: ClientReq = match ciborium::de::from_reader(&frame[..]) {
        Ok(r) => r,
        Err(e) => {
            send_error(
                &smoltcp,
                id,
                ErrorKind::InvalidRequest,
                format!("cbor decode: {e}"),
            )
            .await;
            smoltcp.close_tcp(id);
            return Ok(());
        }
    };

    // Interactive shell takes over the flow with a framed stdio pump.
    if let ClientReq::RequestShell {
        mode: ShellMode::Interactive,
        program,
        args,
    } = &req
    {
        write_resp(&smoltcp, id, &ServerResp::ShellReady).await;
        run_interactive(id, smoltcp, leftover, msg_rx, program.clone(), args.clone()).await;
        return Ok(());
    }

    // TCP / UDP reverse tunnels upgrade the flow to yamux after the
    // Started response.
    if let ClientReq::StartTcpTunnel(spec) | ClientReq::StartUdpTunnel(spec) = &req {
        let proto = if matches!(req, ClientReq::StartTcpTunnel(_)) {
            Proto::Tcp
        } else {
            Proto::Udp
        };
        start_tunnel(id, smoltcp, leftover, msg_rx, registry, proto, spec.clone()).await;
        return Ok(());
    }

    let resp = handle_request(req, &registry).await;
    write_resp(&smoltcp, id, &resp).await;
    smoltcp.close_tcp(id);
    Ok(())
}

async fn handle_request(req: ClientReq, registry: &ReverseRegistry) -> ServerResp {
    match req {
        ClientReq::StartTcpTunnel(_) | ClientReq::StartUdpTunnel(_) => {
            // Dispatched above; reaching here means a wiring mistake.
            ServerResp::Error {
                kind: ErrorKind::Internal,
                msg: "tunnel start reached synchronous path".into(),
            }
        }
        ClientReq::StopReverse { tunnel_id } => match registry.stop(tunnel_id) {
            Ok(_entry) => {
                tracing::info!(?tunnel_id, "reverse tunnel stopped");
                ServerResp::Stopped
            }
            Err(StopError::UnknownTunnel) => ServerResp::Error {
                kind: ErrorKind::UnknownTunnel,
                msg: format!("tunnel {tunnel_id:?} not found"),
            },
        },
        ClientReq::ListReverse => ServerResp::ReverseList(registry.list()),
        ClientReq::RequestShell {
            mode,
            program,
            args,
        } => handle_shell_request(mode, program, args).await,
    }
}

/// Resolve `BindAddr` to the concrete OS interface address to bind on.
/// `Default` / `Any` both map to INADDR_ANY; `Ipv4` is a specific
/// interface (which the host must actually own — otherwise the bind
/// fails with AddrNotAvailable).
fn bind_ip(bind: BindAddr) -> Ipv4Addr {
    match bind {
        BindAddr::Default | BindAddr::Any => Ipv4Addr::UNSPECIFIED,
        BindAddr::Ipv4(x) => x,
    }
}

/// Start a reverse tunnel.
///   1. Resolve bind → OS socket address.
///   2. Bind a real OS listener (`TcpListener` or `UdpSocket`) so that
///      any connection on that port reaches this process through the
///      kernel's network stack.
///   3. Register in `ReverseRegistry` with the opener channel.
///   4. Write `ServerResp::Started`.
///   5. Spawn the per-proto accept loop (each accepted flow requests a
///      yamux substream via the opener, then bridges bytes).
///   6. Upgrade the control flow to yamux server and drive_connection.
///   7. When the client disconnects, `drive_connection` exits; we drop
///      the listener (which terminates the accept loop) and
///      deregister.
#[allow(clippy::too_many_arguments)]
async fn start_tunnel(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    leftover: Vec<u8>,
    msg_rx: mpsc::UnboundedReceiver<ProxyMsg>,
    registry: Arc<ReverseRegistry>,
    proto: Proto,
    spec: TunnelSpec,
) {
    let bind_ipv4 = bind_ip(spec.bind);
    let bind_sock = SocketAddr::V4(SocketAddrV4::new(bind_ipv4, spec.listen_port));

    // Bind the real OS listener up front so we can surface a clean
    // error (e.g. AddrInUse, AddrNotAvailable) before writing Started.
    enum Listener {
        Tcp(TcpListener),
        Udp(UdpSocket),
    }
    let listener = match proto {
        Proto::Tcp => match TcpListener::bind(bind_sock).await {
            Ok(l) => Listener::Tcp(l),
            Err(e) => {
                let kind = match e.kind() {
                    std::io::ErrorKind::AddrInUse => ErrorKind::PortInUse,
                    std::io::ErrorKind::AddrNotAvailable => ErrorKind::InvalidRequest,
                    _ => ErrorKind::Internal,
                };
                send_error(&smoltcp, id, kind, format!("tcp bind {bind_sock}: {e}")).await;
                smoltcp.close_tcp(id);
                return;
            }
        },
        Proto::Udp => match UdpSocket::bind(bind_sock).await {
            Ok(s) => Listener::Udp(s),
            Err(e) => {
                let kind = match e.kind() {
                    std::io::ErrorKind::AddrInUse => ErrorKind::PortInUse,
                    std::io::ErrorKind::AddrNotAvailable => ErrorKind::InvalidRequest,
                    _ => ErrorKind::Internal,
                };
                send_error(&smoltcp, id, kind, format!("udp bind {bind_sock}: {e}")).await;
                smoltcp.close_tcp(id);
                return;
            }
        },
    };

    let (opener_tx, opener_rx) = mpsc::unbounded_channel();
    let tunnel_id = match registry.start(
        proto,
        spec.listen_port,
        spec.bind,
        spec.forward_to.clone(),
        opener_tx.clone(),
    ) {
        Ok(t) => t,
        Err(StartError::PortInUse) => {
            send_error(
                &smoltcp,
                id,
                ErrorKind::PortInUse,
                format!(
                    "tunnel {:?}/{} already registered on {:?}",
                    proto, spec.listen_port, spec.bind
                ),
            )
            .await;
            smoltcp.close_tcp(id);
            return;
        }
    };

    write_resp(&smoltcp, id, &ServerResp::Started { tunnel_id }).await;

    tracing::info!(
        ?proto,
        bind = %bind_sock,
        forward_to = %spec.forward_to,
        ?tunnel_id,
        "reverse tunnel listening; upgrading control flow to yamux"
    );

    // Spawn the accept loop. It holds the listener and owns the opener
    // clone used to request substreams for each accepted flow.
    let accept_task = match listener {
        Listener::Tcp(l) => tokio::spawn(tcp_accept_loop(l, opener_tx.clone())),
        Listener::Udp(s) => tokio::spawn(udp_accept_loop(s, opener_tx.clone())),
    };

    // Upgrade the control flow to yamux.
    let duplex = smoltcp_as_duplex(id, smoltcp.clone(), leftover, msg_rx);
    let conn = yamux::Connection::new(
        duplex.compat(),
        yamux::Config::default(),
        yamux::Mode::Server,
    );
    drive_connection(conn, opener_rx, None).await;

    // Client disconnected or control flow closed — terminate the accept
    // loop (dropping the listener closes the port) and drop the tunnel.
    accept_task.abort();
    let _ = registry.stop(tunnel_id);
    tracing::info!(?tunnel_id, ?proto, "reverse tunnel closed");
}

/// TCP accept loop: on each peer connection, request a fresh yamux
/// substream from the owning client and bridge bytes in both
/// directions until either side closes.
async fn tcp_accept_loop(listener: TcpListener, opener: SubstreamOpener) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::debug!(error = %e, "tcp accept failed; stopping tunnel");
                return;
            }
        };
        let _ = tcp.set_nodelay(true);
        tracing::debug!(%peer, "tcp tunnel: accepted, requesting substream");
        let opener = opener.clone();
        tokio::spawn(async move {
            let Some(substream) = open_substream(&opener).await else {
                return;
            };
            bridge_tcp_to_yamux(tcp, substream).await;
        });
    }
}

async fn bridge_tcp_to_yamux(tcp: TcpStream, substream: yamux::Stream) {
    let compat = substream.compat();
    let (mut y_r, mut y_w) = tokio::io::split(compat);
    let (mut t_r, mut t_w) = tcp.into_split();
    let a = tokio::io::copy(&mut y_r, &mut t_w);
    let b = tokio::io::copy(&mut t_r, &mut y_w);
    let _ = tokio::try_join!(a, b);
}

/// UDP accept loop: open a single substream for the tunnel, serialize
/// outbound frames through a channel-backed writer, and run a reader
/// that decodes frames coming back from the client and sends them to
/// the tagged peer via the local UdpSocket.
async fn udp_accept_loop(socket: UdpSocket, opener: SubstreamOpener) {
    let Some(substream) = open_substream(&opener).await else {
        return;
    };
    let compat = substream.compat();
    let (mut y_r, mut y_w) = tokio::io::split(compat);

    // Writer side: frames emitted into this channel are serialized and
    // written to the yamux substream.
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<(Ipv4Addr, u16, Vec<u8>)>();
    let writer = tokio::spawn(async move {
        while let Some((ip, port, payload)) = frame_rx.recv().await {
            if udp_frame::write(&mut y_w, ip, port, &payload)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let socket = Arc::new(socket);

    // Reader side: client responses come back as framed datagrams on
    // the substream; we sendto the tagged peer using the OS socket.
    let sock_r = Arc::clone(&socket);
    let reader = tokio::spawn(async move {
        loop {
            let (peer_ip, peer_port, payload) = match udp_frame::read(&mut y_r).await {
                Ok(t) => t,
                Err(_) => break,
            };
            let addr = SocketAddr::V4(SocketAddrV4::new(peer_ip, peer_port));
            let _ = sock_r.send_to(&payload, addr).await;
        }
    });

    // Recv loop: each datagram → framed push.
    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::debug!(error = %e, "udp recv_from failed; stopping tunnel");
                break;
            }
        };
        let SocketAddr::V4(peer) = peer else {
            // IPv6 peers aren't modelled by the frame format yet.
            continue;
        };
        if frame_tx
            .send((*peer.ip(), peer.port(), buf[..n].to_vec()))
            .is_err()
        {
            break;
        }
    }

    reader.abort();
    writer.abort();
}

/// Request a new outbound substream on the owning client's yamux
/// connection via the shared `SubstreamOpener` channel.
async fn open_substream(opener: &SubstreamOpener) -> Option<yamux::Stream> {
    let (reply_tx, reply_rx) = oneshot::channel();
    if opener.send(OpenRequest { reply: reply_tx }).is_err() {
        tracing::debug!("opener channel closed; skipping substream");
        return None;
    }
    match reply_rx.await {
        Ok(Ok(s)) => Some(s),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "yamux open_stream failed");
            None
        }
        Err(_) => None,
    }
}

async fn read_n(
    msg_rx: &mut mpsc::UnboundedReceiver<ProxyMsg>,
    leftover: &mut Vec<u8>,
    n: usize,
) -> anyhow::Result<Vec<u8>> {
    while leftover.len() < n {
        match msg_rx.recv().await {
            Some(ProxyMsg::Data(data)) => leftover.extend_from_slice(&data),
            Some(ProxyMsg::PeerFin) | Some(ProxyMsg::Closed) | None => {
                anyhow::bail!("peer closed before full frame");
            }
        }
    }
    Ok(leftover.drain(..n).collect())
}

async fn send_error(smoltcp: &SmoltcpHandle, id: ConnectionId, kind: ErrorKind, msg: String) {
    let resp = ServerResp::Error { kind, msg };
    write_resp(smoltcp, id, &resp).await;
}

async fn write_resp(smoltcp: &SmoltcpHandle, id: ConnectionId, resp: &ServerResp) {
    let mut payload = Vec::new();
    if let Err(e) = ciborium::ser::into_writer(resp, &mut payload) {
        tracing::warn!(?id, error = %e, "control resp: cbor encode failed");
        return;
    }
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(&payload);
    let mut remaining = &framed[..];
    for _ in 0..32 {
        match smoltcp.write_tcp(id, remaining.to_vec()).await {
            Ok(0) => tokio::time::sleep(std::time::Duration::from_millis(2)).await,
            Ok(n) => {
                remaining = &remaining[n..];
                if remaining.is_empty() {
                    return;
                }
            }
            Err(e) => {
                tracing::debug!(?id, error = %e, "control resp: smoltcp gone");
                return;
            }
        }
    }
    if !remaining.is_empty() {
        tracing::warn!(
            ?id,
            "control resp: gave up writing after repeated buffer-full"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_keys_are_unique() {
        let a = listener_key(Ipv4Addr::new(10, 0, 0, 2), 57821);
        let b = listener_key(Ipv4Addr::new(10, 0, 0, 2), 57821);
        assert_ne!(a, b, "each listener_key call must produce a fresh key");
    }

    #[test]
    fn bind_ip_resolves() {
        assert_eq!(bind_ip(BindAddr::Default), Ipv4Addr::UNSPECIFIED);
        assert_eq!(bind_ip(BindAddr::Any), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            bind_ip(BindAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1))),
            Ipv4Addr::new(192, 168, 1, 1)
        );
    }
}
