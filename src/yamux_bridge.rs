//! Infrastructure for client-originated reverse tunnels.
//!
//! A running burrow-client holds one TCP control flow open per tunnel;
//! both sides wrap that flow in yamux. The server never dials the
//! tunnel's `forward_to`; instead, when a peer connects to the tunnel's
//! listen port, the server opens an outbound yamux substream to the
//! owning client, and the client dials its local `forward_to` and
//! pipes bytes.
//!
//! This module owns:
//!   * [`drive_connection`] — the single-owner task that polls a
//!     `yamux::Connection` for both new-outbound (on request) and
//!     next-inbound. Other tasks reach the connection via the
//!     `SubstreamOpener` channel in `reverse_registry`.
//!   * [`UdpFrame`] — length-prefixed datagram format for UDP reverse
//!     tunnels. One substream per tunnel carries all peers' traffic;
//!     each frame tags the peer `(ip, port)` so the client can open /
//!     reuse the right local UDP socket on reply.

use std::future::poll_fn;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use yamux::{Connection, Stream};

use crate::proxy::ProxyMsg;
use crate::reverse_registry::OpenRequest;
use crate::runtime::{ConnectionId, SmoltcpHandle};

/// Adapt a smoltcp-accepted TCP flow into a single AsyncRead+AsyncWrite
/// stream, so it can be handed to `yamux::Connection::new`.
///
/// Spawns two pump tasks:
///   * msg_rx (plus any pre-consumed leftover bytes from the CBOR
///     handshake) → writes into the duplex half that the returned
///     `DuplexStream` reads from.
///   * Reads from the duplex half's write side → `smoltcp.write_tcp`
///     in chunks, retrying briefly on Ok(0).
///
/// Returns the duplex half suitable for yamux. When the returned half
/// is dropped / closes, the write pump calls `close_tcp` so the peer
/// sees a FIN.
pub fn smoltcp_as_duplex(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    leftover: Vec<u8>,
    mut msg_rx: mpsc::UnboundedReceiver<ProxyMsg>,
) -> DuplexStream {
    let (inner, outer) = tokio::io::duplex(128 * 1024);
    let (mut inner_r, mut inner_w) = tokio::io::split(inner);

    // Pump A: smoltcp recv side → duplex.
    tokio::spawn(async move {
        if !leftover.is_empty() && inner_w.write_all(&leftover).await.is_err() {
            return;
        }
        while let Some(msg) = msg_rx.recv().await {
            match msg {
                ProxyMsg::Data(d) => {
                    if inner_w.write_all(&d).await.is_err() {
                        return;
                    }
                }
                ProxyMsg::PeerFin | ProxyMsg::Closed => {
                    let _ = inner_w.shutdown().await;
                    return;
                }
            }
        }
    });

    // Pump B: duplex → smoltcp.write_tcp.
    let smoltcp_for_b = smoltcp.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match inner_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut remaining: &[u8] = &buf[..n];
                    for _ in 0..500 {
                        if remaining.is_empty() {
                            break;
                        }
                        match smoltcp_for_b.write_tcp(id, remaining.to_vec()).await {
                            Ok(0) => tokio::time::sleep(std::time::Duration::from_millis(2)).await,
                            Ok(n) => remaining = &remaining[n..],
                            Err(_) => return,
                        }
                    }
                }
                Err(_) => break,
            }
        }
        smoltcp_for_b.close_tcp(id);
    });

    outer
}

/// Bridge a yamux substream ↔ smoltcp-accepted TCP flow. Symmetric
/// byte pump (each side's reads → the other's writes). Exits when
/// either side closes. Used when a peer connects to a registered TCP
/// tunnel: server opens an outbound yamux substream to the owning
/// client, then wires it to the smoltcp flow with this function.
///
/// yamux::Stream implements `futures::io::AsyncRead/Write` (not
/// tokio's), so we go through the tokio-util compat adapter.
pub async fn bridge_yamux_to_smoltcp(
    yamux_stream: Stream,
    smoltcp_stream: DuplexStream,
) -> std::io::Result<()> {
    let y_compat = yamux_stream.compat();
    let (mut y_r, mut y_w) = tokio::io::split(y_compat);
    let (mut s_r, mut s_w) = tokio::io::split(smoltcp_stream);
    let ab = tokio::io::copy(&mut y_r, &mut s_w);
    let ba = tokio::io::copy(&mut s_r, &mut y_w);
    let _ = tokio::try_join!(ab, ba);
    Ok(())
}

/// Wrap a yamux substream as tokio AsyncRead+AsyncWrite via the
/// futures ↔ tokio compat shim. Used for the UDP framed codec and
/// anywhere a caller wants to keep the substream as one piece.
pub fn yamux_into_tokio(stream: Stream) -> tokio_util::compat::Compat<Stream> {
    stream.compat()
}

/// Drive a yamux connection on one dedicated task: poll
/// `poll_new_outbound` when an opener request arrives, and
/// `poll_next_inbound` for peer-initiated substreams. Ends when the
/// connection closes (peer disconnect) or `open_rx` is dropped.
///
/// `inbound_tx` is `None` for the server side (we never expect inbound
/// substreams — the client doesn't open any); `Some(sender)` on the
/// client so incoming substreams get handed to the per-tunnel handler.
pub async fn drive_connection<T>(
    mut conn: Connection<T>,
    mut open_rx: mpsc::UnboundedReceiver<OpenRequest>,
    inbound_tx: Option<mpsc::UnboundedSender<Stream>>,
) where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            biased;

            // Requests from other tasks to open outbound substreams.
            req = open_rx.recv() => {
                let Some(req) = req else {
                    // No more requesters: close the connection.
                    let _ = poll_fn(|cx| conn.poll_close(cx)).await;
                    return;
                };
                let result = poll_fn(|cx| conn.poll_new_outbound(cx)).await;
                let to_send = result.map_err(|e| e.to_string());
                let _ = req.reply.send(to_send);
            }
            // Inbound substream opened by the peer.
            inbound = poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                match inbound {
                    Some(Ok(stream)) => {
                        if let Some(tx) = inbound_tx.as_ref() {
                            let _ = tx.send(stream);
                        } else {
                            tracing::debug!("unexpected inbound substream on server side — dropping");
                        }
                    }
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "yamux inbound error");
                    }
                    None => {
                        // Connection is done.
                        return;
                    }
                }
            }
        }
    }
}

/// UDP frame format, one datagram per frame on a UDP tunnel's yamux
/// substream:
///
/// ```text
/// | u32 be payload_len | u32 be peer_ipv4 | u16 be peer_port | payload |
/// ```
///
/// `payload_len` is the bytes-after-the-header count, not the total.
/// Only IPv4 for now (matches burrow's smoltcp).
pub mod udp_frame {
    use std::io;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    pub const MAX_PAYLOAD: u32 = 65_535;

    pub async fn write<W: AsyncWrite + Unpin>(
        w: &mut W,
        peer_ip: Ipv4Addr,
        peer_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        if payload.len() as u64 > MAX_PAYLOAD as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("udp payload {} exceeds cap {}", payload.len(), MAX_PAYLOAD),
            ));
        }
        w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
        w.write_all(&peer_ip.octets()).await?;
        w.write_all(&peer_port.to_be_bytes()).await?;
        if !payload.is_empty() {
            w.write_all(payload).await?;
        }
        w.flush().await?;
        Ok(())
    }

    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(Ipv4Addr, u16, Vec<u8>)> {
        let mut hdr = [0u8; 4 + 4 + 2];
        r.read_exact(&mut hdr).await?;
        let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        if len > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("udp frame length {len} exceeds cap {MAX_PAYLOAD}"),
            ));
        }
        let peer_ip = Ipv4Addr::new(hdr[4], hdr[5], hdr[6], hdr[7]);
        let peer_port = u16::from_be_bytes([hdr[8], hdr[9]]);
        let mut payload = vec![0u8; len as usize];
        if len > 0 {
            r.read_exact(&mut payload).await?;
        }
        Ok((peer_ip, peer_port, payload))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::duplex;

        #[tokio::test]
        async fn roundtrip() {
            let (mut a, mut b) = duplex(4096);
            write(&mut a, Ipv4Addr::new(10, 0, 0, 1), 5353, b"hi")
                .await
                .unwrap();
            let (ip, port, payload) = read(&mut b).await.unwrap();
            assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(port, 5353);
            assert_eq!(payload, b"hi");
        }

        #[tokio::test]
        async fn empty_payload_roundtrip() {
            let (mut a, mut b) = duplex(64);
            write(&mut a, Ipv4Addr::new(1, 2, 3, 4), 9, &[])
                .await
                .unwrap();
            let (_, _, payload) = read(&mut b).await.unwrap();
            assert!(payload.is_empty());
        }
    }
}
