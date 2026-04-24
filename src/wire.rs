//! Wire protocol types for the burrow control channel.
//!
//! Encoded as CBOR (via `ciborium`) to give us compact binary with field
//! names preserved — good forward-compat for adding new variants without
//! breaking older clients. Each control-port TCP flow carries a single
//! `ClientReq` from the client followed by one `ServerResp` from the
//! server, framed as:
//!
//! ```text
//! | u32 be length | CBOR bytes |
//! ```
//!
//! One exception: `ClientReq::RequestShell` makes the flow bidirectional
//! for the session lifetime (landing in Phase 16). Phase 13 ships only
//! the request/response shapes.
//!
//! ## TunnelId opacity
//!
//! `TunnelId` is a plain wrapper around `u64` — server-assigned, client
//! stores it only so it can `StopReverse`. Clients MUST NOT
//! interpret the value; format/layout is unspecified and may change.
//!
//! ## Frame-size cap
//!
//! The reader rejects frames whose length field exceeds `MAX_FRAME_LEN`.
//! A hostile or broken client could otherwise force the server to buffer
//! 4 GiB before failing. Control frames carry kilobyte-range payloads at
//! most — 1 MiB is already far more than any realistic request.

use std::io;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single control frame's encoded payload length. Matches
/// the check in `read_frame`.
pub const MAX_FRAME_LEN: u32 = 1 << 20;

/// Transport protocol selector for reverse-tunnel registrations.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Server-assigned opaque handle. Clients pass it back for
/// `StopReverse`. Server chooses the allocation scheme.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TunnelId(pub u64);

/// Shape of a `ListReverse` response entry. Kept small so the response
/// stays under `MAX_FRAME_LEN` even with thousands of active tunnels.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReverseEntry {
    pub tunnel_id: TunnelId,
    pub proto: Proto,
    pub listen_port: u16,
    pub forward_to: String,
    pub bind: BindAddr,
}

/// Reason codes for `ServerResp::Error`. Kept narrow so clients can match
/// on them — message string is for human eyes only.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    PortInUse,
    UnknownTunnel,
    InvalidRequest,
    NotYetSupported,
    Internal,
}

/// Execution mode for `RequestShell`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellMode {
    /// Run the program to completion, capture stdout/stderr/status,
    /// return everything in a single `ShellResult`. No PTY — use for
    /// scripted / non-interactive callers.
    Oneshot,
    /// Spawn the program detached. Server returns `ShellSpawned{pid}`
    /// immediately; no output is captured. The program outlives the
    /// control flow that launched it.
    FireAndForget,
    /// Interactive PTY session. Server responds `ShellReady`; the flow
    /// then switches to a framed stdio protocol for the session
    /// lifetime. Lands in Phase 17 (requires PTY crate + client-side
    /// terminal handling). Phase 16 returns `Error{NotYetSupported}`.
    Interactive,
}

/// Where on burrow's smoltcp interface a reverse tunnel listens. `Default`
/// uses the WG IP; `Any` binds on 0.0.0.0 (peers can target any dst IP
/// that the WG server routes to burrow); `Ipv4` pins a specific address.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BindAddr {
    Default,
    Any,
    Ipv4(Ipv4Addr),
}

impl Default for BindAddr {
    fn default() -> Self {
        Self::Default
    }
}

/// Parameters for a reverse-tunnel start request. `forward_to` is a
/// free-form string ("host:port") — resolved by the CLIENT when a
/// substream lands. Lets the target be any hostname the client's
/// machine can resolve + reach, regardless of what the burrow host
/// sees on its network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelSpec {
    pub listen_port: u16,
    pub forward_to: String,
    #[serde(default)]
    pub bind: BindAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientReq {
    /// Start a TCP reverse tunnel. Upgrades the control flow to
    /// yamux — the client must hold the flow open for the tunnel's
    /// lifetime. Server opens an outbound substream per incoming
    /// peer connection; client dials `forward_to` locally and pipes.
    StartTcpTunnel(TunnelSpec),
    /// Start a UDP reverse tunnel. Same handover pattern as TCP; one
    /// dedicated substream carries all tunnel datagrams, length- +
    /// peer-tagged so the client can preserve reply correlation.
    StartUdpTunnel(TunnelSpec),
    StopReverse {
        tunnel_id: TunnelId,
    },
    ListReverse,
    RequestShell {
        mode: ShellMode,
        /// Executable to run. `None` → per-OS default (`cmd.exe` on
        /// Windows, `$SHELL` or `/bin/sh` on Unix).
        program: Option<String>,
        /// Argv passed verbatim to the child. No shell interpolation
        /// server-side.
        args: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServerResp {
    Started {
        tunnel_id: TunnelId,
    },
    Stopped,
    ReverseList(Vec<ReverseEntry>),
    /// Response for `ShellMode::Oneshot`. `exit_code` is `None` if the
    /// process was terminated by a signal (Unix) or stopped via an
    /// unhandled exception (Windows).
    ShellResult {
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// Response for `ShellMode::FireAndForget`.
    ShellSpawned {
        pid: u32,
    },
    /// Response for `ShellMode::Interactive` (Phase 17). After
    /// sending, the server switches the flow into a framed stdio
    /// protocol for the session lifetime.
    ShellReady,
    Error {
        kind: ErrorKind,
        msg: String,
    },
}

/// Read one length-prefixed CBOR frame. Returns `Err(io::ErrorKind::UnexpectedEof)`
/// on clean close; any other error indicates a protocol violation.
pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("control frame length {len} exceeds cap {MAX_FRAME_LEN}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    ciborium::de::from_reader(&buf[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("cbor decode: {e}")))
}

/// Serialize and emit one length-prefixed CBOR frame.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut payload = Vec::new();
    ciborium::ser::into_writer(value, &mut payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("cbor encode: {e}")))?;
    let len = payload.len();
    if len > MAX_FRAME_LEN as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("encoded frame {len} exceeds cap {MAX_FRAME_LEN}"),
        ));
    }
    writer.write_all(&(len as u32).to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_start_tcp_tunnel() {
        let (mut a, mut b) = duplex(4096);
        let req = ClientReq::StartTcpTunnel(TunnelSpec {
            listen_port: 8080,
            forward_to: "127.0.0.1:9000".into(),
            bind: BindAddr::Default,
        });
        write_frame(&mut a, &req).await.unwrap();
        let got: ClientReq = read_frame(&mut b).await.unwrap();
        match got {
            ClientReq::StartTcpTunnel(spec) => {
                assert_eq!(spec.listen_port, 8080);
                assert_eq!(spec.forward_to, "127.0.0.1:9000");
                assert_eq!(spec.bind, BindAddr::Default);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn roundtrip_start_tcp_tunnel_with_bind() {
        let (mut a, mut b) = duplex(4096);
        let req = ClientReq::StartTcpTunnel(TunnelSpec {
            listen_port: 443,
            forward_to: "example.com:443".into(),
            bind: BindAddr::Any,
        });
        write_frame(&mut a, &req).await.unwrap();
        let got: ClientReq = read_frame(&mut b).await.unwrap();
        match got {
            ClientReq::StartTcpTunnel(spec) => {
                assert_eq!(spec.bind, BindAddr::Any);
                assert_eq!(spec.forward_to, "example.com:443");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn roundtrip_server_resp_list() {
        let (mut a, mut b) = duplex(4096);
        let resp = ServerResp::ReverseList(vec![ReverseEntry {
            tunnel_id: TunnelId(42),
            proto: Proto::Udp,
            listen_port: 53,
            forward_to: "8.8.8.8:53".into(),
            bind: BindAddr::Default,
        }]);
        write_frame(&mut a, &resp).await.unwrap();
        let got: ServerResp = read_frame(&mut b).await.unwrap();
        match got {
            ServerResp::ReverseList(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].tunnel_id, TunnelId(42));
                assert_eq!(entries[0].proto, Proto::Udp);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let (mut a, mut b) = duplex(8);
        // Write a bogus length header claiming 2 GiB.
        tokio::spawn(async move {
            let _ = a.write_all(&(2_000_000_000u32).to_be_bytes()).await;
        });
        let err: io::Result<ClientReq> = read_frame(&mut b).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn clean_close_yields_eof() {
        let (a, mut b) = duplex(8);
        drop(a);
        let err: io::Result<ClientReq> = read_frame(&mut b).await;
        let e = err.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }
}
