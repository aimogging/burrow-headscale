//! Phase 17 integration test for the `burrow-client` binary. Spins up
//! a mock control server on 127.0.0.1, invokes burrow-client as a
//! subprocess, asserts the request on the wire and exit semantics.
//!
//! The mock server reads one CBOR `ClientReq`, validates it, writes a
//! canned `ServerResp`, closes. Mirrors what burrow's real control
//! handler does for `one_shot_request` flows.
//!
//! The `tunnel start` subcommand HOLDS THE FLOW OPEN under the
//! client-originated model (it's the yamux client for the duration of
//! the tunnel). The tunnel tests here send the CBOR handshake and
//! then close the TCP flow; the child sees its yamux session ends and
//! exits cleanly.

use std::net::SocketAddrV4;
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;

use burrow::wire::{ClientReq, Proto, ServerResp, TunnelId, TunnelSpec};

fn burrow_client_path() -> &'static str {
    env!("CARGO_BIN_EXE_burrow-client")
}

async fn bind_mock_server() -> (TcpListener, SocketAddrV4) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => panic!("expected IPv4 bind"),
    };
    (listener, addr)
}

/// Accept one connection, read one length-prefixed CBOR frame, write
/// the given response, close.
async fn handle_one<R>(listener: &TcpListener, respond: impl FnOnce(ClientReq) -> R)
where
    R: Into<ServerResp>,
{
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut frame = vec![0u8; len];
    sock.read_exact(&mut frame).await.unwrap();
    let req: ClientReq = ciborium::de::from_reader(&frame[..]).unwrap();
    let resp: ServerResp = respond(req).into();
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&resp, &mut payload).unwrap();
    sock.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.ok();
}

/// In the client-originated model, `tunnel start` holds the control
/// flow open as the yamux client for the tunnel's lifetime. The mock
/// server replies `Started { tunnel_id: 42 }` and then drops the TCP
/// socket, which ends the child's yamux session and lets the binary
/// exit cleanly.
#[tokio::test]
async fn tunnel_start_tcp_writes_correct_request() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |req| {
            match req {
                ClientReq::StartTcpTunnel(TunnelSpec {
                    listen_port,
                    forward_to,
                    ..
                }) => {
                    assert_eq!(listen_port, 8080);
                    assert_eq!(forward_to, "127.0.0.1:9000");
                }
                other => panic!("expected StartTcpTunnel, got {other:?}"),
            }
            ServerResp::Started {
                tunnel_id: TunnelId(42),
            }
        })
        .await;
    });

    let mut child = TokioCommand::new(burrow_client_path())
        .args([
            "tunnel",
            &addr.ip().to_string(),
            "--control-port",
            &addr.port().to_string(),
            "start",
            "-R",
            "8080:127.0.0.1:9000",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    server.await.unwrap();
    // Server closed its socket — child's yamux session should end and
    // the process should exit within a couple of seconds.
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("child did not exit after mock server closed")
        .unwrap();
    assert!(status.success(), "exit status: {status:?}");
    // Startup banner goes to stderr; no stdout for this subcommand.
    let mut stderr = Vec::new();
    child
        .stderr
        .as_mut()
        .unwrap()
        .read_to_end(&mut stderr)
        .await
        .ok();
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        stderr.contains("tunnel 42 started"),
        "expected startup banner, stderr: {stderr:?}"
    );
}

#[tokio::test]
async fn tunnel_start_udp_flag_sets_proto() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |req| match req {
            ClientReq::StartUdpTunnel(TunnelSpec { listen_port, .. }) => {
                assert_eq!(listen_port, 53);
                ServerResp::Started {
                    tunnel_id: TunnelId(7),
                }
            }
            other => panic!("expected StartUdpTunnel, got {other:?}"),
        })
        .await;
    });

    let mut child = TokioCommand::new(burrow_client_path())
        .args([
            "tunnel",
            &addr.ip().to_string(),
            "--control-port",
            &addr.port().to_string(),
            "start",
            "-U",
            "-R",
            "53:127.0.0.1:53",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    server.await.unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("child did not exit after mock server closed")
        .unwrap();
    assert!(status.success(), "exit status: {status:?}");
}

/// `Proto` imported for symmetry with the old test — keep it around
/// as a compile-time reference to avoid import-drift.
#[allow(dead_code)]
fn _proto_still_exported() -> Proto {
    Proto::Tcp
}

#[tokio::test]
async fn shell_oneshot_prints_captured_stdout_and_exit_code() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |req| match req {
            ClientReq::RequestShell { mode, .. } => {
                assert!(matches!(mode, burrow::wire::ShellMode::Oneshot));
                ServerResp::ShellResult {
                    exit_code: Some(0),
                    stdout: b"mock-stdout\n".to_vec(),
                    stderr: Vec::new(),
                }
            }
            other => panic!("expected RequestShell, got {other:?}"),
        })
        .await;
    });

    let out = tokio::task::spawn_blocking({
        let client_path = burrow_client_path().to_string();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        move || {
            Command::new(&client_path)
                .args([
                    "shell",
                    &ip,
                    "--control-port",
                    &port,
                    "--output",
                    "-",
                    "--program",
                    "anything",
                    "--",
                    "arg1",
                ])
                .stdout(Stdio::piped())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    server.await.unwrap();
    assert!(out.status.success(), "exit: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mock-stdout"),
        "expected 'mock-stdout' in stdout, got {stdout:?}"
    );
}

#[tokio::test]
async fn shell_nonzero_exit_propagates() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |_| ServerResp::ShellResult {
            exit_code: Some(7),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
        .await;
    });

    let out = tokio::task::spawn_blocking({
        let client_path = burrow_client_path().to_string();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        move || {
            Command::new(&client_path)
                .args(["shell", &ip, "--control-port", &port, "--output", "-"])
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    server.await.unwrap();
    assert_eq!(out.status.code(), Some(7), "exit code should be 7");
}

#[tokio::test]
async fn shell_detach_prints_pid() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |req| match req {
            ClientReq::RequestShell { mode, .. } => {
                assert!(matches!(mode, burrow::wire::ShellMode::FireAndForget));
                ServerResp::ShellSpawned { pid: 1234 }
            }
            other => panic!("expected RequestShell, got {other:?}"),
        })
        .await;
    });

    let out = tokio::task::spawn_blocking({
        let client_path = burrow_client_path().to_string();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        move || {
            Command::new(&client_path)
                .args(["shell", &ip, "--control-port", &port, "--detach"])
                .stdout(Stdio::piped())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    server.await.unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "1234");
}

#[tokio::test]
async fn headscale_embed_writes_newline_separated_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("burrow-headscale.txt");

    let out = tokio::task::spawn_blocking({
        let client_path = burrow_client_path().to_string();
        let out_path = out_path.clone();
        move || {
            Command::new(&client_path)
                .args([
                    "headscale-embed",
                    "--server-url",
                    "https://hs.example",
                    "--authkey",
                    "auth-abc-123",
                    "--hostname",
                    "test-node",
                    "--out",
                ])
                .arg(&out_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    assert!(
        out.status.success(),
        "headscale-embed failed: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let body = std::fs::read_to_string(&out_path).expect("embed file readable");
    assert_eq!(body, "https://hs.example\nauth-abc-123\ntest-node\n");
}

#[tokio::test]
async fn headscale_embed_omits_hostname_line_when_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("burrow-headscale.txt");

    let out = tokio::task::spawn_blocking({
        let client_path = burrow_client_path().to_string();
        let out_path = out_path.clone();
        move || {
            Command::new(&client_path)
                .args([
                    "headscale-embed",
                    "--server-url",
                    "https://hs.example",
                    "--authkey",
                    "auth-abc-123",
                    "--out",
                ])
                .arg(&out_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    assert!(out.status.success());
    let body = std::fs::read_to_string(&out_path).expect("embed file readable");
    assert_eq!(body, "https://hs.example\nauth-abc-123\n");
}

#[tokio::test]
async fn headscale_embed_rejects_bad_url() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("burrow-headscale.txt");

    let out = tokio::task::spawn_blocking({
        let client_path = burrow_client_path().to_string();
        let out_path = out_path.clone();
        move || {
            Command::new(&client_path)
                .args([
                    "headscale-embed",
                    "--server-url",
                    "not-a-url",
                    "--authkey",
                    "auth",
                    "--out",
                ])
                .arg(&out_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    assert!(!out.status.success(), "embed must fail for invalid URL");
    // Output file must not have been created.
    assert!(!out_path.exists());
}
