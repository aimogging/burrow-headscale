//! Stage 4d + follow-ups — burrow-client ↔ burrow end-to-end over DERP.
//!
//! Originally the Stage 4d smoke test: a [`ClientSession`] opens a TCP
//! connection to a burrow subprocess and round-trips one CBOR request.
//! Extended in the post-5 hardening pass with full-CLI tests covering
//! the three primary user-facing workflows over real DERP:
//!
//! - `client_session_round_trips_cbor_against_burrow` — the original
//!   smoke test; proves the DERP → smoltcp path carries CBOR bytes.
//! - `tcp_reverse_tunnel_round_trips_bytes_via_real_derp` — spawns
//!   `burrow-client tunnel … start -R`, verifies a plain TCP
//!   connection to `burrow:<listen_port>` echoes through a yamux
//!   substream to a local mock target.
//! - `udp_reverse_tunnel_round_trips_datagrams_via_real_derp` — same,
//!   UDP.
//! - `shell_oneshot_runs_command_via_real_derp` — runs
//!   `burrow-client shell … --program echo-equiv`, asserts captured
//!   stdout.
//!
//! Opt in at runtime:
//!
//!   BURROW_TEST_HEADSCALE_URL      e.g. https://localhost:18443
//!   BURROW_TEST_HEADSCALE_AUTHKEY  a reusable preauth key
//!                                   (Headscale will have the test
//!                                   register multiple nodes against it)
//!
//! Both env vars unset → tests short-circuit. Same pattern as
//! `tests/headscale_register_roundtrip.rs`.
//!
//! Build with `--features insecure-tests` so the DERP client skips
//! TLS validation when the local Headscale uses a self-signed cert.

#![cfg(feature = "insecure-tests")]

use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use burrow::client_session::ClientSession;
use burrow::control::DEFAULT_CONTROL_PORT;
use burrow::wire::{read_frame, write_frame, ClientReq, ServerResp};

fn env() -> Option<(String, String)> {
    let url = std::env::var("BURROW_TEST_HEADSCALE_URL").ok()?;
    let authkey = std::env::var("BURROW_TEST_HEADSCALE_AUTHKEY").ok()?;
    Some((url, authkey))
}

fn init_test_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,burrow=debug,ts_control=info")),
        )
        .with_test_writer()
        .try_init();
}

fn burrow_binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_burrow")
}

fn burrow_client_binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_burrow-client")
}

fn unique_tag() -> String {
    format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
}

/// Spawn `burrow --server-url ... --authkey ... --hostname ...` as a
/// child process. Returns the handle so the test can tear it down on
/// exit, plus a stdout reader for discovering the assigned tailnet IP.
///
/// `tracing_subscriber::fmt()` writes to stdout by default, so lifecycle
/// logs (including the `registered with Headscale tailnet_ip=...` line
/// we parse for discovery) land on the child's stdout — not stderr.
fn spawn_burrow(url: &str, authkey: &str, hostname: &str) -> std::io::Result<Child> {
    Command::new(burrow_binary_path())
        .args([
            "--server-url",
            url,
            "--authkey",
            authkey,
            "--hostname",
            hostname,
        ])
        // Force info-level tracing for our lookup so the "registered"
        // line is emitted even if the parent test doesn't export
        // RUST_LOG. `NO_COLOR=1` stops tracing-subscriber from
        // wrapping field names in ANSI escapes — without this the
        // `tailnet_ip=` substring our parser looks for is split by
        // `\x1b[3m...\x1b[0m` sequences and never matches.
        .env("RUST_LOG", "info,burrow=info,ts_control=warn")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
}

/// Parse `tailnet_ip=100.64.0.X` out of a burrow log line. Returns
/// `None` if the pattern doesn't match.
fn extract_tailnet_ip(line: &str) -> Option<Ipv4Addr> {
    // Log shape (tracing's default format): `<ts> <lvl> <target>: <msg> field=value ...`
    // We look for the substring and parse the value between `=` and the
    // next whitespace.
    let idx = line.find("tailnet_ip=")?;
    let tail = &line[idx + "tailnet_ip=".len()..];
    let end = tail.find(|c: char| c.is_whitespace()).unwrap_or(tail.len());
    tail[..end].parse().ok()
}

/// Drain `stdout` line-by-line until we find the IP log. Also forward
/// every line to the test writer so troubleshooting a stuck subprocess
/// is easy (cargo test --nocapture).
async fn wait_for_tailnet_ip(child: &mut Child, deadline: Duration) -> Option<Ipv4Addr> {
    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout).lines();
    let discover = async move {
        while let Ok(Some(line)) = reader.next_line().await {
            eprintln!("burrow-subprocess: {line}");
            if let Some(ip) = extract_tailnet_ip(&line) {
                return Some(ip);
            }
        }
        None
    };
    timeout(deadline, discover).await.ok().flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_session_round_trips_cbor_against_burrow() {
    let Some((url, authkey)) = env() else {
        eprintln!("BURROW_TEST_HEADSCALE_{{URL,AUTHKEY}} not set; skipping");
        return;
    };
    init_test_tracing();

    let burrow_hostname = format!(
        "burrow-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    );

    // 1. Start the burrow subprocess.
    let mut burrow = spawn_burrow(&url, &authkey, &burrow_hostname).expect("spawn burrow binary");

    // 2. Parallel: build the ClientSession while burrow boots.
    let url_parsed = url::Url::parse(&url).expect("URL parse");
    let client_hostname = format!("{burrow_hostname}-client");
    let session_fut = ClientSession::connect(url_parsed, &authkey, Some(client_hostname.clone()));

    // 3. Wait for burrow to log its tailnet_ip (up to 15s).
    let burrow_ip_fut = wait_for_tailnet_ip(&mut burrow, Duration::from_secs(15));

    let (session_res, burrow_ip_res) = tokio::join!(session_fut, burrow_ip_fut);

    let session = match session_res {
        Ok(s) => s,
        Err(e) => {
            let _ = burrow.kill().await;
            panic!("ClientSession::connect failed: {e:?}");
        }
    };
    let burrow_ip = match burrow_ip_res {
        Some(ip) => ip,
        None => {
            let _ = burrow.kill().await;
            panic!("burrow subprocess never logged a tailnet_ip within 15s");
        }
    };
    eprintln!(
        "test nodes registered: burrow={burrow_ip} (pid={:?}), client={}",
        burrow.id(),
        session.tailnet_ip()
    );

    // 4. Open a TCP connection from client to burrow's control
    //    listener, entirely through DERP. `open_tcp` waits internally
    //    for the peer to appear in the netmap and for the TCP
    //    handshake to complete.
    let mut stream = match timeout(
        Duration::from_secs(30),
        session.open_tcp(burrow_ip, DEFAULT_CONTROL_PORT),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let _ = burrow.kill().await;
            panic!("open_tcp to {burrow_ip}:{DEFAULT_CONTROL_PORT} failed: {e:?}");
        }
        Err(_) => {
            let _ = burrow.kill().await;
            panic!("open_tcp to {burrow_ip} timed out");
        }
    };

    // 5. Speak the CBOR control protocol.
    let req = ClientReq::ListReverse;
    if let Err(e) = write_frame(&mut stream, &req).await {
        let _ = burrow.kill().await;
        panic!("write_frame failed: {e:?}");
    }
    let resp: ServerResp = match timeout(Duration::from_secs(10), read_frame(&mut stream)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let _ = burrow.kill().await;
            panic!("read_frame failed: {e:?}");
        }
        Err(_) => {
            let _ = burrow.kill().await;
            panic!("read_frame timed out — DERP path not carrying bytes");
        }
    };
    let _ = stream.shutdown().await;

    match resp {
        ServerResp::ReverseList(entries) => {
            assert!(
                entries.is_empty(),
                "expected empty reverse list on a fresh burrow, got {entries:?}"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    // Teardown — explicit kill, but `kill_on_drop` also covers panics.
    let _ = burrow.kill().await;
}

/// Spawn `burrow-client --server-url … tunnel <burrow_ip> start -R …`
/// as a long-lived subprocess. The process holds the control flow
/// open until killed (kill_on_drop).
fn spawn_burrow_client_tunnel_tcp(
    url: &str,
    authkey: &str,
    hostname: &str,
    burrow_ip: Ipv4Addr,
    listen_port: u16,
    forward_to: &str,
) -> std::io::Result<Child> {
    let spec = format!("{listen_port}:{forward_to}");
    Command::new(burrow_client_binary_path())
        .args([
            "--server-url",
            url,
            "--authkey",
            authkey,
            "--hostname",
            hostname,
            "tunnel",
            &burrow_ip.to_string(),
            "start",
            "-R",
            &spec,
        ])
        .env("RUST_LOG", "info,burrow=info,ts_control=warn")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
}

fn spawn_burrow_client_tunnel_udp(
    url: &str,
    authkey: &str,
    hostname: &str,
    burrow_ip: Ipv4Addr,
    listen_port: u16,
    forward_to: &str,
) -> std::io::Result<Child> {
    let spec = format!("{listen_port}:{forward_to}");
    Command::new(burrow_client_binary_path())
        .args([
            "--server-url",
            url,
            "--authkey",
            authkey,
            "--hostname",
            hostname,
            "tunnel",
            &burrow_ip.to_string(),
            "start",
            "-U",
            "-R",
            &spec,
        ])
        .env("RUST_LOG", "info,burrow=info,ts_control=warn")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
}

/// Parse `tunnel N started` from a burrow-client stderr line. Matches
/// the literal `run_tunnel_start` banner format in
/// `src/bin/burrow-client.rs`.
fn extract_tunnel_id(line: &str) -> Option<u64> {
    let rest = line.strip_prefix("tunnel ")?;
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

/// Drain burrow-client's stderr until we see the startup banner.
/// Forwards every line to the test writer for visibility.
async fn wait_for_tunnel_banner(child: &mut Child, deadline: Duration) -> Option<u64> {
    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr).lines();
    let discover = async move {
        while let Ok(Some(line)) = reader.next_line().await {
            eprintln!("burrow-client: {line}");
            if let Some(id) = extract_tunnel_id(&line) {
                return Some(id);
            }
        }
        None
    };
    timeout(deadline, discover).await.ok().flatten()
}

/// Pick an unused TCP port on localhost by binding + dropping. The
/// result is subject to a TOCTOU race if another process grabs the
/// port between the drop and burrow's bind — in a test context this
/// is acceptable.
async fn pick_unused_tcp_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

async fn pick_unused_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let p = s.local_addr().unwrap().port();
    drop(s);
    p
}

/// Spawn a trivial TCP echo server bound to 127.0.0.1. Returns the
/// listening port; the task runs until the returned JoinHandle is
/// aborted / dropped.
async fn spawn_tcp_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    (port, task)
}

/// Spawn a trivial UDP echo server bound to 127.0.0.1. Returns
/// (port, task) like [`spawn_tcp_echo`].
async fn spawn_udp_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let _ = sock.send_to(&buf[..n], peer).await;
                }
                Err(_) => return,
            }
        }
    });
    (port, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_reverse_tunnel_round_trips_bytes_via_real_derp() {
    let Some((url, authkey)) = env() else {
        eprintln!("BURROW_TEST_HEADSCALE_{{URL,AUTHKEY}} not set; skipping");
        return;
    };
    init_test_tracing();
    let tag = unique_tag();

    // 1. Local mock TCP echo server — stands in for the user's
    //    "internal service" behind burrow-client.
    let (mock_port, mock_task) = spawn_tcp_echo().await;

    // 2. Pick an unused port for burrow's reverse listener.
    let listen_port = pick_unused_tcp_port().await;

    // 3. Spawn burrow and discover its tailnet IP.
    let mut burrow =
        spawn_burrow(&url, &authkey, &format!("burrow-tcp-rt-{tag}")).expect("spawn burrow");
    let burrow_ip = match wait_for_tailnet_ip(&mut burrow, Duration::from_secs(20)).await {
        Some(ip) => ip,
        None => {
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("burrow subprocess never logged tailnet_ip within 20s");
        }
    };
    eprintln!("burrow_ip={burrow_ip} listen_port={listen_port} mock_port={mock_port}");

    // 4. Spawn burrow-client tunnel start and wait for its banner.
    let forward_to = format!("127.0.0.1:{mock_port}");
    let mut client = spawn_burrow_client_tunnel_tcp(
        &url,
        &authkey,
        &format!("client-tcp-rt-{tag}"),
        burrow_ip,
        listen_port,
        &forward_to,
    )
    .expect("spawn burrow-client tunnel");
    let tunnel_id = match wait_for_tunnel_banner(&mut client, Duration::from_secs(45)).await {
        Some(id) => id,
        None => {
            let _ = client.kill().await;
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("burrow-client never emitted the tunnel-started banner within 45s");
        }
    };
    eprintln!("tunnel_id={tunnel_id}");

    // Small grace window — the tunnel is "started" when the CBOR
    // response arrived, but the real OS listener in burrow's
    // `reverse_registry::start` is spawned on the control handler
    // task and may be a tick behind. 500ms is ample and keeps the
    // assertion deterministic.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 5. Connect to burrow's OS listener on 127.0.0.1:<listen_port>.
    //    burrow binds 0.0.0.0 by default, so loopback reaches it.
    let mut conn = match timeout(
        Duration::from_secs(10),
        TcpStream::connect(("127.0.0.1", listen_port)),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            let _ = client.kill().await;
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("TCP connect to 127.0.0.1:{listen_port} failed: {e}");
        }
        Err(_) => {
            let _ = client.kill().await;
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("TCP connect to 127.0.0.1:{listen_port} timed out — burrow not listening?");
        }
    };

    let payload = b"burrow reverse tunnel over real DERP\n";
    if let Err(e) = conn.write_all(payload).await {
        let _ = client.kill().await;
        let _ = burrow.kill().await;
        mock_task.abort();
        panic!("write_all failed: {e}");
    }
    let _ = conn.flush().await;

    let mut echo = vec![0u8; payload.len()];
    match timeout(Duration::from_secs(20), conn.read_exact(&mut echo)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = client.kill().await;
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("read_exact failed: {e}");
        }
        Err(_) => {
            let _ = client.kill().await;
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("echo read timed out — bytes not reaching the mock target");
        }
    }
    assert_eq!(
        echo.as_slice(),
        payload,
        "echoed bytes must match the payload"
    );

    // Teardown — kill_on_drop covers panic paths.
    drop(conn);
    let _ = client.kill().await;
    let _ = burrow.kill().await;
    mock_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_reverse_tunnel_round_trips_datagrams_via_real_derp() {
    let Some((url, authkey)) = env() else {
        eprintln!("BURROW_TEST_HEADSCALE_{{URL,AUTHKEY}} not set; skipping");
        return;
    };
    init_test_tracing();
    let tag = unique_tag();

    let (mock_port, mock_task) = spawn_udp_echo().await;
    let listen_port = pick_unused_udp_port().await;

    let mut burrow =
        spawn_burrow(&url, &authkey, &format!("burrow-udp-rt-{tag}")).expect("spawn burrow");
    let burrow_ip = match wait_for_tailnet_ip(&mut burrow, Duration::from_secs(20)).await {
        Some(ip) => ip,
        None => {
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("burrow subprocess never logged tailnet_ip within 20s");
        }
    };
    eprintln!("burrow_ip={burrow_ip} listen_port={listen_port} mock_port={mock_port}");

    let forward_to = format!("127.0.0.1:{mock_port}");
    let mut client = spawn_burrow_client_tunnel_udp(
        &url,
        &authkey,
        &format!("client-udp-rt-{tag}"),
        burrow_ip,
        listen_port,
        &forward_to,
    )
    .expect("spawn burrow-client udp tunnel");
    let tunnel_id = match wait_for_tunnel_banner(&mut client, Duration::from_secs(45)).await {
        Some(id) => id,
        None => {
            let _ = client.kill().await;
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("burrow-client (udp) never emitted the tunnel-started banner within 45s");
        }
    };
    eprintln!("tunnel_id={tunnel_id}");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Client-side UDP socket to poke burrow's UDP listener.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"burrow reverse udp over real DERP";
    peer.send_to(payload, ("127.0.0.1", listen_port))
        .await
        .expect("send_to");
    let mut reply = vec![0u8; 65_535];
    let n = match timeout(Duration::from_secs(20), peer.recv_from(&mut reply)).await {
        Ok(Ok((n, _))) => n,
        Ok(Err(e)) => {
            let _ = client.kill().await;
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("udp recv_from failed: {e}");
        }
        Err(_) => {
            let _ = client.kill().await;
            let _ = burrow.kill().await;
            mock_task.abort();
            panic!("udp echo timed out — datagrams not reaching the mock target");
        }
    };
    assert_eq!(&reply[..n], payload);

    let _ = client.kill().await;
    let _ = burrow.kill().await;
    mock_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shell_oneshot_runs_command_via_real_derp() {
    let Some((url, authkey)) = env() else {
        eprintln!("BURROW_TEST_HEADSCALE_{{URL,AUTHKEY}} not set; skipping");
        return;
    };
    init_test_tracing();
    let tag = unique_tag();

    let mut burrow =
        spawn_burrow(&url, &authkey, &format!("burrow-sh-{tag}")).expect("spawn burrow");
    let burrow_ip = match wait_for_tailnet_ip(&mut burrow, Duration::from_secs(20)).await {
        Some(ip) => ip,
        None => {
            let _ = burrow.kill().await;
            panic!("burrow subprocess never logged tailnet_ip within 20s");
        }
    };
    eprintln!("burrow_ip={burrow_ip}");

    // Cross-platform "echo hello" — mirrors the fixture used by
    // `tests/shell_loopback.rs`.
    let (program, args) = if cfg!(windows) {
        ("cmd.exe", vec!["/C", "echo hello"])
    } else {
        ("/bin/sh", vec!["-c", "echo hello"])
    };

    let out = Command::new(burrow_client_binary_path())
        .args([
            "--server-url",
            &url,
            "--authkey",
            &authkey,
            "--hostname",
            &format!("client-sh-{tag}"),
            "shell",
            &burrow_ip.to_string(),
            "--output",
            "-",
            "--program",
            program,
            "--",
        ])
        .args(&args)
        .env("RUST_LOG", "info,burrow=info,ts_control=warn")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();

    let out = match timeout(Duration::from_secs(60), out).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            let _ = burrow.kill().await;
            panic!("burrow-client shell failed to spawn: {e}");
        }
        Err(_) => {
            let _ = burrow.kill().await;
            panic!("burrow-client shell didn't exit within 60s");
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("shell stdout: {stdout:?}");
    eprintln!("shell stderr: {stderr:?}");
    assert!(
        out.status.success(),
        "burrow-client shell exit status: {:?}\nstderr: {stderr}",
        out.status
    );
    assert!(
        stdout.contains("hello"),
        "expected 'hello' in captured stdout, got {stdout:?}"
    );

    let _ = burrow.kill().await;
}

#[cfg(test)]
mod helper_tests {
    use super::extract_tailnet_ip;
    use super::extract_tunnel_id;

    #[test]
    fn extracts_ipv4_from_typical_log_line() {
        let line = "2026-04-24T18:03:11.412942Z  INFO burrow::hs_main: burrow-client \
                    registered with Headscale tailnet_ip=100.64.0.7 regions=1";
        assert_eq!(
            extract_tailnet_ip(line),
            Some("100.64.0.7".parse().unwrap())
        );
    }

    #[test]
    fn extracts_ipv4_at_end_of_line() {
        // No trailing whitespace after the IP.
        let line = "tailnet_ip=10.20.30.40";
        assert_eq!(
            extract_tailnet_ip(line),
            Some("10.20.30.40".parse().unwrap())
        );
    }

    #[test]
    fn returns_none_without_pattern() {
        assert!(extract_tailnet_ip("lorem ipsum no ip here").is_none());
    }

    #[test]
    fn returns_none_for_malformed_ip() {
        assert!(extract_tailnet_ip("tailnet_ip=not-an-ip").is_none());
    }

    #[test]
    fn extract_tunnel_id_from_banner_line() {
        let line = "tunnel 42 started (Tcp 0.0.0.0:9000 -> 127.0.0.1:8080). press ctrl-c to stop.";
        assert_eq!(extract_tunnel_id(line), Some(42));
    }

    #[test]
    fn extract_tunnel_id_returns_none_for_unrelated_line() {
        assert!(extract_tunnel_id("ctrl-c — stopping tunnel").is_none());
    }
}
