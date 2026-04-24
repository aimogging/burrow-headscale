//! Real-DERP end-to-end coverage for burrow-client ↔ burrow.
//!
//! Each test spawns burrow as a subprocess (or two), registers a
//! [`ClientSession`] in-process, and exercises one user-facing path
//! against a live Headscale + DERP. All of these run at 5–10 s each,
//! ~45 s total serial.
//!
//! - `client_session_round_trips_cbor_against_burrow` — the Stage 4d
//!   smoke test; proves the DERP → smoltcp path carries CBOR bytes
//!   (one `ListReverse`).
//! - `tcp_reverse_tunnel_round_trips_bytes_via_real_derp` — spawns
//!   `burrow-client tunnel … start -R`, verifies a plain TCP
//!   connection to `burrow:<listen_port>` echoes through a yamux
//!   substream to a local mock target.
//! - `udp_reverse_tunnel_round_trips_datagrams_via_real_derp` — same
//!   with `-U` + datagrams.
//! - `shell_oneshot_runs_command_via_real_derp` — runs
//!   `burrow-client shell … --program <echo>`, asserts captured stdout.
//! - `dns_resolver_answers_query_via_real_derp` — builds a hickory
//!   A-query for `localhost`, sends via
//!   [`ClientSession::query_udp`], asserts burrow's built-in DNS
//!   service answers.
//! - `client_session_routes_to_multiple_burrow_peers` — two burrow
//!   subprocesses + one session, round-trips CBOR against each;
//!   proves PeerTable reconciliation + per-peer Tunn routing at N>2.
//! - `interactive_shell_runs_chained_commands_via_real_derp` —
//!   bypasses the terminal-requiring CLI path, drives the framed
//!   stdio protocol (`src/shell_protocol.rs`) directly. Sends three
//!   chained commands (`echo one`, `echo two`, `exit`) and scrapes
//!   the PTY output for both echo results + the EXIT frame. Responds
//!   to ConPTY's cursor-position DSR query so Windows doesn't hang.
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

/// DNS end-to-end: burrow's built-in resolver on `(wg_ip, 53/udp)`
/// answers an A query for `localhost` sent from the `ClientSession`
/// over DERP. Exercises the UDP dispatch path in both directions:
/// client-side [`ClientSession::query_udp`] builds + encapsulates a
/// UDP datagram, burrow's `udp_reverse::dispatch_udp_to_wg_ip` routes
/// to `dns_service::handle_query`, the response datagram rides back
/// through DERP, and the client-side UDP listener dispatches it to
/// the awaiting `recv()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_resolver_answers_query_via_real_derp() {
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    let Some((url, authkey)) = env() else {
        eprintln!("BURROW_TEST_HEADSCALE_{{URL,AUTHKEY}} not set; skipping");
        return;
    };
    init_test_tracing();
    let tag = unique_tag();

    let mut burrow =
        spawn_burrow(&url, &authkey, &format!("burrow-dns-{tag}")).expect("spawn burrow");
    let burrow_ip = match wait_for_tailnet_ip(&mut burrow, Duration::from_secs(20)).await {
        Some(ip) => ip,
        None => {
            let _ = burrow.kill().await;
            panic!("burrow subprocess never logged tailnet_ip within 20s");
        }
    };

    let url_parsed = url::Url::parse(&url).expect("URL parse");
    let session =
        match ClientSession::connect(url_parsed, &authkey, Some(format!("client-dns-{tag}"))).await
        {
            Ok(s) => s,
            Err(e) => {
                let _ = burrow.kill().await;
                panic!("ClientSession::connect failed: {e:?}");
            }
        };
    eprintln!(
        "test nodes registered: burrow={burrow_ip}, client={}",
        session.tailnet_ip()
    );

    // Build A-query for "localhost" — same shape as
    // `src/dns_service.rs::tests::build_query`.
    let mut query = Message::new();
    query.set_id(0x4242);
    query.set_message_type(MessageType::Query);
    query.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii("localhost.").expect("name"));
    q.set_query_type(RecordType::A);
    q.set_query_class(DNSClass::IN);
    query.add_query(q);
    let query_bytes = query.to_bytes().expect("encode");

    let reply = match timeout(
        Duration::from_secs(30),
        session.query_udp(burrow_ip, 53, &query_bytes, Duration::from_secs(20)),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let _ = burrow.kill().await;
            panic!("query_udp failed: {e:?}");
        }
        Err(_) => {
            let _ = burrow.kill().await;
            panic!("query_udp timed out at the test-harness level");
        }
    };

    let parsed = Message::from_bytes(&reply).expect("decode DNS response");
    assert_eq!(parsed.id(), 0x4242, "response id must echo the query id");
    assert_eq!(
        parsed.response_code(),
        ResponseCode::NoError,
        "response code for `localhost` should be NoError"
    );
    assert!(
        !parsed.answers().is_empty(),
        "expected at least one A record for localhost — got none; \
         full message: {parsed:?}"
    );
    eprintln!(
        "dns answers for localhost: {:?}",
        parsed.answers().iter().collect::<Vec<_>>()
    );

    let _ = burrow.kill().await;
}

/// Multi-peer end-to-end: one `ClientSession` routes to two
/// independent burrow subprocesses. Verifies that
/// `PeerTable::reconcile` + per-peer `boringtun::Tunn` hold up at
/// N>2 tailnet nodes, and that the outbound egress path picks the
/// right peer by destination IP. Issues a separate CBOR `ListReverse`
/// round-trip against each burrow and asserts both return empty
/// (fresh burrows have no registered tunnels).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_session_routes_to_multiple_burrow_peers() {
    let Some((url, authkey)) = env() else {
        eprintln!("BURROW_TEST_HEADSCALE_{{URL,AUTHKEY}} not set; skipping");
        return;
    };
    init_test_tracing();
    let tag = unique_tag();

    // Spawn two burrow subprocesses in parallel. Distinct hostnames so
    // Headscale doesn't collapse them into re-registrations of the
    // same stable identity.
    let mut burrow_a =
        spawn_burrow(&url, &authkey, &format!("burrow-a-{tag}")).expect("spawn burrow A");
    let mut burrow_b =
        spawn_burrow(&url, &authkey, &format!("burrow-b-{tag}")).expect("spawn burrow B");
    let ip_a_fut = wait_for_tailnet_ip(&mut burrow_a, Duration::from_secs(20));
    let ip_b_fut = wait_for_tailnet_ip(&mut burrow_b, Duration::from_secs(20));
    let (ip_a, ip_b) = tokio::join!(ip_a_fut, ip_b_fut);
    let ip_a = match ip_a {
        Some(ip) => ip,
        None => {
            let _ = burrow_a.kill().await;
            let _ = burrow_b.kill().await;
            panic!("burrow A never logged tailnet_ip within 20s");
        }
    };
    let ip_b = match ip_b {
        Some(ip) => ip,
        None => {
            let _ = burrow_a.kill().await;
            let _ = burrow_b.kill().await;
            panic!("burrow B never logged tailnet_ip within 20s");
        }
    };
    eprintln!("burrow_a={ip_a} burrow_b={ip_b}");

    let url_parsed = url::Url::parse(&url).expect("URL parse");
    let session =
        match ClientSession::connect(url_parsed, &authkey, Some(format!("client-multi-{tag}")))
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let _ = burrow_a.kill().await;
                let _ = burrow_b.kill().await;
                panic!("ClientSession::connect failed: {e:?}");
            }
        };
    eprintln!("client_ip={}", session.tailnet_ip());

    async fn exchange(session: &ClientSession, peer_ip: Ipv4Addr) -> Result<(), String> {
        let mut stream = timeout(
            Duration::from_secs(30),
            session.open_tcp(peer_ip, DEFAULT_CONTROL_PORT),
        )
        .await
        .map_err(|_| format!("open_tcp({peer_ip}) timed out"))?
        .map_err(|e| format!("open_tcp({peer_ip}): {e:?}"))?;
        write_frame(&mut stream, &ClientReq::ListReverse)
            .await
            .map_err(|e| format!("write_frame({peer_ip}): {e}"))?;
        let resp: ServerResp = timeout(Duration::from_secs(15), read_frame(&mut stream))
            .await
            .map_err(|_| format!("read_frame({peer_ip}) timed out"))?
            .map_err(|e| format!("read_frame({peer_ip}): {e}"))?;
        let _ = stream.shutdown().await;
        match resp {
            ServerResp::ReverseList(entries) if entries.is_empty() => Ok(()),
            ServerResp::ReverseList(entries) => {
                Err(format!("expected empty reverse list, got {entries:?}"))
            }
            other => Err(format!("unexpected response: {other:?}")),
        }
    }

    // Talk to A first, then B. Sequential is fine — the point is that
    // both peers show up in the PeerTable concurrently and routing
    // picks the right one.
    if let Err(e) = exchange(&session, ip_a).await {
        let _ = burrow_a.kill().await;
        let _ = burrow_b.kill().await;
        panic!("exchange with burrow A failed: {e}");
    }
    eprintln!("cbor round-trip with burrow A succeeded");
    if let Err(e) = exchange(&session, ip_b).await {
        let _ = burrow_a.kill().await;
        let _ = burrow_b.kill().await;
        panic!("exchange with burrow B failed: {e}");
    }
    eprintln!("cbor round-trip with burrow B succeeded");

    let _ = burrow_a.kill().await;
    let _ = burrow_b.kill().await;
}

/// Interactive shell end-to-end over real DERP.
///
/// The `burrow-client shell` CLI path enables crossterm raw mode +
/// pumps a real terminal, which isn't drivable from a headless cargo
/// test. This test skips the CLI wrapper and drives the wire protocol
/// directly: `ClientSession::open_tcp` to the control port, CBOR
/// handshake for `ShellMode::Interactive`, then switches the same
/// stream into the framed stdio protocol from `src/shell_protocol.rs`.
///
/// Sends three commands through the PTY as separate STDIN frames —
/// the shell runs each in turn + echoes output. The assertion only
/// checks that both command outputs appear somewhere in the
/// accumulated STDOUT stream: on Windows, ConPTY decorates the
/// output with prompts + ANSI + command echoes, and on Unix `/bin/sh`
/// echoes commands back too, so exact matching would be brittle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_shell_runs_chained_commands_via_real_derp() {
    use burrow::shell_protocol as sp;
    use burrow::wire::ShellMode;

    let Some((url, authkey)) = env() else {
        eprintln!("BURROW_TEST_HEADSCALE_{{URL,AUTHKEY}} not set; skipping");
        return;
    };
    init_test_tracing();
    let tag = unique_tag();

    let mut burrow =
        spawn_burrow(&url, &authkey, &format!("burrow-pty-{tag}")).expect("spawn burrow");
    let burrow_ip = match wait_for_tailnet_ip(&mut burrow, Duration::from_secs(20)).await {
        Some(ip) => ip,
        None => {
            let _ = burrow.kill().await;
            panic!("burrow subprocess never logged tailnet_ip within 20s");
        }
    };

    let url_parsed = url::Url::parse(&url).expect("URL parse");
    let session =
        match ClientSession::connect(url_parsed, &authkey, Some(format!("client-pty-{tag}"))).await
        {
            Ok(s) => s,
            Err(e) => {
                let _ = burrow.kill().await;
                panic!("ClientSession::connect failed: {e:?}");
            }
        };

    let mut stream = match timeout(
        Duration::from_secs(30),
        session.open_tcp(burrow_ip, DEFAULT_CONTROL_PORT),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let _ = burrow.kill().await;
            panic!("open_tcp failed: {e:?}");
        }
        Err(_) => {
            let _ = burrow.kill().await;
            panic!("open_tcp timed out");
        }
    };

    // CBOR handshake for interactive mode. Default program: cmd.exe
    // on Windows, /bin/sh on Unix — matches the `burrow-client shell`
    // default so we exercise the same code path.
    let (program, args): (Option<String>, Vec<String>) = if cfg!(windows) {
        (Some("cmd.exe".into()), Vec::new())
    } else {
        (Some("/bin/sh".into()), Vec::new())
    };
    let req = ClientReq::RequestShell {
        mode: ShellMode::Interactive,
        program,
        args,
    };
    if let Err(e) = write_frame(&mut stream, &req).await {
        let _ = burrow.kill().await;
        panic!("write_frame(RequestShell): {e}");
    }
    let resp: ServerResp = match timeout(Duration::from_secs(15), read_frame(&mut stream)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let _ = burrow.kill().await;
            panic!("read_frame(ShellReady): {e}");
        }
        Err(_) => {
            let _ = burrow.kill().await;
            panic!("timeout waiting for ShellReady");
        }
    };
    match resp {
        ServerResp::ShellReady => {}
        other => {
            let _ = burrow.kill().await;
            panic!("expected ShellReady, got {other:?}");
        }
    }

    // Initial PTY size — mirrors `run_shell_interactive` in
    // src/bin/burrow-client.rs. 80x24 is the conservative default.
    if let Err(e) = sp::write_resize(&mut stream, 80, 24).await {
        let _ = burrow.kill().await;
        panic!("write_resize: {e}");
    }

    // Chained commands. Three separate STDIN frames to simulate a
    // user typing each at the prompt. Line endings are CRLF because
    // that's what a terminal sends on Enter; cmd.exe and /bin/sh both
    // tolerate both.
    let commands: [&[u8]; 3] = [b"echo one\r\n", b"echo two\r\n", b"exit\r\n"];

    // Split the duplex so one task can write while the main task
    // reads. Writes go through an mpsc channel so the reader can
    // also emit DSR responses (Windows ConPTY queries cursor
    // position with `\x1b[6n` on startup and hangs if not answered).
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = stdin_rx.recv().await {
            if sp::write_stdin(&mut writer, &bytes).await.is_err() {
                break;
            }
        }
    });

    // Producer task: types the commands after a brief settle so the
    // shell prompt has rendered.
    let stdin_for_cmds = stdin_tx.clone();
    let cmd_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        for cmd in commands {
            if stdin_for_cmds.send(cmd.to_vec()).is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });

    // Drain STDOUT frames until we see EXIT (or the stream closes).
    // On the way, scan each chunk for `\x1b[6n` (cursor position
    // query) and send back a canned `\x1b[24;80R` so ConPTY's
    // terminal-cap probe doesn't block.
    let mut accumulated = Vec::<u8>::new();
    let mut exit_code: Option<i32> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut scratch = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, sp::read_frame(&mut reader, &mut scratch)).await {
            Ok(Ok(sp::Frame::Stdout(data))) => {
                // Respond to cursor-position DSR queries before
                // appending (so we don't accidentally match a later
                // literal `[6n` in command output).
                if data.windows(4).any(|w| w == b"\x1b[6n") {
                    let _ = stdin_tx.send(b"\x1b[24;80R".to_vec());
                }
                accumulated.extend_from_slice(data);
            }
            Ok(Ok(sp::Frame::Exit(code))) => {
                exit_code = Some(code);
                break;
            }
            Ok(Ok(_other)) => {} // Unknown/Stdin/Resize/StdinEof — ignore
            Ok(Err(e)) => {
                eprintln!("read_frame error (likely clean close): {e}");
                break;
            }
            Err(_) => {
                eprintln!(
                    "read timed out; accumulated bytes so far = {}",
                    accumulated.len()
                );
                break;
            }
        }
    }
    cmd_task.abort();
    drop(stdin_tx);
    let _ = writer_task.await;

    let text = String::from_utf8_lossy(&accumulated);
    eprintln!(
        "=== interactive shell STDOUT ({} bytes) ===",
        accumulated.len()
    );
    eprintln!("{text}");
    eprintln!("=== end; exit_code = {exit_code:?} ===");

    assert!(
        text.contains("one"),
        "expected first chained command's output 'one' in STDOUT, got {} bytes",
        accumulated.len()
    );
    assert!(
        text.contains("two"),
        "expected second chained command's output 'two' in STDOUT, got {} bytes",
        accumulated.len()
    );
    assert!(
        exit_code.is_some(),
        "expected EXIT frame after `exit\\r\\n`, did not receive one"
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
