//! Stage 4d — burrow-client ↔ burrow end-to-end over DERP.
//!
//! Spins up the full Stage 4 happy path against a live Headscale:
//!
//! 1. Start a `burrow` subprocess configured for Headscale mode. It
//!    registers a node key, gets a tailnet IPv4, and opens its control
//!    listener on smoltcp.
//! 2. Build a [`ClientSession`] in-process as a second tailnet node.
//!    It registers independently against the same Headscale server.
//! 3. Scan the burrow subprocess's stderr for the
//!    `registered with Headscale tailnet_ip=...` log line to discover
//!    its assigned IP.
//! 4. Open a TCP connection from the client to `burrow_ip:control_port`
//!    via [`ClientSession::open_tcp`] — which internally routes through
//!    DERP, WG-encapsulates on the way out, and smoltcp-accepts on the
//!    burrow side.
//! 5. Speak the CBOR control protocol: send `ListReverse`, read back
//!    `ReverseList(empty)`. A non-empty response or any parse failure
//!    would surface a data-plane corruption.
//!
//! The assertion set is deliberately minimal — the goal is "the DERP-
//! backed transport carries the control protocol byte-for-byte";
//! richer workflows (reverse-tunnels, shell) are covered by the
//! loopback test harness under a stub DERP. What this adds on top is
//! validation of the real DERP + real Headscale + real smoltcp route.
//!
//! Opt in at runtime:
//!
//!   BURROW_TEST_HEADSCALE_URL      e.g. http://localhost:18443
//!   BURROW_TEST_HEADSCALE_AUTHKEY  a Headscale preauth key (reusable,
//!                                   since we register two nodes)
//!
//! Both env vars unset → test short-circuits. Same pattern as
//! `tests/headscale_register_roundtrip.rs`.
//!
//! Build with `--features insecure-tests` so the DERP client skips
//! TLS validation when the local Headscale uses a self-signed cert.

#![cfg(feature = "insecure-tests")]

use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

/// Spawn `burrow --server-url ... --authkey ... --hostname ...` as a
/// child process. Returns the handle so the test can tear it down on
/// exit, plus a stderr reader for discovering the assigned tailnet IP.
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
        // Force info-level tracing for our lookup; stdout is silent on
        // the happy path, all lifecycle logs go to stderr.
        .env("RUST_LOG", "info,burrow=info,ts_control=warn")
        .stdout(Stdio::null())
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

/// Drain `stderr` line-by-line until we find the IP log. Also forward
/// every line to the test writer so troubleshooting a stuck subprocess
/// is easy (cargo test --nocapture).
async fn wait_for_tailnet_ip(child: &mut Child, deadline: Duration) -> Option<Ipv4Addr> {
    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr).lines();
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

#[cfg(test)]
mod helper_tests {
    use super::extract_tailnet_ip;

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
}
