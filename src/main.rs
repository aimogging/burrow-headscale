use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::net::TcpStream;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use burrow::config;
use burrow::control::{listener_key, spawn_control_handler};
use burrow::dataplane::{ingest_tunnel_packet, UdpProxyMap};
use burrow::icmp::IcmpForwarder;
use burrow::nat::{NatKey, NatTable};
use burrow::proxy::{spawn_tcp_proxy_with_stream, ProxyMsg};
use burrow::reverse_registry::ReverseRegistry;
use burrow::rewrite;
use burrow::runtime::{spawn_smoltcp, ConnectionId, SmoltcpEvent};
use burrow::tunnel::WgTunnel;

/// Optional config baked in at build time via the `embedded-config` feature.
/// The path is taken from `BURROW_EMBEDDED_CONFIG` at build time; `build.rs`
/// reads the file and emits `$OUT_DIR/embedded_config.rs` containing
/// `pub const EMBEDDED_CONFIG: &str = "..."`. Cargo's `rerun-if-changed`
/// directive on that path means editing the .conf invalidates the build.
#[cfg(feature = "embedded-config")]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_config.rs"));
}

const EMBEDDED_CONFIG: Option<&str> = {
    #[cfg(feature = "embedded-config")]
    {
        Some(embedded::EMBEDDED_CONFIG)
    }
    #[cfg(not(feature = "embedded-config"))]
    {
        None
    }
};

/// The gateway binary is intentionally minimal: just the runtime. All
/// utility commands (keygen, gen) live in `burrow-client` so they
/// don't bloat the deploy binary.
///
/// Two transports are selected between at runtime:
///
/// - Default (wg-quick): `--config` + optional `--endpoint` /
///   `--keepalive`. Loads a wg-quick conf and connects via UDP to a
///   kernel WG server.
/// - Headscale fork (`--server-url` set, feature-gated at build): reg
///   isters as a tailnet node and runs over DERP. `--config` is
///   ignored on this path.
#[derive(Parser, Debug)]
#[command(version, about = "WireGuard userspace gateway")]
struct Cli {
    /// Path to a wg-quick style configuration file. Optional when the
    /// binary was built with the `embedded-config` feature; required
    /// otherwise. An explicit `--config` always overrides the embedded
    /// one (useful for testing the same binary against a throwaway).
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Override the peer endpoint from the config file (host:port).
    #[arg(long)]
    endpoint: Option<String>,

    /// Override PersistentKeepalive (seconds; 0 disables).
    #[arg(long)]
    keepalive: Option<u16>,

    /// Headscale coordination server URL. If set, the binary uses the
    /// Headscale/DERP transport path instead of the wg-quick path.
    #[arg(long, env = "BURROW_HEADSCALE_URL")]
    server_url: Option<String>,

    /// Headscale preauth key. Required when `--server-url` is set.
    #[arg(long, env = "BURROW_HEADSCALE_AUTHKEY")]
    authkey: Option<String>,

    /// Hostname to advertise to Headscale. Defaults to the OS
    /// hostname (via `gethostname`) inside `ts_control`.
    #[arg(long, env = "BURROW_HEADSCALE_HOSTNAME")]
    hostname: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(server_url) = cli.server_url.as_deref() {
        use burrow::hs_main::{self, HeadscaleArgs};
        let url = url::Url::parse(server_url)
            .with_context(|| format!("parsing --server-url {server_url}"))?;
        let authkey = cli
            .authkey
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--server-url requires --authkey"))?;
        return hs_main::run(HeadscaleArgs {
            server_url: url,
            authkey,
            hostname: cli.hostname.clone(),
        })
        .await;
    }

    run(cli.config, cli.endpoint, cli.keepalive).await
}

async fn run(
    config_path: Option<PathBuf>,
    endpoint: Option<String>,
    keepalive: Option<u16>,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,burrow=debug")),
        )
        .init();

    // Make panics in any thread (including tokio worker tasks and the
    // smoltcp poll thread) loud. Pre-Phase-9 a panic in the smoltcp thread
    // killed only that thread and the rest of the process kept running with
    // every TCP path silently broken; the panic itself never landed in
    // logs. This hook ensures the next stress test fails loudly.
    //
    // When the `silent` feature is on we skip the eprintln and the default
    // libstd hook (which also writes to stderr) — only the `tracing::error!`
    // path runs, and that itself becomes a no-op under `release_max_level_off`.
    #[cfg(not(feature = "silent"))]
    {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current();
            error!(thread = thread.name().unwrap_or("<unnamed>"), %info, "PANIC");
            eprintln!("PANIC in thread {:?}: {}", thread.name(), info);
            default_hook(info);
        }));
    }
    #[cfg(feature = "silent")]
    {
        std::panic::set_hook(Box::new(|info| {
            let thread = std::thread::current();
            error!(thread = thread.name().unwrap_or("<unnamed>"), %info, "PANIC");
        }));
    }

    let mut cfg = match (config_path, EMBEDDED_CONFIG) {
        (Some(path), _) => {
            info!(path = %path.display(), "loading config from file");
            config::load(&path)
                .with_context(|| format!("loading config from {}", path.display()))?
        }
        (None, Some(embedded)) => {
            info!("using embedded config (built with --features embedded-config)");
            config::parse_str(embedded).context("parsing embedded config")?
        }
        (None, None) => bail!(
            "--config is required (this binary was built without the embedded-config feature)"
        ),
    };

    if let Some(ep) = endpoint {
        cfg.peer.endpoint = ep;
    }
    if let Some(ka) = keepalive {
        cfg.peer.persistent_keepalive = if ka == 0 { None } else { Some(ka) };
    }

    info!(
        endpoint = %cfg.peer.endpoint,
        address = %cfg.interface.address,
        keepalive = ?cfg.peer.persistent_keepalive,
        "starting burrow"
    );
    // Phase 11: the `Address` field is parsed for wg-quick file-format
    // compatibility but plays no runtime role. The smoltcp interface uses a
    // fixed synthetic CIDR (198.18.0.0/15) as opaque identifier space; the
    // egress rewrite restores the peer-visible src_ip before any packet
    // leaves burrow, so the configured Address never appears on the wire.
    info!("interface Address is informational under Phase 11 (smoltcp side uses 198.18.0.0/15 internally)");

    let nat = Arc::new(NatTable::new());
    let tunnel = Arc::new(WgTunnel::new(&cfg).await.context("WireGuard tunnel")?);
    info!(local = %tunnel.local_addr()?, peer = %tunnel.endpoint(), "WG socket bound");

    let wg_ip = cfg.interface.address.address();
    let dns_enabled = cfg.interface.dns_enabled;
    let (smoltcp, mut events, smoltcp_tx_rx) = spawn_smoltcp(Arc::clone(&nat), wg_ip);
    info!("smoltcp runtime spawned");

    tunnel
        .initiate_handshake()
        .await
        .context("initial handshake")?;
    info!("handshake initiation sent");

    // Per-NAT-entry UDP forwarders. Sender accepts raw payloads; the proxy
    // task sends them to (original_dst_ip, original_dst_port) and pushes
    // responses (as fully formed IPv4+UDP packets) onto `egress_tx`.
    let udp_proxies: UdpProxyMap = Arc::new(Mutex::new(HashMap::new()));
    // Single shared egress channel for both UDP and ICMP — they both want to
    // emit fully formed IPv4 packets back through the tunnel.
    let (egress_tx, mut egress_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let direct_egress = tokio::spawn({
        let tunnel = Arc::clone(&tunnel);
        async move {
            while let Some(pkt) = egress_rx.recv().await {
                if let Err(e) = tunnel.send_packet(&pkt).await {
                    warn!(error = %e, "direct egress tunnel send");
                }
            }
        }
    });

    // Probe at startup; logs which mode we're in and (if Raw) spawns the
    // raw-socket reader + pending sweeper.
    let icmp = Arc::new(IcmpForwarder::probe(egress_tx.clone()));

    // Spawn the smoltcp egress drainer: receives packets straight off the
    // device tx channel, runs the source rewrite, encapsulates, sends through WG.
    let egress = tokio::spawn(egress_loop(
        Arc::clone(&tunnel),
        smoltcp_tx_rx,
        Arc::clone(&nat),
        wg_ip,
    ));

    // Channel that connect_probe uses to hand a successfully-connected OS
    // TcpStream over to the event loop, where it's parked until the matching
    // smoltcp `TcpConnected` event arrives. Fix #1: the SYN-ACK only goes
    // back to the peer after the OS-side connect succeeds.
    let (arm_tx, mut arm_rx) = mpsc::unbounded_channel::<(NatKey, TcpStream)>();

    // Reverse-tunnel registry: control handlers populate it on tunnel
    // start and drain on client disconnect. The event loop never reads
    // from it — reverse tunnels bind real OS listeners on the burrow
    // host's network interfaces, so peer traffic reaches the tunnel
    // through the kernel, not through smoltcp.
    let reverse_registry = Arc::new(ReverseRegistry::new());
    let control_port = cfg.interface.control_port;

    // Bootstrap the first control-port listener. Subsequent listeners
    // are rearmed in the event loop each time a peer connects.
    let _initial_control_id = smoltcp
        .ensure_listener(wg_ip, control_port, listener_key(wg_ip, control_port))
        .await
        .context("initial control listener")?;
    info!(%wg_ip, control_port, "control listener active");

    // Spawn the smoltcp event consumer: turns runtime events into proxy
    // task lifecycle. The `proxies` and `armed` maps live entirely inside
    // this closure — only one task touches them, so plain HashMaps suffice.
    let event_loop = tokio::spawn({
        let smoltcp = smoltcp.clone();
        let nat = Arc::clone(&nat);
        let reverse_registry = Arc::clone(&reverse_registry);
        async move {
            let mut proxies: HashMap<ConnectionId, mpsc::UnboundedSender<ProxyMsg>> =
                HashMap::new();
            // Streams pre-dialed by connect_probe, awaiting their matching
            // TcpConnected event so we can hand them off to the proxy task.
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
                            if key.original_dst_ip == wg_ip
                                && key.original_dst_port == control_port
                            {
                                // Re-arm so the next peer hits a listener.
                                let next_key = listener_key(wg_ip, control_port);
                                let _ = smoltcp
                                    .ensure_listener(wg_ip, control_port, next_key)
                                    .await;
                                let tx = spawn_control_handler(
                                    id,
                                    smoltcp.clone(),
                                    Arc::clone(&reverse_registry),
                                );
                                proxies.insert(id, tx);
                            } else if key.original_dst_ip == wg_ip {
                                // Anything else to wg_ip is unsolicited —
                                // reverse tunnels bind real OS sockets,
                                // so smoltcp traffic here has no handler.
                                warn!(?key, ?id, "TCP to unregistered wg_ip port — aborting");
                                smoltcp.abort_tcp(id);
                            } else {
                                // NAT path (existing).
                                let Some(stream) = armed.remove(&key) else {
                                    error!(?key, ?id, "TcpConnected with no armed stream — Fix #1 invariant violated; aborting smoltcp side");
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
                            // Defensive: clear any orphaned armed entry.
                            armed.remove(&key);
                        }
                        SmoltcpEvent::TcpAborted { key, id } => {
                            debug!(?key, ?id, "tcp aborted before establishment");
                            if let Some(tx) = proxies.remove(&id) {
                                let _ = tx.send(ProxyMsg::Closed);
                            }
                            armed.remove(&key);
                            // Re-arm the control-port listener if the
                            // aborting flow was for it (single-accept
                            // socket semantics mean the listener slot
                            // is gone and we didn't hit TcpConnected).
                            if key.peer_ip == Ipv4Addr::UNSPECIFIED
                                && key.original_dst_ip == wg_ip
                                && key.original_dst_port == control_port
                            {
                                let next = listener_key(wg_ip, control_port);
                                let _ = smoltcp
                                    .ensure_listener(wg_ip, control_port, next)
                                    .await;
                                debug!(%wg_ip, control_port, "re-armed control listener after abort");
                            }
                        }
                    },
                    else => break,
                }
            }
        }
    });

    // Periodic NAT sweep. Idle UDP entries also drop their proxy sender,
    // which closes the channel and lets the proxy task wind down.
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
                let removed_udp = nat.sweep_udp_idle(now, burrow::nat::DEFAULT_UDP_IDLE);
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

    // Main loop: drive WG timers and process inbound packets.
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let result: Result<()> = loop {
        tokio::select! {
            biased;

            _ = signal::ctrl_c() => {
                info!("ctrl-c received, shutting down");
                break Ok(());
            }
            _ = timer.tick() => {
                if let Err(e) = tunnel.tick_timers().await {
                    warn!(error = %e, "timer tick");
                }
            }
            res = tunnel.recv_step() => {
                match res {
                    Ok(Some(pkt)) => {
                        ingest_tunnel_packet(
                            pkt.data,
                            &smoltcp,
                            &nat,
                            &udp_proxies,
                            &egress_tx,
                            &arm_tx,
                            &icmp,
                            wg_ip,
                            dns_enabled,
                        ).await;
                    }
                    Ok(None) => { /* control plane */ }
                    Err(e) => error!(error = %e, "wg recv"),
                }
            }
        }
    };

    egress.abort();
    event_loop.abort();
    sweep.abort();
    direct_egress.abort();
    result
}

async fn egress_loop(
    tunnel: Arc<WgTunnel>,
    mut tx_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    nat: Arc<NatTable>,
    wg_ip: std::net::Ipv4Addr,
) {
    while let Some(mut pkt) = tx_rx.recv().await {
        // Originated flows (reverse tunnels, DNS, control channel) already
        // have src=wg_ip — they bypass the NAT rewrite. Everything else
        // comes from the synthetic 198.18.0.0/15 pool and needs src
        // restored to original_dst_ip before the peer sees it.
        let src_is_wg = match rewrite::parse_5tuple(&pkt) {
            Ok(v) => v.src_ip == wg_ip,
            Err(_) => false,
        };
        if !src_is_wg {
            if let Err(e) = nat.rewrite_outbound(&mut pkt) {
                debug!(error = %e, "egress rewrite (no NAT entry — likely RST for unknown flow)");
                continue;
            }
        }
        if let Err(e) = tunnel.send_packet(&pkt).await {
            warn!(error = %e, "wg send");
        }
    }
}
