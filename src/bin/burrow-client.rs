//! Companion CLI for burrow. Holds the local-side utilities (`keygen`
//! and `gen` for generating configs) plus the remote operations that
//! talk to a running burrow over the CBOR-framed control protocol
//! (`tunnel`, `shell`).
//!
//! Remote subcommands take `<burrow_wg_ip>` as their first positional;
//! local utilities don't need it. The peer running this binary needs
//! its own WireGuard stack configured so that `burrow_wg_ip` routes
//! through the tunnel — burrow-client itself makes a normal TCP
//! connect and is oblivious to WireGuard at the binary level.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use burrow::client_session::ClientSession;
use burrow::control::DEFAULT_CONTROL_PORT;
use burrow::reverse_registry::OpenRequest;
use burrow::shell_protocol as sp;
use burrow::wire::{
    read_frame, write_frame, BindAddr, ClientReq, ErrorKind, Proto, ServerResp, ShellMode,
    TunnelId, TunnelSpec,
};
use burrow::yamux_bridge::{drive_connection, udp_frame};

/// Combined AsyncRead + AsyncWrite trait object — used as `Box<dyn Conn>`
/// so the tunnel/shell subcommands can drive either a direct OS TCP
/// stream (legacy path) or a DERP-backed [`ClientSession::open_tcp`]
/// stream through the same code.
pub trait Conn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> Conn for T {}

type BoxedConn = Box<dyn Conn>;

/// Where to reach burrow's control listener. `DirectTcp` is the old
/// routing-aware path (user's OS has a route to `burrow_wg_ip` via
/// wg-quick); `Tailnet` dials through a live [`ClientSession`] which
/// encrypts and relays via DERP.
enum BurrowTarget<'a> {
    DirectTcp(SocketAddrV4),
    Tailnet {
        session: &'a ClientSession,
        burrow_ip: Ipv4Addr,
        control_port: u16,
    },
}

impl BurrowTarget<'_> {
    fn label(&self) -> String {
        match self {
            BurrowTarget::DirectTcp(addr) => addr.to_string(),
            BurrowTarget::Tailnet {
                burrow_ip,
                control_port,
                ..
            } => format!("tailnet://{burrow_ip}:{control_port}"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "burrow companion CLI: tunnels, shell, keygen, config gen"
)]
struct Cli {
    /// Headscale server URL. When set, `tunnel` and `shell` reach
    /// burrow through the DERP-backed tailnet instead of dialing
    /// `burrow_wg_ip` directly. Requires `--authkey`.
    #[arg(long, env = "BURROW_HEADSCALE_URL", global = true)]
    server_url: Option<String>,

    /// Headscale preauth key for `--server-url`. Accepted from the env
    /// so scripts don't leak keys through shell history.
    #[arg(long, env = "BURROW_HEADSCALE_AUTHKEY", global = true)]
    authkey: Option<String>,

    /// Hostname to advertise to Headscale. Defaults to the OS hostname.
    #[arg(long, env = "BURROW_HEADSCALE_HOSTNAME", global = true)]
    hostname: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Reverse-tunnel management against a running burrow at <burrow_wg_ip>.
    Tunnel {
        burrow_ip: Ipv4Addr,
        /// Control port (defaults to burrow's DEFAULT_CONTROL_PORT = 57821).
        #[arg(long, default_value_t = DEFAULT_CONTROL_PORT)]
        control_port: u16,
        #[command(subcommand)]
        action: TunnelCmd,
    },
    /// Run / open a shell on the burrow host at <burrow_wg_ip>.
    Shell {
        burrow_ip: Ipv4Addr,
        /// Control port (defaults to burrow's DEFAULT_CONTROL_PORT = 57821).
        #[arg(long, default_value_t = DEFAULT_CONTROL_PORT)]
        control_port: u16,
        #[command(flatten)]
        args: ShellArgs,
    },
    /// Register this client as a tailnet node against a Headscale server.
    /// Prints the tailnet IPv4 that Headscale assigns, then exits.
    ///
    /// Each invocation creates a fresh ephemeral node key (nothing
    /// persists to disk). Longer-lived client workflows will arrive with
    /// the `attach` subcommand once tunnel/shell are ported to ride the
    /// DERP transport.
    Login {
        #[arg(long, env = "BURROW_HEADSCALE_URL")]
        server_url: String,
        #[arg(long, env = "BURROW_HEADSCALE_AUTHKEY")]
        authkey: String,
        /// Hostname to advertise to Headscale. Defaults to the OS
        /// hostname via `gethostname` (applied inside `ts_control`).
        #[arg(long, env = "BURROW_HEADSCALE_HOSTNAME")]
        hostname: Option<String>,
    },
    /// Write a Headscale embed file (server URL + authkey + optional
    /// hostname, newline-separated) that `burrow` picks up when built
    /// with `--features embedded-headscale-config` via the
    /// `BURROW_HEADSCALE_EMBED` env var. Example usage:
    ///
    ///   burrow-client headscale-embed \
    ///       --server-url https://hs.example --authkey <key> \
    ///       --out ./burrow-headscale.txt
    ///   BURROW_HEADSCALE_EMBED=./burrow-headscale.txt cargo build \
    ///       --release --features embedded-headscale-config
    HeadscaleEmbed {
        #[arg(long, env = "BURROW_HEADSCALE_URL")]
        server_url: String,
        #[arg(long, env = "BURROW_HEADSCALE_AUTHKEY")]
        authkey: String,
        /// Optional hostname to advertise to Headscale. Omit to let
        /// `ts_control` default to the OS hostname at runtime.
        #[arg(long, env = "BURROW_HEADSCALE_HOSTNAME")]
        hostname: Option<String>,
        /// Output file path. Existing file is overwritten.
        #[arg(long, default_value = "./burrow-headscale.txt")]
        out: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum TunnelCmd {
    /// Start a reverse tunnel. Syntax: `-R [BIND:]LISTEN:HOST:PORT`.
    Start {
        /// `[BIND:]LISTEN:HOST:PORT` — burrow listens on `<BIND>:<LISTEN>`
        /// (default BIND = 0.0.0.0); incoming connections tunnel back to
        /// the client and originate as `HOST:PORT` locally.
        #[arg(short = 'R', value_name = "[BIND:]LISTEN:HOST:PORT")]
        spec: String,
        /// Use UDP instead of TCP.
        #[arg(short = 'U', long)]
        udp: bool,
    },
    /// Stop a previously-started tunnel by id.
    Stop { tunnel_id: u64 },
    /// List active reverse tunnels.
    List,
}

#[derive(clap::Args, Debug)]
struct ShellArgs {
    /// Run the command non-interactively, capture stdout+stderr.
    /// `--output -` prints to local stdout/stderr; `--output PATH`
    /// writes stdout to the file and stderr still to the terminal.
    /// Mutually exclusive with `--detach`; implies no PTY.
    #[arg(long, value_name = "PATH")]
    output: Option<String>,

    /// Spawn detached; return immediately with the pid. No output
    /// captured. Mutually exclusive with `--output`.
    #[arg(long, conflicts_with = "output")]
    detach: bool,

    /// Request an interactive PTY session. This is the default; the
    /// flag is kept for explicitness and scripts that want to assert
    /// the mode. Mutually exclusive with `--output` and `--detach`.
    #[arg(long, conflicts_with_all = ["output", "detach"])]
    interactive: bool,

    /// Executable to run on the burrow host. Defaults per-OS on the
    /// server side (cmd.exe on Windows, $SHELL / /bin/sh on Unix).
    #[arg(long)]
    program: Option<String>,

    /// Positional args passed after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("burrow-client: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// Initialise a stderr-writing subscriber so tracing output from
/// `ClientSession` / the vendored `ts_control` crates is visible when
/// diagnosing a stuck session. Stderr (not stdout) so it doesn't
/// collide with subcommands that print actual data to stdout (e.g.
/// `login` printing a tailnet IP, `shell --output -` forwarding
/// captured shell stdout).
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,burrow=info,ts_control=warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let Cli {
        server_url,
        authkey,
        hostname,
        cmd,
    } = cli;
    let creds = HeadscaleCreds {
        server_url,
        authkey,
        hostname,
    };
    match cmd {
        Cmd::Tunnel {
            burrow_ip,
            control_port,
            action,
        } => {
            let session = maybe_connect_session(&creds).await?;
            let target = target_for(&session, burrow_ip, control_port);
            run_tunnel(target, action).await
        }
        Cmd::Shell {
            burrow_ip,
            control_port,
            args,
        } => {
            let session = maybe_connect_session(&creds).await?;
            let target = target_for(&session, burrow_ip, control_port);
            run_shell(target, args).await
        }
        Cmd::Login {
            server_url,
            authkey,
            hostname,
        } => run_login(server_url, authkey, hostname).await,
        Cmd::HeadscaleEmbed {
            server_url,
            authkey,
            hostname,
            out,
        } => run_headscale_embed(server_url, authkey, hostname, out),
    }
}

struct HeadscaleCreds {
    server_url: Option<String>,
    authkey: Option<String>,
    hostname: Option<String>,
}

/// When the user supplies headscale credentials, register and bring up
/// a [`ClientSession`]. Otherwise return `None`; subcommands fall back
/// to direct TCP. Errors out if one of `--server-url`/`--authkey` is
/// provided without the other — that's almost certainly a misconfig.
async fn maybe_connect_session(creds: &HeadscaleCreds) -> Result<Option<ClientSession>> {
    match (&creds.server_url, &creds.authkey) {
        (None, None) => Ok(None),
        (Some(url), Some(key)) => {
            let parsed =
                url::Url::parse(url).with_context(|| format!("parsing --server-url {url}"))?;
            let session = ClientSession::connect(parsed, key, creds.hostname.clone())
                .await
                .context("ClientSession::connect")?;
            Ok(Some(session))
        }
        (Some(_), None) => bail!("--server-url requires --authkey (or BURROW_HEADSCALE_AUTHKEY)"),
        (None, Some(_)) => {
            bail!("--authkey requires --server-url (or BURROW_HEADSCALE_URL)")
        }
    }
}

fn target_for<'a>(
    session: &'a Option<ClientSession>,
    burrow_ip: Ipv4Addr,
    control_port: u16,
) -> BurrowTarget<'a> {
    match session {
        Some(s) => BurrowTarget::Tailnet {
            session: s,
            burrow_ip,
            control_port,
        },
        None => BurrowTarget::DirectTcp(SocketAddrV4::new(burrow_ip, control_port)),
    }
}

async fn run_login(
    server_url: String,
    authkey: String,
    hostname: Option<String>,
) -> Result<ExitCode> {
    use burrow::headscale::HeadscaleClient;
    use burrow::node_identity::NodeIdentity;
    use std::time::Duration;

    let url = url::Url::parse(&server_url)
        .with_context(|| format!("parsing --server-url {server_url}"))?;
    let ident = NodeIdentity::generate();
    let client = HeadscaleClient::connect(url, &ident, &authkey, hostname)
        .await
        .context("HeadscaleClient::connect")?;

    // Wait up to 10s for the initial netmap delta that carries our
    // tailnet IP. Matches hs_main's startup gate.
    let mut rx = client.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let tailnet_ip = loop {
        if let Some(ip) = client.snapshot().my_tailnet_ipv4 {
            break ip;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            anyhow::bail!("timed out waiting for Headscale to assign a tailnet IP");
        }
        tokio::time::timeout(deadline - now, rx.changed())
            .await
            .context("netmap stream produced no state change inside 10s")?
            .context("netmap watch channel closed")?;
    };
    println!("{tailnet_ip}");
    Ok(ExitCode::SUCCESS)
}

fn run_headscale_embed(
    server_url: String,
    authkey: String,
    hostname: Option<String>,
    out: PathBuf,
) -> Result<ExitCode> {
    // Sanity-check the URL early so a typo gets a clear error here
    // instead of at build time (where the failure appears inside a
    // `cargo:rerun` step and is easy to misread).
    let _ = url::Url::parse(&server_url)
        .with_context(|| format!("parsing --server-url {server_url}"))?;

    // Reject newlines and empty values that would confuse build.rs's
    // line-at-a-time parser.
    if server_url.is_empty() || authkey.is_empty() {
        bail!("--server-url and --authkey must be non-empty");
    }
    for (name, val) in [("server-url", &server_url), ("authkey", &authkey)] {
        if val.contains('\n') || val.contains('\r') {
            bail!("--{name} must not contain newlines");
        }
    }
    if let Some(h) = &hostname {
        if h.contains('\n') || h.contains('\r') {
            bail!("--hostname must not contain newlines");
        }
    }

    let mut body = String::new();
    body.push_str(&server_url);
    body.push('\n');
    body.push_str(&authkey);
    body.push('\n');
    if let Some(h) = &hostname {
        body.push_str(h);
        body.push('\n');
    }

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir of {}", out.display()))?;
        }
    }
    std::fs::write(&out, body).with_context(|| format!("writing {}", out.display()))?;
    set_private_file_permissions(&out);

    println!("wrote {}", out.display());
    println!();
    println!("next:");
    println!(
        "  BURROW_HEADSCALE_EMBED={} cargo build --release \\",
        out.display()
    );
    println!("      --features embedded-headscale-config,silent --bin burrow");
    Ok(ExitCode::SUCCESS)
}

#[cfg(unix)]
fn set_private_file_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &std::path::Path) {
    // Windows: NTFS ACLs are the right tool; setting them non-trivially
    // is out of scope for v1. Files inherit the parent directory's ACL.
}

async fn connect_control(target: &BurrowTarget<'_>) -> Result<BoxedConn> {
    match target {
        BurrowTarget::DirectTcp(addr) => {
            let stream = TcpStream::connect(*addr)
                .await
                .with_context(|| format!("connecting to burrow control at {addr}"))?;
            stream.set_nodelay(true).ok();
            Ok(Box::new(stream))
        }
        BurrowTarget::Tailnet {
            session,
            burrow_ip,
            control_port,
        } => {
            let stream = session
                .open_tcp(*burrow_ip, *control_port)
                .await
                .with_context(|| {
                    format!("connecting to burrow control at tailnet://{burrow_ip}:{control_port}")
                })?;
            Ok(Box::new(stream))
        }
    }
}

async fn run_tunnel(target: BurrowTarget<'_>, action: TunnelCmd) -> Result<ExitCode> {
    match action {
        TunnelCmd::Start { spec, udp } => {
            let (bind, listen_port, forward_to) = parse_r_spec(&spec)?;
            let proto = if udp { Proto::Udp } else { Proto::Tcp };
            run_tunnel_start(target, proto, bind, listen_port, forward_to).await
        }
        TunnelCmd::Stop { tunnel_id } => {
            let req = ClientReq::StopReverse {
                tunnel_id: TunnelId(tunnel_id),
            };
            let resp = one_shot_request(&target, &req).await?;
            match resp {
                ServerResp::Stopped => {
                    println!("stopped {tunnel_id}");
                    Ok(ExitCode::SUCCESS)
                }
                ServerResp::Error { kind, msg } => {
                    eprintln!("tunnel stop failed: {kind:?}: {msg}");
                    Ok(ExitCode::from(2))
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
        TunnelCmd::List => {
            let resp = one_shot_request(&target, &ClientReq::ListReverse).await?;
            match resp {
                ServerResp::ReverseList(entries) => {
                    if entries.is_empty() {
                        println!("(no active tunnels)");
                    } else {
                        println!(
                            "{:<10} {:<5} {:<10} {}",
                            "TUNNEL", "PROTO", "LISTEN", "FORWARD"
                        );
                        for e in entries {
                            let proto = match e.proto {
                                Proto::Tcp => "TCP",
                                Proto::Udp => "UDP",
                            };
                            println!(
                                "{:<10} {:<5} {:<10} {}",
                                e.tunnel_id.0, proto, e.listen_port, e.forward_to
                            );
                        }
                    }
                    Ok(ExitCode::SUCCESS)
                }
                ServerResp::Error { kind, msg } => {
                    eprintln!("list failed: {kind:?}: {msg}");
                    Ok(ExitCode::from(2))
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
    }
}

async fn run_shell(target: BurrowTarget<'_>, args: ShellArgs) -> Result<ExitCode> {
    // Default is Interactive (matches the plan: an `ssh`-like UX
    // where bare `shell` drops you into a prompt). `--output` opts
    // into one-shot capture; `--detach` opts into fire-and-forget.
    // Fire-and-forget is NEVER the default — silently swallowing
    // output is a footgun.
    let mode = if args.detach {
        ShellMode::FireAndForget
    } else if args.output.is_some() {
        ShellMode::Oneshot
    } else {
        ShellMode::Interactive
    };
    // Interactive takes over the flow after ShellReady. Hand off to a
    // dedicated handler rather than using the one-shot request helper.
    if mode == ShellMode::Interactive {
        return run_shell_interactive(target, args.program, args.args).await;
    }
    let req = ClientReq::RequestShell {
        mode,
        program: args.program,
        args: args.args,
    };
    let resp = one_shot_request(&target, &req).await?;
    match resp {
        ServerResp::ShellResult {
            exit_code,
            stdout,
            stderr,
        } => {
            let target = args.output.as_deref();
            match target {
                Some("-") | None => {
                    use std::io::Write;
                    std::io::stdout().write_all(&stdout).ok();
                    std::io::stderr().write_all(&stderr).ok();
                }
                Some(path) => {
                    let p = PathBuf::from(path);
                    std::fs::write(&p, &stdout)
                        .with_context(|| format!("writing stdout to {}", p.display()))?;
                    // stderr still goes to local stderr so the caller
                    // knows something went wrong.
                    use std::io::Write;
                    std::io::stderr().write_all(&stderr).ok();
                }
            }
            Ok(match exit_code {
                Some(c) if (0..=255).contains(&c) => ExitCode::from(c as u8),
                Some(_) => ExitCode::from(127),
                None => ExitCode::from(128),
            })
        }
        ServerResp::ShellSpawned { pid } => {
            println!("{}", pid);
            Ok(ExitCode::SUCCESS)
        }
        ServerResp::ShellReady => {
            bail!("server opened an interactive session but this client build doesn't support it yet (Phase 17b)");
        }
        ServerResp::Error { kind, msg } => {
            eprintln!("shell failed: {kind:?}: {msg}");
            Ok(match kind {
                ErrorKind::NotYetSupported => ExitCode::from(3),
                _ => ExitCode::from(2),
            })
        }
        other => bail!("unexpected response: {other:?}"),
    }
}

/// Start a reverse tunnel and hold the control flow open. After the
/// `Started` response, upgrades the flow to a yamux client. Each time
/// a peer connects to `<bind>:listen_port` on the burrow host's OS
/// interfaces, the server opens a new outbound substream — this
/// binary accepts it, dials `forward_to` locally, and pumps bytes.
/// Exits on Ctrl-C or when the control flow drops.
async fn run_tunnel_start(
    target: BurrowTarget<'_>,
    proto: Proto,
    bind: BindAddr,
    listen_port: u16,
    forward_to: String,
) -> Result<ExitCode> {
    let mut stream = connect_control(&target).await?;
    let spec = TunnelSpec {
        listen_port,
        forward_to: forward_to.clone(),
        bind,
    };
    let req = match proto {
        Proto::Tcp => ClientReq::StartTcpTunnel(spec),
        Proto::Udp => ClientReq::StartUdpTunnel(spec),
    };
    write_frame(&mut stream, &req).await?;
    let resp: ServerResp = read_frame(&mut stream)
        .await
        .map_err(|e| anyhow!("reading Started: {e}"))?;
    let tunnel_id = match resp {
        ServerResp::Started { tunnel_id } => tunnel_id,
        ServerResp::Error { kind, msg } => {
            eprintln!("tunnel start failed: {kind:?}: {msg}");
            return Ok(ExitCode::from(2));
        }
        other => bail!("unexpected response: {other:?}"),
    };
    let bind_label = match bind {
        BindAddr::Default | BindAddr::Any => "0.0.0.0".to_string(),
        BindAddr::Ipv4(x) => x.to_string(),
    };
    eprintln!(
        "tunnel {} started ({:?} {}:{} -> {}). press ctrl-c to stop.",
        tunnel_id.0, proto, bind_label, listen_port, forward_to
    );

    // Upgrade the control flow to a yamux client. Server opens outbound
    // substreams (one per peer for TCP, one shared for UDP); we accept
    // them and originate local connections for each.
    let compat = stream.compat();
    let conn = yamux::Connection::new(compat, yamux::Config::default(), yamux::Mode::Client);

    // Inbound substreams land here.
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<yamux::Stream>();
    // Held alive for drive_connection's lifetime. The client never opens
    // outbound substreams; drive_connection exits when we drop this.
    let (_opener_tx, opener_rx) = mpsc::unbounded_channel::<OpenRequest>();

    let driver = tokio::spawn(drive_connection(conn, opener_rx, Some(inbound_tx)));

    match proto {
        Proto::Tcp => run_tcp_substreams(&mut inbound_rx, forward_to).await,
        Proto::Udp => run_udp_substream(&mut inbound_rx, forward_to).await,
    };

    driver.abort();
    Ok(ExitCode::SUCCESS)
}

/// Accept inbound yamux substreams. For each, dial `forward_to` locally
/// and copy bytes in both directions. Exits on ctrl-c or when the
/// control flow drops (inbound_rx closes).
async fn run_tcp_substreams(
    inbound_rx: &mut mpsc::UnboundedReceiver<yamux::Stream>,
    forward_to: String,
) {
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("ctrl-c — stopping tunnel");
                return;
            }
            maybe = inbound_rx.recv() => {
                let Some(substream) = maybe else {
                    eprintln!("control flow closed — stopping tunnel");
                    return;
                };
                let forward_to = forward_to.clone();
                tokio::spawn(async move {
                    let tcp = match TcpStream::connect(&forward_to).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("dial {forward_to} failed: {e}");
                            return;
                        }
                    };
                    let _ = tcp.set_nodelay(true);
                    let y_compat = substream.compat();
                    let (mut y_r, mut y_w) = tokio::io::split(y_compat);
                    let (mut t_r, mut t_w) = tcp.into_split();
                    let a = tokio::io::copy(&mut y_r, &mut t_w);
                    let b = tokio::io::copy(&mut t_r, &mut y_w);
                    let _ = tokio::try_join!(a, b);
                });
            }
        }
    }
}

/// Accept the single UDP substream the server opens for this tunnel.
/// Each framed datagram carries `(peer_ip, peer_port, payload)`. For
/// each distinct peer we maintain a local UdpSocket bound to an
/// ephemeral port and connected to `forward_to`: outgoing payloads are
/// `send()`ed, incoming replies are `recv()`ed and framed back over
/// the substream.
async fn run_udp_substream(
    inbound_rx: &mut mpsc::UnboundedReceiver<yamux::Stream>,
    forward_to: String,
) {
    // The server opens exactly one substream for a UDP tunnel; wait for
    // it here (concurrent with ctrl-c).
    let substream = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            eprintln!("ctrl-c — stopping tunnel");
            return;
        }
        maybe = inbound_rx.recv() => {
            match maybe {
                Some(s) => s,
                None => {
                    eprintln!("control flow closed — stopping tunnel");
                    return;
                }
            }
        }
    };

    let y_compat = substream.compat();
    let (mut y_r, y_w) = tokio::io::split(y_compat);

    // Single writer task for the substream — per-peer reply tasks send
    // frames through this channel so writes are serialized.
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<(Ipv4Addr, u16, Vec<u8>)>();
    let writer = tokio::spawn(async move {
        let mut y_w = y_w;
        while let Some((ip, port, data)) = frame_rx.recv().await {
            if udp_frame::write(&mut y_w, ip, port, &data).await.is_err() {
                break;
            }
        }
    });

    // Per-peer send channels: incoming frame → push payload into the
    // peer's UdpSocket writer task.
    type PeerMap = Arc<Mutex<HashMap<(Ipv4Addr, u16), mpsc::UnboundedSender<Vec<u8>>>>>;
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("ctrl-c — stopping tunnel");
                break;
            }
            res = udp_frame::read(&mut y_r) => {
                let (peer_ip, peer_port, payload) = match res {
                    Ok(t) => t,
                    Err(_) => break,
                };
                let key = (peer_ip, peer_port);
                let tx = {
                    let mut map = peers.lock().await;
                    if let Some(tx) = map.get(&key) {
                        tx.clone()
                    } else {
                        let (send_tx, mut send_rx) =
                            mpsc::unbounded_channel::<Vec<u8>>();
                        map.insert(key, send_tx.clone());
                        let forward_to = forward_to.clone();
                        let frame_tx = frame_tx.clone();
                        let peers_for_evict = Arc::clone(&peers);
                        tokio::spawn(async move {
                            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                                Ok(s) => s,
                                Err(e) => {
                                    eprintln!("udp bind failed: {e}");
                                    return;
                                }
                            };
                            if let Err(e) = sock.connect(&forward_to).await {
                                eprintln!("udp connect {forward_to}: {e}");
                                return;
                            }
                            let sock = Arc::new(sock);
                            // Reply reader: recv replies from forward_to,
                            // frame them back over the substream.
                            let r_sock = Arc::clone(&sock);
                            let r_frame_tx = frame_tx.clone();
                            let reader = tokio::spawn(async move {
                                let mut buf = vec![0u8; 65_535];
                                loop {
                                    match r_sock.recv(&mut buf).await {
                                        Ok(n) => {
                                            if r_frame_tx
                                                .send((peer_ip, peer_port, buf[..n].to_vec()))
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                            // Writer: payloads from the yamux frames →
                            // sock.send. Also terminates the reader on
                            // exit so the socket gets dropped.
                            while let Some(payload) = send_rx.recv().await {
                                if sock.send(&payload).await.is_err() {
                                    break;
                                }
                            }
                            reader.abort();
                            // Evict from the peer map so a new frame for
                            // this peer can start fresh.
                            peers_for_evict.lock().await.remove(&key);
                        });
                        send_tx
                    }
                };
                let _ = tx.send(payload);
            }
        }
    }

    drop(frame_tx);
    writer.abort();
}

/// Send one request, read one response, close. Most subcommands follow
/// this shape.
async fn one_shot_request(target: &BurrowTarget<'_>, req: &ClientReq) -> Result<ServerResp> {
    let mut stream = connect_control(target).await?;
    write_frame(&mut stream, req).await?;
    let resp: ServerResp = read_frame(&mut stream)
        .await
        .map_err(|e| anyhow!("reading response from {}: {e}", target.label()))?;
    let _ = stream.shutdown().await;
    Ok(resp)
}

/// Restore terminal raw mode (and Windows console modes) on scope
/// exit, including panic unwind. On Windows, crossterm's raw mode
/// doesn't touch `ENABLE_VIRTUAL_TERMINAL_INPUT` /
/// `ENABLE_VIRTUAL_TERMINAL_PROCESSING`, so arrow keys arrive as
/// Windows-native console events (which cmd.exe's line editor can't
/// parse as VT sequences) and PTY-generated ANSI on the way back isn't
/// processed. We set both flags explicitly and save the prior modes
/// for restoration.
struct TermGuard {
    #[cfg(windows)]
    prev_stdin_mode: Option<u32>,
    #[cfg(windows)]
    prev_stdout_mode: Option<u32>,
}

impl TermGuard {
    fn new() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("enable_raw_mode")?;
        #[cfg(windows)]
        {
            let (prev_stdin_mode, prev_stdout_mode) = configure_windows_console();
            return Ok(Self {
                prev_stdin_mode,
                prev_stdout_mode,
            });
        }
        #[cfg(not(windows))]
        {
            Ok(Self {})
        }
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            restore_windows_console(self.prev_stdin_mode, self.prev_stdout_mode);
        }
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(windows)]
fn configure_windows_console() -> (Option<u32>, Option<u32>) {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, DISABLE_NEWLINE_AUTO_RETURN,
        ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_INPUT_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    let (mut prev_in, mut prev_out) = (None, None);
    unsafe {
        let h_in = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        if !h_in.is_null() && GetConsoleMode(h_in, &mut mode) != 0 {
            prev_in = Some(mode);
            let _ = SetConsoleMode(h_in, mode | ENABLE_VIRTUAL_TERMINAL_INPUT);
        }
        let h_out = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: u32 = 0;
        if !h_out.is_null() && GetConsoleMode(h_out, &mut mode) != 0 {
            prev_out = Some(mode);
            let _ = SetConsoleMode(
                h_out,
                mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN,
            );
        }
    }
    (prev_in, prev_out)
}

#[cfg(windows)]
fn restore_windows_console(prev_stdin: Option<u32>, prev_stdout: Option<u32>) {
    use windows_sys::Win32::System::Console::{
        GetStdHandle, SetConsoleMode, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    unsafe {
        if let Some(m) = prev_stdin {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            if !h.is_null() {
                let _ = SetConsoleMode(h, m);
            }
        }
        if let Some(m) = prev_stdout {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            if !h.is_null() {
                let _ = SetConsoleMode(h, m);
            }
        }
    }
}

/// Drive an interactive shell session. After the CBOR request/ShellReady
/// handshake, the control flow carries the framed stdio protocol in
/// both directions: STDIN / RESIZE / STDIN_EOF client→server, STDOUT /
/// EXIT server→client.
async fn run_shell_interactive(
    target: BurrowTarget<'_>,
    program: Option<String>,
    cmd_args: Vec<String>,
) -> Result<ExitCode> {
    let mut stream = connect_control(&target).await?;
    let req = ClientReq::RequestShell {
        mode: ShellMode::Interactive,
        program,
        args: cmd_args,
    };
    write_frame(&mut stream, &req).await?;
    let resp: ServerResp = read_frame(&mut stream)
        .await
        .map_err(|e| anyhow!("reading ShellReady: {e}"))?;
    match resp {
        ServerResp::ShellReady => {}
        ServerResp::Error { kind, msg } => {
            eprintln!("interactive shell: {kind:?}: {msg}");
            return Ok(ExitCode::from(match kind {
                ErrorKind::NotYetSupported => 3,
                _ => 2,
            }));
        }
        other => bail!("unexpected response: {other:?}"),
    }

    // Enable raw mode before we start reading stdin or writing PTY
    // output. `_guard` restores on drop, including the panic path.
    let _guard = TermGuard::new()?;
    // Best-effort: a panic hook that disables raw mode before the
    // default handler runs, so stack traces print cleanly.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        default_hook(info);
    }));

    let (mut reader, mut writer) = tokio::io::split(stream);

    // Send the initial terminal size so the server sizes the PTY
    // correctly on the first prompt render.
    let (cols0, rows0) = crossterm::terminal::size().unwrap_or((80, 24));
    sp::write_resize(&mut writer, cols0, rows0).await?;

    // Single writer channel: stdin bytes and resize events both funnel
    // through here so writes to the socket are serialized.
    enum Out {
        Stdin(Vec<u8>),
        Resize(u16, u16),
        StdinEof,
    }
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Out>();

    // stdin pump — reads raw bytes from the local terminal and forwards
    // as STDIN frames. Ends on EOF or error.
    let stdin_tx = out_tx.clone();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 4096];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => {
                    let _ = stdin_tx.send(Out::StdinEof);
                    break;
                }
                Ok(n) => {
                    if stdin_tx.send(Out::Stdin(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Resize poller — crossterm's EventStream would be the idiomatic
    // cross-platform path but requires an extra feature. Polling
    // `terminal::size()` at 200 ms is simpler and works on all targets;
    // SIGWINCH-driven precision doesn't matter for terminal resize UX.
    let resize_tx = out_tx.clone();
    let resize_task = tokio::spawn(async move {
        let mut last = (cols0, rows0);
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        loop {
            interval.tick().await;
            match crossterm::terminal::size() {
                Ok(size) if size != last => {
                    last = size;
                    if resize_tx.send(Out::Resize(size.0, size.1)).is_err() {
                        break;
                    }
                }
                _ => {}
            }
        }
    });

    // Writer task: serializes frames to the TCP half.
    let writer_task = tokio::spawn(async move {
        while let Some(out) = out_rx.recv().await {
            let res = match out {
                Out::Stdin(data) => sp::write_stdin(&mut writer, &data).await,
                Out::Resize(cols, rows) => sp::write_resize(&mut writer, cols, rows).await,
                Out::StdinEof => {
                    let r = sp::write_stdin_eof(&mut writer).await;
                    if r.is_err() {
                        break;
                    }
                    // After EOF we keep the channel open for resize
                    // events — the shell might still be running.
                    continue;
                }
            };
            if res.is_err() {
                break;
            }
        }
    });

    // Main read loop — decode STDOUT / EXIT frames, write to local
    // stdout.
    let mut stdout = tokio::io::stdout();
    let mut scratch = Vec::new();
    let mut exit_code: i32 = 0;
    loop {
        match sp::read_frame(&mut reader, &mut scratch).await {
            Ok(sp::Frame::Stdout(data)) => {
                if stdout.write_all(data).await.is_err() {
                    break;
                }
                let _ = stdout.flush().await;
            }
            Ok(sp::Frame::Exit(code)) => {
                exit_code = code;
                break;
            }
            Ok(_) => { /* ignore unknown or server-only frames */ }
            Err(_) => break,
        }
    }

    stdin_task.abort();
    resize_task.abort();
    writer_task.abort();
    // `_guard` drops here → raw mode restored.
    // Clamp negative / large codes to 1..=255 so ExitCode is sane.
    Ok(ExitCode::from(match exit_code {
        0 => 0u8,
        c if (1..=255).contains(&c) => c as u8,
        _ => 1,
    }))
}

/// Parse `[BIND:]LISTEN:HOST:PORT`.
///
/// * Without a BIND prefix (3 parts): `BindAddr::Default` — burrow
///   picks a sensible default (currently `0.0.0.0`).
/// * With a BIND prefix (4 parts): BIND is an IPv4 address. `0.0.0.0`
///   becomes `BindAddr::Any`; anything else becomes
///   `BindAddr::Ipv4(x)` and requires the burrow host to own an
///   interface with that address (the kernel enforces this at bind
///   time).
///
/// LISTEN and PORT are u16. HOST is any string the client's local
/// machine can resolve (IPv4, hostname, etc.); resolution happens at
/// substream time.
fn parse_r_spec(spec: &str) -> Result<(BindAddr, u16, String)> {
    let parts: Vec<&str> = spec.splitn(4, ':').collect();
    let (bind, listen_str, host, port_str) = match parts.len() {
        3 => (BindAddr::Default, parts[0], parts[1].to_string(), parts[2]),
        4 => {
            let bind_ip: Ipv4Addr = parts[0].parse().with_context(|| {
                format!(
                    "invalid BIND `{}` — must be an IPv4 address (e.g. 0.0.0.0, 127.0.0.1, 192.168.1.1)",
                    parts[0]
                )
            })?;
            let bind = if bind_ip == Ipv4Addr::UNSPECIFIED {
                BindAddr::Any
            } else {
                BindAddr::Ipv4(bind_ip)
            };
            (bind, parts[1], parts[2].to_string(), parts[3])
        }
        _ => bail!("expected [BIND:]LISTEN:HOST:PORT, got `{spec}`"),
    };
    let listen: u16 = listen_str
        .parse()
        .with_context(|| format!("invalid LISTEN port `{listen_str}`"))?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid PORT `{port_str}`"))?;
    if host.is_empty() {
        bail!("empty HOST in `{spec}`");
    }
    Ok((bind, listen, format!("{host}:{port}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_r_spec_3part_defaults_bind() {
        let (bind, listen, fwd) = parse_r_spec("443:127.0.0.1:443").unwrap();
        assert_eq!(bind, BindAddr::Default);
        assert_eq!(listen, 443);
        assert_eq!(fwd, "127.0.0.1:443");
    }

    #[test]
    fn parse_r_spec_happy_hostname() {
        let (bind, listen, fwd) = parse_r_spec("8080:example.com:80").unwrap();
        assert_eq!(bind, BindAddr::Default);
        assert_eq!(listen, 8080);
        assert_eq!(fwd, "example.com:80");
    }

    #[test]
    fn parse_r_spec_bind_any() {
        let (bind, listen, fwd) = parse_r_spec("0.0.0.0:443:127.0.0.1:443").unwrap();
        assert_eq!(bind, BindAddr::Any);
        assert_eq!(listen, 443);
        assert_eq!(fwd, "127.0.0.1:443");
    }

    #[test]
    fn parse_r_spec_bind_specific() {
        let (bind, listen, fwd) = parse_r_spec("10.0.0.2:443:127.0.0.1:443").unwrap();
        assert_eq!(bind, BindAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(listen, 443);
        assert_eq!(fwd, "127.0.0.1:443");
    }

    #[test]
    fn parse_r_spec_rejects_bad_input() {
        assert!(parse_r_spec("443:127.0.0.1").is_err()); // missing port
        assert!(parse_r_spec("not-a-port:127.0.0.1:443").is_err());
        assert!(parse_r_spec("443::443").is_err()); // empty host
    }
}
