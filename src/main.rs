//! Gateway binary entry. Registers with Headscale, connects to DERP,
//! runs the userspace WireGuard data plane inside `burrow::hs_main`.
//!
//! Configuration sources (checked in order):
//!   1. Explicit CLI flags (`--server-url`, `--authkey`, `--hostname`).
//!   2. Environment (`BURROW_HEADSCALE_URL`, `BURROW_HEADSCALE_AUTHKEY`,
//!      `BURROW_HEADSCALE_HOSTNAME`) via clap's `env`.
//!   3. Build-time embed (`--features embedded-headscale-config`, reads
//!      `$BURROW_HEADSCALE_EMBED` at build time).
//!
//! Any field missing from all three sources is an error. The URL +
//! authkey are mandatory; hostname defaults to the OS hostname inside
//! `ts_control`.

use anyhow::{Context, Result};
use clap::Parser;

/// Headscale credentials baked in at build time via the
/// `embedded-headscale-config` feature. `build.rs` reads
/// `$BURROW_HEADSCALE_EMBED` (a two- or three-line file
/// `<server_url>\n<authkey>[\n<hostname>]`) and emits
/// `$OUT_DIR/embedded_headscale.rs`. Without the feature this stays
/// `None` and CLI/env-based config is mandatory.
#[derive(Debug, Clone, Copy)]
pub struct HeadscaleEmbed {
    pub server_url: &'static str,
    pub authkey: &'static str,
    pub hostname: Option<&'static str>,
}

#[cfg(feature = "embedded-headscale-config")]
mod embedded_headscale {
    include!(concat!(env!("OUT_DIR"), "/embedded_headscale.rs"));
}

const EMBEDDED_HEADSCALE: Option<HeadscaleEmbed> = {
    #[cfg(feature = "embedded-headscale-config")]
    {
        Some(embedded_headscale::EMBEDDED_HEADSCALE)
    }
    #[cfg(not(feature = "embedded-headscale-config"))]
    {
        None
    }
};

#[derive(Parser, Debug)]
#[command(version, about = "Userspace WireGuard gateway over Headscale + DERP")]
struct Cli {
    /// Headscale coordination server URL (e.g. https://headscale.example).
    #[arg(long, env = "BURROW_HEADSCALE_URL")]
    server_url: Option<String>,

    /// Headscale preauth key (must be reusable if registering multiple
    /// nodes against the same key).
    #[arg(long, env = "BURROW_HEADSCALE_AUTHKEY")]
    authkey: Option<String>,

    /// Hostname to advertise to Headscale. Defaults to the OS hostname
    /// (via `gethostname`) inside `ts_control`.
    #[arg(long, env = "BURROW_HEADSCALE_HOSTNAME")]
    hostname: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let server_url = cli
        .server_url
        .clone()
        .or_else(|| EMBEDDED_HEADSCALE.map(|e| e.server_url.to_owned()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing server URL — pass --server-url, set BURROW_HEADSCALE_URL, or build \
                 with --features embedded-headscale-config"
            )
        })?;
    let authkey = cli
        .authkey
        .clone()
        .or_else(|| EMBEDDED_HEADSCALE.map(|e| e.authkey.to_owned()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing authkey — pass --authkey, set BURROW_HEADSCALE_AUTHKEY, or build \
                 with --features embedded-headscale-config"
            )
        })?;
    let hostname = cli.hostname.clone().or_else(|| {
        EMBEDDED_HEADSCALE
            .and_then(|e| e.hostname)
            .map(str::to_owned)
    });

    let url =
        url::Url::parse(&server_url).with_context(|| format!("parsing server URL {server_url}"))?;

    burrow::hs_main::run(burrow::hs_main::HeadscaleArgs {
        server_url: url,
        authkey,
        hostname,
    })
    .await
}
