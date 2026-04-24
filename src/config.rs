use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

pub use smoltcp::wire::Ipv4Cidr;

/// Parse a wg-quick `Address` / `AllowedIPs` entry like `10.0.0.2/24` (or a
/// bare host address, treated as `/32`) into an `Ipv4Cidr`. smoltcp's
/// `Ipv4Cidr` has no `FromStr` impl in 0.13, so this helper bridges that gap
/// while still letting the rest of the codebase use smoltcp's typed CIDR
/// directly.
pub fn parse_ipv4_cidr(s: &str) -> Result<Ipv4Cidr> {
    let s = s.trim();
    let (addr_str, prefix_str) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let address: Ipv4Addr = addr_str
        .parse()
        .with_context(|| format!("invalid IPv4 address: {addr_str}"))?;
    let prefix_len = match prefix_str {
        Some(p) => p
            .parse::<u8>()
            .with_context(|| format!("invalid CIDR prefix: {p}"))?,
        None => 32,
    };
    if prefix_len > 32 {
        bail!("CIDR prefix length out of range: {prefix_len}");
    }
    Ok(Ipv4Cidr::new(address, prefix_len))
}

#[derive(Clone)]
pub struct InterfaceConfig {
    pub private_key: StaticSecret,
    pub address: Ipv4Cidr,
    /// TCP port on the WG interface address where burrow accepts control
    /// requests (reverse-tunnel registrations, shell sessions in Phase
    /// 16). Default if unset: `DEFAULT_CONTROL_PORT` (57821).
    pub control_port: u16,
    /// Whether the built-in DNS resolver (`wg_ip:53/udp`) is active.
    /// On by default; opt out with `DnsEnabled = false`. A UDP
    /// reverse-tunnel registration on port 53 always takes precedence
    /// over the DNS service regardless of this flag.
    pub dns_enabled: bool,
}

/// Default TCP port for the burrow control channel on the WG interface
/// address. Chosen to avoid common services and not collide with
/// WireGuard's default 51820.
pub const DEFAULT_CONTROL_PORT: u16 = 57821;

impl fmt::Debug for InterfaceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceConfig")
            .field("private_key", &"<redacted>")
            .field("address", &self.address)
            .finish()
    }
}

#[derive(Clone)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub endpoint: String,
    pub allowed_ips: Vec<Ipv4Cidr>,
    pub persistent_keepalive: Option<u16>,
    pub preshared_key: Option<[u8; 32]>,
}

impl fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerConfig")
            .field("public_key", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub interface: InterfaceConfig,
    pub peer: PeerConfig,
}

#[derive(Default)]
struct InterfaceBuilder {
    private_key: Option<StaticSecret>,
    address: Option<Ipv4Cidr>,
    control_port: Option<u16>,
    dns_enabled: Option<bool>,
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<PublicKey>,
    endpoint: Option<String>,
    allowed_ips: Vec<Ipv4Cidr>,
    persistent_keepalive: Option<u16>,
    preshared_key: Option<[u8; 32]>,
}

enum Section {
    None,
    Interface,
    Peer,
}

pub fn parse_str(input: &str) -> Result<Config> {
    let mut iface = InterfaceBuilder::default();
    let mut peer = PeerBuilder::default();
    let mut section = Section::None;
    let mut peer_count = 0;

    for (lineno, raw_line) in input.lines().enumerate() {
        let lineno = lineno + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = parse_section_header(line) {
            match name.to_ascii_lowercase().as_str() {
                "interface" => section = Section::Interface,
                "peer" => {
                    peer_count += 1;
                    if peer_count > 1 {
                        bail!("line {lineno}: only a single [Peer] is supported in this version");
                    }
                    section = Section::Peer;
                }
                _ => bail!("line {lineno}: unknown section [{name}]"),
            }
            continue;
        }
        let (key, value) =
            parse_kv(line).with_context(|| format!("line {lineno}: expected `Key = Value`"))?;
        match section {
            Section::None => {
                bail!("line {lineno}: key/value `{key}` outside of any section")
            }
            Section::Interface => apply_interface_kv(&mut iface, &key, value, lineno)?,
            Section::Peer => apply_peer_kv(&mut peer, &key, value, lineno)?,
        }
    }

    let interface = InterfaceConfig {
        private_key: iface
            .private_key
            .ok_or_else(|| anyhow!("[Interface] missing PrivateKey"))?,
        address: iface
            .address
            .ok_or_else(|| anyhow!("[Interface] missing Address"))?,
        control_port: iface.control_port.unwrap_or(DEFAULT_CONTROL_PORT),
        dns_enabled: iface.dns_enabled.unwrap_or(true),
    };
    let peer = PeerConfig {
        public_key: peer
            .public_key
            .ok_or_else(|| anyhow!("[Peer] missing PublicKey"))?,
        endpoint: peer
            .endpoint
            .ok_or_else(|| anyhow!("[Peer] missing Endpoint"))?,
        allowed_ips: peer.allowed_ips,
        persistent_keepalive: peer.persistent_keepalive,
        preshared_key: peer.preshared_key,
    };
    if peer.allowed_ips.is_empty() {
        bail!("[Peer] AllowedIPs must contain at least one IPv4 entry");
    }
    Ok(Config { interface, peer })
}

pub fn load(path: &Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    parse_str(&contents)
}

fn strip_comment(line: &str) -> &str {
    if let Some(idx) = line.find(['#', ';']) {
        &line[..idx]
    } else {
        line
    }
}

fn parse_section_header(line: &str) -> Option<&str> {
    if line.starts_with('[') && line.ends_with(']') {
        Some(line[1..line.len() - 1].trim())
    } else {
        None
    }
}

fn parse_kv(line: &str) -> Result<(String, &str)> {
    let (k, v) = line
        .split_once('=')
        .ok_or_else(|| anyhow!("missing `=` in `{line}`"))?;
    Ok((k.trim().to_string(), v.trim()))
}

fn apply_interface_kv(
    builder: &mut InterfaceBuilder,
    key: &str,
    value: &str,
    lineno: usize,
) -> Result<()> {
    match key.to_ascii_lowercase().as_str() {
        "privatekey" => {
            let bytes = decode_key32(value)
                .with_context(|| format!("line {lineno}: invalid PrivateKey"))?;
            builder.private_key = Some(StaticSecret::from(bytes));
        }
        "address" => {
            let cidr = parse_ipv4_cidr(value)
                .with_context(|| format!("line {lineno}: invalid Address"))?;
            builder.address = Some(cidr);
        }
        "controlport" => {
            let port = value
                .parse::<u16>()
                .with_context(|| format!("line {lineno}: invalid ControlPort"))?;
            if port == 0 {
                bail!("line {lineno}: ControlPort must be non-zero");
            }
            builder.control_port = Some(port);
        }
        "dnsenabled" => {
            let enabled = match value.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => true,
                "false" | "no" | "off" | "0" => false,
                other => bail!(
                    "line {lineno}: DnsEnabled expects true/false/yes/no/on/off/1/0, got `{other}`"
                ),
            };
            builder.dns_enabled = Some(enabled);
        }
        "listenport" | "dns" | "mtu" | "fwmark" | "table" | "preup" | "postup" | "predown"
        | "postdown" | "saveconfig" => {
            // recognized wg-quick keys we currently ignore
            tracing::debug!("ignoring unsupported [Interface] key `{key}` at line {lineno}");
        }
        other => bail!("line {lineno}: unknown [Interface] key `{other}`"),
    }
    Ok(())
}

fn apply_peer_kv(builder: &mut PeerBuilder, key: &str, value: &str, lineno: usize) -> Result<()> {
    match key.to_ascii_lowercase().as_str() {
        "publickey" => {
            let bytes =
                decode_key32(value).with_context(|| format!("line {lineno}: invalid PublicKey"))?;
            builder.public_key = Some(PublicKey::from(bytes));
        }
        "endpoint" => {
            if value.is_empty() {
                bail!("line {lineno}: empty Endpoint");
            }
            builder.endpoint = Some(value.to_string());
        }
        "allowedips" => {
            for entry in value.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                if entry.contains(':') {
                    tracing::warn!(
                        "line {lineno}: skipping IPv6 AllowedIP `{entry}` (IPv4 only in initial version)"
                    );
                    continue;
                }
                let cidr = parse_ipv4_cidr(entry)
                    .with_context(|| format!("line {lineno}: invalid AllowedIP `{entry}`"))?;
                builder.allowed_ips.push(cidr);
            }
        }
        "persistentkeepalive" => {
            let seconds = value
                .parse::<u16>()
                .with_context(|| format!("line {lineno}: invalid PersistentKeepalive"))?;
            builder.persistent_keepalive = Some(seconds);
        }
        "presharedkey" => {
            let bytes = decode_key32(value)
                .with_context(|| format!("line {lineno}: invalid PresharedKey"))?;
            builder.preshared_key = Some(bytes);
        }
        other => bail!("line {lineno}: unknown [Peer] key `{other}`"),
    }
    Ok(())
}

fn decode_key32(value: &str) -> Result<[u8; 32]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .context("base64 decode failed")?;
    if decoded.len() != 32 {
        bail!(
            "expected 32 bytes after base64 decode, got {}",
            decoded.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const VALID_PUBKEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn sample_config() -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {VALID_KEY}\n\
             Address = 10.0.0.2/24\n\
             \n\
             [Peer]\n\
             PublicKey = {VALID_PUBKEY}\n\
             Endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 192.168.1.0/24, 10.0.0.0/24\n\
             PersistentKeepalive = 25\n"
        )
    }

    #[test]
    fn parses_minimal_valid_config() {
        let cfg = parse_str(&sample_config()).expect("should parse");
        assert_eq!(cfg.interface.address.prefix_len(), 24);
        assert_eq!(cfg.interface.address.address(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(cfg.peer.endpoint, "198.51.100.1:51820");
        assert_eq!(cfg.peer.allowed_ips.len(), 2);
        assert_eq!(cfg.peer.persistent_keepalive, Some(25));
        assert!(cfg.peer.preshared_key.is_none());
    }

    #[test]
    fn parses_optional_preshared_key() {
        let mut cfg = sample_config();
        cfg.push_str(&format!("PresharedKey = {VALID_KEY}\n"));
        let parsed = parse_str(&cfg).expect("should parse with PSK");
        assert!(parsed.peer.preshared_key.is_some());
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let cfg = format!(
            "# top comment\n\
             ; semicolon comment\n\
             [Interface]\n\
             # inline section comment\n\
             PrivateKey = {VALID_KEY}  # trailing comment\n\
             Address = 10.0.0.2/24\n\
             \n\
             [Peer]\n\
             PublicKey = {VALID_PUBKEY}\n\
             Endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 192.168.1.0/24\n"
        );
        parse_str(&cfg).expect("comments and blanks should be tolerated");
    }

    #[test]
    fn case_insensitive_keys_and_section_names() {
        let cfg = format!(
            "[interface]\n\
             privatekey = {VALID_KEY}\n\
             ADDRESS = 10.0.0.2/24\n\
             [PEER]\n\
             PUBLICKEY = {VALID_PUBKEY}\n\
             endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 192.168.1.0/24\n"
        );
        parse_str(&cfg).expect("should be case insensitive");
    }

    #[test]
    fn ipv6_allowed_ips_skipped_with_warning() {
        let cfg = format!(
            "[Interface]\n\
             PrivateKey = {VALID_KEY}\n\
             Address = 10.0.0.2/24\n\
             [Peer]\n\
             PublicKey = {VALID_PUBKEY}\n\
             Endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 192.168.1.0/24, ::/0, 2001:db8::/32\n"
        );
        let parsed = parse_str(&cfg).expect("should parse, skipping IPv6");
        assert_eq!(parsed.peer.allowed_ips.len(), 1);
    }

    #[test]
    fn rejects_missing_privatekey() {
        let cfg = format!(
            "[Interface]\n\
             Address = 10.0.0.2/24\n\
             [Peer]\n\
             PublicKey = {VALID_PUBKEY}\n\
             Endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 192.168.1.0/24\n"
        );
        let err = parse_str(&cfg).expect_err("must require PrivateKey");
        assert!(err.to_string().contains("PrivateKey"));
    }

    #[test]
    fn rejects_invalid_base64_key() {
        let cfg = "[Interface]\nPrivateKey = not-base64!!!\nAddress = 10.0.0.2/24\n";
        let err = parse_str(cfg).expect_err("must reject invalid base64");
        assert!(
            err.to_string().to_lowercase().contains("base64")
                || err
                    .chain()
                    .any(|e| e.to_string().to_lowercase().contains("base64"))
        );
    }

    #[test]
    fn rejects_short_key() {
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let cfg = format!("[Interface]\nPrivateKey = {short}\nAddress = 10.0.0.2/24\n");
        let err = parse_str(&cfg).expect_err("must reject short keys");
        assert!(err.chain().any(|e| e.to_string().contains("32 bytes")));
    }

    #[test]
    fn rejects_unknown_section() {
        let cfg = "[Bogus]\nFoo = bar\n";
        let err = parse_str(cfg).expect_err("must reject unknown section");
        assert!(err.to_string().contains("Bogus"));
    }

    #[test]
    fn rejects_kv_outside_section() {
        let cfg = "PrivateKey = abc\n";
        parse_str(cfg).expect_err("must reject kv outside section");
    }

    #[test]
    fn rejects_multiple_peers() {
        let cfg = format!(
            "[Interface]\n\
             PrivateKey = {VALID_KEY}\n\
             Address = 10.0.0.2/24\n\
             [Peer]\n\
             PublicKey = {VALID_PUBKEY}\n\
             Endpoint = 198.51.100.1:51820\n\
             AllowedIPs = 192.168.1.0/24\n\
             [Peer]\n\
             PublicKey = {VALID_PUBKEY}\n\
             Endpoint = 198.51.100.2:51820\n\
             AllowedIPs = 192.168.2.0/24\n"
        );
        parse_str(&cfg).expect_err("must reject multiple peers");
    }

    #[test]
    fn ipv4_cidr_contains() {
        let net = parse_ipv4_cidr("192.168.1.0/24").unwrap();
        assert!(net.contains_addr(&Ipv4Addr::new(192, 168, 1, 50)));
        assert!(!net.contains_addr(&Ipv4Addr::new(192, 168, 2, 50)));
        let any = parse_ipv4_cidr("0.0.0.0/0").unwrap();
        assert!(any.contains_addr(&Ipv4Addr::new(8, 8, 8, 8)));
        let host = parse_ipv4_cidr("10.0.0.1").unwrap();
        assert_eq!(host.prefix_len(), 32);
        assert!(host.contains_addr(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!host.contains_addr(&Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn key_roundtrip_static_to_public() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(VALID_KEY)
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let secret = StaticSecret::from(arr);
        let public = PublicKey::from(&secret);
        // Public key derived from the secret must be deterministic and 32 bytes.
        assert_eq!(public.as_bytes().len(), 32);
        // A different secret yields a different public key.
        let other = StaticSecret::from([1u8; 32]);
        assert_ne!(public.as_bytes(), PublicKey::from(&other).as_bytes());
    }
}
