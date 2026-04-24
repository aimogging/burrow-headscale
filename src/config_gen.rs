//! Config generator for a full burrow deployment. Given the WG server's
//! public endpoint and the routes the burrow host should expose, emits
//! three kinds of file:
//!
//!   * `server.conf` — for the WG server. Multi-peer (burrow + each
//!     client). Consumed by `wg-quick` on the server, not by our own
//!     single-peer parser.
//!   * `burrow.conf` — fed to `burrow run --config burrow.conf`.
//!   * `clientN.conf` — one per client peer, starting at N=1.
//!     Consumed by `wg-quick` on each client machine.
//!
//! IP layout inside the subnet:
//!   * `.1` → WG server
//!   * `.2` → burrow (the gateway host)
//!   * `.10..` → clients (one per requested client, sequential)
//!
//! Pure — returns the list of `(filename, contents)` pairs so the
//! caller writes them to disk (or tests assert on them). Callers are
//! responsible for file IO and permissions.
//!
//! Single-peer parser limitation: `config::parse_str` only supports
//! one `[Peer]`. `burrow.conf` and each `clientN.conf` are single-peer
//! and therefore round-trippable through our parser; `server.conf` is
//! not — the server-side config is for `wg-quick`, which is the
//! canonical multi-peer consumer.

use std::net::Ipv4Addr;

use anyhow::{bail, Result};
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{Ipv4Cidr, DEFAULT_CONTROL_PORT};

/// First octet-offset used for client peers. `.1` = server, `.2` =
/// gateway, `.3..=.9` reserved for future service roles, `.10+` = clients.
const CLIENT_OFFSET: u32 = 10;

pub struct GenParams {
    /// WG server's public `ip:port` (goes into each peer's `Endpoint`).
    pub endpoint: String,
    /// Routes the burrow host will expose (CIDRs). Empty = pure
    /// peer-to-peer WG with no subnet exposure — clients can still use
    /// burrow's DNS / reverse-tunnel services.
    pub routes: Vec<String>,
    /// DNS resolvers to write into each client's `[Interface]` as
    /// `DNS = ...`. Empty (the default) means no `DNS =` line —
    /// clients keep their system resolver. Pass the burrow host's
    /// WG IP to opt clients into burrow's built-in resolver; append
    /// public resolvers (e.g. `1.1.1.1`) if you want wg-quick fallback.
    pub dns: Vec<String>,
    /// WG network subnet (e.g. `10.0.0.0/24`). Must have room for
    /// `.1`, `.2`, and `.10..=.(10 + clients - 1)`.
    pub subnet: Ipv4Cidr,
    /// Number of client peers to generate. Must be ≥ 1.
    pub clients: u16,
    /// WG server's UDP listen port (goes into `server.conf` and each
    /// peer's `Endpoint` port).
    pub listen_port: u16,
    /// burrow control port (goes into `burrow.conf`).
    pub control_port: u16,
}

impl Default for GenParams {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            routes: Vec::new(),
            dns: Vec::new(),
            subnet: Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            clients: 1,
            listen_port: 51820,
            control_port: DEFAULT_CONTROL_PORT,
        }
    }
}

pub struct GeneratedConfig {
    pub filename: String,
    pub contents: String,
}

/// Generate the full trio (+ N-1 extra client configs). Order of the
/// returned vec: `server.conf`, `burrow.conf`, `client1.conf`, ...,
/// `clientN.conf`.
pub fn generate(params: &GenParams) -> Result<Vec<GeneratedConfig>> {
    if params.clients == 0 {
        bail!("--clients must be >= 1");
    }
    if params.endpoint.is_empty() {
        bail!("--endpoint is required (ip:port)");
    }

    let (server_ip, gateway_ip, client_ips) = allocate_ips(&params.subnet, params.clients)?;
    let prefix = params.subnet.prefix_len();

    let server = Keypair::new();
    let gateway = Keypair::new();
    let clients: Vec<Keypair> = (0..params.clients).map(|_| Keypair::new()).collect();

    let routes_suffix = if params.routes.is_empty() {
        String::new()
    } else {
        format!(", {}", params.routes.join(", "))
    };

    let mut out = Vec::with_capacity(2 + clients.len());
    out.push(GeneratedConfig {
        filename: "server.conf".into(),
        contents: build_server_conf(
            params,
            &server,
            server_ip,
            &gateway,
            gateway_ip,
            &clients,
            &client_ips,
            &routes_suffix,
            prefix,
        ),
    });
    out.push(GeneratedConfig {
        filename: "burrow.conf".into(),
        contents: build_burrow_conf(params, &gateway, gateway_ip, &server, prefix),
    });
    for (i, c) in clients.iter().enumerate() {
        out.push(GeneratedConfig {
            filename: format!("client{}.conf", i + 1),
            contents: build_client_conf(params, c, client_ips[i], &server, &routes_suffix, prefix),
        });
    }
    Ok(out)
}

fn build_server_conf(
    params: &GenParams,
    server: &Keypair,
    server_ip: Ipv4Addr,
    gateway: &Keypair,
    gateway_ip: Ipv4Addr,
    clients: &[Keypair],
    client_ips: &[Ipv4Addr],
    routes_suffix: &str,
    prefix: u8,
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "[Interface]\nPrivateKey = {}\nListenPort = {}\nAddress = {}/{}\n",
        server.private, params.listen_port, server_ip, prefix
    ));
    s.push_str(&format!(
        "\n# burrow\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32{}\n",
        gateway.public, gateway_ip, routes_suffix
    ));
    for (i, c) in clients.iter().enumerate() {
        s.push_str(&format!(
            "\n# client{}\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\n",
            i + 1,
            c.public,
            client_ips[i],
        ));
    }
    s
}

fn build_burrow_conf(
    params: &GenParams,
    gateway: &Keypair,
    gateway_ip: Ipv4Addr,
    server: &Keypair,
    prefix: u8,
) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {}\n\
         Address = {}/{}\n\
         ControlPort = {}\n\
         DnsEnabled = true\n\
         \n\
         [Peer]\n\
         PublicKey = {}\n\
         Endpoint = {}\n\
         AllowedIPs = {}/{}\n\
         PersistentKeepalive = 25\n",
        gateway.private,
        gateway_ip,
        prefix,
        params.control_port,
        server.public,
        params.endpoint,
        params.subnet.network().address(),
        prefix,
    )
}

fn build_client_conf(
    params: &GenParams,
    client: &Keypair,
    client_ip: Ipv4Addr,
    server: &Keypair,
    routes_suffix: &str,
    prefix: u8,
) -> String {
    // `DNS = ...` is wg-quick's hook for flipping the peer's system
    // resolver while the tunnel is up (resolvconf on Linux/macOS, the
    // official WireGuard client on Windows). Emit it only if the user
    // explicitly asked — silent DNS rerouting is surprising.
    let dns_line = if params.dns.is_empty() {
        String::new()
    } else {
        format!("DNS = {}\n", params.dns.join(", "))
    };
    format!(
        "[Interface]\n\
         PrivateKey = {}\n\
         Address = {}/{}\n\
         {}\
         \n\
         [Peer]\n\
         PublicKey = {}\n\
         Endpoint = {}\n\
         AllowedIPs = {}/{}{}\n\
         PersistentKeepalive = 25\n",
        client.private,
        client_ip,
        prefix,
        dns_line,
        server.public,
        params.endpoint,
        params.subnet.network().address(),
        prefix,
        routes_suffix,
    )
}

struct Keypair {
    private: String,
    public: String,
}

impl Keypair {
    fn new() -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let b64 = base64::engine::general_purpose::STANDARD;
        Self {
            private: b64.encode(secret.to_bytes()),
            public: b64.encode(public.as_bytes()),
        }
    }
}

/// Lay out `.1` for the server, `.2` for the gateway, and `.10..` for
/// clients within the subnet. Errors if the subnet can't fit them all.
fn allocate_ips(subnet: &Ipv4Cidr, clients: u16) -> Result<(Ipv4Addr, Ipv4Addr, Vec<Ipv4Addr>)> {
    let network = subnet.network().address();
    let prefix = subnet.prefix_len();
    let host_bits = 32 - prefix;
    // Minimum: CLIENT_OFFSET + clients + 1 distinct host indices
    // (server, gateway, N clients — plus network+broadcast reserved).
    // For /28 (14 usable) with clients=1, highest needed = 10 + 1 - 1 = 10.
    // Broadcast is at index (2^host_bits) - 1.
    let highest_index = CLIENT_OFFSET + u32::from(clients) - 1;
    let broadcast_index = (1u32 << host_bits) - 1;
    if highest_index >= broadcast_index {
        bail!(
            "subnet {} cannot fit {} clients (need host index {} but broadcast is {})",
            subnet,
            clients,
            highest_index,
            broadcast_index
        );
    }

    let base = u32::from(network);
    let server = Ipv4Addr::from(base + 1);
    let gateway = Ipv4Addr::from(base + 2);
    let client_ips: Vec<Ipv4Addr> = (0..u32::from(clients))
        .map(|i| Ipv4Addr::from(base + CLIENT_OFFSET + i))
        .collect();
    Ok((server, gateway, client_ips))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse_ipv4_cidr, parse_str};

    fn default_params() -> GenParams {
        GenParams {
            endpoint: "198.51.100.1:51820".into(),
            routes: vec!["192.168.1.0/24".into()],
            ..Default::default()
        }
    }

    #[test]
    fn single_client_default_subnet() {
        let out = generate(&default_params()).unwrap();
        let names: Vec<&str> = out.iter().map(|c| c.filename.as_str()).collect();
        assert_eq!(names, vec!["server.conf", "burrow.conf", "client1.conf"]);
    }

    #[test]
    fn multiple_clients_all_emitted() {
        let mut p = default_params();
        p.clients = 3;
        let out = generate(&p).unwrap();
        let names: Vec<&str> = out.iter().map(|c| c.filename.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "server.conf",
                "burrow.conf",
                "client1.conf",
                "client2.conf",
                "client3.conf",
            ]
        );
    }

    #[test]
    fn clients_zero_rejected() {
        let mut p = default_params();
        p.clients = 0;
        assert!(generate(&p).is_err());
    }

    #[test]
    fn empty_endpoint_rejected() {
        let p = GenParams {
            endpoint: "".into(),
            ..Default::default()
        };
        assert!(generate(&p).is_err());
    }

    #[test]
    fn burrow_conf_roundtrips_through_parser() {
        let out = generate(&default_params()).unwrap();
        let gw = out.iter().find(|c| c.filename == "burrow.conf").unwrap();
        let cfg = parse_str(&gw.contents).expect("burrow.conf must parse cleanly");
        assert_eq!(cfg.interface.address.prefix_len(), 24);
        assert_eq!(cfg.interface.address.address(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(cfg.interface.control_port, DEFAULT_CONTROL_PORT);
        assert!(cfg.interface.dns_enabled);
        assert_eq!(cfg.peer.endpoint, "198.51.100.1:51820");
        assert_eq!(cfg.peer.persistent_keepalive, Some(25));
    }

    #[test]
    fn client_conf_roundtrips_through_parser() {
        let out = generate(&default_params()).unwrap();
        let client = out.iter().find(|c| c.filename == "client1.conf").unwrap();
        let cfg = parse_str(&client.contents).expect("client1.conf must parse cleanly");
        assert_eq!(cfg.interface.address.address(), Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(cfg.peer.endpoint, "198.51.100.1:51820");
        let allowed: Vec<String> = cfg
            .peer
            .allowed_ips
            .iter()
            .map(|c| format!("{}/{}", c.network().address(), c.prefix_len()))
            .collect();
        assert!(allowed.contains(&"10.0.0.0/24".to_string()));
        assert!(allowed.contains(&"192.168.1.0/24".to_string()));
    }

    #[test]
    fn server_conf_has_one_interface_and_n_plus_one_peers() {
        let mut p = default_params();
        p.clients = 2;
        let out = generate(&p).unwrap();
        let server = out.iter().find(|c| c.filename == "server.conf").unwrap();
        let iface_count = server.contents.matches("[Interface]").count();
        let peer_count = server.contents.matches("[Peer]").count();
        assert_eq!(iface_count, 1);
        // 1 burrow peer + 2 clients = 3.
        assert_eq!(peer_count, 3);
        // burrow peer carries the routes.
        assert!(server.contents.contains("192.168.1.0/24"));
    }

    #[test]
    fn ip_allocation_in_custom_subnet() {
        let subnet = parse_ipv4_cidr("10.50.0.0/24").unwrap();
        let (server, gateway, clients) = allocate_ips(&subnet, 2).unwrap();
        assert_eq!(server, Ipv4Addr::new(10, 50, 0, 1));
        assert_eq!(gateway, Ipv4Addr::new(10, 50, 0, 2));
        assert_eq!(
            clients,
            vec![Ipv4Addr::new(10, 50, 0, 10), Ipv4Addr::new(10, 50, 0, 11),]
        );
    }

    #[test]
    fn ip_allocation_respects_network_base_when_subnet_not_aligned() {
        // Caller passes "10.0.0.50/24" — we still allocate .1/.2/.10..
        // relative to the network (10.0.0.0), not the configured address.
        let subnet = parse_ipv4_cidr("10.0.0.50/24").unwrap();
        let (server, gateway, clients) = allocate_ips(&subnet, 1).unwrap();
        assert_eq!(server, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(gateway, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(clients, vec![Ipv4Addr::new(10, 0, 0, 10)]);
    }

    #[test]
    fn small_subnet_rejects_overflow() {
        // /28 has 16 addresses: .0 (network) and .15 (broadcast) are
        // reserved, leaving indices 1..=14 for hosts. With
        // CLIENT_OFFSET=10, clients=5 fills indices 10..=14 (last
        // usable) and should succeed. clients=6 would need index 15
        // (broadcast), which must be rejected.
        let subnet = parse_ipv4_cidr("10.0.0.0/28").unwrap();
        assert!(allocate_ips(&subnet, 5).is_ok());
        assert!(allocate_ips(&subnet, 6).is_err());
    }

    #[test]
    fn client_conf_has_no_dns_by_default() {
        let out = generate(&default_params()).unwrap();
        let client = out.iter().find(|c| c.filename == "client1.conf").unwrap();
        assert!(
            !client.contents.contains("DNS ="),
            "default gen must not emit a DNS line; got:\n{}",
            client.contents
        );
    }

    #[test]
    fn client_conf_emits_dns_line_when_requested() {
        let mut p = default_params();
        p.dns = vec!["10.0.0.2".into()];
        let out = generate(&p).unwrap();
        let client = out.iter().find(|c| c.filename == "client1.conf").unwrap();
        assert!(
            client.contents.contains("DNS = 10.0.0.2\n"),
            "expected `DNS = 10.0.0.2`, got:\n{}",
            client.contents
        );
    }

    #[test]
    fn client_conf_joins_multiple_dns_servers() {
        let mut p = default_params();
        p.dns = vec!["10.0.0.2".into(), "1.1.1.1".into(), "9.9.9.9".into()];
        let out = generate(&p).unwrap();
        let client = out.iter().find(|c| c.filename == "client1.conf").unwrap();
        assert!(
            client
                .contents
                .contains("DNS = 10.0.0.2, 1.1.1.1, 9.9.9.9\n"),
            "expected comma-joined DNS list, got:\n{}",
            client.contents
        );
    }

    #[test]
    fn multiple_routes_propagate_to_server_and_clients() {
        let p = GenParams {
            routes: vec!["192.168.1.0/24".into(), "10.50.0.0/24".into()],
            ..default_params()
        };
        let out = generate(&p).unwrap();
        let server = out.iter().find(|c| c.filename == "server.conf").unwrap();
        assert!(server.contents.contains("192.168.1.0/24"));
        assert!(server.contents.contains("10.50.0.0/24"));
        let client = out.iter().find(|c| c.filename == "client1.conf").unwrap();
        assert!(client.contents.contains("192.168.1.0/24"));
        assert!(client.contents.contains("10.50.0.0/24"));
    }

    #[test]
    fn no_routes_means_empty_routes_suffix() {
        let p = GenParams {
            routes: vec![],
            ..default_params()
        };
        let out = generate(&p).unwrap();
        let server = out.iter().find(|c| c.filename == "server.conf").unwrap();
        assert!(server.contents.contains("AllowedIPs = 10.0.0.2/32\n"));
        let client = out.iter().find(|c| c.filename == "client1.conf").unwrap();
        assert!(client.contents.contains("AllowedIPs = 10.0.0.0/24\n"));
    }

    #[test]
    fn generated_keys_are_distinct() {
        let mut p = default_params();
        p.clients = 2;
        let out = generate(&p).unwrap();
        let keys: Vec<&str> = out
            .iter()
            .filter_map(|c| {
                c.contents
                    .lines()
                    .find(|l| l.starts_with("PrivateKey = "))
                    .map(|l| l.trim_start_matches("PrivateKey = "))
            })
            .collect();
        assert_eq!(keys.len(), 4); // server, gateway, 2 clients
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), keys.len(), "private keys must be distinct");
    }
}
