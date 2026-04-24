# burrow — WireGuard Userspace Gateway

A CLI tool that runs on a host inside a private network, connects outbound to a WireGuard server, and acts as a transparent MASQUERADE NAT gateway for other WireGuard peers — with no TUN interface, no kernel drivers, and no OS network configuration required.

## Problem Statement

Enable a host behind NAT on a private network to act as a gateway for external WireGuard peers to reach internal resources, without requiring:
- A TUN/TAP interface
- Kernel drivers (Wintun, wireguard-nt, etc.)
- Root/Administrator privileges (beyond raw sockets for ICMP)
- Any changes to the internal network

## Network Topology

```
[my client]
    | WireGuard peer
    v
[WireGuard server]  ← standard Linux WireGuard, publicly reachable
    | routes via AllowedIPs
    v
[burrow — NAT gateway]  ← behind NAT on internal network, connects outbound
    | real OS sockets
    v
[internal network hosts]
```

### WireGuard Server Config

The server routes between peers using AllowedIPs:

```ini
[Peer]
# my client
PublicKey = ...
AllowedIPs = 10.0.0.1/32

[Peer]
# burrow (this tool)
PublicKey = ...
AllowedIPs = 10.0.0.2/32, 192.168.1.0/24   # advertises the internal network
```

`net.ipv4.ip_forward = 1` must be set on the server.

### NAT Gateway Behavior

- Connects outbound to the WireGuard server via UDP (NAT-friendly)
- Maintains the NAT mapping with PersistentKeepalive
- Receives IP packets from WireGuard peers destined for internal hosts
- Opens real OS sockets to those destinations (MASQUERADE: internal hosts see gateway's real LAN IP)
- Returns responses through the WireGuard tunnel with correct src/dst

"My client" requires no special configuration — it just routes to its WireGuard interface normally.

## Architecture

```
[UDP socket] ←→ boringtun Tunn (WireGuard encap/decap)
                      ↕ raw IP packets
              [destination rewrite shim]
                      ↕
              smoltcp Interface (userspace TCP/IP)
                      ↕ smoltcp TCP/UDP sockets
              [NAT table lookup → real OS sockets]
                      ↕
              [internal network hosts]
```

### Destination Rewrite (transparent proxy shim)

smoltcp only processes packets destined for its configured interface address. To handle arbitrary destinations transparently:

1. **Inbound** (from WireGuard tunnel → smoltcp):
   - Intercept packet before smoltcp
   - Record `(src_ip, src_port, dst_ip, dst_port)` → `original_dst` in NAT table
   - Rewrite `dst` to smoltcp's interface IP (e.g. `10.0.0.2`)
   - Feed rewritten packet to smoltcp

2. **smoltcp accepts** the connection (it thinks the client is connecting to it directly)

3. **Outbound** (smoltcp data → internal network):
   - Look up original destination from NAT table
   - Open real OS `TcpStream` / `UdpSocket` to `original_dst`
   - Proxy data between smoltcp socket and real OS socket

4. **Response** (internal network → WireGuard tunnel):
   - Receive data from real OS socket
   - Feed back through smoltcp
   - smoltcp constructs response packet: `src=10.0.0.2, dst=10.0.0.1`
   - Rewrite `src` back to `original_dst` (e.g. `192.168.1.50`)
   - Feed to boringtun → encrypt → send to WireGuard server

### Protocol Support

| Protocol | Approach |
|---|---|
| TCP | smoltcp state machine + real OS `TcpStream` |
| UDP | stateless NAT table + real OS `UdpSocket` |
| ICMP | raw socket (requires privilege); graceful fallback if unavailable |

If raw socket creation fails at startup, ICMP echo requests from peers receive **ICMP Type 3, Code 13 (Communication Administratively Prohibited)** in response. This is constructed in userspace and injected back through the WireGuard tunnel — no raw socket needed to send it. The response is semantically accurate (policy/privilege blocked it) and distinguishable from host-unreachable or timeout.

## Constraints

- **No Go** — Rust only
- **No GUI** — CLI only
- **No TUN interface** — no Wintun, wireguard-nt, or `/dev/tun`
- **No kernel drivers**
- **Cross-platform** — must work on Windows; Linux support is a bonus
- **IPv4 only** in initial version; IPv6 deferred
- Behavior should mirror what `boringtun` + `iptables -j MASQUERADE` achieves on Linux

## Crates

| Crate | Role |
|---|---|
| `boringtun` (no `device` feature) | WireGuard noise protocol (encap/decap) |
| `smoltcp` | Userspace TCP/IP stack |
| `tokio` | Async runtime, UDP/TCP I/O |
| `clap` | CLI argument parsing |

## Key Design Decisions

- **No device feature**: `boringtun` is used as a pure protocol library (`noise::Tunn`). The entire `device` module (epoll, TUN, UAPI socket) is excluded — it is Unix-only and unnecessary.
- **smoltcp as TCP server**: smoltcp handles the TCP state machine for connections initiated by WireGuard peers. Real OS sockets handle the outbound side to internal hosts.
- **NAT table keyed on 5-tuple**: uses the original dst (pre-rewrite). Two indices are maintained:
  - `(proto, src_ip, src_port, dst_port)` → `original_dst_ip` — for smoltcp lookups (post-rewrite, original dst_ip is lost)
  - `(proto, src_ip, src_port, original_dst_ip, dst_port)` → `(smoltcp_socket_handle, real_os_socket)` — full record
  - Collision on the first index (same client, same dst_port, different dst_ip) is theoretically possible but negligible in practice.
- **smoltcp on a dedicated thread**: smoltcp's API is pull-based (`poll()` loop), not async. It runs on its own thread and communicates with tokio tasks via channels.
- **Connection lifecycle via smoltcp socket state**: smoltcp tracks TCP state (ESTABLISHED, CLOSE_WAIT, TIME_WAIT, CLOSED) for the tunnel-facing side. NAT table entries are not removed immediately on close — a 60-second expiry timer starts when smoltcp reports a socket has reached CLOSED/TIME_WAIT. A background task sweeps expired entries. If a new SYN arrives for an expiring entry and smoltcp confirms the old socket is done, a new smoltcp socket + OS socket pair is created and the entry is replaced. The OS-side TcpStream handles its own TIME_WAIT internally when dropped.
- **PersistentKeepalive**: required to maintain the outbound NAT UDP mapping to the WireGuard server.
- **WireGuard server does the routing**: standard AllowedIPs config, no custom routing logic needed on the gateway itself.

## Workflow Rules

- **Commit regularly.** After feature additions, major code changes, and logical stopping points. Don't let large unrelated changes pile up in a single commit.
- **Every code addition must be backed by appropriate tests.** Unit, integration, regression, or end-to-end — whichever fits. Don't ship a feature without a test (or an explicit note explaining why a layer is genuinely N/A, e.g. the code requires external infra that hasn't been authorised).
- **Prefer Test-Driven Development.** Write the failing test, then the implementation. Strongest for pure library code (key types, protocol primitives, data structures); relaxed for I/O glue where test and code are entangled.
- **Always format code before pushing.** `cargo fmt --all` at every push boundary. If edits landed without `cargo fmt`, fix before pushing.
- **Update plan docs in place.** Burrow-headscale's implementation plan lives at `C:\Users\user\.claude\plans\system-reminder-you-re-running-in-functional-narwhal.md`. Edit it as decisions evolve. Do not flood the directory with new markdown files.
- **Prompt before standing up E2E infrastructure.** End-to-end tests require external infrastructure (WireGuard server, Headscale + DERP, internal network targets). Ask before assuming infra exists or starting to provision it.
