# burrow-headscale

A userspace WireGuard gateway that joins a Tailscale-compatible tailnet
via Headscale coordination + DERP transport. No TUN interface, no
kernel drivers, no admin privileges beyond raw sockets for ICMP.

This fork diverged from upstream burrow at Stage 0 (see `git log
--grep=stage-0` for the cut point) and retired the wg-quick transport
in Stage 5. The smoltcp + NAT + reverse-tunnel machinery inherited
from upstream is unchanged; only the transport (DERP in place of a
fixed UDP peer) and coordination (Headscale in place of a hand-rolled
wg-quick config) swapped out.

## Topology

```
 tailnet peer (burrow-client or any tailscale node)
                   │  DERP relay
                   ▼
              [DERP server]   ← Tailscale's derper or Headscale embedded
                   │  DERP relay
                   ▼
 burrow-headscale (behind NAT, no inbound port)
                   │  real OS sockets, MASQUERADE
                   ▼
               LAN hosts

                   │  separately: HTTPS + Noise IK
                   ▼
             [Headscale control server]
```

Coordination: Headscale issues node identities + assigns tailnet IPs +
keeps the netmap current.
Transport: DERP relays encrypted WG datagrams between peers (no
direct P2P — Tailscale's NAT-traversal magic is out of scope here,
DERP-only by design).
Data plane: boringtun `Tunn` per peer (decrypts inbound, encrypts
outbound) → smoltcp netstack → NAT → real OS sockets to LAN.

Node identity is regenerated at every process start; nothing persists
to disk. Headscale's `ephemeral=true` registration flag means stale
entries age out on their own.

## Architecture

```
[DERP WebSocket] ←→ peer_table (Tunn per NodePublicKey)
                         ↕ plaintext IPv4
                 [destination rewrite shim]
                         ↕
                 smoltcp Interface
                         ↕ TCP/UDP sockets
                 [NAT table → real OS sockets]
                         ↕
                   LAN hosts
```

### Destination rewrite (transparent proxy shim)

smoltcp only processes packets destined for its interface address. To
handle arbitrary tailnet destinations transparently we rewrite the dst
IP to the synthetic `198.18.0.0/15` range on ingress and restore it on
egress. The NAT table holds the original 5-tuple so both directions
resolve.

1. **Inbound** (peer → DERP → burrow → smoltcp): record
   `(proto, src_ip, src_port, dst_ip, dst_port)` → `original_dst`,
   rewrite `dst_ip` to smoltcp's interface addr, enqueue.
2. **smoltcp accepts** the connection (it thinks the client connected
   directly).
3. **Outbound** (smoltcp → LAN): look up `original_dst` in the NAT
   table, open a real OS TCP/UDP socket, proxy bytes both ways.
4. **Response** (LAN → smoltcp → DERP): smoltcp produces a packet with
   `src = interface_addr`; rewrite `src` back to `original_dst_ip` so
   the peer sees the same address it dialled.

### Protocol support

| Proto | Approach |
|---|---|
| TCP   | smoltcp state machine + real OS `TcpStream` |
| UDP   | stateless NAT table + real OS `UdpSocket` |
| ICMP  | raw socket if available; otherwise Type 3 Code 13 synthesised in userspace |

## Constraints

- Rust only. No Go, no GUI.
- No TUN interface, no kernel drivers. Cross-platform (Windows first,
  Linux second).
- IPv4-only data plane for now. Control-plane IPv6 is present (tailnet
  IPv6 is assigned by Headscale) but we don't route it.
- Nothing persists to disk — fresh node identity every boot.

## Key crates

| Crate | Role |
|---|---|
| `boringtun` (no `device`) | WireGuard noise protocol (encap/decap), one `Tunn` per peer |
| `ts_control`, `ts_control_noise`, `ts_control_serde` | Headscale handshake + netmap stream |
| `ts_transport_derp`, `ts_packet`, `ts_keys` | DERP WebSocket client + framing + key types |
| `smoltcp` | Userspace TCP/IP stack |
| `tokio` | Async runtime |
| `dashmap` | Lock-free PeerTable indices |

Vendored tailscale-rs lives in `vendor/tailscale-rs/`; pinned commit in
`vendor/tailscale-rs/REVISION`.

## Key design decisions

- **`boringtun` as pure protocol lib**: `noise::Tunn` only; its `device`
  module (epoll/TUN/UAPI) is excluded.
- **Tunn per peer**: `PeerTable` holds an `Arc<Peer>` per
  `NodePublicKey`, each with its own `boringtun::Tunn`. The reconciler
  (`src/peer_reconciler.rs`) keeps the table aligned with the Headscale
  netmap.
- **node_key == wg_public**: Tailscale's protocol uses the node public
  key as the WireGuard peer public key. Our `wg_private` is
  `NodeIdentity.state.node_keys.private` cast through raw bytes (ts_keys
  rides on x25519-dalek 3.0-pre while boringtun pins 2.x, so the
  blanket `From` impl doesn't resolve).
- **NAT table keyed on 5-tuple** with two indices: one pre-rewrite
  (`proto, src, dst_port` → `original_dst_ip`) and one full record
  (full 5-tuple → smoltcp handle + OS socket). Collision on the first
  index (same client, same dst_port, different dst_ip) is theoretically
  possible but negligible.
- **smoltcp on a dedicated thread**: smoltcp's API is pull-based, not
  async. It runs on its own OS thread and communicates with tokio tasks
  via channels.
- **Connection lifecycle via smoltcp socket state**: 60s grace window
  after CLOSED/TIME_WAIT, background sweeper. SYN-for-expiring entry
  replaces the slot.
- **DERP-only transport**: direct peer-to-peer (Tailscale's disco /
  NAT-traversal magic) is explicitly out of scope. Everything relays.

## Workflow rules

- **Commit regularly.** After feature additions, major code changes,
  and logical stopping points. Don't let large unrelated changes pile
  up in a single commit.
- **Every code addition must be backed by appropriate tests** — unit,
  integration, regression, or end-to-end. If a layer is genuinely N/A
  (e.g. a binary's `main` wrapping already-tested library code, or a
  feature needs external infra that hasn't been authorised), say so
  explicitly rather than silently skipping.
- **Prefer Test-Driven Development.** Write the failing test, then
  the implementation. Strongest for pure library code; relaxed for
  I/O glue.
- **Format before pushing**, but scope the format to files you
  touched. Use `rustfmt --edition 2021 <files>` or `cargo fmt -p
  burrow`. Do NOT use `cargo fmt --all` — it walks into
  `vendor/tailscale-rs/` and reformats upstream code, which we must
  not modify.
- **Update plan docs in place.** The implementation plan lives at
  `C:\Users\user\.claude\plans\system-reminder-you-re-running-in-functional-narwhal.md`.
  Edit as decisions evolve; don't flood the directory with new md
  files.
- **Prompt before standing up E2E infrastructure.** Integration tests
  that need a real Headscale / DERP / LAN target require external
  resources. Ask before assuming infra exists or provisioning it.

## Build & test quick-reference

- `cargo build` / `cargo test` — default build, Headscale + DERP
  compile unconditionally (no feature flag since the Stage 2b/c commit).
- `cargo test --features insecure-tests` — enables the real-DERP and
  real-Headscale integration tests, which forward
  `ts_transport_derp/insecure-for-tests` and
  `ts_control/insecure-keyfetch` so a loopback tunnel with a
  self-signed cert or plain HTTP works.
- Integration tests that need infra:
  - `tests/derp_real_roundtrip.rs` → needs `BURROW_TEST_DERP_URL`.
  - `tests/headscale_register_roundtrip.rs` → needs
    `BURROW_TEST_HEADSCALE_URL` + `BURROW_TEST_HEADSCALE_AUTHKEY`.
  Both short-circuit cleanly without those vars so the suite stays
  hermetic.

Binary entry points:
- `src/main.rs` — the gateway. Always goes through `hs_main::run`.
  Needs `--server-url`/`--authkey`/`--hostname` (or matching
  `BURROW_HEADSCALE_*` env, or a build-time embed via
  `--features embedded-headscale-config`).
- `src/bin/burrow-client.rs` — companion CLI. Same top-level
  credentials flags (propagated with `global = true`). When set,
  `tunnel` / `shell` route through `burrow::client_session::ClientSession`
  (DERP transport); when unset, they fall back to direct TCP — useful
  for the in-process mock-server tests in `tests/burrow_client_cli.rs`.

`burrow-client` subcommands: `tunnel`, `shell`, `login` (register +
print tailnet IP, for scripts), `headscale-embed` (write the 2- or
3-line file that feeds `BURROW_HEADSCALE_EMBED` at build time). The
old `gen`/`keygen` subcommands retired with wg-quick in Stage 5.
