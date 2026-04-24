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
- **smoltcp event ordering — data before FIN**: `run_smoltcp_thread`
  drains `TcpData` *before* emitting `TcpFinFromPeer` when a state
  transition + buffered inbound bytes happen in the same poll cycle.
  `DerpTcpStream` treats `PeerFin` as EOF, so emitting in the other
  order drops the last CBOR frame written immediately before
  `close_tcp`. See `src/runtime.rs::run_smoltcp_thread` + the comment
  block around the `can_recv()` branch.
- **Connection lifecycle via smoltcp socket state**: 60s grace window
  after CLOSED/TIME_WAIT, background sweeper. SYN-for-expiring entry
  replaces the slot.
- **DERP-only transport**: direct peer-to-peer (Tailscale's disco /
  NAT-traversal magic) is explicitly out of scope. Everything relays.
- **`ClientSession` polls the PeerTable, not the Headscale watch,
  for peer readiness**: `wait_for_peer` races the reconciler task —
  `watch::Receiver::changed()` can fire before the reconciler's
  insert lands in the `DashMap`, and no later netmap update arrives
  to re-wake the waiter. A 50 ms polling loop observes the insert
  directly and is trivially small wall-time (Headscale typically
  delivers peers within a few hundred ms of registration).
- **`ClientSession` has a monotonic ephemeral-port allocator**: smoltcp
  0.13 rejects port 0 on `connect()` with `Unaddressable`, despite
  what the docs imply. The session hands out ports from the
  RFC 6335 range (49152..=65535) for both outbound TCP connects and
  UDP binds (`src/client_session.rs::alloc_ephemeral_port`).

## ClientSession public API

`src/client_session.rs` exposes the full tailnet-client surface for
anything that wants to ride the DERP transport without wrapping the
`burrow-client` binary. Burrow-client itself is a thin shell around
this module.

- `ClientSession::connect(url, authkey, hostname)` — register + bring
  up the data plane. Returns once tailnet IP + DERP region are known.
- `ClientSession::open_tcp(dst, port) -> DerpTcpStream` — outbound
  TCP, AsyncRead + AsyncWrite.
- `ClientSession::bind_udp() -> UdpReceiver` — bind an ephemeral
  port for UDP. Drop to release.
- `ClientSession::send_udp(src_port, dst, dst_port, payload)` — raw
  UDP send; pairs with `bind_udp`.
- `ClientSession::query_udp(dst, port, payload, timeout) -> Vec<u8>`
  — one-shot request-reply convenience (DNS etc).

Ingress routes UDP datagrams for bound ephemeral ports to the
matching `UdpReceiver`; everything else falls through to smoltcp.

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
  self-signed cert or plain HTTP works. For production-signed certs
  use `BURROW_EXTRA_CA_BUNDLE=/path/to/ca.pem` instead — that keeps
  verification on.
- Integration tests that need infra (all short-circuit cleanly
  without their env vars so the hermetic suite stays green):
  - `tests/headscale_register_roundtrip.rs` → needs
    `BURROW_TEST_HEADSCALE_URL` + `BURROW_TEST_HEADSCALE_AUTHKEY`.
    Covers register + netmap stream against live Headscale.
  - `tests/burrow_client_headscale.rs` → same env, 7 full-workflow
    E2E cases (CBOR smoke, TCP reverse tunnel, UDP reverse tunnel,
    shell one-shot, DNS query, multi-peer routing, interactive-shell
    framed stdio). Total ~45 s serial wall time.
  - `tests/derp_real_roundtrip.rs` → `#[ignore]`d; needs
    `BURROW_TEST_DERP_URL` pointing at a **bare** derper. Headscale's
    embedded DERP validates node keys, which the test doesn't
    register, so it fails there. Superseded by
    `burrow_client_headscale.rs` for real-transport coverage.

## Subprocess-driven E2E harness notes

`tests/burrow_client_headscale.rs` spawns `burrow` and sometimes
`burrow-client` as tokio subprocesses to exercise the real binaries.
A few Windows/PTY gotchas that took debugging:

- **Tracing goes to stdout, not stderr.** `tracing_subscriber::fmt()`
  writes to stdout by default. The subprocess harness pipes both
  streams and parses stdout for the `registered with Headscale
  tailnet_ip=…` line.
- **`NO_COLOR=1` on subprocess env.** Without it, tracing wraps
  field names in ANSI escapes (`\x1b[3mtailnet_ip\x1b[0m=…`) that
  defeat `line.find("tailnet_ip=")`.
- **burrow-client initialises tracing to stderr** (`init_tracing` in
  `src/bin/burrow-client.rs`). Separate stream from its stdout so
  `shell --output -` stdout capture doesn't get log spam mixed in.
- **ConPTY cursor-position DSR.** On Windows, when `burrow` spawns
  a PTY via the ConPTY backend, the PTY probes its client with
  `\x1b[6n` and may hang if not answered. The interactive-shell test
  scans STDOUT frames for this sequence and replies with a canned
  `\x1b[24;80R`.
- **`tokio::process::Command::kill_on_drop(true)`** — always. tokio
  doesn't kill children on task cancellation by default; without
  this, a panicking test leaks burrow processes that stay registered
  as Headscale nodes until Headscale's ephemeral expiry fires.

Binary entry points:
- `src/main.rs` — the gateway. Always goes through `hs_main::run`.
  Needs `--server-url`/`--authkey`/`--hostname` (or matching
  `BURROW_HEADSCALE_*` env, or a build-time embed via
  `--features embedded-headscale-config`).
- `src/bin/burrow-client.rs` — companion CLI. Thin wrapper around
  `burrow::client_session::ClientSession`. Same top-level credentials
  flags propagated with `clap(global = true)`. When set, `tunnel` /
  `shell` route through DERP; when unset they fall back to direct
  TCP — useful for the in-process mock-server tests in
  `tests/burrow_client_cli.rs`. `login` and `headscale-embed` always
  need credentials (they're the credentials-consuming subcommands).

`burrow-client` subcommands: `tunnel`, `shell`, `login` (register +
print tailnet IP, for scripts), `headscale-embed` (write the 2- or
3-line file that feeds `BURROW_HEADSCALE_EMBED` at build time). The
old `gen`/`keygen` subcommands retired with wg-quick in Stage 5.
