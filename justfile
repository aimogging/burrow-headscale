# burrow build recipes.
#
# Install just:
#   Windows:  winget install Casey.Just  (or: scoop install just)
#   Linux:    your package manager, or `cargo install just`
#   macOS:    brew install just
#
# `set windows-shell` makes recipes run via powershell.exe (5.1, ships
# with every Windows). Without it just defaults to `sh`, which most
# Windows installs do not have on PATH.
#
# Cross-compile by either passing TARGET as a positional argument
# (`just embed deploy.conf x86_64-unknown-linux-musl`) or by exporting
# `BURROW_TARGET` once for the session
# (`$env:BURROW_TARGET = "x86_64-unknown-linux-musl"`). Recipes default
# their TARGET parameter to that env var.
#
# Cross-compilation requires the toolchain (`rustup target add <triple>`)
# and a working linker. Common triples:
#   x86_64-unknown-linux-musl   static linux
#   x86_64-unknown-linux-gnu    dynamic linux
#   x86_64-pc-windows-msvc      windows (native on Windows hosts)
#   x86_64-pc-windows-gnu       windows (mingw-w64)
#   aarch64-apple-darwin        apple silicon macOS
# For non-native targets the smoothest path is `cargo install cross` and
# substituting `cross` for `cargo` in the recipes.
#
# `embed` caveat: the PrivateKey ends up in the gateway binary's
# read-only data segment; anyone with read access can extract it via
# `strings`, do not share the binary with anyone you would not trust
# with the original .conf.

set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

target := env_var_or_default("BURROW_TARGET", "")

# List recipes.
default:
    @just --list

# Debug build of both binaries. Optional TARGET triple for cross-compile.
build TARGET=target:
    cargo build {{ if TARGET == "" { "" } else { "--target " + TARGET } }}

# Release build of both binaries. Optional TARGET triple.
release TARGET=target:
    cargo build --release {{ if TARGET == "" { "" } else { "--target " + TARGET } }}

# Min-sized silent burrow with CONFIG embedded, plus matching burrow-client.
#
# Computes RUSTFLAGS with `--remap-path-prefix` entries so that source
# paths embedded in panic strings (from `unwrap`/`expect`/`assert!` in
# any crate) don't leak the build user's home dir, the cargo registry
# hash, or the working-directory layout. `cargo` and `deps` and `src`
# replace the real prefixes.
[unix]
embed CONFIG TARGET=target:
    #!/usr/bin/env bash
    set -eu
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
    repo="$(pwd)"
    registry_src="$(find "$cargo_home/registry/src" -maxdepth 1 -type d -name 'index.crates.io-*' 2>/dev/null | head -1)"
    remap="--remap-path-prefix=$repo=src --remap-path-prefix=$cargo_home=cargo --remap-path-prefix=$rustup_home=rustup"
    if [ -n "$registry_src" ]; then
        remap="$remap --remap-path-prefix=$registry_src=deps"
    fi
    target_flag=""
    if [ -n "{{TARGET}}" ]; then
        target_flag="--target {{TARGET}}"
    fi
    BURROW_EMBEDDED_CONFIG="$(realpath '{{CONFIG}}')" RUSTFLAGS="$remap" \
        cargo build --bin burrow --profile min \
        --features embedded-config,silent $target_flag
    RUSTFLAGS="$remap" \
        cargo build --bin burrow-client --profile min --features silent $target_flag

# Min-sized silent burrow with CONFIG embedded, plus matching burrow-client.
[windows]
embed CONFIG TARGET=target:
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { "$env:USERPROFILE\.cargo" }; \
    $rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { "$env:USERPROFILE\.rustup" }; \
    $repo = (Get-Location).Path; \
    $registrySrc = (Get-ChildItem "$cargoHome\registry\src" -Directory -Filter 'index.crates.io-*' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName; \
    $remap = "--remap-path-prefix=$repo=src --remap-path-prefix=$cargoHome=cargo --remap-path-prefix=$rustupHome=rustup"; \
    if ($registrySrc) { $remap = "$remap --remap-path-prefix=$registrySrc=deps" }; \
    $env:RUSTFLAGS = $remap; \
    $env:BURROW_EMBEDDED_CONFIG = (Resolve-Path '{{CONFIG}}').Path; \
    $t = if ('{{TARGET}}' -eq '') { @() } else { @('--target','{{TARGET}}') }; \
    cargo build --bin burrow --profile min --features embedded-config,silent @t; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; \
    cargo build --bin burrow-client --profile min --features silent @t

# Generate the config trio AND build min-sized binaries in one step.
gen-embed *GEN_ARGS:
    cargo run --release --bin burrow-client -- gen {{GEN_ARGS}} --out ./burrow-configs
    @just embed ./burrow-configs/burrow.conf {{target}}

# Passthrough to `burrow-client gen`. Same args as the binary's gen subcommand.
gen *ARGS:
    cargo run --release --bin burrow-client -- gen {{ARGS}}

# Min-sized silent burrow with Headscale credentials embedded. Same
# path-remap + secrets caveat as `embed`.
[unix]
headscale-embed EMBED TARGET=target:
    #!/usr/bin/env bash
    set -eu
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
    repo="$(pwd)"
    registry_src="$(find "$cargo_home/registry/src" -maxdepth 1 -type d -name 'index.crates.io-*' 2>/dev/null | head -1)"
    remap="--remap-path-prefix=$repo=src --remap-path-prefix=$cargo_home=cargo --remap-path-prefix=$rustup_home=rustup"
    if [ -n "$registry_src" ]; then
        remap="$remap --remap-path-prefix=$registry_src=deps"
    fi
    target_flag=""
    if [ -n "{{TARGET}}" ]; then
        target_flag="--target {{TARGET}}"
    fi
    BURROW_HEADSCALE_EMBED="$(realpath '{{EMBED}}')" RUSTFLAGS="$remap" \
        cargo build --bin burrow --profile min \
        --features embedded-headscale-config,silent $target_flag
    RUSTFLAGS="$remap" \
        cargo build --bin burrow-client --profile min --features silent $target_flag

# Min-sized silent burrow with Headscale credentials embedded. Same
# path-remap + secrets caveat as `embed`.
[windows]
headscale-embed EMBED TARGET=target:
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { "$env:USERPROFILE\.cargo" }; \
    $rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { "$env:USERPROFILE\.rustup" }; \
    $repo = (Get-Location).Path; \
    $registrySrc = (Get-ChildItem "$cargoHome\registry\src" -Directory -Filter 'index.crates.io-*' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName; \
    $remap = "--remap-path-prefix=$repo=src --remap-path-prefix=$cargoHome=cargo --remap-path-prefix=$rustupHome=rustup"; \
    if ($registrySrc) { $remap = "$remap --remap-path-prefix=$registrySrc=deps" }; \
    $env:RUSTFLAGS = $remap; \
    $env:BURROW_HEADSCALE_EMBED = (Resolve-Path '{{EMBED}}').Path; \
    $t = if ('{{TARGET}}' -eq '') { @() } else { @('--target','{{TARGET}}') }; \
    cargo build --bin burrow --profile min --features embedded-headscale-config,silent @t; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; \
    cargo build --bin burrow-client --profile min --features silent @t

# One-shot: generate the headscale embed file AND build min-sized
# binaries. Forwards HEADSCALE_ARGS to `burrow-client headscale-embed`
# (e.g. `just headscale-gen-embed --server-url https://hs.example \
# --authkey xxx`). The embed file lands at ./burrow-headscale.txt and
# ships into `burrow` via `embedded-headscale-config`.
headscale-gen-embed *HEADSCALE_ARGS:
    cargo run --release --bin burrow-client -- headscale-embed {{HEADSCALE_ARGS}} --out ./burrow-headscale.txt
    @just headscale-embed ./burrow-headscale.txt {{target}}

# Run the debug burrow binary with args passed through.
run *ARGS:
    cargo run --bin burrow -- {{ARGS}}

# Run the debug burrow-client binary with args passed through.
run-client *ARGS:
    cargo run --bin burrow-client -- {{ARGS}}

# Full test suite (lib + integration).
test:
    cargo test

# Lint; fail on any warning.
clippy:
    cargo clippy --all-targets -- -D warnings

# Quick compile check of everything.
check:
    cargo check --all-targets

# Format the codebase.
fmt:
    cargo fmt

# Wipe build artifacts.
clean:
    cargo clean

# Bring a WG server up inside a netns. Local by default; --target for remote.
deploy-server *ARGS:
    bash scripts/deploy-server.sh {{ARGS}}

# Bring a WG client up inside a netns. Local by default; --target for remote.
deploy-client *ARGS:
    bash scripts/deploy-client.sh {{ARGS}}

# Drop into an interactive shell inside the burrow netns. Local by default.
netns-shell *ARGS:
    bash scripts/netns-shell.sh {{ARGS}}

# List sizes of built burrow / burrow-client binaries across profiles.
[unix]
size:
    #!/usr/bin/env bash
    find target -type f \
        \( -name burrow -o -name burrow.exe -o -name burrow-client -o -name burrow-client.exe \) \
        -not -path '*/deps/*' 2>/dev/null \
      | xargs -I {} sh -c 'printf "%10d  %s\n" "$(stat -c%s "{}" 2>/dev/null || stat -f%z "{}")" "{}"'

# List sizes of built burrow / burrow-client binaries across profiles.
[windows]
size:
    Get-ChildItem -Path target -Recurse -File -Include burrow.exe,burrow-client.exe \
    | Where-Object { $_.FullName -notmatch '[\\/]deps[\\/]' } \
    | ForEach-Object { '{0,12}  {1}' -f $_.Length, $_.FullName }
