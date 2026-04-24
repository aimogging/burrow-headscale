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
# (`just embed deploy.txt x86_64-unknown-linux-musl`) or by exporting
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
# `embed` caveat: the Headscale preauth key ends up in the gateway
# binary's read-only data segment; anyone with read access can extract
# it via `strings`. Treat a built binary with the same care as the
# preauth key itself.

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

# Min-sized silent burrow with Headscale credentials (read from EMBED)
# baked into the binary. EMBED is the path to a 2- or 3-line file:
# <server_url>\n<authkey>[\n<hostname>]. See `embed-gen` to produce
# one from CLI/env.
#
# Computes RUSTFLAGS with `--remap-path-prefix` entries so that source
# paths embedded in panic strings (from `unwrap`/`expect`/`assert!` in
# any crate) don't leak the build user's home dir, the cargo registry
# hash, or the working-directory layout. `cargo` and `deps` and `src`
# replace the real prefixes.
[unix]
embed EMBED TARGET=target:
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
# remap + secrets caveat as the unix variant.
[windows]
embed EMBED TARGET=target:
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

# One-shot: write the Headscale embed file from HEADSCALE_ARGS (e.g.
# `just gen-embed --server-url https://hs.example --authkey xxx`) and
# build the min-sized binaries in one step. The file lands at
# ./burrow-headscale.txt.
gen-embed *HEADSCALE_ARGS:
    cargo run --release --bin burrow-client -- headscale-embed {{HEADSCALE_ARGS}} --out ./burrow-headscale.txt
    @just embed ./burrow-headscale.txt {{target}}

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
