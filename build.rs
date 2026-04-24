use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=BURROW_HEADSCALE_EMBED");

    if env::var_os("CARGO_FEATURE_EMBEDDED_HEADSCALE_CONFIG").is_none() {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    emit_headscale_embed(&out_dir);
}

/// Parse a 2- or 3-line file:
/// ```text
/// <server_url>
/// <authkey>
/// <hostname>        (optional — omit the line, or leave blank, to skip)
/// ```
/// and emit `$OUT_DIR/embedded_headscale.rs` containing a module-local
/// `EMBEDDED_HEADSCALE: crate::HeadscaleEmbed`.
fn emit_headscale_embed(out_dir: &PathBuf) {
    let path = env::var("BURROW_HEADSCALE_EMBED").expect(
        "feature `embedded-headscale-config` is enabled but BURROW_HEADSCALE_EMBED is not set; \
         e.g. BURROW_HEADSCALE_EMBED=./burrow-headscale.txt cargo build \
         --features embedded-headscale-config",
    );
    println!("cargo:rerun-if-changed={path}");

    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read BURROW_HEADSCALE_EMBED ({path}): {e}"));
    let mut lines = contents.lines();
    let url = lines.next().unwrap_or("").trim().to_owned();
    let authkey = lines.next().unwrap_or("").trim().to_owned();
    let hostname = lines.next().map(str::trim).filter(|s| !s.is_empty());

    if url.is_empty() || authkey.is_empty() {
        panic!(
            "BURROW_HEADSCALE_EMBED file {path:?} must contain at least two non-empty lines: \
             <server_url>\\n<authkey>[\\n<hostname>]"
        );
    }

    let hostname_expr = match hostname {
        Some(h) => format!("Some({h:?})"),
        None => "None".to_owned(),
    };

    let body = format!(
        "pub const EMBEDDED_HEADSCALE: super::HeadscaleEmbed = super::HeadscaleEmbed {{\n\
         \x20   server_url: {url:?},\n\
         \x20   authkey: {authkey:?},\n\
         \x20   hostname: {hostname_expr},\n\
         }};\n"
    );
    let dest = out_dir.join("embedded_headscale.rs");
    fs::write(&dest, body).unwrap_or_else(|e| panic!("write {}: {e}", dest.display()));
}
