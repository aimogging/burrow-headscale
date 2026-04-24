//! Builder for `ts_ffi` invoking cbindgen.

use std::{env, path::PathBuf};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let bindings = cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(cbindgen::Config::from_file("cbindgen.toml").unwrap())
        .generate()
        .unwrap();

    bindings.write_to_file("tailscale.h");

    let out = env::var("OUT_DIR").unwrap();
    let out = PathBuf::from(out);
    bindings.write_to_file(out.join("tailscale.h"));
}
