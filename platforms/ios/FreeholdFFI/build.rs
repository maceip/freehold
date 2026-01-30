//! Build script for generating C headers with cbindgen

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = PathBuf::from(&crate_dir).join("include");

    // Create include directory
    std::fs::create_dir_all(&out_dir).ok();

    // Generate C header
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("Failed to read cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Failed to generate bindings")
        .write_to_file(out_dir.join("freehold_ffi.h"));

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
