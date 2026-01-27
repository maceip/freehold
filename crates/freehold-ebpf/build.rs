use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/main.bpf.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj = out_dir.join("freehold.bpf.o");

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm64",
        _ => "x86",
    };

    let status = Command::new("clang")
        .args(["-g", "-O2", "-target", "bpf"])
        .arg(format!("-D__TARGET_ARCH_{}", arch))
        .args(["-I/usr/include", "-c", "src/main.bpf.c", "-o"])
        .arg(&obj)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-env=FREEHOLD_BPF={}", obj.display());
        }
        _ => {
            println!("cargo:warning=eBPF build skipped (clang required)");
        }
    }
}
