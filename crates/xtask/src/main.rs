use std::process::Command;
use std::path::Path;

use anyhow::Context as _;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Parser)]
enum Commands {
    BuildEbpf(BuildEbpfOptions),
}

#[derive(Debug, Parser)]
pub struct BuildEbpfOptions {
    #[clap(long)]
    release: bool,
}

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();

    match opts.command {
        Commands::BuildEbpf(opts) => build_ebpf(opts),
    }
}

fn find_clang() -> String {
    // Check common locations for clang
    let candidates = [
        // System clang
        "clang",
        // NDK clang (common location)
        "/home/pooppoop/dev/ndk/26.3.11579264/toolchains/llvm/prebuilt/linux-x86_64/bin/clang",
    ];

    for candidate in &candidates {
        if let Ok(output) = Command::new(candidate).arg("--version").output() {
            if output.status.success() {
                return candidate.to_string();
            }
        }
    }

    "clang".to_string() // fallback
}

fn build_ebpf(opts: BuildEbpfOptions) -> anyhow::Result<()> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| ".".to_string());
    // Go up two levels: crates/xtask -> crates -> project root
    let project_root = Path::new(&manifest_dir).parent().unwrap().parent().unwrap();

    let src_file = project_root.join("crates/ebpf-program/src/main.bpf.c");

    // Create output directory
    let out_dir = if opts.release {
        project_root.join("target/bpf/release")
    } else {
        project_root.join("target/bpf/debug")
    };

    std::fs::create_dir_all(&out_dir)
        .context("failed to create output directory")?;

    let out_file = out_dir.join("ebpf-program.bpf.o");

    // Find clang
    let clang = find_clang();

    // Include path for BPF headers
    let include_dir = project_root.join("crates/ebpf-program/include");
    let include_arg = format!("-I{}", include_dir.display());

    // Build clang arguments
    let args = vec![
        "-target".to_string(),
        "bpf".to_string(),
        "-g".to_string(),
        "-O2".to_string(),
        "-c".to_string(),
        include_arg,
        src_file.to_str().unwrap().to_string(),
        "-o".to_string(),
        out_file.to_str().unwrap().to_string(),
    ];

    println!("Compiling eBPF C program...");
    println!("  Using clang: {}", clang);
    println!("  Source: {}", src_file.display());
    println!("  Output: {}", out_file.display());

    let status = Command::new(&clang)
        .args(&args)
        .status()
        .context("failed to run clang - is it installed?")?;

    if !status.success() {
        anyhow::bail!("clang compilation failed");
    }

    println!("eBPF program compiled successfully!");

    Ok(())
}
