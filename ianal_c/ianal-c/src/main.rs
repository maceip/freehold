use aya::{include_bytes_aligned, maps::HashMap, programs::{Xdp, XdpFlags}, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let opt = Opt::parse();

    // 1. Load the eBPF object file (compiled from C with clang)
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpf/debug/ianal-c.bpf.o"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpf/release/ianal-c.bpf.o"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // 2. Load and attach the XDP program
    let program: &mut Xdp = bpf.program_mut("specular_ingress").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;

    info!("Attached specular_ingress to {}", opt.iface);

    // 3. Map Access Examples

    // Access 'registrations'
    let registrations: HashMap<_, u16, [u8; 48]> = HashMap::try_from(bpf.map_mut("registrations").unwrap())?;
    // Note: [u8; 48] is an approximation of the struct size (u64*4 + u32*2 + u16 + pad).
    // In production, generate bindings using `aya-tool`.

    info!("Maps initialized. Packet processing is active in kernel.");
    info!("Any UDP packet to an unclaimed port will register the sender (if quota allows).");

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
