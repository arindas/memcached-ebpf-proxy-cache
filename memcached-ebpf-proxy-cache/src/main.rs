#[allow(unused)]
use anyhow::Context;
#[allow(unused)]
use aya::maps::ProgramArray;
#[allow(unused)]
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
#[allow(unused)]
use memcached_ebpf_proxy_cache_common::CallableProgXdp;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/memcached-ebpf-proxy-cache"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/memcached-ebpf-proxy-cache"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mut map_callable_progs_xdp =
        ProgramArray::try_from(bpf.take_map("MAP_CALLABLE_PROGS_XDP").unwrap())?;

    let mut num_callable_xdp_programs_loaded = 0;

    for callable_prog_xdp in CallableProgXdp::variants() {
        let xdp_program: Option<&mut Xdp> = bpf
            .program_mut(callable_prog_xdp.as_ref())
            .and_then(|x| x.try_into().ok());

        let xdp_fd = xdp_program
            .and_then(|x| x.load().ok().and(Some(x)))
            .and_then(|x| x.fd().ok());

        if let Some(xdp_fd) = xdp_fd {
            info!("Loading program: {}", callable_prog_xdp.as_ref());
            map_callable_progs_xdp.set(callable_prog_xdp as u32, xdp_fd, 0)?;
            num_callable_xdp_programs_loaded += 1;
        }
    }

    info!(
        "Num callable XDP programs loaded: {}",
        num_callable_xdp_programs_loaded
    );

    let rx_filter_program: &mut Xdp = bpf.program_mut("rx_filter").unwrap().try_into()?;
    rx_filter_program.load()?;
    rx_filter_program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
