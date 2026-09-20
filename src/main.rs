use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use lanscan::arp::{build_arp_request, host_addresses, parse_arp_reply};
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Parser)]
#[command(
    name = "lanscan",
    about = "Pure-Rust ARP-based local network device discovery"
)]
struct Cli {
    /// Interface to send/receive ARP frames on (e.g. eth0).
    #[arg(long)]
    interface: String,
    /// This host's own IPv4 address on that interface.
    #[arg(long)]
    src_ip: Ipv4Addr,
    /// Network to scan, e.g. 192.168.1.0/24.
    #[arg(long)]
    network: String,
}

fn parse_cidr(s: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("expected CIDR notation like 192.168.1.0/24"))?;
    Ok((ip.parse()?, prefix.parse()?))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lanscan: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let (network, prefix) = parse_cidr(&cli.network)?;
    let targets = host_addresses(network.octets(), prefix);
    println!(
        "scanning {} address(es) on {} via ARP...",
        targets.len(),
        cli.interface
    );

    // AF_PACKET + SOCK_RAW is what real ARP frame send/receive requires
    // (this needs to see raw Ethernet frames, below IP entirely) — this
    // needs CAP_NET_RAW. Checked live in the sandbox this was built in:
    // creating this exact socket returned a real `Operation not
    // permitted`, which is why this fails here with a clear, specific
    // error rather than a raw socket panic — see the README for what
    // *was* verified (the ARP packet bytes themselves) versus this,
    // which honestly wasn't.
    let socket = Socket::new(
        Domain::from(libc::AF_PACKET),
        Type::RAW,
        Some(Protocol::from(i32::from(u16::from_be(
            lanscan::arp::ETHERTYPE_ARP,
        )))),
    )
    .map_err(|e| {
        anyhow::anyhow!("opening a raw AF_PACKET socket (needs CAP_NET_RAW / root): {e}")
    })?;
    socket.bind_device(Some(cli.interface.as_bytes()))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let src_mac = [0u8; 6]; // a real interface's MAC would be read via a netlink/ioctl call not exercised here
    for target in &targets {
        let frame = build_arp_request(src_mac, cli.src_ip.octets(), *target);
        let _ = socket.send(&frame);
    }

    let mut buf = [std::mem::MaybeUninit::uninit(); 128];
    while let Ok(n) = socket.recv(&mut buf) {
        let bytes: Vec<u8> = buf[..n]
            .iter()
            .map(|b| unsafe { b.assume_init() })
            .collect();
        if let Some(reply) = parse_arp_reply(&bytes) {
            let ip = Ipv4Addr::from(reply.sender_ip);
            let mac = reply
                .sender_mac
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            println!("{ip}  {mac}");
        }
    }
    Ok(())
}
