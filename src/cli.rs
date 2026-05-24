use clap::Parser;
use std::time::Duration;

pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Parser)]
#[command(
    name = "vpnc",
    version,
    about = "Quick network and VPN status snapshot for your machine",
    long_about = "Print date/time, OS, IP, DNS, and whether a VPN tunnel looks active.\n\
                  VPN detection is best-effort heuristics, not a security guarantee.",
    after_help = "Exit codes:\n  \
                  0  VPN not detected\n  \
                  1  VPN detected\n  \
                  2  Unknown (checks failed or inconclusive)"
)]
pub struct Cli {
    #[arg(long, short, help = "Show evidence and data sources")]
    pub verbose: bool,

    #[arg(long, help = "Skip public IP lookup (fully local mode)")]
    pub no_public_ip: bool,

    #[arg(long, help = "Public IP lookup endpoint (HTTPS only by default)")]
    pub public_ip_url: Option<String>,

    #[arg(long, help = "Run an opt-in remote DNS leak check")]
    pub dns_leak_check: bool,

    #[arg(
        long,
        help = "Allow non-HTTPS public IP URLs (not recommended)"
    )]
    pub allow_insecure_url: bool,

    #[arg(long, help = "Print machine-readable JSON output")]
    pub json: bool,
}

impl Cli {
    pub fn public_ip_url(&self) -> String {
        self.public_ip_url
            .clone()
            .unwrap_or_else(|| crate::net::public_ip::DEFAULT_PUBLIC_IP_URL.to_string())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(DEFAULT_TIMEOUT_SECS)
    }
}
