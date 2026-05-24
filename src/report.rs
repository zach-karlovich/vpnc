use crate::cli::Cli;
use crate::dns::{DnsInfo, run_dns_leak_check};
use crate::net::public_ip;
use crate::platform::{self, PlatformProbe};
use crate::vpn::{VpnDetection, evaluate_vpn};
use chrono::Local;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    pub datetime: String,
    pub os: String,
    pub local_ips: Vec<String>,
    pub public_ip: Option<String>,
    pub public_ip_source: Option<String>,
    pub public_ip_error: Option<String>,
    pub dns: DnsInfo,
    pub vpn: VpnDetection,
}

impl StatusReport {
    pub fn build(cli: &Cli) -> Self {
        let probe = platform::probe();
        let (local_ips, _local_ip_error) = probe.local_ips();
        let (resolvers, dns_source) = probe.dns_resolvers();
        let (vpn_signals, vpn_errors) = probe.vpn_signals();

        let mut dns = DnsInfo {
            resolvers,
            source: dns_source,
            leak_check: None,
        };

        if cli.dns_leak_check {
            dns.leak_check = match run_dns_leak_check() {
                Ok(result) => Some(result),
                Err(error) => Some(crate::dns::DnsLeakResult {
                    observed: format!("Unavailable ({error})"),
                    source: "remote DNS leak check".to_string(),
                }),
            };
        }

        let (public_ip, public_ip_source, public_ip_error) = if cli.no_public_ip {
            (None, None, None)
        } else {
            match public_ip::fetch_public_ip(
                &cli.public_ip_url(),
                cli.allow_insecure_url,
                cli.timeout(),
            ) {
                Ok((ip, source)) => (Some(ip), Some(source), None),
                Err(error) => (None, Some(cli.public_ip_url()), Some(error)),
            }
        };

        let vpn = evaluate_vpn(vpn_signals, vpn_errors);

        Self {
            datetime: Local::now().format("%Y-%m-%d %H:%M:%S %:z").to_string(),
            os: probe.os_info(),
            local_ips,
            public_ip,
            public_ip_source,
            public_ip_error,
            dns,
            vpn,
        }
    }

    pub fn print_compact(&self, verbose: bool, json: bool) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
            );
            return;
        }

        println!("Date/Time: {}", self.datetime);
        println!("OS: {}", self.os);
        println!("IP: {}", self.format_ip_line());
        println!("DNS: {}", self.format_dns_line());
        println!("VPN Detected: {}", self.format_vpn_status());

        if verbose {
            if let Some(source) = &self.public_ip_source {
                println!("IP Source: public endpoint {source}");
            } else if self.public_ip.is_none() && self.public_ip_error.is_none() {
                println!("IP Source: local interfaces only");
            }

            if let Some(error) = &self.public_ip_error {
                println!("IP Error: {error}");
            }

            println!("DNS Source: {}", self.dns.source);

            if !self.vpn.signals.is_empty() {
                let reasons = self
                    .vpn
                    .signals
                    .iter()
                    .map(|signal| signal.description())
                    .collect::<Vec<_>>()
                    .join("; ");
                println!("VPN Reasons: {reasons}");
            }

            if !self.vpn.errors.is_empty() {
                println!("VPN Errors: {}", self.vpn.errors.join("; "));
            }

            if let Some(leak) = &self.dns.leak_check {
                println!("DNS Leak Check: resolver observed as {}", leak.observed);
                println!("DNS Leak Source: {}", leak.source);
            }
        } else if let Some(leak) = &self.dns.leak_check {
            println!("DNS Leak Check: resolver observed as {}", leak.observed);
        }
    }

    fn format_ip_line(&self) -> String {
        let local = if self.local_ips.is_empty() {
            "unavailable".to_string()
        } else {
            self.local_ips.join(", ")
        };

        match &self.public_ip {
            Some(public) => format!("local {local}, public {public}"),
            None if self.public_ip_error.is_some() => {
                format!("local {local}, public unavailable")
            }
            None => format!("local {local}"),
        }
    }

    fn format_dns_line(&self) -> String {
        if self.dns.resolvers.is_empty() {
            "unavailable".to_string()
        } else {
            self.dns.resolvers.join(", ")
        }
    }

    fn format_vpn_status(&self) -> &'static str {
        match self.vpn.status {
            crate::vpn::VpnStatus::Detected => "Yes",
            crate::vpn::VpnStatus::NotDetected => "No",
            crate::vpn::VpnStatus::Unknown => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsInfo;
    use crate::vpn::{VpnDetection, VpnSignal, VpnStatus};

    fn sample_report() -> StatusReport {
        StatusReport {
            datetime: "2026-05-24 10:01:00 -0400".to_string(),
            os: "macOS 15.0".to_string(),
            local_ips: vec!["192.168.1.23".to_string()],
            public_ip: Some("203.0.113.10".to_string()),
            public_ip_source: Some("https://api.ipify.org".to_string()),
            public_ip_error: None,
            dns: DnsInfo {
                resolvers: vec!["192.168.1.1".to_string(), "1.1.1.1".to_string()],
                source: "scutil --dns".to_string(),
                leak_check: None,
            },
            vpn: VpnDetection {
                status: VpnStatus::Detected,
                signals: vec![VpnSignal::SplitTunnelRoute],
                errors: vec![],
            },
        }
    }

    #[test]
    fn compact_output_has_five_core_lines() {
        let report = sample_report();
        assert_eq!(report.format_ip_line(), "local 192.168.1.23, public 203.0.113.10");
        assert_eq!(report.format_dns_line(), "192.168.1.1, 1.1.1.1");
        assert_eq!(report.format_vpn_status(), "Yes");
    }

    #[test]
    fn json_output_is_valid() {
        let report = sample_report();
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.contains("\"datetime\""));
        assert!(json.contains("\"vpn\""));
    }
}
