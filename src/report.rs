use crate::cli::Cli;
use crate::dns::{DnsInfo, run_dns_leak_check};
use crate::net::public_ip;
use crate::platform::{self, PlatformProbe};
use crate::vpn::{VpnDetection, VpnStatus, evaluate_vpn};
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

        print_field("Date/Time", &self.datetime);
        print_field("OS", &self.os);
        println!();
        print_field("Local IP", &self.format_local_ip_line());
        print_field("Public IP", &self.format_public_ip_line());
        print_field("DNS", &self.format_dns_line());
        print_field("VPN", self.format_vpn_status());
        println!();

        if verbose {
            if let Some(source) = &self.public_ip_source {
                print_field("IP source", source);
            } else if self.public_ip.is_none() && self.public_ip_error.is_none() {
                print_field("IP source", "local interfaces only (public lookup skipped)");
            }

            if let Some(error) = &self.public_ip_error {
                print_field("IP error", error);
            }

            print_field("DNS source", &self.dns.source);

            if !self.vpn.signals.is_empty() {
                print_field("VPN evidence", &self.format_vpn_evidence());
            }

            if !self.vpn.errors.is_empty() {
                print_field("VPN errors", &self.vpn.errors.join("; "));
            }

            if let Some(leak) = &self.dns.leak_check {
                print_field("DNS leak check", &leak.observed);
                print_field("DNS leak source", &leak.source);
            }
        } else if let Some(leak) = &self.dns.leak_check {
            print_field("DNS leak check", &leak.observed);
        }
    }

    fn format_local_ip_line(&self) -> String {
        if self.local_ips.is_empty() {
            "unavailable".to_string()
        } else {
            self.local_ips.join(", ")
        }
    }

    fn format_public_ip_line(&self) -> String {
        match &self.public_ip {
            Some(public) => public.clone(),
            None if self.public_ip_error.is_some() => "unavailable".to_string(),
            None if self.public_ip_source.is_none() => "skipped (--no-public-ip)".to_string(),
            None => "unavailable".to_string(),
        }
    }

    fn format_vpn_evidence(&self) -> String {
        self.vpn
            .signals
            .iter()
            .map(|signal| signal.description())
            .collect::<Vec<_>>()
            .join("; ")
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
            VpnStatus::Detected => "Detected",
            VpnStatus::NotDetected => "Not detected",
            VpnStatus::Unknown => "Unknown",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self.vpn.status {
            VpnStatus::NotDetected => 0,
            VpnStatus::Detected => 1,
            VpnStatus::Unknown => 2,
        }
    }
}

fn print_field(label: &str, value: &str) {
    println!("{label:<11} {value}");
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
    fn compact_output_fields_are_clear() {
        let report = sample_report();
        assert_eq!(report.format_local_ip_line(), "192.168.1.23");
        assert_eq!(report.format_public_ip_line(), "203.0.113.10");
        assert_eq!(report.format_dns_line(), "192.168.1.1, 1.1.1.1");
        assert_eq!(report.format_vpn_status(), "Detected");
    }

    #[test]
    fn json_output_is_valid() {
        let report = sample_report();
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.contains("\"datetime\""));
        assert!(json.contains("\"vpn\""));
    }

    #[test]
    fn exit_code_detected_is_one() {
        assert_eq!(sample_report().exit_code(), 1);
    }

    #[test]
    fn exit_code_not_detected_is_zero() {
        let mut report = sample_report();
        report.vpn.status = VpnStatus::NotDetected;
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn exit_code_unknown_is_two() {
        let mut report = sample_report();
        report.vpn.status = VpnStatus::Unknown;
        assert_eq!(report.exit_code(), 2);
    }
}
