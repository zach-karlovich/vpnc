use crate::vpn::{VpnSignal, is_vpn_interface};
use std::collections::HashSet;
use std::process::Command;

pub struct MacProbe;

impl MacProbe {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl super::PlatformProbe for MacProbe {
    fn os_info(&self) -> String {
        let version = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        format!("macOS {version}")
    }

    fn local_ips(&self) -> (Vec<String>, Option<String>) {
        match Command::new("ifconfig").output() {
            Ok(output) if output.status.success() => {
                (parse_ifconfig_local_ips(&String::from_utf8_lossy(&output.stdout)), None)
            }
            Ok(_) => (vec![], Some("ifconfig returned non-zero exit status".to_string())),
            Err(error) => (vec![], Some(format!("ifconfig failed: {error}"))),
        }
    }

    fn dns_resolvers(&self) -> (Vec<String>, String) {
        match Command::new("scutil").arg("--dns").output() {
            Ok(output) if output.status.success() => {
                let resolvers =
                    parse_scutil_dns(&String::from_utf8_lossy(&output.stdout));
                (resolvers, "scutil --dns".to_string())
            }
            Ok(_) => (vec![], "scutil --dns (failed)".to_string()),
            Err(_) => (vec![], "scutil --dns (unavailable)".to_string()),
        }
    }

    fn vpn_signals(&self) -> (Vec<VpnSignal>, Vec<String>) {
        let mut signals = Vec::new();
        let mut errors = Vec::new();

        if let Ok(output) = Command::new("ifconfig").output() {
            if output.status.success() {
                for interface in
                    parse_ifconfig_vpn_interfaces(&String::from_utf8_lossy(&output.stdout))
                {
                    signals.push(VpnSignal::VpnInterface { interface });
                }
            } else {
                errors.push("ifconfig returned non-zero exit status".to_string());
            }
        } else {
            errors.push("ifconfig unavailable".to_string());
        }

        if let Ok(output) = Command::new("scutil").arg("--nc").arg("list").output() {
            if output.status.success() {
                for name in parse_scutil_nc_connected(&String::from_utf8_lossy(&output.stdout)) {
                    signals.push(VpnSignal::VpnProfileConnected { name });
                }
            } else {
                errors.push("scutil --nc list returned non-zero exit status".to_string());
            }
        }

        if let Ok(output) = Command::new("netstat").args(["-rn"]).output() {
            if output.status.success() {
                let route_signals =
                    parse_netstat_routes(&String::from_utf8_lossy(&output.stdout));
                signals.extend(route_signals);
            } else {
                errors.push("netstat -rn returned non-zero exit status".to_string());
            }
        }

        if let Ok(output) = Command::new("route").args(["-n", "get", "default"]).output() {
            if output.status.success() {
                if let Some(interface) =
                    parse_route_default_interface(&String::from_utf8_lossy(&output.stdout))
                {
                    if is_vpn_interface(&interface) {
                        signals.push(VpnSignal::DefaultRouteViaVpn { interface });
                    }
                }
            }
        }

        (signals, errors)
    }
}

pub fn parse_ifconfig_local_ips(output: &str) -> Vec<String> {
    let mut ips = Vec::new();
    let mut current_up = false;
    let mut current_loopback = false;

    for line in output.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') {
            current_up = line.contains("UP") && line.contains("RUNNING");
            current_loopback = line.starts_with("lo0:");
            continue;
        }

        if !current_up || current_loopback {
            continue;
        }

        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(ip) = rest.split_whitespace().next() {
                if ip != "127.0.0.1" && ip.contains('.') {
                    ips.push(ip.to_string());
                }
            }
        }
    }

    dedupe(ips)
}

pub fn parse_ifconfig_vpn_interfaces(output: &str) -> Vec<String> {
    let mut interfaces = Vec::new();
    let mut current_name = None;
    let mut current_up = false;

    for line in output.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') {
            current_name = line.split(':').next().map(str::trim).map(str::to_string);
            current_up = line.contains("UP") && line.contains("RUNNING");
            continue;
        }

        if !current_up {
            continue;
        }

        if line.trim().starts_with("inet ") {
            if let Some(name) = current_name.as_deref() {
                if is_vpn_interface(name) {
                    interfaces.push(name.to_string());
                }
            }
        }
    }

    dedupe(interfaces)
}

pub fn parse_scutil_dns(output: &str) -> Vec<String> {
    let mut resolvers = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver[") {
            if let Some((_, value)) = trimmed.split_once(" : ") {
                let resolver = value.trim();
                if !resolver.is_empty() {
                    resolvers.push(resolver.to_string());
                }
            }
        }
    }

    dedupe(resolvers)
}

pub fn parse_scutil_nc_connected(output: &str) -> Vec<String> {
    let mut names = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("(Connected)") {
            if let Some(name) = trimmed.split('"').nth(1) {
                names.push(name.to_string());
            }
        }
    }

    names
}

pub fn parse_netstat_routes(output: &str) -> Vec<VpnSignal> {
    let mut signals = Vec::new();
    let mut has_split_lower = false;
    let mut has_split_upper = false;

    for line in output.lines().map(str::trim) {
        if line.starts_with("0.0.0.0/1") {
            has_split_lower = true;
        }
        if line.starts_with("128.0.0.0/1") {
            has_split_upper = true;
        }

        if line.starts_with("default") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(interface) = parts.last() {
                if is_vpn_interface(interface) {
                    signals.push(VpnSignal::DefaultRouteViaVpn {
                        interface: (*interface).to_string(),
                    });
                }
            }
        }
    }

    if has_split_lower && has_split_upper {
        signals.push(VpnSignal::SplitTunnelRoute);
    }

    signals
}

pub fn parse_route_default_interface(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(interface) = trimmed.strip_prefix("interface:") {
            let value = interface.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(name: &str) -> String {
        fs::read_to_string(format!("tests/fixtures/macos/{name}"))
            .unwrap_or_else(|error| panic!("failed to read fixture {name}: {error}"))
    }

    #[test]
    fn parses_local_ips_without_vpn() {
        let ips = parse_ifconfig_local_ips(&fixture("ifconfig_no_vpn.txt"));
        assert!(ips.contains(&"192.168.1.23".to_string()));
        assert!(!ips.contains(&"127.0.0.1".to_string()));
    }

    #[test]
    fn parses_vpn_interfaces_when_active() {
        let interfaces = parse_ifconfig_vpn_interfaces(&fixture("ifconfig_vpn_active.txt"));
        assert!(interfaces.iter().any(|name| name.starts_with("utun")));
    }

    #[test]
    fn parses_scutil_dns_resolvers() {
        let resolvers = parse_scutil_dns(&fixture("scutil_dns.txt"));
        assert_eq!(
            resolvers,
            vec![
                "192.168.1.1".to_string(),
                "1.1.1.1".to_string(),
                "fd7a:115c:a1e0::53".to_string(),
            ]
        );
    }

    #[test]
    fn parses_connected_vpn_profile() {
        let profiles = parse_scutil_nc_connected(&fixture("scutil_nc_connected.txt"));
        assert_eq!(profiles, vec!["Office VPN".to_string()]);
    }

    #[test]
    fn detects_split_tunnel_routes() {
        let signals = parse_netstat_routes(&fixture("netstat_rn_split_tunnel.txt"));
        assert!(signals.iter().any(|signal| matches!(signal, VpnSignal::SplitTunnelRoute)));
    }

    #[test]
    fn detects_default_route_via_vpn_interface() {
        let interface = parse_route_default_interface(&fixture("route_default_utun.txt"));
        assert_eq!(interface, Some("utun4".to_string()));
    }
}
