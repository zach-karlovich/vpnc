use crate::vpn::{VpnSignal, is_vpn_interface};
use std::collections::HashSet;
use std::process::Command;

pub struct LinuxProbe;

impl LinuxProbe {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl super::PlatformProbe for LinuxProbe {
    fn os_info(&self) -> String {
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                    return value.trim_matches('"').to_string();
                }
            }
        }

        "Linux".to_string()
    }

    fn local_ips(&self) -> (Vec<String>, Option<String>) {
        if let Ok(output) = Command::new("ip").args(["-j", "addr"]).output() {
            if output.status.success() {
                return (
                    parse_ip_json_addrs(&String::from_utf8_lossy(&output.stdout)),
                    None,
                );
            }
        }

        match Command::new("ip").args(["-o", "addr"]).output() {
            Ok(output) if output.status.success() => (
                parse_ip_addr_output(&String::from_utf8_lossy(&output.stdout)),
                None,
            ),
            Ok(_) => (vec![], Some("ip addr returned non-zero exit status".to_string())),
            Err(error) => (vec![], Some(format!("ip addr failed: {error}"))),
        }
    }

    fn dns_resolvers(&self) -> (Vec<String>, String) {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            let resolvers = parse_resolv_conf(&content);
            if !resolvers.is_empty() {
                return (resolvers, "/etc/resolv.conf".to_string());
            }
        }

        if let Ok(output) = Command::new("resolvectl").arg("status").output() {
            if output.status.success() {
                let resolvers =
                    parse_resolvectl_status(&String::from_utf8_lossy(&output.stdout));
                if !resolvers.is_empty() {
                    return (resolvers, "resolvectl status".to_string());
                }
            }
        }

        (vec![], "/etc/resolv.conf".to_string())
    }

    fn vpn_signals(&self) -> (Vec<VpnSignal>, Vec<String>) {
        let mut signals = Vec::new();
        let mut errors = Vec::new();

        if let Ok(output) = Command::new("ip").args(["-o", "link"]).output() {
            if output.status.success() {
                for interface in parse_ip_link_interfaces(&String::from_utf8_lossy(&output.stdout)) {
                    signals.push(VpnSignal::VpnInterface { interface });
                }
            } else {
                errors.push("ip link returned non-zero exit status".to_string());
            }
        } else {
            errors.push("ip link unavailable".to_string());
        }

        if let Ok(output) = Command::new("ip").args(["route", "show"]).output() {
            if output.status.success() {
                signals.extend(parse_ip_routes(&String::from_utf8_lossy(&output.stdout)));
            } else {
                errors.push("ip route returned non-zero exit status".to_string());
            }
        }

        if let Ok(output) = Command::new("wg").arg("show").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.lines().any(|line| line.starts_with("interface:")) {
                    signals.push(VpnSignal::WireGuardActive);
                }
            }
        }

        (signals, errors)
    }
}

pub fn parse_ip_json_addrs(output: &str) -> Vec<String> {
    let mut ips = Vec::new();

    let value: serde_json::Value = match serde_json::from_str(output) {
        Ok(value) => value,
        Err(_) => return ips,
    };

    if let Some(interfaces) = value.as_array() {
        for interface in interfaces {
            let name = interface
                .get("ifname")
                .and_then(|value| value.as_str())
                .unwrap_or_default();

            if name == "lo" {
                continue;
            }

            if let Some(addresses) = interface.get("addr_info").and_then(|value| value.as_array())
            {
                for address in addresses {
                    if address.get("family").and_then(|value| value.as_str()) != Some("inet") {
                        continue;
                    }

                    if let Some(local) = address.get("local").and_then(|value| value.as_str()) {
                        ips.push(local.to_string());
                    }
                }
            }
        }
    }

    dedupe(ips)
}

pub fn parse_ip_addr_output(output: &str) -> Vec<String> {
    let mut ips = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        if parts[0] == "1:" || parts[1] == "lo" {
            continue;
        }

        if parts[2] == "inet" {
            if let Some(ip) = parts[3].split('/').next() {
                ips.push(ip.to_string());
            }
        }
    }

    dedupe(ips)
}

pub fn parse_resolv_conf(content: &str) -> Vec<String> {
    let mut resolvers = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("nameserver") {
            let resolver = value.trim();
            if !resolver.is_empty() {
                resolvers.push(resolver.to_string());
            }
        }
    }

    dedupe(resolvers)
}

pub fn parse_resolvectl_status(output: &str) -> Vec<String> {
    let mut resolvers = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("DNS Servers:") {
            for resolver in value.split_whitespace() {
                resolvers.push(resolver.to_string());
            }
        }
    }

    dedupe(resolvers)
}

pub fn parse_ip_link_interfaces(output: &str) -> Vec<String> {
    let mut interfaces = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let name = parts[1].trim_end_matches(':');
        let flags = parts[2];

        if flags.contains("UP") && is_vpn_interface(name) {
            interfaces.push(name.to_string());
        }
    }

    dedupe(interfaces)
}

pub fn parse_ip_routes(output: &str) -> Vec<VpnSignal> {
    let mut signals = Vec::new();
    let mut has_split_lower = false;
    let mut has_split_upper = false;

    for line in output.lines() {
        if line.contains("0.0.0.0/1") {
            has_split_lower = true;
        }
        if line.contains("128.0.0.0/1") {
            has_split_upper = true;
        }

        if line.starts_with("default") {
            if let Some(interface) = line.split_whitespace().last() {
                if is_vpn_interface(interface) {
                    signals.push(VpnSignal::DefaultRouteViaVpn {
                        interface: interface.to_string(),
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
        fs::read_to_string(format!("tests/fixtures/linux/{name}"))
            .unwrap_or_else(|error| panic!("failed to read fixture {name}: {error}"))
    }

    #[test]
    fn parses_ip_addr_output() {
        let ips = parse_ip_addr_output(&fixture("ip_addr.txt"));
        assert!(ips.contains(&"10.0.0.5".to_string()));
    }

    #[test]
    fn parses_resolv_conf() {
        let resolvers = parse_resolv_conf(&fixture("resolv.conf"));
        assert_eq!(resolvers, vec!["127.0.0.53".to_string()]);
    }

    #[test]
    fn parses_vpn_interfaces() {
        let interfaces = parse_ip_link_interfaces(&fixture("ip_link.txt"));
        assert!(interfaces.iter().any(|name| name == "wg0"));
    }

    #[test]
    fn parses_split_tunnel_routes() {
        let signals = parse_ip_routes(&fixture("ip_route_split_tunnel.txt"));
        assert!(signals.iter().any(|signal| matches!(signal, VpnSignal::SplitTunnelRoute)));
    }
}
