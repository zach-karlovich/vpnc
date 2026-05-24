use crate::vpn::{VpnSignal, is_vpn_interface};
use std::process::Command;

pub struct WindowsProbe;

impl WindowsProbe {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl super::PlatformProbe for WindowsProbe {
    fn os_info(&self) -> String {
        run_powershell("(Get-CimInstance Win32_OperatingSystem).Caption")
            .unwrap_or_else(|| "Windows".to_string())
    }

    fn local_ips(&self) -> (Vec<String>, Option<String>) {
        match run_powershell(
            "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -ExpandProperty IPAddress",
        ) {
            Some(output) => (parse_line_list(&output), None),
            None => (
                vec![],
                Some("Get-NetIPAddress unavailable".to_string()),
            ),
        }
    }

    fn dns_resolvers(&self) -> (Vec<String>, String) {
        match run_powershell(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses",
        ) {
            Some(output) => (parse_line_list(&output), "Get-DnsClientServerAddress".to_string()),
            None => (vec![], "Get-DnsClientServerAddress (unavailable)".to_string()),
        }
    }

    fn vpn_signals(&self) -> (Vec<VpnSignal>, Vec<String>) {
        let mut signals = Vec::new();
        let mut errors = Vec::new();

        if let Some(output) = run_powershell(
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name",
        ) {
            for interface in parse_line_list(&output) {
                if is_vpn_interface(&interface) {
                    signals.push(VpnSignal::VpnInterface { interface });
                }
            }
        } else {
            errors.push("Get-NetAdapter unavailable".to_string());
        }

        if let Some(output) = run_powershell(
            "Get-VpnConnection | Where-Object { $_.ConnectionStatus -eq 'Connected' } | Select-Object -ExpandProperty Name",
        ) {
            for name in parse_line_list(&output) {
                signals.push(VpnSignal::VpnProfileConnected { name });
            }
        }

        if let Some(output) = run_powershell(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty InterfaceAlias",
        ) {
            for interface in parse_line_list(&output) {
                if is_vpn_interface(&interface) {
                    signals.push(VpnSignal::DefaultRouteViaVpn { interface });
                }
            }
        }

        if let Some(output) = run_powershell(
            "Get-NetRoute | Select-Object -ExpandProperty DestinationPrefix",
        ) {
            signals.extend(parse_windows_route_prefixes(&output));
        }

        (signals, errors)
    }
}

fn run_powershell(command: &str) -> Option<String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", command])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

pub fn parse_line_list(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn parse_windows_route_prefixes(output: &str) -> Vec<VpnSignal> {
    let mut has_split_lower = false;
    let mut has_split_upper = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed == "0.0.0.0/1" {
            has_split_lower = true;
        }
        if trimmed == "128.0.0.0/1" {
            has_split_upper = true;
        }
    }

    if has_split_lower && has_split_upper {
        vec![VpnSignal::SplitTunnelRoute]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_line_list_output() {
        let values = parse_line_list("Wintun\r\nEthernet\r\n");
        assert_eq!(values, vec!["Wintun".to_string(), "Ethernet".to_string()]);
    }

    #[test]
    fn detects_split_tunnel_prefixes() {
        let signals = parse_windows_route_prefixes("0.0.0.0/1\r\n128.0.0.0/1\r\n");
        assert!(signals.iter().any(|signal| matches!(signal, VpnSignal::SplitTunnelRoute)));
    }
}
