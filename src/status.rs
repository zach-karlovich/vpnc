use reqwest;
use serde::Deserialize;
use std::process::Command;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
pub struct IpInfo {
    pub ip: String,
    pub loc: String,
    #[allow(dead_code)]
    pub org: String,
    #[allow(dead_code)]
    pub hostname: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub asn: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub company: Option<Company>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Company {
    pub name: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub domain: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub type_: Option<String>,
}

pub enum VpnStatus {
    Active,
    Inactive,
    Unknown,
}

impl IpInfo {
    pub fn detect_vpn(&self) -> VpnStatus {
        // Combine multiple detection methods for more accurate results
        let detection_methods = vec![
            check_active_connections(),
            check_network_interfaces(),
            check_routing_table(),
        ];

        // Count how many methods detect a VPN
        let active_detections = detection_methods.iter()
            .filter(|status| matches!(status, Ok(VpnStatus::Active)))
            .count();

        // If any two methods detect a VPN, we're more confident it's actually active
        if active_detections >= 2 {
            return VpnStatus::Active;
        }

        // If all methods return Inactive, we're confident there's no VPN
        if detection_methods.iter().all(|status| matches!(status, Ok(VpnStatus::Inactive))) {
            return VpnStatus::Inactive;
        }

        VpnStatus::Unknown
    }
}

fn check_active_connections() -> Result<VpnStatus, std::io::Error> {
    // Check active connections using ss or netstat
    if let Ok(output) = Command::new("ss").args(["-tulpn"]).output() {
        let connections = String::from_utf8_lossy(&output.stdout);
        let vpn_ports = ["1194", "443", "1723", "500", "4500", "51820", "1701"];
        
        for port in vpn_ports {
            if connections.contains(port) {
                return Ok(VpnStatus::Active);
            }
        }
    }
    
    Ok(VpnStatus::Inactive)
}

fn check_network_interfaces() -> Result<VpnStatus, std::io::Error> {
    let mut active_interfaces = HashSet::new();
    
    // Check using ip command
    if let Ok(output) = Command::new("ip").args(["link", "show"]).output() {
        let interfaces = String::from_utf8_lossy(&output.stdout);
        for line in interfaces.lines() {
            if line.contains("state UP") {
                if let Some(interface) = line.split(':').next() {
                    active_interfaces.insert(interface.trim().to_string());
                }
            }
        }
    }

    // VPN interface patterns
    let vpn_patterns = [
        "tun", "tap", "wg", "ppp", "ipsec", "nordlynx", 
        "proton", "mullvad", "vpn", "wireguard"
    ];

    // Check if any active interface matches VPN patterns
    for interface in active_interfaces {
        for pattern in vpn_patterns.iter() {
            if interface.to_lowercase().contains(pattern) {
                return Ok(VpnStatus::Active);
            }
        }
    }

    Ok(VpnStatus::Inactive)
}

fn check_routing_table() -> Result<VpnStatus, std::io::Error> {
    // Check routing table for VPN routes
    if let Ok(output) = Command::new("ip").args(["route", "show"]).output() {
        let routes = String::from_utf8_lossy(&output.stdout);
        
        // Look for typical VPN routing patterns
        let vpn_indicators = [
            "tun", "tap", "wg", "ppp", "ipsec",
            "0.0.0.0/1", "128.0.0.0/1",  // Split tunnel indicators
        ];

        for indicator in vpn_indicators.iter() {
            if routes.contains(indicator) {
                return Ok(VpnStatus::Active);
            }
        }
    }

    Ok(VpnStatus::Inactive)
}

pub fn get_ip_info() -> Result<IpInfo, reqwest::Error> {
    let token = std::env::var("IPINFO_TOKEN").unwrap_or_default();
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
        
    let url = if token.is_empty() {
        "https://ipinfo.io/json".to_string()
    } else {
        format!("https://ipinfo.io/json?token={}", token)
    };

    let response = client.get(&url).send()?;
    let info: IpInfo = response.json()?;
    Ok(info)
}
