use reqwest;
use serde::Deserialize;
use std::process::Command;

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
        // First check local network interfaces
        if let Ok(status) = check_local_vpn_interfaces() {
            if let VpnStatus::Active = status {
                return VpnStatus::Active;
            }
        }

        // Fall back to remote checks...
        self.check_remote_indicators()
    }

    fn check_remote_indicators(&self) -> VpnStatus {
        // Simplified remote checking logic
        VpnStatus::Inactive
    }
}

fn check_local_vpn_interfaces() -> Result<VpnStatus, std::io::Error> {
    let vpn_keywords = [
        "tun", "tap", "wg", "ppp", "ipsec", "nordlynx", "proton", "mullvad", "vpn",
    ];

    // Try running 'ip a' command (Linux)
    if let Ok(output) = Command::new("ip").arg("a").output() {
        if output.status.success() {
            let interfaces = String::from_utf8_lossy(&output.stdout);
            for line in interfaces.lines() {
                for keyword in &vpn_keywords {
                    if line.to_lowercase().contains(keyword) {
                        return Ok(VpnStatus::Active);
                    }
                }
            }
            return Ok(VpnStatus::Inactive);
        }
    }

    // If 'ip a' fails, try 'ifconfig' (macOS/BSD)
    if let Ok(output) = Command::new("ifconfig").output() {
        if output.status.success() {
            let interfaces = String::from_utf8_lossy(&output.stdout);
            for line in interfaces.lines() {
                for keyword in &vpn_keywords {
                    if line.to_lowercase().contains(keyword) {
                        return Ok(VpnStatus::Active);
                    }
                }
            }
            return Ok(VpnStatus::Inactive);
        }
    }

    // If neither command works, return Unknown
    Ok(VpnStatus::Unknown)
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
