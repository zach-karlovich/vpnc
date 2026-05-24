use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsInfo {
    pub resolvers: Vec<String>,
    pub source: String,
    pub leak_check: Option<DnsLeakResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsLeakResult {
    pub observed: String,
    pub source: String,
}

pub fn run_dns_leak_check() -> Result<DnsLeakResult, String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if let Ok(output) = Command::new("dig")
            .args(["+short", "whoami.akamai.net", "TXT"])
            .output()
        {
            if output.status.success() {
                let observed = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(|line| line.trim_matches('"').to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                if !observed.is_empty() {
                    return Ok(DnsLeakResult {
                        observed,
                        source: "dig whoami.akamai.net".to_string(),
                    });
                }
            }
        }

        if let Ok(output) = Command::new("nslookup")
            .arg("whoami.akamai.net")
            .output()
        {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );

            for line in combined.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("Address:") {
                    let address = rest.trim();
                    if !address.is_empty() && address != "#53" && address.contains('.') {
                        return Ok(DnsLeakResult {
                            observed: address.to_string(),
                            source: "nslookup whoami.akamai.net".to_string(),
                        });
                    }
                }
            }
        }

        return Err("DNS leak check requires dig or nslookup".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Resolve-DnsName -Name whoami.akamai.net -Type TXT | Select-Object -ExpandProperty Strings",
            ])
            .output()
        {
            if output.status.success() {
                let observed = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !observed.is_empty() {
                    return Ok(DnsLeakResult {
                        observed,
                        source: "Resolve-DnsName whoami.akamai.net".to_string(),
                    });
                }
            }
        }

        return Err("DNS leak check failed on Windows".to_string());
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("DNS leak check is unsupported on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_info_defaults_without_leak_check() {
        let info = DnsInfo {
            resolvers: vec!["192.168.1.1".to_string()],
            source: "system".to_string(),
            leak_check: None,
        };
        assert!(info.leak_check.is_none());
    }
}
