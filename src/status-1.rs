use reqwest;

// Serde dependencies
use serde::Deserialize;

// Struct to represent IP info
#[derive(Debug, Deserialize)]
pub struct IpInfo {
    pub ip: String,
    pub loc: String,
}

// Function to fetch IP information from ipinfo.io
pub fn get_ip_info() -> Result<IpInfo, reqwest::Error> {
    let response = reqwest::blocking::get("https://ipinfo.io/json")?;
    let info: IpInfo = response.json()?;
    Ok(info)
}
