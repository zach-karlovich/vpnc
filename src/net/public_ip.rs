use std::net::IpAddr;
use std::time::Duration;

pub const DEFAULT_PUBLIC_IP_URL: &str = "https://api.ipify.org";
const MAX_PUBLIC_IP_BODY_LEN: usize = 128;

pub fn validate_public_ip_url(url: &str, allow_insecure: bool) -> Result<(), String> {
    let parsed =
        reqwest::Url::parse(url).map_err(|error| format!("invalid public IP URL: {error}"))?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure => Ok(()),
        "http" => Err("public IP URL must use HTTPS unless --allow-insecure-url is set".to_string()),
        other => Err(format!("unsupported URL scheme: {other}")),
    }
}

pub fn fetch_public_ip(
    url: &str,
    allow_insecure: bool,
    timeout: Duration,
) -> Result<(String, String), String> {
    validate_public_ip_url(url, allow_insecure)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(allow_insecure)
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;

    let response = client
        .get(url)
        .send()
        .map_err(|error| format!("public IP request failed: {error}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "public IP request returned status {}",
            response.status()
        ));
    }

    let body = response
        .text()
        .map_err(|error| format!("failed to read public IP response: {error}"))?
        .trim()
        .to_string();

    let ip = parse_public_ip_body(&body)?;

    Ok((ip, url.to_string()))
}

pub fn parse_public_ip_body(body: &str) -> Result<String, String> {
    if body.len() > MAX_PUBLIC_IP_BODY_LEN {
        return Err(format!(
            "public IP response exceeds {MAX_PUBLIC_IP_BODY_LEN} bytes"
        ));
    }

    let candidate = body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "public IP response was empty".to_string())?;

    candidate
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| format!("public IP response is not a valid IP address: {candidate}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_http_by_default() {
        let result = validate_public_ip_url("http://example.com", false);
        assert!(result.is_err());
    }

    #[test]
    fn allows_http_when_insecure_enabled() {
        let result = validate_public_ip_url("http://example.com", true);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_https() {
        let result = validate_public_ip_url("https://api.ipify.org", false);
        assert!(result.is_ok());
    }

    #[test]
    fn parses_ipv4_response() {
        assert_eq!(
            parse_public_ip_body("203.0.113.10\n").unwrap(),
            "203.0.113.10"
        );
    }

    #[test]
    fn parses_ipv6_response() {
        assert_eq!(
            parse_public_ip_body("2001:db8::1").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn rejects_html_response() {
        assert!(parse_public_ip_body("<html>not an ip</html>").is_err());
    }

    #[test]
    fn rejects_oversized_response() {
        let body = "1".repeat(MAX_PUBLIC_IP_BODY_LEN + 1);
        assert!(parse_public_ip_body(&body).is_err());
    }
}
