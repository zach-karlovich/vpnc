use std::time::Duration;

pub const DEFAULT_PUBLIC_IP_URL: &str = "https://api.ipify.org";

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

    if body.is_empty() {
        return Err("public IP response was empty".to_string());
    }

    Ok((body, url.to_string()))
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
}
