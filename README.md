# vpnc

Privacy-focused, cross-platform network status checker. `vpnc` prints a compact report with date/time, OS, IP, DNS, and VPN detection status.

## Features

- Compact default output with only a few lines
- Cross-platform support for macOS, Linux, and Windows
- Local VPN detection using OS-native signals (interfaces, routes, VPN profiles)
- Minimal public IP lookup via HTTPS (IP only, no enrichment)
- Opt-in remote DNS leak check
- Fully local mode with `--no-public-ip`

## Privacy And Security

- Default public IP lookup uses `https://api.ipify.org` and returns only the IP address.
- Public IP lookup reveals your egress IP to the configured provider. Use `--no-public-ip` to disable all outbound requests.
- DNS leak checking is disabled by default and only runs with `--dns-leak-check`.
- Non-HTTPS public IP URLs are rejected unless `--allow-insecure-url` is explicitly set.
- No ip geolocation, ASN, company, or hostname enrichment is performed.

## Installation

```bash
cargo build --release
```

## Usage

```bash
cargo run
```

Compact output:

```text
Date/Time: 2026-05-24 10:01:00 -04:00
OS: macOS 15.0
IP: local 192.168.1.23, public 203.0.113.10
DNS: 192.168.1.1, 1.1.1.1
VPN Detected: Yes
```

### Flags

- `--verbose` — show evidence and data sources
- `--no-public-ip` — skip public IP lookup (fully local mode)
- `--public-ip-url <url>` — configure the public IP endpoint
- `--dns-leak-check` — run an opt-in remote DNS leak check
- `--allow-insecure-url` — allow non-HTTPS public IP URLs
- `--json` — print machine-readable JSON output

Examples:

```bash
vpnc --no-public-ip
vpnc --verbose
vpnc --dns-leak-check
vpnc --public-ip-url https://ifconfig.me/ip
vpnc --json
```

## VPN Detection

VPN detection uses weighted local signals:

- Strong: connected VPN profile, default route via VPN interface, split-tunnel routes, active WireGuard tunnel
- Weak: VPN-like interface active (requires additional route evidence)

The legacy port-scan heuristic has been removed.

## Limitations

- Browser-only proxies may not be detected as VPN
- Some split-tunnel VPNs may report `Unknown`
- macOS `utun` interfaces can exist for non-VPN system services
- DNS leak checks require external resolver behavior and are best-effort

## License

MIT License
