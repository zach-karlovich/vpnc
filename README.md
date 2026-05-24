# vpnc

![CI](https://github.com/zach-karlovich/vpnc/actions/workflows/ci.yml/badge.svg)

A small cross-platform CLI for a quick snapshot of date/time, OS, IPs, DNS, and whether a VPN tunnel looks active on your machine.

## Disclaimer

- **Best-effort only** — VPN detection uses local heuristics and may be wrong.
- **Not a security product** — do not use for compliance, threat modeling, or as proof that you are "safe" or "leak-free."
- **Default run uses the network** — public IP lookup contacts a third-party HTTPS endpoint unless you pass `--no-public-ip`.
- **DNS leak check is optional** — only runs with `--dns-leak-check` and is not a full leak test.

## Features

- Compact default output with only a few lines
- Cross-platform support for macOS, Linux, and Windows
- Local VPN detection using OS-native signals (interfaces, routes, VPN profiles)
- Minimal public IP lookup via HTTPS (IP only, no enrichment)
- Opt-in remote DNS leak check
- Fully local mode with `--no-public-ip`

## Privacy Notes

- Default public IP lookup uses `https://api.ipify.org` and returns only the IP address.
- Public IP lookup reveals your egress IP to the configured provider. Use `--no-public-ip` to disable all outbound requests.
- DNS leak checking is disabled by default and only runs with `--dns-leak-check`.
- Non-HTTPS public IP URLs are rejected unless `--allow-insecure-url` is explicitly set.
- No ip geolocation, ASN, company, or hostname enrichment is performed.

## Installation

Requires [Rust](https://rustup.rs/) and Cargo.

```bash
cargo install --path .
```

Ensure `~/.cargo/bin` is on your `PATH`, then run `vpnc`.

To build without installing:

```bash
cargo build --release
./target/release/vpnc
```

## Usage

```bash
vpnc
```

Compact output:

```text
Date/Time:  2026-05-24 10:01:00 -04:00
OS:         macOS 15.0

Local IP:   192.168.1.23
Public IP:  203.0.113.10
DNS:        192.168.1.1, 1.1.1.1
VPN:        Detected

```

### Flags

- `-h`, `--help` — show usage and exit codes
- `-V`, `--version` — show version
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

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | VPN not detected |
| `1` | VPN detected |
| `2` | Unknown (checks failed or inconclusive) |

Example:

```bash
vpnc --no-public-ip || echo "VPN may be active or status unknown (exit $?)"
```

## VPN Detection

VPN detection uses weighted local signals:

- Strong: connected VPN profile, default route via VPN interface, split-tunnel routes, active WireGuard tunnel
- Weak: VPN-like interface active (requires additional route evidence)

## Limitations

- Browser-only proxies may not be detected as VPN
- Some split-tunnel VPNs may report `Unknown`
- macOS `utun` interfaces can exist for non-VPN system services
- DNS leak checks require external resolver behavior and are best-effort

See [SECURITY.md](SECURITY.md) for reporting security issues and out-of-scope items.

## License

MIT License. The license file is in the repository.
