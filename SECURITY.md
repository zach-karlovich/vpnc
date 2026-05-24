# Security Policy

## What vpnc Is

`vpnc` is a small cross-platform CLI that prints a quick snapshot of date/time, OS, local and public IP, configured DNS resolvers, and whether a VPN-like tunnel appears active on the machine. It is a **diagnostic helper**, not a VPN client, firewall, or security audit tool.

## What vpnc Is Not

- Not a guarantee of privacy, anonymity, or "no DNS leak"
- Not suitable for compliance, threat modeling, or legal attestation
- Not a substitute for your VPN provider's own status or leak-test tools

VPN detection uses local heuristics (interfaces, routes, OS VPN profiles) and can report **Yes**, **No**, or **Unknown** incorrectly.

## Reporting a Vulnerability

If you believe you found a security issue in `vpnc` itself (for example: command injection, unsafe remote URL handling, or memory safety bugs in this codebase), please report it privately:

1. Open a [GitHub Security Advisory](https://github.com/zach-karlovich/vpnc/security/advisories/new) (preferred), or
2. Contact the repository owner via GitHub with details.

Include:

- `vpnc` version or commit SHA
- Operating system
- Steps to reproduce
- Impact you believe it has

We will acknowledge reports as soon as we can and aim to address confirmed issues in `main`.

## Out of Scope

The following are limitations of the tool, not security vulnerabilities:

- False positive or false negative VPN detection
- Behavior of third-party services used when you opt in (for example `https://api.ipify.org` for public IP, or DNS queries for `--dns-leak-check`)
- Missing detection of browser proxies, corporate VPN edge cases, or split-tunnel setups
- Platform differences when required OS tools are unavailable

## Supported Versions

Security fixes apply to the latest commit on `main`. There are no long-term release branches at this time.
