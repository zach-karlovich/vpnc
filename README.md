# VPN Checker (vpnc)
vpnc is a lightweight and simple Rust application that fetches information about your IP address using the ipinfo.io API and detects VPN activity. It is designed for privacy-conscious users who want quick insights into their current network status.

## Features
Retrieves and displays:
- Current IP address
- Geographical location (latitude and longitude)
- Organization and hostname details (if available)
- Detects VPN usage through:
  - Local network interface checks
  - Simplified remote checks
- Configurable via IPINFO_TOKEN for extended functionality.

## Installation
### Prerequisites
Rust: Ensure you have the latest stable version of Rust and Cargo installed. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
### Dependencies
The following dependencies are used:

- reqwest: For making HTTP requests.
- serde: For JSON deserialization.

Install them automatically during the build process.

### Build
To build the application: 
```bash
cargo build --release 

```
This will produce an optimized executable in the target/release directory.

### Usage
#### Set Up API Token (Optional)
If you have an API token from ipinfo.io, set it in your environment:
```bash
export IPINFO_TOKEN=<your_api_token>
```

### Run the Application
Execute the application using Cargo:
```bash
cargo run
```
Or use the compiled binary:
```bash
./target/release/vpnc
```

### Example Output
```bash
IP Address: 203.0.113.1
Location: 40.7128,-74.0060
VPN Status: Active
```

### VPN Detection Logic
#### Local Interface Check:
Scans local network interfaces for keywords (tun, tap, wg, etc.) to detect active VPN tunnels.

#### Remote Indicator Check:
Uses basic heuristics for remote detection of VPNs when local methods fail.

### License
This project is open source and available under the MIT License.

### Contributing
Contributions are welcome! If you have ideas, bug reports, or feature requests, feel free to open an issue or submit a pull request.

### Development
To contribute:
1. Fork the repository.
2. Create a feature branch:
```bash
git checkout -b feature/your-feature
```
3. Test your changes thoroughly before opening a pull request.

### Feedback
For questions or feedback, open an issue in the repository or contact the project maintainer.
