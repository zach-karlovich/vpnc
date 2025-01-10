# IP Information Checker

A simple Rust application that fetches and displays information about your IP address using the ipinfo.io API.

## Features
* Retrieves current IP address
* Shows geographical location
* Placeholder for VPN detection (coming soon)

## Prerequisites
------------
* Rust (latest stable version)
* Cargo package manager

## Dependencies
* reqwest: For making HTTP requests
* serde: For JSON deserialization

## Building
To build the project, run:
```bash
cargo build
```

## Running
To run the application:
```bash
cargo run
```
## Example Output
```bash
IP Address: 203.0.113.1
Location: 40.7128,-74.0060
VPN Service: Not checked
```

## License
This project is open source and available under the MIT License.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.