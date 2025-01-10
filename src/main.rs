mod status;
use status::VpnStatus;

// Main function
fn main() {
    match status::get_ip_info() {
        Ok(info) => {
            println!("IP Address: {}", info.ip);
            println!("Location: {}", info.loc);
            
            // Check VPN status
            match info.detect_vpn() {
                VpnStatus::Active => println!("VPN Status: ACTIVE"),
                VpnStatus::Inactive => println!("VPN Status: INACTIVE"),
                VpnStatus::Unknown => println!("VPN Status: UNKNOWN - Could not determine"),
            }
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}
