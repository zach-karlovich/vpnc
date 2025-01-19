mod status;
use status::VpnStatus;

// Main function
fn main() {
    println!("Checking VPN status...");
    
    match status::get_ip_info() {
        Ok(info) => {
            println!("IP Address: {}", info.ip);
            println!("Location: {}", info.loc);
            
            println!("Performing VPN detection...");
            match info.detect_vpn() {
                VpnStatus::Active => println!("VPN Status: ACTIVE (Confirmed)"),
                VpnStatus::Inactive => println!("VPN Status: INACTIVE (No VPN detected)"),
                VpnStatus::Unknown => println!("VPN Status: UNKNOWN (Could not determine with confidence)"),
            }
        }
        Err(err) => {
            eprintln!("Error checking IP info: {}", err);
        }
    }
}
