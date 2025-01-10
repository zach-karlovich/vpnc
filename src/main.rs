mod status;

// Main function
fn main() {
    match status::get_ip_info() {
        Ok(info) => {
            println!("IP Address: {}", info.ip);
            println!("Location: {}", info.loc);
            // Add logic to check for VPN service here
            // For now, let's print a placeholder
            println!("VPN Service: Not checked");
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}
