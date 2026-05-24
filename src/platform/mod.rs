#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "linux", test))]
#[allow(dead_code)]
mod linux;
#[cfg(any(target_os = "windows", test))]
#[allow(dead_code)]
mod windows;

use crate::vpn::VpnSignal;

pub trait PlatformProbe {
    fn os_info(&self) -> String;
    fn local_ips(&self) -> (Vec<String>, Option<String>);
    fn dns_resolvers(&self) -> (Vec<String>, String);
    fn vpn_signals(&self) -> (Vec<VpnSignal>, Vec<String>);
}

#[cfg(target_os = "macos")]
pub fn probe() -> impl PlatformProbe {
    macos::MacProbe::new()
}

#[cfg(target_os = "linux")]
pub fn probe() -> impl PlatformProbe {
    linux::LinuxProbe::new()
}

#[cfg(target_os = "windows")]
pub fn probe() -> impl PlatformProbe {
    windows::WindowsProbe::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub struct UnsupportedProbe;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
impl PlatformProbe for UnsupportedProbe {
    fn os_info(&self) -> String {
        "unsupported".to_string()
    }

    fn local_ips(&self) -> (Vec<String>, Option<String>) {
        (vec![], Some("unsupported platform".to_string()))
    }

    fn dns_resolvers(&self) -> (Vec<String>, String) {
        (vec![], "unsupported platform".to_string())
    }

    fn vpn_signals(&self) -> (Vec<VpnSignal>, Vec<String>) {
        (vec![], vec!["unsupported platform".to_string()])
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn probe() -> UnsupportedProbe {
    UnsupportedProbe
}
