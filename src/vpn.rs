use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VpnSignalStrength {
    Strong,
    Weak,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VpnSignal {
    VpnProfileConnected { name: String },
    DefaultRouteViaVpn { interface: String },
    SplitTunnelRoute,
    #[allow(dead_code)]
    WireGuardActive,
    VpnInterface { interface: String },
}

impl VpnSignal {
    pub fn strength(&self) -> VpnSignalStrength {
        match self {
            VpnSignal::VpnProfileConnected { .. }
            | VpnSignal::DefaultRouteViaVpn { .. }
            | VpnSignal::SplitTunnelRoute
            | VpnSignal::WireGuardActive => VpnSignalStrength::Strong,
            VpnSignal::VpnInterface { .. } => VpnSignalStrength::Weak,
        }
    }

    pub fn description(&self) -> String {
        match self {
            VpnSignal::VpnProfileConnected { name } => {
                format!("VPN profile connected ({name})")
            }
            VpnSignal::DefaultRouteViaVpn { interface } => {
                format!("default route via {interface}")
            }
            VpnSignal::SplitTunnelRoute => "split tunnel route detected".to_string(),
            VpnSignal::WireGuardActive => "WireGuard tunnel active".to_string(),
            VpnSignal::VpnInterface { interface } => {
                format!("VPN-like interface active ({interface})")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VpnStatus {
    Detected,
    NotDetected,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct VpnDetection {
    pub status: VpnStatus,
    pub signals: Vec<VpnSignal>,
    pub errors: Vec<String>,
}

pub fn evaluate_vpn(signals: Vec<VpnSignal>, errors: Vec<String>) -> VpnDetection {
    let has_strong = signals
        .iter()
        .any(|signal| signal.strength() == VpnSignalStrength::Strong);

    if has_strong {
        return VpnDetection {
            status: VpnStatus::Detected,
            signals,
            errors,
        };
    }

    let weak_count = signals
        .iter()
        .filter(|signal| signal.strength() == VpnSignalStrength::Weak)
        .count();

    let has_route_evidence = signals.iter().any(|signal| {
        matches!(
            signal,
            VpnSignal::DefaultRouteViaVpn { .. } | VpnSignal::SplitTunnelRoute
        )
    });

    let has_vpn_interface = signals
        .iter()
        .any(|signal| matches!(signal, VpnSignal::VpnInterface { .. }));

    if weak_count >= 2 || (has_vpn_interface && has_route_evidence) {
        return VpnDetection {
            status: VpnStatus::Detected,
            signals,
            errors,
        };
    }

    if signals.is_empty() {
        if errors.is_empty() {
            VpnDetection {
                status: VpnStatus::NotDetected,
                signals,
                errors,
            }
        } else {
            VpnDetection {
                status: VpnStatus::Unknown,
                signals,
                errors,
            }
        }
    } else {
        VpnDetection {
            status: VpnStatus::Unknown,
            signals,
            errors,
        }
    }
}

pub fn is_vpn_interface(name: &str) -> bool {
    let lower = name.to_lowercase();
    [
        "utun", "tun", "tap", "wg", "ppp", "ipsec", "nordlynx", "wireguard", "wintun",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_signal_detects_vpn() {
        let result = evaluate_vpn(
            vec![VpnSignal::SplitTunnelRoute],
            vec![],
        );
        assert_eq!(result.status, VpnStatus::Detected);
    }

    #[test]
    fn no_signals_and_no_errors_means_not_detected() {
        let result = evaluate_vpn(vec![], vec![]);
        assert_eq!(result.status, VpnStatus::NotDetected);
    }

    #[test]
    fn errors_without_signals_means_unknown() {
        let result = evaluate_vpn(vec![], vec!["ifconfig failed".to_string()]);
        assert_eq!(result.status, VpnStatus::Unknown);
    }

    #[test]
    fn weak_interface_plus_route_means_detected() {
        let result = evaluate_vpn(
            vec![
                VpnSignal::VpnInterface {
                    interface: "utun4".to_string(),
                },
                VpnSignal::SplitTunnelRoute,
            ],
            vec![],
        );
        assert_eq!(result.status, VpnStatus::Detected);
    }

    #[test]
    fn single_weak_signal_means_unknown() {
        let result = evaluate_vpn(
            vec![VpnSignal::VpnInterface {
                interface: "utun4".to_string(),
            }],
            vec![],
        );
        assert_eq!(result.status, VpnStatus::Unknown);
    }
}
