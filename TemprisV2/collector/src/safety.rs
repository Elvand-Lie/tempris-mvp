use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tracing::warn;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetType {
    #[serde(alias = "ipv4", alias = "ipv6")]
    Ip,
    Hostname,
    Domain,
}

impl TargetType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "ip" | "ipv4" | "ipv6" => Some(TargetType::Ip),
            "hostname" => Some(TargetType::Hostname),
            "domain" => Some(TargetType::Domain),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkScope {
    Internal,
}

impl NetworkScope {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "internal" => Some(NetworkScope::Internal),
            _ => None,
        }
    }
}

/// Checks if an IPv4 address belongs to a forbidden class:
/// - Loopback (127.0.0.0/8)
/// - Link-Local (169.254.0.0/16)
/// - Multicast (224.0.0.0/4)
/// - Unspecified (0.0.0.0)
/// - Broadcast (255.255.255.255)
pub fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // Loopback: 127.0.0.0/8
    if octets[0] == 127 || ip.is_loopback() {
        return true;
    }

    // Link-Local: 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 || ip.is_link_local() {
        return true;
    }

    // Multicast: 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
    if octets[0] >= 224 && octets[0] <= 239 || ip.is_multicast() {
        return true;
    }

    // Unspecified: 0.0.0.0/8
    if octets[0] == 0 || ip.is_unspecified() {
        return true;
    }

    // Broadcast: 255.255.255.255
    if ip.is_broadcast() || ip == Ipv4Addr::new(255, 255, 255, 255) {
        return true;
    }

    // Reserved / Future: 240.0.0.0/4
    if octets[0] >= 240 {
        return true;
    }

    false
}

/// Checks if an IPv6 address belongs to a forbidden class:
/// - Loopback (::1)
/// - Link-Local (fe80::/10)
/// - Multicast (ff00::/8)
/// - Unspecified (::)
pub fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    // Loopback: ::1
    if ip.is_loopback() || ip == Ipv6Addr::LOCALHOST {
        return true;
    }

    // Unspecified: ::
    if ip.is_unspecified() || ip == Ipv6Addr::UNSPECIFIED {
        return true;
    }

    // Multicast: ff00::/8
    if ip.is_multicast() || (ip.segments()[0] & 0xff00) == 0xff00 {
        return true;
    }

    // Link-Local: fe80::/10 (fe80:: - febf::)
    let seg0 = ip.segments()[0];
    if (seg0 & 0xffc0) == 0xfe80 {
        return true;
    }

    // IPv4-mapped IPv6 address: ::ffff:a.b.c.d
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        if is_forbidden_ipv4(ipv4) {
            return true;
        }
    }

    false
}

/// Checks if an IP address belongs to any forbidden address class.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_forbidden_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_forbidden_ipv6(ipv6),
    }
}

/// Validates target syntax.
pub fn validate_target_syntax(
    target_value: &str,
    target_type_hint: Option<&TargetType>,
) -> Result<()> {
    let clean = target_value.trim();
    if clean.is_empty() {
        return Err(anyhow!("Target value cannot be empty"));
    }

    if clean.contains('/')
        || (clean.contains(':') && !clean.contains("::") && clean.parse::<Ipv6Addr>().is_err())
    {
        if clean.contains("://") || clean.contains('/') {
            return Err(anyhow!(
                "Target value must be a pure IP address or hostname without scheme or path: '{}'",
                clean
            ));
        }
    }

    if let Some(hint) = target_type_hint {
        match hint {
            TargetType::Ip => {
                if clean.parse::<Ipv4Addr>().is_err() && clean.parse::<Ipv6Addr>().is_err() {
                    return Err(anyhow!("Invalid IP target value: '{}'", clean));
                }
            }
            TargetType::Hostname | TargetType::Domain => {
                validate_hostname_syntax(clean)?;
            }
        }
    } else {
        // Auto-detect only if no type hint is provided (fallback)
        if clean.parse::<Ipv4Addr>().is_err() && clean.parse::<Ipv6Addr>().is_err() {
            validate_hostname_syntax(clean)?;
        }
    }

    Ok(())
}

pub fn validate_hostname_syntax(hostname: &str) -> Result<()> {
    if hostname.len() > 253 {
        return Err(anyhow!("Hostname exceeds maximum length of 253 characters"));
    }

    let labels: Vec<&str> = hostname.split('.').collect();
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return Err(anyhow!("Invalid hostname label in '{}'", hostname));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(anyhow!(
                "Hostname label cannot start or end with a hyphen: '{}'",
                label
            ));
        }
        if !label
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!("Invalid character in hostname label: '{}'", label));
        }
    }

    Ok(())
}

/// Resolves target exactly once via DNS and returns the pinned IpAddr.
/// Enforces forbidden address class validation before any socket connect.
pub async fn resolve_and_pin_safe_target(
    target_value: &str,
    target_type_hint: Option<&TargetType>,
) -> Result<IpAddr> {
    let clean = target_value.trim();
    validate_target_syntax(clean, target_type_hint)?;

    // 1. If it's already a raw IP address, validate immediately
    if let Ok(ip) = clean.parse::<IpAddr>() {
        if is_forbidden_ip(ip) {
            warn!(
                "Rejected forbidden target IP address '{}' with zero socket connect",
                ip
            );
            return Err(anyhow!("Target IP '{}' belongs to a forbidden address class (loopback, link-local, multicast, unspecified, or broadcast)", ip));
        }
        return Ok(ip);
    }

    // 2. Perform Single DNS Resolution (pinned)
    let host_port = format!("{}:80", clean);
    let resolved_addrs: Vec<SocketAddr> = tokio::net::lookup_host(&host_port)
        .await
        .map_err(|e| anyhow!("DNS resolution failed for '{}': {}", clean, e))?
        .collect();

    if resolved_addrs.is_empty() {
        return Err(anyhow!("No DNS records resolved for '{}'", clean));
    }

    // Check all resolved addresses - if any address is forbidden (e.g. localhost resolving to 127.0.0.1), reject!
    for sa in &resolved_addrs {
        if is_forbidden_ip(sa.ip()) {
            warn!(
                "Rejected hostname '{}' resolving to forbidden IP '{}' with zero socket connect",
                clean,
                sa.ip()
            );
            return Err(anyhow!("Hostname '{}' resolved to forbidden IP '{}' (loopback, link-local, multicast, unspecified, or broadcast)", clean, sa.ip()));
        }
    }

    // Return the pinned IP address (the first resolved safe address)
    let pinned_ip = resolved_addrs[0].ip();
    Ok(pinned_ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_forbidden_ipv4_addresses_non_negotiable_gate() {
        let forbidden_ipv4 = [
            ("127.0.0.1", "IPv4 Loopback address"),
            ("127.0.0.2", "IPv4 Loopback subnet"),
            ("127.255.255.255", "IPv4 Loopback subnet end"),
            ("169.254.0.1", "IPv4 Link-Local subnet start"),
            ("169.254.169.254", "IPv4 Link-Local metadata service"),
            ("169.254.255.255", "IPv4 Link-Local subnet end"),
            ("224.0.0.1", "IPv4 Multicast all hosts"),
            ("224.0.0.251", "IPv4 Multicast mDNS"),
            ("239.255.255.250", "IPv4 Multicast SSDP"),
            ("0.0.0.0", "IPv4 Unspecified address"),
            ("255.255.255.255", "IPv4 Limited Broadcast address"),
            ("240.0.0.1", "IPv4 Reserved address"),
        ];

        for (ip_str, desc) in forbidden_ipv4 {
            let ip = Ipv4Addr::from_str(ip_str).unwrap();
            assert!(
                is_forbidden_ipv4(ip),
                "Non-Negotiable Safety Gate Failed: {} ({}) must be forbidden!",
                ip_str,
                desc
            );
            assert!(
                is_forbidden_ip(IpAddr::V4(ip)),
                "Non-Negotiable Safety Gate Failed: {} ({}) must be forbidden in is_forbidden_ip!",
                ip_str,
                desc
            );
        }
    }

    #[test]
    fn test_forbidden_ipv6_addresses_non_negotiable_gate() {
        let forbidden_ipv6 = [
            ("::1", "IPv6 Loopback address"),
            ("::", "IPv6 Unspecified address"),
            ("fe80::1", "IPv6 Link-Local address"),
            ("fe80::1234:5678:abcd:ef01", "IPv6 Link-Local random host"),
            ("ff00::1", "IPv6 Multicast base"),
            ("ff02::1", "IPv6 Multicast all nodes"),
            ("ff02::fb", "IPv6 Multicast mDNS"),
            ("::ffff:127.0.0.1", "IPv4-mapped IPv6 loopback"),
            ("::ffff:169.254.169.254", "IPv4-mapped IPv6 link-local"),
        ];

        for (ip_str, desc) in forbidden_ipv6 {
            let ip = Ipv6Addr::from_str(ip_str).unwrap();
            assert!(
                is_forbidden_ipv6(ip),
                "Non-Negotiable Safety Gate Failed: {} ({}) must be forbidden!",
                ip_str,
                desc
            );
            assert!(
                is_forbidden_ip(IpAddr::V6(ip)),
                "Non-Negotiable Safety Gate Failed: {} ({}) must be forbidden in is_forbidden_ip!",
                ip_str,
                desc
            );
        }
    }

    #[test]
    fn test_allowed_internal_and_public_addresses() {
        let allowed_ips = [
            "192.168.1.1",
            "192.168.1.50",
            "10.0.0.1",
            "10.254.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "fd00::1",
        ];

        for ip_str in allowed_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                !is_forbidden_ip(ip),
                "Address {} should be allowed for reachability verification",
                ip_str
            );
        }
    }

    #[tokio::test]
    async fn test_dns_resolution_and_pinning_rejects_localhost_with_zero_socket_connect() {
        let res = resolve_and_pin_safe_target("localhost", Some(&TargetType::Hostname)).await;
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("forbidden IP") || err_msg.contains("forbidden address class"),
            "Unexpected error message: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_dns_resolution_and_pinning_rejects_raw_forbidden_ips() {
        let forbidden_raw = [
            "127.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "ff02::1",
        ];

        for raw in forbidden_raw {
            let res = resolve_and_pin_safe_target(raw, None).await;
            assert!(res.is_err(), "Expected resolve_and_pin to reject '{}'", raw);
        }
    }

    #[test]
    fn test_target_syntax_validation() {
        assert!(validate_target_syntax("192.168.1.1", Some(&TargetType::Ip)).is_ok());
        assert!(validate_target_syntax("fe80::1", Some(&TargetType::Ip)).is_ok());
        assert!(validate_target_syntax("internal.corp.local", Some(&TargetType::Hostname)).is_ok());
        assert!(
            validate_target_syntax("app-server-01.domain.internal", Some(&TargetType::Domain))
                .is_ok()
        );

        // Invalid syntax (schemes, paths, cidrs)
        assert!(validate_target_syntax("http://192.168.1.1", None).is_err());
        assert!(validate_target_syntax("192.168.1.1/24", None).is_err());
        assert!(validate_target_syntax("internal.corp.local/api", None).is_err());
        assert!(validate_target_syntax("", None).is_err());
    }

    #[test]
    fn test_typed_scope_and_target_type_rejection() {
        assert_eq!(TargetType::from_str("ip"), Some(TargetType::Ip));
        assert_eq!(TargetType::from_str("ipv4"), Some(TargetType::Ip));
        assert_eq!(TargetType::from_str("ipv6"), Some(TargetType::Ip));
        assert_eq!(TargetType::from_str("hostname"), Some(TargetType::Hostname));
        assert_eq!(TargetType::from_str("domain"), Some(TargetType::Domain));
        assert_eq!(TargetType::from_str("unknown_type"), None);

        assert_eq!(
            NetworkScope::from_str("internal"),
            Some(NetworkScope::Internal)
        );
        assert_eq!(NetworkScope::from_str("external"), None);
        assert_eq!(NetworkScope::from_str("public"), None);
    }
}
