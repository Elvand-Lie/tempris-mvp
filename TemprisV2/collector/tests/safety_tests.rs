use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tempris_collector::safety::{
    is_forbidden_ip, is_forbidden_ipv4, is_forbidden_ipv6, resolve_and_pin_safe_target,
    validate_target_syntax, NetworkScope, TargetType,
};

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
        validate_target_syntax("app-server-01.domain.internal", Some(&TargetType::Domain)).is_ok()
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
    assert_eq!(TargetType::from_str("arbitrary_unknown"), None);

    assert_eq!(
        NetworkScope::from_str("internal"),
        Some(NetworkScope::Internal)
    );
    assert_eq!(NetworkScope::from_str("external"), None);
    assert_eq!(NetworkScope::from_str("public"), None);
    assert_eq!(NetworkScope::from_str("dmz"), None);
}
