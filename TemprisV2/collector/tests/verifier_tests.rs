use tempris_collector::safety::TargetType;
use tempris_collector::verifier::verify_internal_target;

#[tokio::test]
async fn test_verify_forbidden_addresses_rejects_with_zero_socket_connect() {
    let forbidden = [
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "ff02::1",
    ];

    for target in forbidden {
        let outcome = verify_internal_target(target, None).await;
        assert_eq!(
            outcome.reachability_status, "unreachable",
            "Target '{}' must be unreachable due to safety gate rejection",
            target
        );
        assert_eq!(outcome.port_reached, None);
        assert!(
            outcome.error_message.is_some(),
            "Target '{}' must have safety error explanation",
            target
        );
        let err = outcome.error_message.unwrap();
        assert!(
            err.contains("forbidden") || err.contains("safety"),
            "Error for '{}' should mention safety gate: {}",
            target,
            err
        );
    }
}

#[tokio::test]
async fn test_verify_unreachable_private_ip() {
    let outcome = verify_internal_target("192.168.1.253", Some(&TargetType::Ip)).await;
    assert_eq!(outcome.reachability_status, "unreachable");
    assert_eq!(outcome.port_reached, None);
}
