use tempris_collector::protocol::{ClientFrame, ServerFrame};
use uuid::Uuid;

#[test]
fn test_all_server_frames_roundtrip() {
    let challenge = ServerFrame::AUTH_CHALLENGE {
        nonce: "test_nonce_32bytes_b64url_string".to_string(),
        expires_at: "2026-08-28T12:00:30Z".to_string(),
    };
    let json_c = serde_json::to_string(&challenge).unwrap();
    assert!(json_c.contains("\"type\":\"AUTH_CHALLENGE\""));
    let deserialized_c: ServerFrame = serde_json::from_str(&json_c).unwrap();
    match deserialized_c {
        ServerFrame::AUTH_CHALLENGE { nonce, expires_at } => {
            assert_eq!(nonce, "test_nonce_32bytes_b64url_string");
            assert_eq!(expires_at, "2026-08-28T12:00:30Z");
        }
        _ => panic!("Expected AUTH_CHALLENGE"),
    }

    let success_id = Uuid::new_v4();
    let success = ServerFrame::AUTH_SUCCESS {
        collector_id: success_id,
        status: "connected".to_string(),
    };
    let json_s = serde_json::to_string(&success).unwrap();
    let deserialized_s: ServerFrame = serde_json::from_str(&json_s).unwrap();
    match deserialized_s {
        ServerFrame::AUTH_SUCCESS {
            collector_id,
            status,
        } => {
            assert_eq!(collector_id, success_id);
            assert_eq!(status, "connected");
        }
        _ => panic!("Expected AUTH_SUCCESS"),
    }

    let hb_ack = ServerFrame::HEARTBEAT_ACK {
        timestamp: "2026-08-28T12:01:00Z".to_string(),
    };
    let json_hb = serde_json::to_string(&hb_ack).unwrap();
    let deserialized_hb: ServerFrame = serde_json::from_str(&json_hb).unwrap();
    match deserialized_hb {
        ServerFrame::HEARTBEAT_ACK { timestamp } => {
            assert_eq!(timestamp, "2026-08-28T12:01:00Z");
        }
        _ => panic!("Expected HEARTBEAT_ACK"),
    }

    let job_id = Uuid::new_v4();
    let asset_id = Uuid::new_v4();
    let verify = ServerFrame::VERIFY_TARGET {
        job_id,
        operation: Some("verify_target".to_string()),
        asset_id: Some(asset_id),
        correlation_id: Some("corr-123".to_string()),
        target: Some("10.0.0.5".to_string()),
        target_value: None,
        target_type: Some("ip".to_string()),
        network_scope: Some("internal".to_string()),
        expires_at: Some("2026-08-28T12:05:00Z".to_string()),
        timeout_seconds: Some(8),
    };
    let json_v = serde_json::to_string(&verify).unwrap();
    let deserialized_v: ServerFrame = serde_json::from_str(&json_v).unwrap();
    match deserialized_v {
        ServerFrame::VERIFY_TARGET {
            job_id: j,
            operation,
            asset_id: a_id,
            correlation_id,
            target,
            target_type,
            network_scope,
            expires_at,
            timeout_seconds,
            ..
        } => {
            assert_eq!(j, job_id);
            assert_eq!(operation, Some("verify_target".to_string()));
            assert_eq!(a_id, Some(asset_id));
            assert_eq!(correlation_id, Some("corr-123".to_string()));
            assert_eq!(target, Some("10.0.0.5".to_string()));
            assert_eq!(target_type, Some("ip".to_string()));
            assert_eq!(network_scope, Some("internal".to_string()));
            assert_eq!(expires_at, Some("2026-08-28T12:05:00Z".to_string()));
            assert_eq!(timeout_seconds, Some(8));
        }
        _ => panic!("Expected VERIFY_TARGET"),
    }
}

#[test]
fn test_all_client_frames_roundtrip() {
    let col_id = Uuid::new_v4();
    let auth_resp = ClientFrame::AUTH_RESPONSE {
        collector_id: col_id,
        nonce: "nonce123".to_string(),
        expires_at: "2026-08-28T12:00:30Z".to_string(),
        signature: "sig456".to_string(),
    };
    let json_r = serde_json::to_string(&auth_resp).unwrap();
    let deserialized_r: ClientFrame = serde_json::from_str(&json_r).unwrap();
    match deserialized_r {
        ClientFrame::AUTH_RESPONSE {
            collector_id,
            nonce,
            expires_at,
            signature,
        } => {
            assert_eq!(collector_id, col_id);
            assert_eq!(nonce, "nonce123");
            assert_eq!(expires_at, "2026-08-28T12:00:30Z");
            assert_eq!(signature, "sig456");
        }
        _ => panic!("Expected AUTH_RESPONSE"),
    }

    let hb = ClientFrame::HEARTBEAT {
        timestamp: "2026-08-28T12:01:00Z".to_string(),
    };
    let json_hb = serde_json::to_string(&hb).unwrap();
    let deserialized_hb: ClientFrame = serde_json::from_str(&json_hb).unwrap();
    match deserialized_hb {
        ClientFrame::HEARTBEAT { timestamp } => {
            assert_eq!(timestamp, "2026-08-28T12:01:00Z");
        }
        _ => panic!("Expected HEARTBEAT"),
    }

    let job_id = Uuid::new_v4();
    let result_frame = ClientFrame::VERIFY_TARGET_RESULT {
        job_id,
        status: "completed".to_string(),
        reachable: true,
        method: "tcp_probe".to_string(),
        port: Some(443),
        port_reached: Some(443),
        reachability_status: "verified".to_string(),
        latency_ms: Some(15.2),
        error_message: None,
        started_at: "2026-08-28T12:00:00Z".to_string(),
        completed_at: "2026-08-28T12:00:01Z".to_string(),
    };
    let json_res = serde_json::to_string(&result_frame).unwrap();
    let deserialized_res: ClientFrame = serde_json::from_str(&json_res).unwrap();
    match deserialized_res {
        ClientFrame::VERIFY_TARGET_RESULT {
            job_id: j,
            status,
            reachable,
            method,
            port,
            reachability_status,
            port_reached,
            latency_ms,
            error_message,
            started_at,
            completed_at,
        } => {
            assert_eq!(j, job_id);
            assert_eq!(status, "completed");
            assert!(reachable);
            assert_eq!(method, "tcp_probe");
            assert_eq!(port, Some(443));
            assert_eq!(port_reached, Some(443));
            assert_eq!(reachability_status, "verified");
            assert_eq!(latency_ms, Some(15.2));
            assert_eq!(error_message, None);
            assert_eq!(started_at, "2026-08-28T12:00:00Z");
            assert_eq!(completed_at, "2026-08-28T12:00:01Z");
        }
        _ => panic!("Expected VERIFY_TARGET_RESULT"),
    }
}
