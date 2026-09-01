use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(non_camel_case_types)]
pub enum ServerFrame {
    AUTH_CHALLENGE {
        nonce: String,
        expires_at: String,
    },
    AUTH_SUCCESS {
        collector_id: Uuid,
        status: String,
    },
    HEARTBEAT_ACK {
        timestamp: String,
    },
    VERIFY_TARGET {
        job_id: Uuid,
        #[serde(default)]
        operation: Option<String>,
        #[serde(default)]
        asset_id: Option<Uuid>,
        #[serde(default)]
        correlation_id: Option<String>,
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        target_value: Option<String>,
        #[serde(default)]
        target_type: Option<String>,
        #[serde(default)]
        network_scope: Option<String>,
        #[serde(default)]
        expires_at: Option<String>,
        #[serde(default)]
        timeout_seconds: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(non_camel_case_types)]
pub enum ClientFrame {
    AUTH_RESPONSE {
        collector_id: Uuid,
        nonce: String,
        expires_at: String,
        signature: String,
    },
    HEARTBEAT {
        timestamp: String,
    },
    VERIFY_TARGET_RESULT {
        job_id: Uuid,
        #[serde(default = "default_status")]
        status: String, // "completed" | "failed" | "rejected"
        #[serde(default)]
        reachable: bool,
        #[serde(default = "default_method")]
        method: String, // "tcp_probe"
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port_reached: Option<u16>, // alias for port
        reachability_status: String, // "verified" | "unreachable"
        #[serde(skip_serializing_if = "Option::is_none")]
        latency_ms: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_message: Option<String>,
        #[serde(default)]
        started_at: String,
        #[serde(default)]
        completed_at: String,
    },
}

fn default_status() -> String {
    "completed".to_string()
}

fn default_method() -> String {
    "tcp_probe".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_frame_deserialization() {
        let json_challenge = r#"{"type":"AUTH_CHALLENGE","nonce":"abc123nonce","expires_at":"2026-08-28T12:00:30Z"}"#;
        let frame: ServerFrame = serde_json::from_str(json_challenge).unwrap();
        match frame {
            ServerFrame::AUTH_CHALLENGE { nonce, expires_at } => {
                assert_eq!(nonce, "abc123nonce");
                assert_eq!(expires_at, "2026-08-28T12:00:30Z");
            }
            _ => panic!("Expected AUTH_CHALLENGE"),
        }

        let json_verify = r#"{"type":"VERIFY_TARGET","operation":"verify_target","job_id":"9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d","asset_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","target":"192.168.1.1","target_type":"ipv4","network_scope":"internal","expires_at":"2026-08-28T12:05:00Z","timeout_seconds":8}"#;
        let frame_v: ServerFrame = serde_json::from_str(json_verify).unwrap();
        match frame_v {
            ServerFrame::VERIFY_TARGET {
                job_id,
                operation,
                asset_id,
                target,
                target_type,
                network_scope,
                expires_at,
                timeout_seconds,
                ..
            } => {
                assert_eq!(job_id.to_string(), "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d");
                assert_eq!(operation, Some("verify_target".to_string()));
                assert_eq!(
                    asset_id.map(|u| u.to_string()),
                    Some("3fa85f64-5717-4562-b3fc-2c963f66afa6".to_string())
                );
                assert_eq!(target, Some("192.168.1.1".to_string()));
                assert_eq!(target_type, Some("ipv4".to_string()));
                assert_eq!(network_scope, Some("internal".to_string()));
                assert_eq!(expires_at, Some("2026-08-28T12:05:00Z".to_string()));
                assert_eq!(timeout_seconds, Some(8));
            }
            _ => panic!("Expected VERIFY_TARGET"),
        }
    }

    #[test]
    fn test_client_frame_serialization() {
        let col_id = Uuid::new_v4();
        let frame = ClientFrame::AUTH_RESPONSE {
            collector_id: col_id,
            nonce: "test-nonce".to_string(),
            expires_at: "2026-08-28T12:00:30Z".to_string(),
            signature: "sig123".to_string(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"type\":\"AUTH_RESPONSE\""));
        assert!(json.contains(&col_id.to_string()));

        let job_id = Uuid::new_v4();
        let res_frame = ClientFrame::VERIFY_TARGET_RESULT {
            job_id,
            status: "completed".to_string(),
            reachable: true,
            method: "tcp_probe".to_string(),
            port: Some(443),
            port_reached: Some(443),
            reachability_status: "verified".to_string(),
            latency_ms: Some(12.34),
            error_message: None,
            started_at: "2026-08-28T12:00:00Z".to_string(),
            completed_at: "2026-08-28T12:00:01Z".to_string(),
        };
        let res_json = serde_json::to_string(&res_frame).unwrap();
        assert!(res_json.contains("\"type\":\"VERIFY_TARGET_RESULT\""));
        assert!(res_json.contains("\"reachability_status\":\"verified\""));
        assert!(res_json.contains("\"port_reached\":443"));
        assert!(res_json.contains("\"method\":\"tcp_probe\""));
        assert!(res_json.contains("\"status\":\"completed\""));
    }
}
