use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckUpdatePayload {
    #[serde(default)]
    pub check_id: Option<Uuid>,
    #[serde(default)]
    pub force_recheck: Option<bool>,
}

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
    SCOUT_JOB {
        job_id: Uuid,
        engine: String,
        profile: String,
        target: String,
        target_type: String,
        network_scope: String,
        timeout_seconds: u64,
        expires_at: String,
    },
    CHECK_UPDATE(CheckUpdatePayload),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineCapability {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub templates_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prerequisite_health: Option<String>,
}

impl Default for EngineCapability {
    fn default() -> Self {
        Self {
            available: false,
            version: None,
            templates_version: None,
            managed: None,
            status: None,
            integrity_status: None,
            path: None,
            last_checked_at: None,
            prerequisite_health: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScoutCapabilities {
    pub nmap: EngineCapability,
    pub nuclei: EngineCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nuclei_templates: Option<EngineCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<String>,
}

impl Default for ScoutCapabilities {
    fn default() -> Self {
        Self {
            nmap: EngineCapability::default(),
            nuclei: EngineCapability::default(),
            nuclei_templates: None,
            collector_version: None,
            manifest_sequence: None,
            channel: None,
            update_status: None,
            last_checked_at: None,
        }
    }
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
    SCOUT_CAPABILITIES {
        capabilities: ScoutCapabilities,
    },
    SCOUT_JOB_RESULT {
        job_id: Uuid,
        engine: String,
        status: String, // "completed" | "failed" | "rejected"
        #[serde(default)]
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
        stdout_bytes: usize,
        stderr_bytes: usize,
        started_at: String,
        completed_at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_message: Option<String>,
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

        let scout_job_json = r#"{"type":"SCOUT_JOB","job_id":"a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d","engine":"nmap","profile":"SERVICE_DISCOVERY","target":"10.0.0.5","target_type":"ip","network_scope":"internal","timeout_seconds":180,"expires_at":"2026-09-05T12:00:00Z"}"#;
        let scout_frame: ServerFrame = serde_json::from_str(scout_job_json).unwrap();
        match scout_frame {
            ServerFrame::SCOUT_JOB {
                job_id,
                engine,
                profile,
                target,
                target_type,
                network_scope,
                timeout_seconds,
                expires_at,
            } => {
                assert_eq!(job_id.to_string(), "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d");
                assert_eq!(engine, "nmap");
                assert_eq!(profile, "SERVICE_DISCOVERY");
                assert_eq!(target, "10.0.0.5");
                assert_eq!(target_type, "ip");
                assert_eq!(network_scope, "internal");
                assert_eq!(timeout_seconds, 180);
                assert_eq!(expires_at, "2026-09-05T12:00:00Z");
            }
            _ => panic!("Expected SCOUT_JOB"),
        }

        let cap_frame = ClientFrame::SCOUT_CAPABILITIES {
            capabilities: ScoutCapabilities {
                nmap: EngineCapability {
                    available: true,
                    version: Some("7.94".to_string()),
                    templates_version: None,
                    managed: Some(false),
                    status: Some("ready".to_string()),
                    integrity_status: Some("verified".to_string()),
                    path: Some("[EXTERNAL_NMAP]".to_string()),
                    last_checked_at: Some("2026-09-05T12:00:00Z".to_string()),
                    prerequisite_health: Some("healthy".to_string()),
                },
                nuclei: EngineCapability {
                    available: false,
                    version: None,
                    templates_version: None,
                    managed: Some(true),
                    status: Some("missing".to_string()),
                    integrity_status: None,
                    path: None,
                    last_checked_at: Some("2026-09-05T12:00:00Z".to_string()),
                    prerequisite_health: None,
                },
                nuclei_templates: None,
                collector_version: Some("0.4.0".to_string()),
                manifest_sequence: Some(1),
                channel: Some("stable".to_string()),
                update_status: Some("up_to_date".to_string()),
                last_checked_at: Some("2026-09-05T12:00:00Z".to_string()),
            },
        };
        let cap_json = serde_json::to_string(&cap_frame).unwrap();
        assert!(cap_json.contains("\"type\":\"SCOUT_CAPABILITIES\""));
        assert!(cap_json.contains("\"available\":true"));
        assert!(cap_json.contains("\"version\":\"7.94\""));
        assert!(cap_json.contains("\"path\":\"[EXTERNAL_NMAP]\""));
        assert!(cap_json.contains("\"collector_version\":\"0.4.0\""));
        assert!(cap_json.contains("\"manifest_sequence\":1"));
        assert!(cap_json.contains("\"update_status\":\"up_to_date\""));

        let scout_res = ClientFrame::SCOUT_JOB_RESULT {
            job_id: Uuid::new_v4(),
            engine: "nuclei".to_string(),
            status: "completed".to_string(),
            exit_code: Some(0),
            stdout: "{\"template-id\":\"CVE-2024-1234\"}\n".to_string(),
            stderr: "".to_string(),
            stdout_bytes: 35,
            stderr_bytes: 0,
            started_at: "2026-09-05T12:00:00Z".to_string(),
            completed_at: "2026-09-05T12:00:05Z".to_string(),
            error_message: None,
        };
        let scout_res_json = serde_json::to_string(&scout_res).unwrap();
        assert!(scout_res_json.contains("\"type\":\"SCOUT_JOB_RESULT\""));
        assert!(scout_res_json.contains("\"engine\":\"nuclei\""));
        assert!(scout_res_json.contains("\"status\":\"completed\""));
        assert!(scout_res_json.contains("\"stdout_bytes\":35"));
    }
}
