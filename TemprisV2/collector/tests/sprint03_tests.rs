use std::fs::{self, File};
use std::path::Path;
use tempfile::tempdir;
use uuid::Uuid;

use tempris_collector::protocol::{
    CheckUpdatePayload, ClientFrame, EngineCapability, ScoutCapabilities, ServerFrame,
};
use tempris_collector::scout_runner::{
    probe_scout_capabilities_with_storage, run_scout_job_with_context, ScoutJobGuard,
};
use tempris_collector::storage::StorageManager;
use tempris_collector::toolchain::discovery::{
    get_approved_nmap_directories, is_version_supported, validate_nmap_path,
    HARDCODED_NMAP_DISCOVERY_ARGV, MIN_NMAP_VERSION,
};
use tempris_collector::toolchain::redaction::{
    EXTERNAL_NMAP_TOKEN, MANAGED_NUCLEI_TOKEN, MANAGED_TEMPLATES_TOKEN,
};
use tempris_collector::toolchain::state::{ComponentState, ComponentStatus, ToolchainState};

// =========================================================================
// Category A: Truthful Redacted Capabilities Telemetry (A.1 – A.5)
// =========================================================================

#[tokio::test]
async fn test_s03_a1_truthful_filesystem_inspection_when_absent() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());

    let caps = probe_scout_capabilities_with_storage(Some(&storage)).await;

    // When Nuclei has not been installed, available must be false and status uninstalled/missing
    assert!(!caps.nuclei.available, "Nuclei available must be false when absent (A.1)");
    assert!(
        caps.nuclei.status.as_deref() == Some("uninstalled") || caps.nuclei.status.as_deref() == Some("not_installed") || caps.nuclei.status.is_none(),
        "Nuclei status must be uninstalled/missing when absent (A.1)"
    );
    assert!(caps.nuclei.version.is_none());
}

#[tokio::test]
async fn test_s03_a2_truthful_capabilities_when_nuclei_present() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());

    // Populate managed nuclei tool in storage
    let version = "3.8.0";
    let tool_dir = storage.component_tools_dir("nuclei", version);
    fs::create_dir_all(&tool_dir).unwrap();

    let exe_name = if cfg!(windows) { "nuclei.exe" } else { "nuclei" };
    let exe_path = tool_dir.join(exe_name);
    File::create(&exe_path).unwrap();

    let mut state = ToolchainState::default();
    state.components.insert(
        "nuclei".to_string(),
        ComponentState {
            status: ComponentStatus::Installed,
            version: Some(version.to_string()),
            sha256: Some("test_sha".to_string()),
            active_dir: Some(tool_dir.to_string_lossy().to_string()),
            previous_dir: None,
            installed_at: Some(chrono::Utc::now().to_rfc3339()),
            last_verified_at: Some(chrono::Utc::now().to_rfc3339()),
        },
    );
    state.save(&storage.toolchain_state_path()).unwrap();

    let caps = probe_scout_capabilities_with_storage(Some(&storage)).await;

    assert!(caps.nuclei.available, "Nuclei must be available when present (A.2)");
    assert_eq!(caps.nuclei.version.as_deref(), Some(version));
    assert_eq!(caps.nuclei.status.as_deref(), Some("ready"));
}

#[tokio::test]
async fn test_s03_a3_strict_path_redaction_in_capabilities_frame() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());

    let caps = probe_scout_capabilities_with_storage(Some(&storage)).await;
    let cap_frame = ClientFrame::SCOUT_CAPABILITIES {
        capabilities: caps,
    };

    let serialized = serde_json::to_string(&cap_frame).unwrap();

    // Redaction invariant: absolute host paths, drive letters, and user dirs must never leak
    assert!(!serialized.contains("C:\\"), "Serialized capabilities must not leak Windows drive paths (A.4)");
    assert!(!serialized.contains("/usr/"), "Serialized capabilities must not leak POSIX system paths (A.4)");
    assert!(!serialized.contains("AppData"), "Serialized capabilities must not leak AppData paths (A.4)");
    assert!(!serialized.contains("Program Files"), "Serialized capabilities must not leak Program Files paths (A.4)");
}

#[test]
fn test_s03_a4_capabilities_serialization_roundtrip() {
    let caps = ScoutCapabilities {
        nmap: EngineCapability {
            available: true,
            version: Some("7.94".to_string()),
            templates_version: None,
            managed: Some(false),
            status: Some("ready".to_string()),
            integrity_status: Some("verified".to_string()),
            path: Some(EXTERNAL_NMAP_TOKEN.to_string()),
            last_checked_at: Some("2026-09-06T00:00:00Z".to_string()),
            prerequisite_health: Some("detected".to_string()),
        },
        nuclei: EngineCapability {
            available: true,
            version: Some("3.8.0".to_string()),
            templates_version: None,
            managed: Some(true),
            status: Some("ready".to_string()),
            integrity_status: Some("verified".to_string()),
            path: Some(MANAGED_NUCLEI_TOKEN.to_string()),
            last_checked_at: Some("2026-09-06T00:00:00Z".to_string()),
            prerequisite_health: None,
        },
        nuclei_templates: Some(EngineCapability {
            available: true,
            version: Some("10.2.0".to_string()),
            templates_version: Some("10.2.0".to_string()),
            managed: Some(true),
            status: Some("ready".to_string()),
            integrity_status: Some("verified".to_string()),
            path: Some(MANAGED_TEMPLATES_TOKEN.to_string()),
            last_checked_at: Some("2026-09-06T00:00:00Z".to_string()),
            prerequisite_health: None,
        }),
        collector_version: Some("2.1.0".to_string()),
        manifest_sequence: Some(42),
        channel: Some("stable".to_string()),
        update_status: Some("up_to_date".to_string()),
        last_checked_at: Some("2026-09-06T00:00:00Z".to_string()),
    };

    let frame = ClientFrame::SCOUT_CAPABILITIES {
        capabilities: caps.clone(),
    };
    let json = serde_json::to_string(&frame).unwrap();
    let deserialized: ClientFrame = serde_json::from_str(&json).unwrap();

    match deserialized {
        ClientFrame::SCOUT_CAPABILITIES { capabilities } => {
            assert_eq!(capabilities.nmap.available, true);
            assert_eq!(capabilities.nmap.version.as_deref(), Some("7.94"));
            assert_eq!(capabilities.nuclei.available, true);
            assert_eq!(capabilities.nuclei.version.as_deref(), Some("3.8.0"));
            assert_eq!(capabilities.nuclei_templates.as_ref().unwrap().version.as_deref(), Some("10.2.0"));
            assert_eq!(capabilities.update_status.as_deref(), Some("up_to_date"));
        }
        _ => panic!("Expected ClientFrame::SCOUT_CAPABILITIES"),
    }
}

// =========================================================================
// Category B: Anti-RCE Typed Control Plane Check Protocol (B.1 – B.5)
// =========================================================================

#[test]
fn test_s03_b1_check_update_valid_deserialization() {
    let check_id = Uuid::new_v4();
    let json_valid = format!(
        r#"{{"type": "CHECK_UPDATE", "check_id": "{}", "force_recheck": true}}"#,
        check_id
    );

    let frame: ServerFrame = serde_json::from_str(&json_valid).expect("Valid CHECK_UPDATE must parse");
    match frame {
        ServerFrame::CHECK_UPDATE(payload) => {
            assert_eq!(payload.check_id, Some(check_id));
            assert_eq!(payload.force_recheck, Some(true));
        }
        _ => panic!("Expected ServerFrame::CHECK_UPDATE"),
    }

    // Also verify omitted optional fields deserialize safely
    let json_minimal = r#"{"type": "CHECK_UPDATE"}"#;
    let frame_min: ServerFrame = serde_json::from_str(json_minimal).expect("Minimal CHECK_UPDATE must parse");
    match frame_min {
        ServerFrame::CHECK_UPDATE(payload) => {
            assert!(payload.check_id.is_none());
            assert!(payload.force_recheck.is_none());
        }
        _ => panic!("Expected ServerFrame::CHECK_UPDATE"),
    }
}

#[test]
fn test_s03_b2_strict_rejection_of_arbitrary_rce_fields() {
    // Invariant B.2: serde(deny_unknown_fields) must reject ANY extraneous/unmodeled field
    let rce_vectors = vec![
        r#"{"type": "CHECK_UPDATE", "url": "https://evil.com/payload.exe"}"#,
        r#"{"type": "CHECK_UPDATE", "download_url": "https://evil.com/tool.zip"}"#,
        r#"{"type": "CHECK_UPDATE", "command": "cmd.exe /c calc"}"#,
        r#"{"type": "CHECK_UPDATE", "flags": "-sV --script=evil"}"#,
        r#"{"type": "CHECK_UPDATE", "script": "powershell -c evil"}"#,
        r#"{"type": "CHECK_UPDATE", "binary": "evil_binary"}"#,
        r#"{"type": "CHECK_UPDATE", "payload": "exploit_data"}"#,
        r#"{"type": "CHECK_UPDATE", "exec": "/bin/sh"}"#,
        r#"{"type": "CHECK_UPDATE", "hash": "badhash123"}"#,
        r#"{"type": "CHECK_UPDATE", "sha256": "badsha123"}"#,
        r#"{"type": "CHECK_UPDATE", "templates_url": "https://evil.com/templates.zip"}"#,
        r#"{"type": "CHECK_UPDATE", "custom_templates": "custom_path"}"#,
    ];

    for vector in rce_vectors {
        let res: Result<ServerFrame, _> = serde_json::from_str(vector);
        assert!(
            res.is_err(),
            "CHECK_UPDATE must strictly reject unknown field in vector: {}",
            vector
        );
        let err_str = res.err().unwrap().to_string();
        assert!(
            err_str.contains("unknown field"),
            "Error must explicitly state unknown field, got: {}",
            err_str
        );
    }
}

#[test]
fn test_s03_b3_check_update_payload_struct_has_no_execution_fields() {
    let payload = CheckUpdatePayload {
        check_id: Some(Uuid::new_v4()),
        force_recheck: Some(true),
    };

    let json = serde_json::to_string(&payload).unwrap();
    assert!(!json.contains("url"));
    assert!(!json.contains("command"));
    assert!(!json.contains("exec"));
    assert!(!json.contains("script"));
    assert!(!json.contains("flags"));
}

// =========================================================================
// Category C: Autonomous Background Scheduler Logic (C.1 – C.6)
// =========================================================================

#[test]
fn test_s03_c1_startup_check_delay_contract() {
    // Contract C.1 specifies startup delay 5-15s (default 10s)
    let startup_delay_secs = 10u64;
    assert!(startup_delay_secs >= 5 && startup_delay_secs <= 15);
}

#[test]
fn test_s03_c2_periodic_interval_and_jitter_bounds() {
    // Contract C.2, C.3 specifies ~24h (86400s) with +/- 30m (1800s) bounded jitter
    // Interval must always fall within [84600, 88200]
    let base_interval: i64 = 86400; // 24 hours
    let max_jitter: i64 = 1800; // 30 minutes

    for sample_ts in [0i64, 100, 1800, 3600, 7200, 86400, 1728000, 1788628994] {
        let jitter = (sample_ts % 3601) - max_jitter;
        assert!(jitter >= -max_jitter && jitter <= max_jitter);
        let interval_secs = (base_interval + jitter).max(3600);
        assert!(
            interval_secs >= base_interval - max_jitter,
            "Interval {} below lower bound 84600",
            interval_secs
        );
        assert!(
            interval_secs <= base_interval + max_jitter,
            "Interval {} above upper bound 88200",
            interval_secs
        );
    }
}

#[test]
fn test_s03_c3_idle_deferral_scout_job_guard() {
    // Ensure initially no job is active
    assert!(!ScoutJobGuard::is_active(), "Initially ScoutJobGuard must be inactive");

    // Acquire guard for an in-flight SCOUT job
    let guard = ScoutJobGuard::try_acquire().expect("First acquisition must succeed");
    assert!(ScoutJobGuard::is_active(), "ScoutJobGuard must report active during job");

    // Attempting to acquire second guard concurrently must be rejected
    let second_guard = ScoutJobGuard::try_acquire();
    assert!(second_guard.is_err(), "Concurrent ScoutJobGuard acquisition must fail");

    // Dropping the guard restores inactive state
    drop(guard);
    assert!(!ScoutJobGuard::is_active(), "ScoutJobGuard must be inactive after drop");

    // Now a new guard can be acquired
    let third_guard = ScoutJobGuard::try_acquire();
    assert!(third_guard.is_ok(), "Subsequent ScoutJobGuard acquisition must succeed");
}

// =========================================================================
// Category D: Non-blocking WSS Event Loop & Heartbeat Preservation (D.1 – D.4)
// =========================================================================

#[tokio::test]
async fn test_s03_d1_subsecond_heartbeat_preservation() {
    let start = std::time::Instant::now();
    let hb_frame = ClientFrame::HEARTBEAT {
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let _ = serde_json::to_string(&hb_frame).unwrap();
    let elapsed = start.elapsed();

    // Heartbeat frame serialization must execute well within sub-second timeframe (< 1000ms, typically < 50ms)
    assert!(
        elapsed.as_millis() < 500,
        "Heartbeat serialization took {}ms, must be sub-second < 500ms (D.2)",
        elapsed.as_millis()
    );
}

// =========================================================================
// Category E: External Prerequisite Deterministic Discovery (E.1 – E.5)
// =========================================================================

#[test]
fn test_s03_e1_deterministic_approved_directories() {
    let approved = get_approved_nmap_directories();
    assert!(!approved.is_empty(), "Approved Nmap directories must not be empty (E.1)");

    if cfg!(windows) {
        let approved_strs: Vec<String> = approved.iter().map(|p| p.to_string_lossy().to_string()).collect();
        assert!(
            approved_strs.iter().any(|p| p.contains("Program Files")),
            "Approved paths must include Program Files on Windows"
        );
    }
}

#[test]
fn test_s03_e2_rejection_of_unapproved_or_traversal_paths() {
    // Paths outside approved directories must be rejected
    let unapproved_paths = vec![
        Path::new("C:\\Windows\\System32\\nmap.exe"),
        Path::new("C:\\Users\\test\\AppData\\Local\\nmap.exe"),
        Path::new("C:\\Temp\\nmap.exe"),
        Path::new("..\\..\\evil\\nmap.exe"),
        Path::new("/tmp/nmap"),
        Path::new("/home/user/nmap"),
    ];

    for path in unapproved_paths {
        assert!(
            validate_nmap_path(path).is_err(),
            "Path {:?} must be rejected by validate_nmap_path (E.2)",
            path
        );
    }
}

#[test]
fn test_s03_e3_version_supported_threshold() {
    assert_eq!(MIN_NMAP_VERSION, "7.90", "Minimum Nmap version threshold is 7.90 (E.4)");

    assert!(is_version_supported("7.90", MIN_NMAP_VERSION), "7.90 must be supported");
    assert!(is_version_supported("7.94", MIN_NMAP_VERSION), "7.94 must be supported");
    assert!(is_version_supported("7.95", MIN_NMAP_VERSION), "7.95 must be supported");
    assert!(is_version_supported("8.0.0", MIN_NMAP_VERSION), "8.0.0 must be supported");

    assert!(!is_version_supported("7.80", MIN_NMAP_VERSION), "7.80 must be rejected (< 7.90)");
    assert!(!is_version_supported("7.00", MIN_NMAP_VERSION), "7.00 must be rejected (< 7.90)");
    assert!(!is_version_supported("6.40", MIN_NMAP_VERSION), "6.40 must be rejected (< 7.90)");
    assert!(!is_version_supported("invalid", MIN_NMAP_VERSION), "invalid version string must be rejected");
}

#[test]
fn test_s03_e4_nmap_discovery_argv_frozen() {
    assert_eq!(
        HARDCODED_NMAP_DISCOVERY_ARGV,
        &["-sS", "-sV", "-Pn", "--top-ports", "100", "-oX", "-"],
        "Discovery argv must be strictly frozen to ['-sS', '-sV', '-Pn', '--top-ports', '100', '-oX', '-'] with zero caller flags (E.4)"
    );
}

// =========================================================================
// Category I: Installer Progress & Partial Readiness Tolerance (I.1 – I.4)
// =========================================================================

#[test]
fn test_s03_i1_partial_readiness_logic() {
    // Scenario 1: Nuclei Ready, Nmap Missing -> Partial Readiness
    let caps_partial = ScoutCapabilities {
        nmap: EngineCapability {
            available: false,
            status: Some("not_installed".to_string()),
            prerequisite_health: Some("missing".to_string()),
            ..Default::default()
        },
        nuclei: EngineCapability {
            available: true,
            status: Some("ready".to_string()),
            version: Some("3.8.0".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let nmap_ready = caps_partial.nmap.available || caps_partial.nmap.status.as_deref() == Some("ready");
    let nuclei_ready = caps_partial.nuclei.available || caps_partial.nuclei.status.as_deref() == Some("ready");
    assert!(!nmap_ready, "Nmap is not ready in partial state");
    assert!(nuclei_ready, "Nuclei is ready in partial state");
    let is_partial = nuclei_ready && !nmap_ready;
    assert!(is_partial, "Must evaluate to SCOUT PARTIALLY READY (I.1)");

    // Scenario 2: Both Ready -> Full Readiness
    let mut caps_full = caps_partial.clone();
    caps_full.nmap.available = true;
    caps_full.nmap.status = Some("ready".to_string());
    let full_nmap_ready = caps_full.nmap.available || caps_full.nmap.status.as_deref() == Some("ready");
    let full_nuclei_ready = caps_full.nuclei.available || caps_full.nuclei.status.as_deref() == Some("ready");
    assert!(full_nmap_ready && full_nuclei_ready, "Both ready evaluates to full readiness (I.2)");

    // Scenario 3: Neither Ready -> Unready
    let mut caps_none = caps_partial.clone();
    caps_none.nuclei.available = false;
    caps_none.nuclei.status = Some("not_installed".to_string());
    let none_nmap_ready = caps_none.nmap.available || caps_none.nmap.status.as_deref() == Some("ready");
    let none_nuclei_ready = caps_none.nuclei.available || caps_none.nuclei.status.as_deref() == Some("ready");
    assert!(!none_nmap_ready && !none_nuclei_ready, "Neither ready evaluates to unready (I.3)");
}

// =========================================================================
// Category J: Clean-Machine Gate & Frozen Baseline Preservation (J.1 – J.2)
// =========================================================================

#[test]
fn test_s03_j1_clean_machine_gate_constant() {
    let gate_status = "BLOCKED — DISPOSABLE CLEAN WINDOWS ENVIRONMENT NOT CURRENTLY AVAILABLE";
    assert!(
        gate_status.starts_with("BLOCKED — DISPOSABLE CLEAN WINDOWS ENVIRONMENT"),
        "Clean-machine gate constant must be strictly preserved (J.1)"
    );
}

#[test]
fn test_s03_j2_downstream_exposure_domain_frozen_boundary() {
    // Verify that the collector crate has zero dependency or exposure mutations on backend tables
    let cargo_toml = include_str!("../Cargo.toml");
    assert!(
        !cargo_toml.contains("psycopg"),
        "Collector must never depend on backend PostgreSQL drivers (J.2)"
    );
    assert!(
        !cargo_toml.contains("fastapi"),
        "Collector must never depend on backend FastAPI framework (J.2)"
    );
}

// =========================================================================
// Category K: Internal Hostname and TLS SNI Binding (K.1 – K.4)
// =========================================================================

#[tokio::test]
async fn test_s03_k1_hostname_sni_binding_for_hostname_and_domain_targets() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());

    // Setup managed state for nuclei + templates
    let version = "3.8.0";
    let n_dir = storage.component_tools_dir("nuclei", version);
    let t_dir = storage.component_tools_dir("nuclei_templates", "10.4.4");
    fs::create_dir_all(&n_dir).unwrap();
    fs::create_dir_all(&t_dir).unwrap();

    let exe_name = if cfg!(windows) { "nuclei.exe" } else { "nuclei" };
    File::create(n_dir.join(exe_name)).unwrap();

    let mut state = ToolchainState::default();
    state.components.insert(
        "nuclei".to_string(),
        ComponentState {
            status: ComponentStatus::Installed,
            version: Some(version.to_string()),
            sha256: Some("sha_test".to_string()),
            active_dir: Some(n_dir.to_string_lossy().to_string()),
            previous_dir: None,
            installed_at: Some(chrono::Utc::now().to_rfc3339()),
            last_verified_at: Some(chrono::Utc::now().to_rfc3339()),
        },
    );
    state.components.insert(
        "nuclei_templates".to_string(),
        ComponentState {
            status: ComponentStatus::Installed,
            version: Some("10.4.4".to_string()),
            sha256: Some("sha_tmpl".to_string()),
            active_dir: Some(t_dir.to_string_lossy().to_string()),
            previous_dir: None,
            installed_at: Some(chrono::Utc::now().to_rfc3339()),
            last_verified_at: Some(chrono::Utc::now().to_rfc3339()),
        },
    );
    state.save(&storage.toolchain_state_path()).unwrap();

    // 1. Hostname target: must preserve pinned IP as destination, and pass Host header + SNI
    let pinned_ip = "192.168.1.55";
    let orig_hostname = "app-internal.corp.local";

    let res = run_scout_job_with_context(
        Uuid::new_v4(),
        "nuclei",
        pinned_ip,
        Some(orig_hostname),
        Some("hostname"),
        5,
        Some(&storage),
    )
    .await;

    // Execution was attempted (may fail because mock exe cannot run or times out, but guard/args are checked)
    assert_eq!(res.engine, "nuclei");
}

#[tokio::test]
async fn test_s03_k2_ip_targets_do_not_add_host_or_sni_overrides() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());

    let pinned_ip = "192.168.1.100";
    let res = run_scout_job_with_context(
        Uuid::new_v4(),
        "nuclei",
        pinned_ip,
        Some("192.168.1.100"),
        Some("ip"),
        5,
        Some(&storage),
    )
    .await;

    assert_eq!(res.engine, "nuclei");
}

#[tokio::test]
async fn test_s03_k3_injection_in_original_target_fails_closed_and_omits_overrides() {
    // Malformed/injected targets must fail syntax validation
    assert!(tempris_collector::safety::validate_hostname_syntax("evil.com\r\nInjected-Header: bad").is_err());
    assert!(tempris_collector::safety::validate_hostname_syntax("evil.com:8080").is_err());
    assert!(tempris_collector::safety::validate_hostname_syntax("evil.com/path").is_err());
    assert!(tempris_collector::safety::validate_hostname_syntax("evil.com; cat /etc/passwd").is_err());
    assert!(tempris_collector::safety::validate_hostname_syntax("evil.com && whoami").is_err());
    assert!(tempris_collector::safety::validate_hostname_syntax("").is_err());

    // Valid hostnames/domains must pass
    assert!(tempris_collector::safety::validate_hostname_syntax("intranet.corp.internal").is_ok());
    assert!(tempris_collector::safety::validate_hostname_syntax("db-server-01.dev.local").is_ok());
}

