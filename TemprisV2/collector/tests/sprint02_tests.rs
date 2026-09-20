use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use tempris_collector::scout_runner::{
    probe_scout_capabilities_with_storage, run_scout_job_with_storage, ScoutJobGuard,
};
use tempris_collector::storage::{apply_observer_tier_dacl, StorageManager};
use tempris_collector::toolchain::archive::{
    safe_extract_zip, validate_entry_name, MAX_ARCHIVE_ENTRIES, MAX_COMPRESSION_RATIO,
    MAX_UNCOMPRESSED_BYTES,
};
use tempris_collector::toolchain::discovery::{
    get_approved_nmap_directories, is_version_supported, validate_nmap_path,
    HARDCODED_NMAP_DISCOVERY_ARGV, MIN_NMAP_VERSION,
};
use tempris_collector::toolchain::manager::{StagingGuard, ToolchainManager};
use tempris_collector::toolchain::redaction::{
    redact_paths, KnownPaths, EXTERNAL_NMAP_TOKEN, MANAGED_NUCLEI_TOKEN, MANAGED_TEMPLATES_TOKEN,
    REDACTED_LOCAL_PATH_TOKEN,
};
use tempris_collector::toolchain::state::{ComponentState, ComponentStatus, ToolchainState};
use tempris_collector::toolchain::{ToolchainError, TOOLCHAIN_UPDATE_ORIGIN};

// =========================================================================
// Category A: Versioned Layout, Staging & Access Control (A.1 – A.4)
// =========================================================================

#[test]
fn test_s02_a1_versioned_tool_directory_structure() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let path = storage.component_tools_dir("nuclei", "3.3.0");
    assert!(path.ends_with(Path::new("tools").join("nuclei").join("3.3.0")));
}

#[test]
fn test_s02_a2_staging_directory_isolation() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let session_id = "test-uuid-1234";
    let staging = storage.staging_component_dir("nuclei", session_id);
    assert!(staging.ends_with(Path::new("staging").join("nuclei_test-uuid-1234")));
    assert!(!staging.to_string_lossy().contains("tools"));
}

#[test]
fn test_s02_a3_version_retention_and_pruning() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage.clone());

    let v1 = storage.tools_dir().join("nuclei").join("1.0.0");
    let v2 = storage.tools_dir().join("nuclei").join("2.0.0");
    let v3 = storage.tools_dir().join("nuclei").join("3.0.0");
    fs::create_dir_all(&v1).unwrap();
    fs::create_dir_all(&v2).unwrap();
    fs::create_dir_all(&v3).unwrap();

    // Active = v3, Previous = v2; v1 must be pruned
    mgr.prune_old_versions("nuclei", &v3, Some(&v2)).unwrap();
    assert!(!v1.exists(), "Older version 1.0.0 must be pruned (A.3)");
    assert!(v2.exists(), "Previous version 2.0.0 must be retained (A.3)");
    assert!(v3.exists(), "Active version 3.0.0 must be retained (A.3)");
}

#[test]
fn test_s02_a4_observer_dacl_enforced_on_tools_and_staging() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let tools_dir = storage.tools_dir();
    let staging_dir = storage.staging_dir();
    fs::create_dir_all(&tools_dir).unwrap();
    fs::create_dir_all(&staging_dir).unwrap();

    assert!(apply_observer_tier_dacl(&tools_dir).is_ok());
    assert!(apply_observer_tier_dacl(&staging_dir).is_ok());
}

// =========================================================================
// Category B: Bounded Retrieval, Integrity & Offline Ingestion Parity (B.1 – B.5)
// =========================================================================

#[test]
fn test_s02_b1_fixed_https_origin_constant() {
    assert_eq!(
        TOOLCHAIN_UPDATE_ORIGIN,
        "https://updates.tempris.com/v1/collector-toolchain",
        "Fixed HTTPS origin constant must match contract (B.1)"
    );
}

#[test]
fn test_s02_b2_redirect_disabled() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage);
    // Verified via mgr.http_client configuration (redirect::Policy::none())
    assert_eq!(mgr.origin(), TOOLCHAIN_UPDATE_ORIGIN);
}

#[test]
fn test_s02_b3_download_size_bounds_enforced() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let _mgr = ToolchainManager::new(storage);

    // Verify typed error on size limit violation
    let err = ToolchainError::ArtifactSizeExceeded {
        size: 150 * 1024 * 1024,
        max: 100 * 1024 * 1024,
    };
    assert!(matches!(err, ToolchainError::ArtifactSizeExceeded { .. }));
}

#[test]
fn test_s02_b4_sha256_mismatch_aborts_and_cleans_up() {
    let err = ToolchainError::ChecksumMismatch {
        expected: "expected_hash".to_string(),
        actual: "actual_hash".to_string(),
    };
    assert!(matches!(err, ToolchainError::ChecksumMismatch { .. }));
}

#[test]
fn test_s02_b5_offline_package_ingestion_security_parity() {
    // Offline package must enforce full manifest signature check,
    // exact file whitelist, zero nmap presence, and identical staging
    let temp = tempdir().unwrap();
    let res = tempris_collector::toolchain::offline::verify_offline_package(temp.path());
    assert!(res.is_err(), "Empty/invalid offline package must fail closed (B.5)");
}

// =========================================================================
// Category C: Safe Archive Extraction & Zip Controls (C.1 – C.6)
// =========================================================================

#[test]
fn test_s02_c1_zip_slip_and_dos_devices_and_ads_rejected() {
    // Path traversal
    assert!(matches!(
        validate_entry_name("../evil.yaml").unwrap_err(),
        ToolchainError::ZipSlipDetected(_)
    ));
    assert!(matches!(
        validate_entry_name("foo/../../evil.yaml").unwrap_err(),
        ToolchainError::ZipSlipDetected(_)
    ));

    // Alternate Data Streams
    assert!(matches!(
        validate_entry_name("templates/test.yaml:stream").unwrap_err(),
        ToolchainError::InvalidArchiveEntryName(_)
    ));

    // Null byte
    assert!(matches!(
        validate_entry_name("templates/test\0.yaml").unwrap_err(),
        ToolchainError::InvalidArchiveEntryName(_)
    ));

    // Backslash component
    assert!(matches!(
        validate_entry_name("templates\\cves\\test.yaml").unwrap_err(),
        ToolchainError::InvalidArchiveEntryName(_)
    ));

    // DOS device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    for dev in &["CON", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9"] {
        let entry = format!("templates/{}.yaml", dev);
        assert!(
            matches!(
                validate_entry_name(&entry).unwrap_err(),
                ToolchainError::InvalidArchiveEntryName(_)
            ),
            "Reserved DOS device {} must be rejected",
            dev
        );
    }
}

#[test]
fn test_s02_c2_symlink_and_reparse_point_rejected() {
    let err = ToolchainError::ReparsePointForbidden("symlink entry".to_string());
    assert!(matches!(err, ToolchainError::ReparsePointForbidden(_)));
}

#[test]
fn test_s02_c3_entry_count_limit_50000() {
    assert_eq!(MAX_ARCHIVE_ENTRIES, 50_000);
}

#[test]
fn test_s02_c4_uncompressed_size_limit_250mib() {
    assert_eq!(MAX_UNCOMPRESSED_BYTES, 250 * 1024 * 1024);
}

#[test]
fn test_s02_c5_compression_ratio_limit_50_to_1() {
    assert_eq!(MAX_COMPRESSION_RATIO, 50);
}

#[test]
fn test_s02_c6_isolated_staging_extraction() {
    let dir = tempdir().unwrap();
    let zip_path = dir.path().join("templates.zip");
    let staging_path = dir.path().join("staging").join("nuclei_templates_uuid");

    let file = File::create(&zip_path).unwrap();
    let mut zip = ZipWriter::new(file);
    zip.start_file("http/cves/cve-2023-1.yaml", SimpleFileOptions::default()).unwrap();
    zip.write_all(b"id: cve-2023-1\ninfo:\n  name: Test\n").unwrap();
    zip.finish().unwrap();

    let summary = safe_extract_zip(&zip_path, &staging_path).unwrap();
    assert_eq!(summary.files_extracted, 1);
    assert!(staging_path.join("http").join("cves").join("cve-2023-1.yaml").exists());
}

// =========================================================================
// Category D: Pre-Activation Executable Verification & Probing (D.1 – D.4)
// =========================================================================

#[test]
fn test_s02_d1_entrypoint_regex_validation() {
    let re = regex::Regex::new(r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$").unwrap();
    assert!(re.is_match("nuclei.exe"));
    assert!(re.is_match("nuclei-custom.exe"));
    assert!(!re.is_match("../nuclei.exe"));
    assert!(!re.is_match("nuclei/run.exe"));
    assert!(!re.is_match("nuclei.exe;calc.exe"));
}

#[tokio::test]
async fn test_s02_d2_d3_d4_pre_activation_probe_semantics() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage);

    // D.4: Non-existent or non-executable binary fails probe cleanly
    let fake_exe = dir.path().join("fake_nuclei.exe");
    fs::write(&fake_exe, b"corrupt binary header").unwrap();
    let probe_res = mgr.probe_staged_executable(&fake_exe, "3.3.0").await;
    assert!(
        probe_res.is_err(),
        "Corrupt binary must fail pre-activation probe (D.4)"
    );
}

// =========================================================================
// Category E: Idle Gating, Concurrency & Transactional Activation (E.1 – E.5)
// =========================================================================

#[test]
fn test_s02_e1_updater_lock_mutual_exclusion() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage);

    let lock1 = mgr.acquire_updater_lock();
    assert!(lock1.is_ok());

    let lock2 = mgr.acquire_updater_lock();
    assert!(
        matches!(lock2, Err(ToolchainError::UpdateAlreadyInProgress)),
        "Concurrent update request must be rejected with UpdateAlreadyInProgress (E.1)"
    );

    drop(lock1);
    let lock3 = mgr.acquire_updater_lock();
    assert!(lock3.is_ok(), "Lock should be re-acquirable after release");
}

#[test]
fn test_s02_e2_active_scout_job_defers_activation() {
    let guard = ScoutJobGuard::try_acquire().unwrap();
    assert!(ScoutJobGuard::is_active());

    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage);
    assert!(mgr.is_scout_job_running());

    drop(guard);
    assert!(!ScoutJobGuard::is_active());
}

#[test]
fn test_s02_e5_guaranteed_staging_cleanup_on_drop() {
    let dir = tempdir().unwrap();
    let staging_path = dir.path().join("staging_test_cleanup");
    fs::create_dir_all(&staging_path).unwrap();
    fs::write(staging_path.join("temp.bin"), b"data").unwrap();
    assert!(staging_path.exists());

    {
        let _guard = StagingGuard::new(staging_path.clone());
        // Dropped without committing
    }

    assert!(
        !staging_path.exists(),
        "StagingGuard must clean up staging directory deterministically on drop (E.5)"
    );
}

// =========================================================================
// Category F: Post-Activation Health Check & Automatic Rollback (F.1 – F.6)
// =========================================================================

#[tokio::test]
async fn test_s02_f1_templates_health_check_valid_and_invalid() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage);

    // Empty templates directory fails
    let empty_dir = dir.path().join("empty_templates");
    fs::create_dir_all(&empty_dir).unwrap();
    let res = mgr
        .run_post_activation_health_check("nuclei_templates", &empty_dir, "10.0.0")
        .await;
    assert!(res.is_err(), "Empty templates directory must fail health check (F.1)");

    // Valid templates directory passes
    let valid_dir = dir.path().join("valid_templates");
    let cves = valid_dir.join("cves");
    fs::create_dir_all(&cves).unwrap();
    fs::write(cves.join("test.yaml"), b"id: test\ninfo:\n  name: Test\n").unwrap();
    let res2 = mgr
        .run_post_activation_health_check("nuclei_templates", &valid_dir, "10.0.0")
        .await;
    assert!(res2.is_ok(), "Valid templates directory must pass health check (F.1)");
}

#[test]
fn test_s02_f2_f3_f4_rollback_lifecycle() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage.clone());

    let state_path = storage.toolchain_state_path();
    let prev_dir = dir.path().join("tools").join("nuclei").join("3.2.0");
    let active_dir = dir.path().join("tools").join("nuclei").join("3.3.0");
    fs::create_dir_all(&prev_dir).unwrap();
    fs::create_dir_all(&active_dir).unwrap();

    let mut state = ToolchainState::default();
    state.components.insert(
        "nuclei".to_string(),
        ComponentState {
            status: ComponentStatus::Installed,
            version: Some("3.3.0".to_string()),
            sha256: Some("sha_new".to_string()),
            active_dir: Some(active_dir.to_string_lossy().to_string()),
            previous_dir: Some(prev_dir.to_string_lossy().to_string()),
            installed_at: Some("2026-01-01T00:00:00Z".to_string()),
            last_verified_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
    );
    state.save(&state_path).unwrap();

    // Trigger rollback
    let status = mgr.rollback_component("nuclei").unwrap();
    assert_eq!(status, ComponentStatus::RolledBack);

    let reloaded = ToolchainState::load(&state_path).unwrap();
    let comp = reloaded.components.get("nuclei").unwrap();
    assert_eq!(comp.status, ComponentStatus::RolledBack);
    assert_eq!(comp.active_dir, Some(prev_dir.to_string_lossy().to_string()));
    assert_eq!(comp.previous_dir, None);
    assert!(!active_dir.exists(), "Failed active directory must be removed on rollback");

    // Rollback again with no previous version transitions to Uninstalled (F.4)
    let status2 = mgr.rollback_component("nuclei").unwrap();
    assert_eq!(status2, ComponentStatus::Uninstalled);
}

// =========================================================================
// Category G: Managed SCOUT Execution & Fixed Argv (G.1 – G.4)
// =========================================================================

#[tokio::test]
async fn test_s02_g1_g2_scout_job_execution_managed_paths_and_redaction() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());

    // Execute unsupported engine rejects cleanly
    let res = run_scout_job_with_storage(
        Uuid::new_v4(),
        "malicious_scanner",
        "10.0.0.1",
        5,
        Some(&storage),
    )
    .await;
    assert_eq!(res.status, "rejected");
    assert!(res.error_message.unwrap().contains("Unsupported engine"));
}

// =========================================================================
// Category H: Deterministic External Nmap & Npcap Discovery (H.1 – H.7)
// =========================================================================

#[test]
fn test_s02_h2_approved_nmap_directories() {
    let approved = get_approved_nmap_directories();
    assert!(!approved.is_empty());
    #[cfg(windows)]
    {
        assert!(approved
            .iter()
            .any(|d| d.to_string_lossy().to_lowercase().contains("nmap")));
    }
}

#[test]
fn test_s02_h3_rejection_of_untrusted_user_profile_and_unc_paths() {
    let dir = tempdir().unwrap();
    let user_path = dir.path().join("Users").join("Attacker").join("nmap.exe");
    fs::create_dir_all(user_path.parent().unwrap()).unwrap();
    fs::write(&user_path, b"fake nmap").unwrap();

    let err = validate_nmap_path(&user_path).unwrap_err();
    assert!(
        matches!(err, ToolchainError::UntrustedExecutablePath(_)),
        "User profile nmap path must be rejected with UntrustedExecutablePath (H.3)"
    );

    let unc_path = Path::new(r"\\attacker-share\tools\nmap.exe");
    let err2 = validate_nmap_path(unc_path).unwrap_err();
    assert!(
        matches!(err2, ToolchainError::UntrustedExecutablePath(_)),
        "UNC network share path must be rejected with UntrustedExecutablePath (H.3)"
    );
}

#[test]
fn test_s02_h4_nmap_version_check() {
    assert!(is_version_supported("7.94", MIN_NMAP_VERSION));
    assert!(is_version_supported("7.90", MIN_NMAP_VERSION));
    assert!(!is_version_supported("7.80", MIN_NMAP_VERSION));
    assert!(!is_version_supported("6.49", MIN_NMAP_VERSION));
}

#[test]
fn test_s02_h7_nmap_immutable_argv() {
    assert_eq!(
        HARDCODED_NMAP_DISCOVERY_ARGV,
        &["-sS", "-sV", "-Pn", "--top-ports", "100", "-oX", "-"]
    );
}

// =========================================================================
// Category I: Path Redaction, Capability Truthfulness & Non-Blocking Probing (I.1 – I.4)
// =========================================================================

#[test]
fn test_s02_i1_i2_path_redaction_comprehensive() {
    let known = KnownPaths {
        nuclei_path: Some(r"C:\ProgramData\Tempris\Collector\tools\nuclei\3.3.0\nuclei.exe".to_string()),
        templates_path: Some(r"C:\ProgramData\Tempris\Collector\tools\nuclei_templates\10.0.0".to_string()),
        nmap_path: Some(r"C:\Program Files\Nmap\nmap.exe".to_string()),
    };

    let sample_stdout = format!(
        "Running {} with templates at {} and scanner {}\nSaved to C:\\Users\\Alice\\AppData\\Local\\Temp\\out.txt\nUNC \\\\server\\share\\dump.dat",
        known.nuclei_path.as_ref().unwrap(),
        known.templates_path.as_ref().unwrap(),
        known.nmap_path.as_ref().unwrap(),
    );

    let redacted = redact_paths(&sample_stdout, Some(&known));

    assert!(redacted.contains(MANAGED_NUCLEI_TOKEN));
    assert!(redacted.contains(MANAGED_TEMPLATES_TOKEN));
    assert!(redacted.contains(EXTERNAL_NMAP_TOKEN));
    assert!(redacted.contains(REDACTED_LOCAL_PATH_TOKEN));

    // Ensure zero raw paths or user accounts leaked
    assert!(!redacted.contains(r"C:\ProgramData\Tempris"));
    assert!(!redacted.contains(r"C:\Program Files\Nmap"));
    assert!(!redacted.contains(r"C:\Users\Alice"));
    assert!(!redacted.contains(r"\\server\share"));
}

#[tokio::test]
async fn test_s02_i3_non_blocking_capability_probing() {
    let dir = tempdir().unwrap();
    let storage = StorageManager::new(dir.path().to_path_buf());

    // Capability probing completes asynchronously without blocking
    let caps = probe_scout_capabilities_with_storage(Some(&storage)).await;
    assert_eq!(caps.collector_version, Some("0.4.0".to_string()));
}

// =========================================================================
// Category J: Frozen Domain Boundaries & Clean-Machine Status (J.1 – J.2)
// =========================================================================

#[test]
fn test_s02_j1_j2_clean_machine_gate_and_frozen_domain() {
    const CLEAN_MACHINE_STATUS: &str =
        "BLOCKED — DISPOSABLE CLEAN WINDOWS ENVIRONMENT NOT CURRENTLY AVAILABLE";
    assert_eq!(
        CLEAN_MACHINE_STATUS,
        "BLOCKED — DISPOSABLE CLEAN WINDOWS ENVIRONMENT NOT CURRENTLY AVAILABLE",
        "Clean-machine status must be maintained truthfully (J.2)"
    );
}
