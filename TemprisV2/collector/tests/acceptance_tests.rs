use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, Verifier};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

use tempris_collector::autostart::{AutoStartError, AutoStartManager};
use tempris_collector::crypto::{
    generate_keypair, public_key_from_base64url, public_key_to_base64url,
};
use tempris_collector::lifecycle::{RuntimeSnapshot, RuntimeStatus};
use tempris_collector::logging::BoundedLogger;
use tempris_collector::safety::is_forbidden_ip;
use tempris_collector::singleton::{LockResult, SingleInstanceGuard};
use tempris_collector::storage::{CollectorState, StorageError, StorageManager};
use tempris_collector::ui::CollectorApp;
use tempris_collector::verifier::verify_internal_target;

/// Helper to create a temporary test directory
fn create_test_storage_dir(prefix: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "tempris_e2e_{}_{}",
        prefix,
        Uuid::new_v4().simple()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Cleanup helper
fn cleanup_test_dir(dir: &PathBuf) {
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_e2e_restart_identity_continuity() {
    let test_dir = create_test_storage_dir("restart_continuity");
    let storage = StorageManager::new(test_dir.clone());

    let (signing_key_original, verifying_key_original) = generate_keypair();
    let original_col_id = Uuid::new_v4();
    let original_pubkey_b64 = public_key_to_base64url(&verifying_key_original);
    let original_col_name = "Workstation-PROD-01";
    let original_server_url = "https://sandbox.tempris.tech/v2-assets";

    // 1. Initial enrollment & persistence
    let initial_state = CollectorState::new(
        original_col_id,
        original_col_name.to_string(),
        original_server_url.to_string(),
        original_pubkey_b64.clone(),
        Utc::now(),
    );

    storage
        .save(&initial_state, &signing_key_original)
        .expect("Failed to save enrolled collector identity");

    // 2. Simulate complete process restart: drop old in-memory objects and reload freshly from disk
    drop(storage);
    drop(signing_key_original);

    let restarted_storage = StorageManager::new(test_dir.clone());
    let load_res = restarted_storage.load();
    assert!(
        load_res.is_ok(),
        "Restarted storage load must succeed without prompting"
    );

    let (loaded_state, loaded_signing_key) = load_res.unwrap();

    // 3. Verify exact identity and crypto key continuity
    assert_eq!(loaded_state.collector_id, original_col_id);
    assert_eq!(loaded_state.collector_name, original_col_name);
    assert_eq!(loaded_state.server_url, original_server_url);
    assert_eq!(loaded_state.public_key, original_pubkey_b64);

    // Verify loaded signing key reproduces exact verifying key and valid signatures
    let derived_verifying_key = loaded_signing_key.verifying_key();
    let derived_pubkey_b64 = public_key_to_base64url(&derived_verifying_key);
    assert_eq!(derived_pubkey_b64, original_pubkey_b64);

    let challenge = b"tempris-auth-challenge-nonce-123456";
    let signature = loaded_signing_key.sign(challenge);
    let verifier_pk = public_key_from_base64url(&original_pubkey_b64).expect("Valid public key");
    assert!(verifier_pk.verify(challenge, &signature).is_ok());

    cleanup_test_dir(&test_dir);
}

#[test]
fn test_e2e_advanced_reset_wipes_all_artifacts_and_task() {
    let test_dir = create_test_storage_dir("advanced_reset");
    let storage = StorageManager::new(test_dir.clone());

    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let state = CollectorState::new(
        col_id,
        "Reset-Target-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        pubkey_b64,
        Utc::now(),
    );

    // Save enrollment state
    storage.save(&state, &signing_key).unwrap();

    // Write runtime snapshot
    let snapshot = RuntimeSnapshot::new(
        col_id,
        "Reset-Target-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snapshot.save_atomic(&storage.runtime_path()).unwrap();

    // Verify files exist prior to reset
    assert!(storage.state_path().exists());
    assert!(storage.identity_path().exists());
    assert!(storage.runtime_path().exists());

    // Setup custom autostart manager for test task name
    let test_task_name = format!("TemprisTestResetTask_{}", Uuid::new_v4().simple());
    let autostart = AutoStartManager::new(Some(&test_task_name));

    // Execute two-step destructive reset
    let unregister_res = autostart.unregister();
    assert!(unregister_res.is_ok());

    let reset_res = storage.reset();
    assert!(reset_res.is_ok(), "Storage reset must return Ok");

    // Verify all credentials and snapshots are wiped
    assert!(!storage.state_path().exists(), "state.json must be removed");
    assert!(
        !storage.identity_path().exists(),
        "protected_identity.dat must be removed"
    );
    assert!(
        !storage.runtime_path().exists(),
        "runtime.json must be removed"
    );

    // Verify reloading reports unenrolled (NotFound)
    match storage.load() {
        Err(StorageError::NotFound) => {
            // Expected
        }
        other => panic!(
            "Expected StorageError::NotFound after reset, got {:?}",
            other
        ),
    }

    cleanup_test_dir(&test_dir);
}

#[test]
fn test_e2e_zero_secret_leakage_audit() {
    let test_dir = create_test_storage_dir("secret_leakage_audit");
    let storage = StorageManager::new(test_dir.clone());

    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let secret_raw_bytes = signing_key.to_bytes();
    let secret_hex = hex::encode(secret_raw_bytes);
    let secret_base64 = base64::engine::general_purpose::STANDARD.encode(secret_raw_bytes);
    let secret_url_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_raw_bytes);

    let state = CollectorState::new(
        col_id,
        "Audit-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        pubkey_b64,
        Utc::now(),
    );

    // Save enrollment state
    storage.save(&state, &signing_key).unwrap();

    // Write runtime snapshot
    let mut snapshot = RuntimeSnapshot::new(
        col_id,
        "Audit-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snapshot.current_activity = "Verifying 10.0.0.1:443".to_string();
    snapshot.save_atomic(&storage.runtime_path()).unwrap();

    // Write logs
    let logs_dir = storage.logs_dir();
    let logger = BoundedLogger::new(logs_dir);
    logger.log("INFO", "Collector connected to control plane");
    logger.log("INFO", "Received VERIFY_TARGET job for 10.0.0.1:443");
    logger.log("INFO", "Verification completed: OPEN");

    // Perform comprehensive static sweep of all files in storage directory
    let entries = fs::read_dir(&test_dir).unwrap();
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            let content = fs::read(&path).unwrap();
            let content_str = String::from_utf8_lossy(&content).to_string();

            if path.file_name().unwrap() != "protected_identity.dat" {
                // Assert no secret representations in plain text files
                assert!(
                    !content_str.contains(&secret_hex),
                    "Secret hex found in plaintext file {:?}",
                    path
                );
                assert!(
                    !content_str.contains(&secret_base64),
                    "Secret base64 found in plaintext file {:?}",
                    path
                );
                assert!(
                    !content_str.contains(&secret_url_b64),
                    "Secret url-safe base64 found in plaintext file {:?}",
                    path
                );
                assert!(
                    !content_str.contains("private_key"),
                    "Keyword 'private_key' found in plaintext file {:?}",
                    path
                );
                assert!(
                    !content_str.contains("signing_key"),
                    "Keyword 'signing_key' found in plaintext file {:?}",
                    path
                );
            }
        }
    }

    cleanup_test_dir(&test_dir);
}

#[test]
fn test_e2e_singleton_prevents_duplicate_daemon_and_exits_cleanly() {
    let suffix = format!("_e2e_{}", Uuid::new_v4().simple());

    // 1. First daemon acquires the singleton lock
    let daemon1 = SingleInstanceGuard::acquire(Some(&suffix));
    let guard1 = match daemon1 {
        LockResult::Acquired(g) => g,
        other => panic!("Daemon 1 must acquire singleton lock, got {:?}", other),
    };

    // 2. Second daemon attempts to acquire the lock and detects already running
    let daemon2 = SingleInstanceGuard::acquire(Some(&suffix));
    assert_eq!(
        daemon2,
        LockResult::AlreadyRunning,
        "Daemon 2 must detect active singleton and return AlreadyRunning"
    );

    // 3. GUI checks if background daemon is running without acquiring
    assert!(SingleInstanceGuard::is_another_instance_running(Some(
        &suffix
    )));

    // 4. First daemon cleanly drops on termination
    drop(guard1);

    // 5. Subsequent daemon can now acquire lock
    assert!(!SingleInstanceGuard::is_another_instance_running(Some(
        &suffix
    )));
    let daemon3 = SingleInstanceGuard::acquire(Some(&suffix));
    assert!(matches!(daemon3, LockResult::Acquired(_)));
}

#[tokio::test]
async fn test_e2e_verify_target_safe_execution() {
    // 1. Forbidden IP checks
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert!(is_forbidden_ip(loopback));

    let link_local: std::net::IpAddr = "169.254.1.1".parse().unwrap();
    assert!(is_forbidden_ip(link_local));

    let multicast: std::net::IpAddr = "224.0.0.1".parse().unwrap();
    assert!(is_forbidden_ip(multicast));

    let unspecified: std::net::IpAddr = "0.0.0.0".parse().unwrap();
    assert!(is_forbidden_ip(unspecified));

    let valid_internal: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(!is_forbidden_ip(valid_internal));

    // 2. Forbidden target rejected with zero socket connect
    let forbidden_outcome = verify_internal_target("127.0.0.1", None).await;
    assert_eq!(forbidden_outcome.reachability_status, "unreachable");
    assert!(forbidden_outcome
        .error_message
        .unwrap()
        .contains("forbidden"));

    // 3. Invalid target syntax rejected with zero socket connect
    let invalid_outcome = verify_internal_target("https://invalid-url-with-path/test", None).await;
    assert_eq!(invalid_outcome.reachability_status, "unreachable");
    assert!(invalid_outcome.error_message.is_some());

    // 4. Unreachable private target
    let unreachable_outcome = verify_internal_target(
        "192.168.1.253",
        Some(&tempris_collector::safety::TargetType::Ip),
    )
    .await;
    assert_eq!(unreachable_outcome.reachability_status, "unreachable");
    assert_eq!(unreachable_outcome.port_reached, None);
}

#[test]
fn test_e2e_gui_observer_and_core_process_lifecycle_independence() {
    let suffix = format!("_lifecycle_{}", Uuid::new_v4().simple());
    let test_dir = create_test_storage_dir("gui_observer_core");
    let storage = StorageManager::new(test_dir.clone());

    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let state = CollectorState::new(
        col_id,
        "Independent-Core-Test".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    // 1. Independent Core process starts and acquires singleton
    let core_guard = match SingleInstanceGuard::acquire(Some(&suffix)) {
        LockResult::Acquired(g) => g,
        other => panic!("Core instance must acquire lock, got {:?}", other),
    };

    // Core writes runtime snapshot and disk logs
    let mut snap = RuntimeSnapshot::new(
        col_id,
        "Independent-Core-Test".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snap.last_heartbeat = Some(Utc::now());
    snap.jobs_verified = 5;
    snap.save_atomic(&storage.runtime_path())
        .expect("save runtime");

    let logger = BoundedLogger::new(storage.logs_dir());
    logger.log("INFO", "Core daemon initialized and connected to WSS");
    logger.log("INFO", "Heartbeat acknowledged by server");

    // 2. GUI opens in observer mode
    assert!(SingleInstanceGuard::is_another_instance_running(Some(
        &suffix
    )));
    // Observer reads state, runtime snapshot and tails logs without acquiring mutex
    let (loaded_state, _) = storage.load().expect("load state");
    assert_eq!(loaded_state.collector_id, col_id);

    let loaded_snap =
        RuntimeSnapshot::load_from(&storage.runtime_path()).expect("load runtime snapshot");
    assert_eq!(loaded_snap.status, RuntimeStatus::Connected);
    assert_eq!(loaded_snap.jobs_verified, 5);

    let tailed_logs = BoundedLogger::tail_from_disk(logger.log_path(), 50);
    assert_eq!(tailed_logs.len(), 2);
    assert!(tailed_logs[0].message.contains("Core daemon initialized"));

    // 3. Simulate closing GUI (observer drops its in-memory context)
    drop(loaded_snap);
    drop(loaded_state);
    drop(tailed_logs);

    // 4. Verify core remains alive and still holds singleton
    assert!(SingleInstanceGuard::is_another_instance_running(Some(
        &suffix
    )));

    // 5. Core terminates
    drop(core_guard);
    assert!(!SingleInstanceGuard::is_another_instance_running(Some(
        &suffix
    )));

    cleanup_test_dir(&test_dir);
}

#[test]
fn test_advanced_reset_fails_closed_when_core_running_and_preserves_identity() {
    let suffix = format!("_reset_fail_core_{}", Uuid::new_v4().simple());
    let test_dir = create_test_storage_dir("reset_fail_core");
    let storage = StorageManager::new(test_dir.clone());

    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let state = CollectorState::new(
        col_id,
        "Core-Running-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    let snap = RuntimeSnapshot::new(
        col_id,
        "Core-Running-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snap.save_atomic(&storage.runtime_path())
        .expect("save runtime");

    // 1. Simulate an independent core daemon actively holding the singleton mutex (does not exit)
    let core_guard = match SingleInstanceGuard::acquire(Some(&suffix)) {
        LockResult::Acquired(g) => g,
        other => panic!("Must acquire test lock, got {:?}", other),
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut app = CollectorApp::new(
        storage.clone(),
        Some(state.clone()),
        None,
        rt.handle().clone(),
    );

    assert!(app.state().is_some());
    assert_eq!(app.state().unwrap().collector_id, col_id);
    assert!(app.recovery_error().is_none());

    // 2. Attempt execute_advanced_reset while core is running (short timeout)
    let reset_result = app.execute_advanced_reset_custom(
        Some(&suffix),
        Some("NonExistentTask"),
        std::time::Duration::from_millis(300),
    );

    // 3. Verify reset FAILED closed
    assert!(
        reset_result.is_err(),
        "Reset must return Err when core fails to exit or cannot be signaled"
    );
    assert!(
        app.recovery_error().is_some(),
        "Recovery UI error must be populated"
    );
    let err_msg = app.recovery_error().unwrap();
    assert!(
        err_msg.contains("Background core process") || err_msg.contains("Failed to signal"),
        "Error message must specify core process failure, got: {}",
        err_msg
    );

    // 4. Verify in-memory state and credentials on disk were PRESERVED (not wiped)
    assert!(
        app.state().is_some(),
        "In-memory state must be preserved on reset failure"
    );
    assert_eq!(app.state().unwrap().collector_id, col_id);
    assert!(
        storage.state_path().exists(),
        "state.json must not be deleted on failure"
    );
    assert!(
        storage.identity_path().exists(),
        "protected_identity.dat must not be deleted on failure"
    );
    assert!(
        storage.runtime_path().exists(),
        "runtime.json must not be deleted on failure"
    );

    // 5. Verify retry_load() can reload existing state
    app.retry_load();
    assert!(
        app.recovery_error().is_none(),
        "retry_load clears recovery error upon loading valid state"
    );
    assert_eq!(app.state().unwrap().collector_id, col_id);

    // Clean up
    drop(core_guard);
    cleanup_test_dir(&test_dir);
}

#[test]
fn test_advanced_reset_fails_closed_when_autostart_unregister_fails_and_preserves_identity() {
    let suffix = format!("_reset_fail_autostart_{}", Uuid::new_v4().simple());
    let test_dir = create_test_storage_dir("reset_fail_autostart");
    let storage = StorageManager::new(test_dir.clone());

    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let state = CollectorState::new(
        col_id,
        "Autostart-Fail-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    let snap = RuntimeSnapshot::new(
        col_id,
        "Autostart-Fail-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snap.save_atomic(&storage.runtime_path())
        .expect("save runtime");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut app = CollectorApp::new(
        storage.clone(),
        Some(state.clone()),
        None,
        rt.handle().clone(),
    );

    // Simulate autostart unregister failure (e.g. Access Denied in Task Scheduler)
    let reset_result = app.execute_advanced_reset_with_unreg(
        Some(&suffix),
        std::time::Duration::from_millis(300),
        || {
            Err(AutoStartError::ExecutionFailed(
                "Access is denied to Task Scheduler".to_string(),
            ))
        },
    );

    // Verify reset FAILED closed
    assert!(
        reset_result.is_err(),
        "Reset must return Err when autostart unregistration fails"
    );
    assert!(
        app.recovery_error().is_some(),
        "Recovery UI error must be set"
    );
    let err_msg = app.recovery_error().unwrap();
    assert!(
        err_msg.contains("Failed to unregister Task Scheduler auto-start task"),
        "Error message must specify autostart unregister failure, got: {}",
        err_msg
    );

    // Verify in-memory state and credentials on disk were PRESERVED (not wiped)
    assert!(
        app.state().is_some(),
        "In-memory state must be preserved on reset failure"
    );
    assert_eq!(app.state().unwrap().collector_id, col_id);
    assert!(
        storage.state_path().exists(),
        "state.json must not be deleted on failure"
    );
    assert!(
        storage.identity_path().exists(),
        "protected_identity.dat must not be deleted on failure"
    );
    assert!(
        storage.runtime_path().exists(),
        "runtime.json must not be deleted on failure"
    );

    cleanup_test_dir(&test_dir);
}

#[test]
fn test_advanced_reset_success_path_cleans_credentials_and_updates_ui() {
    let suffix = format!("_reset_success_{}", Uuid::new_v4().simple());
    let test_dir = create_test_storage_dir("reset_success");
    let storage = StorageManager::new(test_dir.clone());

    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);

    let state = CollectorState::new(
        col_id,
        "Success-Reset-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        pubkey_b64,
        Utc::now(),
    );
    storage.save(&state, &signing_key).expect("save state");

    let snap = RuntimeSnapshot::new(
        col_id,
        "Success-Reset-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        RuntimeStatus::Connected,
    );
    snap.save_atomic(&storage.runtime_path())
        .expect("save runtime");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut app = CollectorApp::new(
        storage.clone(),
        Some(state.clone()),
        None,
        rt.handle().clone(),
    )
    .with_autostart_manager(AutoStartManager::new(Some(&format!(
        "TemprisTestTask_{}",
        suffix
    ))));

    // Execute reset where core is not running and autostart unregister succeeds (already absent or clean delete)
    let reset_result = app.execute_advanced_reset_with_unreg(
        Some(&suffix),
        std::time::Duration::from_millis(300),
        || Ok(()),
    );

    assert!(
        reset_result.is_ok(),
        "Reset must succeed when prerequisites are met"
    );
    assert!(app.recovery_error().is_none());
    assert!(
        app.state().is_none(),
        "In-memory state must be cleared to None upon successful reset"
    );

    // Verify all credentials and snapshots on disk are wiped
    assert!(
        !storage.state_path().exists(),
        "state.json must be deleted on successful reset"
    );
    assert!(
        !storage.identity_path().exists(),
        "protected_identity.dat must be deleted on successful reset"
    );
    assert!(
        !storage.runtime_path().exists(),
        "runtime.json must be deleted on successful reset"
    );
    assert!(matches!(storage.load(), Err(StorageError::NotFound)));

    cleanup_test_dir(&test_dir);
}
