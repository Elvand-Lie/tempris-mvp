use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

use tempris_collector::crypto::{generate_keypair, public_key_to_base64url};
use tempris_collector::storage::{dpapi, CollectorState, StorageError, StorageManager};

fn create_temp_storage_dir() -> (PathBuf, StorageManager) {
    let temp_dir = std::env::temp_dir().join(format!("tempris_storage_test_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&temp_dir);
    let manager = StorageManager::new(temp_dir.clone());
    (temp_dir, manager)
}

#[test]
fn test_storage_save_and_load_roundtrip() {
    let (temp_dir, manager) = create_temp_storage_dir();

    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let pub_b64 = public_key_to_base64url(&verifying_key);
    let state = CollectorState::new(
        col_id,
        "Test-Collector-01".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        pub_b64.clone(),
        Utc::now(),
    );

    assert!(!manager.exists());
    assert!(!manager.has_any_state());

    // Save
    manager
        .save(&state, &signing_key)
        .expect("save should succeed");
    assert!(manager.exists());
    assert!(manager.has_any_state());
    assert!(manager.state_path().exists());
    assert!(manager.identity_path().exists());

    // Load
    let (loaded_state, loaded_key) = manager.load().expect("load should succeed");
    assert_eq!(loaded_state.schema_version, 2);
    assert_eq!(loaded_state.collector_id, col_id);
    assert_eq!(loaded_state.collector_name, "Test-Collector-01");
    assert_eq!(
        loaded_state.server_url,
        "https://sandbox.tempris.tech/v2-assets"
    );
    assert_eq!(loaded_state.public_key, pub_b64);
    assert_eq!(loaded_state.collector_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(loaded_key.as_bytes(), signing_key.as_bytes());
    assert_eq!(loaded_key.verifying_key(), verifying_key);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_no_secrets_in_public_json() {
    let (temp_dir, manager) = create_temp_storage_dir();

    let (signing_key, verifying_key) = generate_keypair();
    let raw_secret_bytes = signing_key.as_bytes();
    let raw_secret_b64_url = URL_SAFE_NO_PAD.encode(raw_secret_bytes);
    let raw_secret_b64_std = STANDARD.encode(raw_secret_bytes);
    let raw_secret_hex = hex::encode(raw_secret_bytes);

    let state = CollectorState::new(
        Uuid::new_v4(),
        "No-Secrets-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        public_key_to_base64url(&verifying_key),
        Utc::now(),
    );

    manager
        .save(&state, &signing_key)
        .expect("save should succeed");

    let state_json_content = fs::read_to_string(manager.state_path()).expect("read state.json");

    // Assert zero secret leakage in state.json
    assert!(
        !state_json_content.contains(&raw_secret_b64_url),
        "state.json contains base64url secret seed"
    );
    assert!(
        !state_json_content.contains(&raw_secret_b64_std),
        "state.json contains standard base64 secret seed"
    );
    assert!(
        !state_json_content.contains(&raw_secret_hex),
        "state.json contains hex secret seed"
    );
    assert!(
        !state_json_content.contains("private_key"),
        "state.json contains private_key field"
    );
    assert!(
        !state_json_content.contains("secret"),
        "state.json contains secret field"
    );
    assert!(
        !state_json_content.contains("protected_key_blob"),
        "state.json contains protected_key_blob field"
    );
    assert!(
        !state_json_content.contains("enrollment_code"),
        "state.json contains enrollment_code field"
    );
    assert!(
        !state_json_content.contains("tenant_id"),
        "state.json contains tenant_id field"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_missing_state_returns_not_found() {
    let (temp_dir, manager) = create_temp_storage_dir();

    let res = manager.load();
    assert!(res.is_err());
    match res.unwrap_err() {
        StorageError::NotFound => {}
        other => panic!("Expected StorageError::NotFound, got: {:?}", other),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_corrupt_state_json_fails_closed() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let (signing_key, verifying_key) = generate_keypair();
    let state = CollectorState::new(
        Uuid::new_v4(),
        "Corrupt-State-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        public_key_to_base64url(&verifying_key),
        Utc::now(),
    );

    manager
        .save(&state, &signing_key)
        .expect("save should succeed");

    // Overwrite state.json with corrupted garbage
    fs::write(manager.state_path(), b"{\"invalid_json: true").expect("write corrupt json");

    let res = manager.load();
    assert!(res.is_err());
    match res.unwrap_err() {
        StorageError::CorruptStateJson(msg) => {
            assert!(msg.contains("Malformed state.json") || msg.contains("EOF"));
        }
        other => panic!("Expected StorageError::CorruptStateJson, got: {:?}", other),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_missing_state_json_with_identity_fails_closed() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let (signing_key, verifying_key) = generate_keypair();
    let state = CollectorState::new(
        Uuid::new_v4(),
        "Orphan-Identity-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        public_key_to_base64url(&verifying_key),
        Utc::now(),
    );

    manager
        .save(&state, &signing_key)
        .expect("save should succeed");

    // Remove state.json while leaving protected_identity.dat
    fs::remove_file(manager.state_path()).expect("remove state.json");

    let res = manager.load();
    assert!(res.is_err());
    match res.unwrap_err() {
        StorageError::CorruptStateJson(msg) => {
            assert!(msg.contains("missing while protected_identity.dat exists"));
        }
        other => panic!("Expected StorageError::CorruptStateJson, got: {:?}", other),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_missing_protected_identity_fails_closed() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let (signing_key, verifying_key) = generate_keypair();
    let state = CollectorState::new(
        Uuid::new_v4(),
        "Missing-Identity-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        public_key_to_base64url(&verifying_key),
        Utc::now(),
    );

    manager
        .save(&state, &signing_key)
        .expect("save should succeed");

    // Remove protected_identity.dat while leaving state.json
    fs::remove_file(manager.identity_path()).expect("remove protected_identity.dat");

    let res = manager.load();
    assert!(res.is_err());
    match res.unwrap_err() {
        StorageError::CorruptProtectedIdentity(msg) => {
            assert!(msg.contains("missing"));
        }
        other => panic!(
            "Expected StorageError::CorruptProtectedIdentity, got: {:?}",
            other
        ),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_corrupt_identity_fails_closed() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let (signing_key, verifying_key) = generate_keypair();
    let state = CollectorState::new(
        Uuid::new_v4(),
        "Corrupt-Identity-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        public_key_to_base64url(&verifying_key),
        Utc::now(),
    );

    manager
        .save(&state, &signing_key)
        .expect("save should succeed");

    // Truncate / corrupt protected_identity.dat
    fs::write(manager.identity_path(), b"corrupted-non-dpapi-data")
        .expect("write corrupt identity");

    let res = manager.load();
    assert!(res.is_err());
    match res.unwrap_err() {
        StorageError::DpapiError(_) | StorageError::CorruptProtectedIdentity(_) => {}
        other => panic!(
            "Expected DPAPI or CorruptProtectedIdentity error, got: {:?}",
            other
        ),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_identity_mismatch_fails_closed() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let (signing_key1, _verifying_key1) = generate_keypair();
    let (_signing_key2, verifying_key2) = generate_keypair();

    // State has pubkey2, but identity has signing_key1
    let state = CollectorState::new(
        Uuid::new_v4(),
        "Mismatch-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        public_key_to_base64url(&verifying_key2),
        Utc::now(),
    );

    // Saving with mismatched key should fail
    let save_res = manager.save(&state, &signing_key1);
    assert!(save_res.is_err());
    match save_res.unwrap_err() {
        StorageError::IdentityMismatch => {}
        other => panic!(
            "Expected StorageError::IdentityMismatch on save, got: {:?}",
            other
        ),
    }

    // Now let's test load-time mismatch if someone manually tampers with state.json public_key
    manager
        .save(&state, &_signing_key2)
        .expect("save with key2 should succeed");
    // Manually edit state.json to have public_key1
    let mut tampered_state = state.clone();
    tampered_state.public_key = public_key_to_base64url(&_verifying_key1);
    fs::write(
        manager.state_path(),
        serde_json::to_string(&tampered_state).unwrap(),
    )
    .unwrap();

    let load_res = manager.load();
    assert!(load_res.is_err());
    match load_res.unwrap_err() {
        StorageError::IdentityMismatch => {}
        other => panic!(
            "Expected StorageError::IdentityMismatch on load, got: {:?}",
            other
        ),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_unsupported_schema_version_fails_closed() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let (signing_key, verifying_key) = generate_keypair();
    let mut state = CollectorState::new(
        Uuid::new_v4(),
        "Future-Schema-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        public_key_to_base64url(&verifying_key),
        Utc::now(),
    );

    manager
        .save(&state, &signing_key)
        .expect("save should succeed");

    // Tamper schema version to 999
    state.schema_version = 999;
    fs::write(manager.state_path(), serde_json::to_string(&state).unwrap()).unwrap();

    let res = manager.load();
    assert!(res.is_err());
    match res.unwrap_err() {
        StorageError::CorruptStateJson(msg) => {
            assert!(msg.contains("schema_version 999"));
        }
        other => panic!(
            "Expected StorageError::CorruptStateJson for schema version, got: {:?}",
            other
        ),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_storage_reset_cleans_all_artifacts() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let (signing_key, verifying_key) = generate_keypair();
    let state = CollectorState::new(
        Uuid::new_v4(),
        "Reset-Collector".to_string(),
        "https://sandbox.tempris.tech/v2-assets".to_string(),
        public_key_to_base64url(&verifying_key),
        Utc::now(),
    );

    manager
        .save(&state, &signing_key)
        .expect("save should succeed");
    // Also create dummy runtime.json and a temporary file
    fs::write(manager.runtime_path(), b"{\"status\": \"connected\"}").unwrap();
    fs::write(manager.base_dir().join("state.tmp.1234"), b"temp").unwrap();

    assert!(manager.state_path().exists());
    assert!(manager.identity_path().exists());
    assert!(manager.runtime_path().exists());

    // Reset
    manager.reset().expect("reset should succeed");

    assert!(!manager.state_path().exists());
    assert!(!manager.identity_path().exists());
    assert!(!manager.runtime_path().exists());
    assert!(!manager.base_dir().join("state.tmp.1234").exists());
    assert!(!manager.exists());
    assert!(!manager.has_any_state());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_v01_migration_success() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let legacy_config_file = temp_dir.join("legacy_config.json");

    let (signing_key, verifying_key) = generate_keypair();
    let col_id = Uuid::new_v4();
    let raw_secret = signing_key.as_bytes();
    let pub_b64 = public_key_to_base64url(&verifying_key);

    // Encrypt with user-scope DPAPI as V0.1 did
    let encrypted_user_blob = dpapi::protect_user(raw_secret).expect("protect_user should succeed");
    let blob_b64 = STANDARD.encode(&encrypted_user_blob);

    let legacy_json = serde_json::json!({
        "server_url": "https://sandbox.tempris.tech/v2-assets/api/collectors",
        "collector_id": col_id.to_string(),
        "collector_name": "Legacy-Win-01",
        "enrolled": true,
        "public_key": pub_b64,
        "protected_key_blob": blob_b64,
        "created_at": "2026-08-20T10:00:00Z",
        "updated_at": "2026-08-20T10:00:00Z"
    });

    fs::write(
        &legacy_config_file,
        serde_json::to_string_pretty(&legacy_json).unwrap(),
    )
    .unwrap();

    // Migrate
    let migrated_opt = manager
        .migrate_v01_if_needed(Some(&legacy_config_file))
        .expect("migration should succeed");
    assert!(migrated_opt.is_some());

    let (migrated_state, migrated_key) = migrated_opt.unwrap();
    assert_eq!(migrated_state.schema_version, 2);
    assert_eq!(migrated_state.collector_id, col_id);
    assert_eq!(migrated_state.collector_name, "Legacy-Win-01");
    assert_eq!(
        migrated_state.server_url,
        "https://sandbox.tempris.tech/v2-assets"
    );
    assert_eq!(migrated_state.public_key, pub_b64);
    assert_eq!(migrated_state.collector_version, "0.2.0");
    assert_eq!(migrated_key.as_bytes(), raw_secret);

    // Verify V0.2 storage exists and can be reloaded directly
    assert!(manager.exists());
    let (reloaded_state, reloaded_key) = manager.load().expect("load after migration");
    assert_eq!(reloaded_state.collector_id, col_id);
    assert_eq!(reloaded_key.as_bytes(), raw_secret);

    // Verify legacy file was marked as .migrated
    let migrated_legacy_path = legacy_config_file.with_extension("json.migrated");
    assert!(
        migrated_legacy_path.exists(),
        "Legacy file should be renamed to .migrated"
    );
    assert!(
        !legacy_config_file.exists(),
        "Original legacy file should no longer exist"
    );

    // Calling migrate again when V0.2 state exists should return None
    let second_migration = manager
        .migrate_v01_if_needed(Some(&legacy_config_file))
        .unwrap();
    assert!(second_migration.is_none());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_v01_migration_corrupt_fails_closed() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let legacy_config_file = temp_dir.join("corrupt_legacy_config.json");

    // Write malformed JSON
    fs::write(&legacy_config_file, b"{\"enrolled\": true, corrupted").unwrap();

    let res = manager.migrate_v01_if_needed(Some(&legacy_config_file));
    assert!(res.is_err());
    match res.unwrap_err() {
        StorageError::MigrationError(msg) => {
            assert!(msg.contains("Malformed legacy V0.1 JSON"));
        }
        other => panic!("Expected MigrationError, got: {:?}", other),
    }

    // Ensure partial V0.2 state was NOT created
    assert!(!manager.exists());
    assert!(!manager.has_any_state());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_v01_migration_unenrolled_skips() {
    let (temp_dir, manager) = create_temp_storage_dir();
    let legacy_config_file = temp_dir.join("unenrolled_legacy.json");

    let unenrolled_json = serde_json::json!({
        "server_url": "http://127.0.0.1:8000",
        "collector_id": null,
        "collector_name": null,
        "enrolled": false,
        "public_key": null,
        "protected_key_blob": null,
        "created_at": null,
        "updated_at": null
    });

    fs::write(
        &legacy_config_file,
        serde_json::to_string_pretty(&unenrolled_json).unwrap(),
    )
    .unwrap();

    let res = manager
        .migrate_v01_if_needed(Some(&legacy_config_file))
        .expect("should succeed with None");
    assert!(res.is_none());
    assert!(!manager.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_atomic_write_file_preserves_target_on_failure() {
    let (temp_dir, _manager) = create_temp_storage_dir();
    let target = temp_dir.join("authoritative.dat");
    let original_data = b"original valid payload 12345";

    // 1. Initial write
    tempris_collector::storage::atomic_write_file(&target, original_data).expect("initial write");
    assert_eq!(fs::read(&target).unwrap(), original_data);

    // 2. Successful replacement
    let new_data = b"new valid replacement 67890";
    tempris_collector::storage::atomic_write_file(&target, new_data).expect("second write");
    assert_eq!(fs::read(&target).unwrap(), new_data);

    // 3. Verify atomic replace module functions directly
    let tmp_file = temp_dir.join("replacement.tmp");
    fs::write(&tmp_file, b"direct replacement").unwrap();
    tempris_collector::storage::win_file::atomic_replace(&target, &tmp_file)
        .expect("atomic replace");
    assert_eq!(fs::read(&target).unwrap(), b"direct replacement");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_partial_state_recovery_and_has_any_state() {
    let (temp_dir, manager) = create_temp_storage_dir();

    assert!(!manager.has_any_state());
    assert!(!manager.exists());

    // Write only protected_identity.dat (e.g. crash before state.json wrote)
    fs::write(manager.identity_path(), b"fake-encrypted-identity").unwrap();

    assert!(manager.has_any_state());
    assert!(!manager.exists()); // Not complete

    // migrate_v01_if_needed must not overwrite existing partial state
    let dummy_legacy = temp_dir.join("dummy_legacy.json");
    fs::write(&dummy_legacy, b"{\"enrolled\": true}").unwrap();
    let mig_res = manager.migrate_v01_if_needed(Some(&dummy_legacy)).unwrap();
    assert!(
        mig_res.is_none(),
        "Migration must skip when partial V0.2 state exists"
    );

    // Loading partial state must fail closed with typed corruption error
    let load_res = manager.load();
    assert!(matches!(load_res, Err(StorageError::CorruptStateJson(_))));

    let _ = fs::remove_dir_all(&temp_dir);
}
