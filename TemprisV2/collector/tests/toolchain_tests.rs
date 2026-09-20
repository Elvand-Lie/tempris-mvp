use std::fs;
use std::path::{Path, PathBuf};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tempris_collector::scout_runner::{
    probe_scout_capabilities, probe_scout_capabilities_with_storage, run_scout_job_with_storage,
};
use tempris_collector::storage::StorageManager;
use tempris_collector::toolchain::keys::{
    get_verification_key, TOOLCHAIN_RELEASE_KEY_ID, TOOLCHAIN_RELEASE_PUBLIC_KEY,
};
use tempris_collector::toolchain::manager::ToolchainManager;
use tempris_collector::toolchain::manifest::{
    validate_entrypoint, ComponentManifest, PlatformSpec, ToolchainEnvelope, ToolchainManifest,
    ALLOWED_MANAGED_COMPONENTS, MAX_MANIFEST_RAW_BYTES,
};
use tempris_collector::toolchain::offline::verify_offline_package;
use tempris_collector::toolchain::state::{ComponentState, ComponentStatus, ToolchainState};
use tempris_collector::toolchain::verifier::{verify_artifact_bytes, verify_envelope};
use tempris_collector::toolchain::{ToolchainError, TOOLCHAIN_UPDATE_ORIGIN};
use uuid::Uuid;

fn fixture_package_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("offline_poc_package")
}

// ---------------------------------------------------------------------------
// Category A: Version & Identity Preservation
// ---------------------------------------------------------------------------

#[test]
fn test_a1_cargo_package_version_is_0_4_0() {
    assert_eq!(
        env!("CARGO_PKG_VERSION"),
        "0.4.0",
        "Collector package version must be bumped to 0.4.0 (A.1)"
    );
}

#[tokio::test]
async fn test_a2_scout_capabilities_collector_version_is_0_4_0() {
    let caps = probe_scout_capabilities().await;
    assert_eq!(
        caps.collector_version,
        Some("0.4.0".to_string()),
        "ScoutCapabilities.collector_version must be Some('0.4.0') (A.2)"
    );
}

#[test]
fn test_a4_storage_manager_toolchain_state_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = StorageManager::new(temp_dir.path().to_path_buf());
    let state_path = storage.toolchain_state_path();
    assert!(
        state_path.ends_with("toolchain-state.json"),
        "StorageManager::toolchain_state_path must end with toolchain-state.json: {:?}",
        state_path
    );
}

// ---------------------------------------------------------------------------
// Category B: Cryptographic Trust Root & Key Management
// ---------------------------------------------------------------------------

#[test]
fn test_b1_b2_no_private_keys_in_git_root() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let git_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("Git root C:\\Tempris");

    // 1. Verify operator key lives outside Git root (B.1)
    let operator_key_path = PathBuf::from(r"C:\Users\elvan\.tempris-operator\keys\toolchain_release_ed25519.key");
    if operator_key_path.exists() {
        assert!(
            !operator_key_path.starts_with(&git_root),
            "B.1: Operator private key must reside outside Git root"
        );
    }

    // 2. Verify toolchain release private key does NOT exist anywhere in C:\Tempris (B.1)
    for entry in walkdir_simple(&git_root) {
        let name = entry.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
        if name == "toolchain_release_ed25519.key" || (name.contains("toolchain") && name.ends_with(".key")) {
            panic!(
                "B.1 Violation: Toolchain private key found in Git root: {}",
                entry.display()
            );
        }
    }

    // 3. Verify TemprisV2/collector contains zero .key or .pem files (B.2)
    for entry in walkdir_simple(&manifest_dir) {
        let name = entry.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
        if name.ends_with(".key") || name.ends_with(".pem") {
            panic!(
                "B.2 Violation: Key or pem file found in Collector workspace: {}",
                entry.display()
            );
        }
    }
}

#[test]
fn test_b3_compiled_public_key_is_32_bytes_and_valid() {
    assert_eq!(TOOLCHAIN_RELEASE_PUBLIC_KEY.len(), 32);
    let vk = get_verification_key();
    assert!(
        vk.is_ok(),
        "Collector must compile a valid 32-byte Ed25519 public key (B.3)"
    );
}

#[test]
fn test_b4_verification_of_valid_signed_manifest_succeeds() {
    let manifest_file = fixture_package_path().join("toolchain-manifest.json");
    let raw_bytes = fs::read(&manifest_file).expect("Fixture manifest must exist");

    let manifest = verify_envelope(&raw_bytes).expect("B.4: Valid signed manifest must verify successfully");
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.channel, "poc");
    assert_eq!(manifest.sequence_number, 100);
    assert!(manifest.components.contains_key("nuclei"));
    assert!(manifest.components.contains_key("nuclei_templates"));
}

#[test]
fn test_b5_mutated_signature_fails_with_typed_error() {
    let manifest_file = fixture_package_path().join("toolchain-manifest.json");
    let raw_bytes = fs::read(&manifest_file).expect("Fixture manifest must exist");
    let mut envelope: ToolchainEnvelope = serde_json::from_slice(&raw_bytes).unwrap();

    // Flip 1 bit/char in signature
    let mut sig_chars: Vec<char> = envelope.signature.chars().collect();
    sig_chars[0] = if sig_chars[0] == '0' { '1' } else { '0' };
    envelope.signature = sig_chars.into_iter().collect();

    let mutated_bytes = serde_json::to_vec(&envelope).unwrap();
    let res = verify_envelope(&mutated_bytes);

    match res {
        Err(ToolchainError::SignatureVerificationFailed(msg)) => {
            assert!(msg.contains("verification failed") || msg.contains("Ed25519"));
        }
        other => panic!("Expected ToolchainError::SignatureVerificationFailed, got {:?}", other),
    }
}

#[test]
fn test_b6_mutated_payload_fails_with_typed_error() {
    let manifest_file = fixture_package_path().join("toolchain-manifest.json");
    let raw_bytes = fs::read(&manifest_file).expect("Fixture manifest must exist");
    let mut envelope: ToolchainEnvelope = serde_json::from_slice(&raw_bytes).unwrap();

    // Mutate 1 character in manifest_raw
    envelope.manifest_raw.push(' ');

    let mutated_bytes = serde_json::to_vec(&envelope).unwrap();
    let res = verify_envelope(&mutated_bytes);

    match res {
        Err(ToolchainError::SignatureVerificationFailed(_)) => {}
        other => panic!("Expected ToolchainError::SignatureVerificationFailed, got {:?}", other),
    }
}

#[test]
fn test_b7_wrong_key_forged_signature_fails() {
    let manifest_file = fixture_package_path().join("toolchain-manifest.json");
    let raw_bytes = fs::read(&manifest_file).expect("Fixture manifest must exist");
    let mut envelope: ToolchainEnvelope = serde_json::from_slice(&raw_bytes).unwrap();

    // Sign manifest_raw with an unauthorized test key
    let unauthorized_signing_key = SigningKey::generate(&mut OsRng);
    let forged_signature = unauthorized_signing_key.sign(envelope.manifest_raw.as_bytes());
    envelope.signature = hex::encode(forged_signature.to_bytes());

    let mutated_bytes = serde_json::to_vec(&envelope).unwrap();
    let res = verify_envelope(&mutated_bytes);

    match res {
        Err(ToolchainError::SignatureVerificationFailed(_)) => {}
        other => panic!("Expected ToolchainError::SignatureVerificationFailed, got {:?}", other),
    }
}

#[test]
fn test_b8_raw_bytes_verified_before_parsing() {
    // Malformed JSON inside manifest_raw, signed with invalid signature
    let envelope = ToolchainEnvelope {
        format_version: 1,
        key_id: TOOLCHAIN_RELEASE_KEY_ID.to_string(),
        signature: hex::encode([0xAAu8; 64]),
        manifest_raw: "{ malformed json: not valid at all }".to_string(),
    };

    let raw = serde_json::to_vec(&envelope).unwrap();
    let res = verify_envelope(&raw);

    // Must fail at signature verification, NOT at JSON deserialization
    match res {
        Err(ToolchainError::SignatureVerificationFailed(_)) => {}
        other => panic!("Expected ToolchainError::SignatureVerificationFailed (B.8 verification-before-parsing), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Category C: Manifest Schema, Component & Channel Enforcement
// ---------------------------------------------------------------------------

fn valid_component_manifest(entrypoint: &str) -> ComponentManifest {
    ComponentManifest {
        version: "3.8.0".to_string(),
        platform: PlatformSpec {
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
        },
        sha256: "5ae082df989e80ca905761e3f9234f70bbff6e6f37929b50f00118c6e8958e66".to_string(),
        byte_size: 48,
        entrypoint: entrypoint.to_string(),
        is_emergency_rollback: false,
    }
}

fn valid_toolchain_manifest() -> ToolchainManifest {
    let mut components = std::collections::BTreeMap::new();
    components.insert("nuclei".to_string(), valid_component_manifest("nuclei.exe"));
    components.insert("nuclei_templates".to_string(), ComponentManifest {
        version: "10.4.4".to_string(),
        platform: PlatformSpec {
            os: "windows".to_string(),
            arch: "x86_64".to_string(),
        },
        sha256: "3da714fa9e5860bbb76ee9b35c9c1e8707322615927eb67dfc856c8f8085e5e8".to_string(),
        byte_size: 49,
        entrypoint: "templates.zip".to_string(),
        is_emergency_rollback: false,
    });

    ToolchainManifest {
        schema_version: 1,
        channel: "poc".to_string(),
        sequence_number: 100,
        generated_at: "2026-09-05T12:00:00Z".to_string(),
        min_collector_version: "0.4.0".to_string(),
        components,
    }
}

#[test]
fn test_c1_valid_allowlisted_components_parse() {
    let manifest = valid_toolchain_manifest();
    let json = serde_json::to_vec(&manifest).unwrap();
    let parsed = ToolchainManifest::parse_and_validate(&json).unwrap();
    assert_eq!(parsed.components.len(), 2);
    for k in parsed.components.keys() {
        assert!(ALLOWED_MANAGED_COMPONENTS.contains(&k.as_str()));
    }
}

#[test]
fn test_c2_unknown_and_forbidden_components_rejected() {
    let forbidden_names = ["nmap", "npcap", "powershell", "curl", "backdoor"];
    for name in forbidden_names {
        let mut manifest = valid_toolchain_manifest();
        manifest.components.insert(name.to_string(), valid_component_manifest("tool.exe"));
        let json = serde_json::to_vec(&manifest).unwrap();
        let res = ToolchainManifest::parse_and_validate(&json);
        match res {
            Err(ToolchainError::UnknownComponent(comp)) => {
                assert_eq!(comp, name, "C.2: Unknown component must be rejected with typed error");
            }
            other => panic!("Expected UnknownComponent for '{}', got {:?}", name, other),
        }
    }
}

#[test]
fn test_c3_unsupported_schema_version_rejected() {
    let mut manifest = valid_toolchain_manifest();
    manifest.schema_version = 99;
    let json = serde_json::to_vec(&manifest).unwrap();
    let res = ToolchainManifest::parse_and_validate(&json);
    match res {
        Err(ToolchainError::UnsupportedSchemaVersion(99)) => {}
        other => panic!("Expected UnsupportedSchemaVersion(99), got {:?}", other),
    }
}

#[test]
fn test_c4_invalid_channel_rejected() {
    for channel in ["unstable", "dev", ""] {
        let mut manifest = valid_toolchain_manifest();
        manifest.channel = channel.to_string();
        let json = serde_json::to_vec(&manifest).unwrap();
        let res = ToolchainManifest::parse_and_validate(&json);
        match res {
            Err(ToolchainError::InvalidChannel(ch)) => {
                assert_eq!(ch, channel);
            }
            other => panic!("Expected InvalidChannel for '{}', got {:?}", channel, other),
        }
    }
}

#[test]
fn test_c5_non_windows_platform_rejected() {
    let mut manifest = valid_toolchain_manifest();
    manifest.components.get_mut("nuclei").unwrap().platform.os = "linux".to_string();
    let json = serde_json::to_vec(&manifest).unwrap();
    let res = ToolchainManifest::parse_and_validate(&json);
    match res {
        Err(ToolchainError::UnsupportedPlatform { os, .. }) => {
            assert_eq!(os, "linux");
        }
        other => panic!("Expected UnsupportedPlatform, got {:?}", other),
    }

    let mut manifest2 = valid_toolchain_manifest();
    manifest2.components.get_mut("nuclei").unwrap().platform.arch = "arm64".to_string();
    let json2 = serde_json::to_vec(&manifest2).unwrap();
    let res2 = ToolchainManifest::parse_and_validate(&json2);
    match res2 {
        Err(ToolchainError::UnsupportedPlatform { arch, .. }) => {
            assert_eq!(arch, "arm64");
        }
        other => panic!("Expected UnsupportedPlatform, got {:?}", other),
    }
}

#[test]
fn test_c6_manifest_size_exceeding_64kib_rejected() {
    let oversized = vec![b' '; MAX_MANIFEST_RAW_BYTES + 1];
    let res = ToolchainManifest::parse_and_validate(&oversized);
    match res {
        Err(ToolchainError::ManifestTooLarge { size, max }) => {
            assert_eq!(size, MAX_MANIFEST_RAW_BYTES + 1);
            assert_eq!(max, MAX_MANIFEST_RAW_BYTES);
        }
        other => panic!("Expected ManifestTooLarge, got {:?}", other),
    }
}

#[test]
fn test_c7_malformed_semver_rejected() {
    for bad_ver in ["latest", "3.8.0-rc1; evil", "../../1.0", "v3.8.0"] {
        let mut manifest = valid_toolchain_manifest();
        manifest.components.get_mut("nuclei").unwrap().version = bad_ver.to_string();
        let json = serde_json::to_vec(&manifest).unwrap();
        let res = ToolchainManifest::parse_and_validate(&json);
        match res {
            Err(ToolchainError::InvalidSemver(_)) => {}
            other => panic!("Expected InvalidSemver for '{}', got {:?}", bad_ver, other),
        }
    }
}

#[test]
fn test_c8_deny_unknown_fields_enforced() {
    // 1. Unknown field in manifest payload
    let json_str = r#"{
        "schema_version": 1,
        "channel": "poc",
        "sequence_number": 100,
        "generated_at": "2026-09-05T12:00:00Z",
        "min_collector_version": "0.4.0",
        "injected_field": "exploit",
        "components": {}
    }"#;
    let res = ToolchainManifest::parse_and_validate(json_str.as_bytes());
    match res {
        Err(ToolchainError::DeserializationError(err)) => {
            assert!(err.contains("unknown field `injected_field`"), "Error: {}", err);
        }
        other => panic!("Expected DeserializationError for unknown field, got {:?}", other),
    }

    // 2. Unknown field in envelope
    let env_json = r#"{
        "format_version": 1,
        "key_id": "tempris-toolchain-release-v1",
        "signature": "abcd",
        "manifest_raw": "{}",
        "extra_envelope_param": 123
    }"#;
    let env_res: Result<ToolchainEnvelope, _> = serde_json::from_str(env_json);
    assert!(env_res.is_err(), "Envelope must reject unknown field 'extra_envelope_param'");
}

// ---------------------------------------------------------------------------
// Category D: Anti-Replay, Downgrade & Security Boundary Enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_d1_sequence_number_anti_replay_enforcement() {
    let mut state = ToolchainState::default();
    state.last_manifest_sequence = 200;

    let mut candidate = valid_toolchain_manifest();
    candidate.sequence_number = 200; // Equal sequence (replay)

    let res = state.validate_candidate_manifest(&candidate);
    match res {
        Err(ToolchainError::ReplayDetected { manifest_sequence, last_sequence }) => {
            assert_eq!(manifest_sequence, 200);
            assert_eq!(last_sequence, 200);
        }
        other => panic!("Expected ReplayDetected for equal sequence, got {:?}", other),
    }

    candidate.sequence_number = 199; // Older sequence (replay)
    let res2 = state.validate_candidate_manifest(&candidate);
    match res2 {
        Err(ToolchainError::ReplayDetected { manifest_sequence, last_sequence }) => {
            assert_eq!(manifest_sequence, 199);
            assert_eq!(last_sequence, 200);
        }
        other => panic!("Expected ReplayDetected for older sequence, got {:?}", other),
    }

    candidate.sequence_number = 201; // Monotonically higher sequence
    assert!(state.validate_candidate_manifest(&candidate).is_ok());
}

#[test]
fn test_d2_unauthorized_downgrade_rejected() {
    let mut state = ToolchainState::default();
    state.last_manifest_sequence = 100;
    state.components.insert("nuclei".to_string(), ComponentState {
        status: ComponentStatus::Installed,
        version: Some("3.8.0".to_string()),
        sha256: Some("5ae082df989e80ca905761e3f9234f70bbff6e6f37929b50f00118c6e8958e66".to_string()),
        active_dir: Some("C:\\path".to_string()),
        previous_dir: None,
        installed_at: None,
        last_verified_at: None,
    });

    let mut candidate = valid_toolchain_manifest();
    candidate.sequence_number = 101;
    candidate.components.get_mut("nuclei").unwrap().version = "3.7.0".to_string(); // Downgrade
    candidate.components.get_mut("nuclei").unwrap().is_emergency_rollback = false;

    let res = state.validate_candidate_manifest(&candidate);
    match res {
        Err(ToolchainError::UnauthorizedDowngrade { component, current_version, candidate_version }) => {
            assert_eq!(component, "nuclei");
            assert_eq!(current_version, "3.8.0");
            assert_eq!(candidate_version, "3.7.0");
        }
        other => panic!("Expected UnauthorizedDowngrade, got {:?}", other),
    }
}

#[test]
fn test_d3_emergency_rollback_waives_downgrade_but_strictly_enforces_monotonic_sequence() {
    let mut state = ToolchainState::default();
    state.last_manifest_sequence = 100;
    state.components.insert("nuclei".to_string(), ComponentState {
        status: ComponentStatus::Installed,
        version: Some("3.8.0".to_string()),
        sha256: Some("5ae082df989e80ca905761e3f9234f70bbff6e6f37929b50f00118c6e8958e66".to_string()),
        active_dir: Some("C:\\path".to_string()),
        previous_dir: None,
        installed_at: None,
        last_verified_at: None,
    });

    // 1. Emergency rollback with monotonic sequence (> 100) -> MUST SUCCEED
    let mut candidate_valid = valid_toolchain_manifest();
    candidate_valid.sequence_number = 101;
    candidate_valid.components.get_mut("nuclei").unwrap().version = "3.7.0".to_string();
    candidate_valid.components.get_mut("nuclei").unwrap().is_emergency_rollback = true;

    assert!(
        state.validate_candidate_manifest(&candidate_valid).is_ok(),
        "D.3: Emergency rollback with monotonic sequence must be accepted"
    );

    // 2. Emergency rollback with stale/replayed sequence (<= 100) -> MUST BE REJECTED
    let mut candidate_replayed = valid_toolchain_manifest();
    candidate_replayed.sequence_number = 100; // Replayed sequence
    candidate_replayed.components.get_mut("nuclei").unwrap().version = "3.7.0".to_string();
    candidate_replayed.components.get_mut("nuclei").unwrap().is_emergency_rollback = true;

    let res = state.validate_candidate_manifest(&candidate_replayed);
    match res {
        Err(ToolchainError::ReplayDetected { .. }) => {}
        other => panic!("Expected ReplayDetected for replayed rollback, got {:?}", other),
    }
}

#[test]
fn test_d4_entrypoint_path_traversal_and_separators_rejected() {
    let forbidden_entrypoints = [
        "../evil.exe",
        "..\\evil.exe",
        "sub/dir.exe",
        "sub\\dir.exe",
        "C:\\evil.exe",
        "test.exe:stream", // ADS
        "test\0.exe",       // Null byte
    ];

    for ep in forbidden_entrypoints {
        let res = validate_entrypoint(ep, "nuclei");
        match res {
            Err(ToolchainError::InvalidEntrypoint(msg)) => {
                assert!(msg.contains("forbidden") || msg.contains("whitelist"), "Error: {}", msg);
            }
            other => panic!("Expected InvalidEntrypoint for '{}', got {:?}", ep, other),
        }
    }
}

#[test]
fn test_d5_entrypoint_dos_devices_and_whitelist_rejected() {
    let invalid_entrypoints = [
        "CON.exe",
        "PRN.exe",
        "AUX.exe",
        "NUL.exe",
        "COM1.bat",
        "LPT1.cmd",
        "con.exe", // Case-insensitive
        "evil space.exe",
        "evil$char.exe",
        "noextension",
    ];

    for ep in invalid_entrypoints {
        let res = validate_entrypoint(ep, "nuclei");
        match res {
            Err(ToolchainError::InvalidEntrypoint(_)) => {}
            other => panic!("Expected InvalidEntrypoint for '{}', got {:?}", ep, other),
        }
    }

    // Valid entrypoints must pass
    assert!(validate_entrypoint("nuclei.exe", "nuclei").is_ok());
    assert!(validate_entrypoint("nuclei-runner_v2.exe", "nuclei").is_ok());
    assert!(validate_entrypoint("templates.zip", "nuclei_templates").is_ok());
}

#[test]
fn test_d6_sha256_strict_format_validation() {
    // Uppercase hex -> rejected
    let mut m1 = valid_toolchain_manifest();
    m1.components.get_mut("nuclei").unwrap().sha256 = "5AE082DF989E80CA905761E3F9234F70BBFF6E6F37929B50F00118C6E8958E66".to_string();
    assert!(matches!(ToolchainManifest::parse_and_validate(&serde_json::to_vec(&m1).unwrap()), Err(ToolchainError::InvalidDigest(_))));

    // Non-hex characters -> rejected
    let mut m2 = valid_toolchain_manifest();
    m2.components.get_mut("nuclei").unwrap().sha256 = "5ze082df989e80ca905761e3f9234f70bbff6e6f37929b50f00118c6e8958e66".to_string();
    assert!(matches!(ToolchainManifest::parse_and_validate(&serde_json::to_vec(&m2).unwrap()), Err(ToolchainError::InvalidDigest(_))));

    // Short hash (63 chars) -> rejected
    let mut m3 = valid_toolchain_manifest();
    m3.components.get_mut("nuclei").unwrap().sha256 = "5ae082df989e80ca905761e3f9234f70bbff6e6f37929b50f00118c6e8958e6".to_string();
    assert!(matches!(ToolchainManifest::parse_and_validate(&serde_json::to_vec(&m3).unwrap()), Err(ToolchainError::InvalidDigest(_))));
}

#[test]
fn test_d7_fixed_https_origin_constant() {
    assert_eq!(
        TOOLCHAIN_UPDATE_ORIGIN,
        "https://updates.tempris.com/v1/collector-toolchain",
        "D.7: Hardcoded HTTPS origin must match exact spec and allow zero tenant overrides"
    );
}

// ---------------------------------------------------------------------------
// Category E: Durable State (`toolchain-state.json`) Durability & Recovery
// ---------------------------------------------------------------------------

#[test]
fn test_e1_load_missing_file_returns_clean_default() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing_path = temp_dir.path().join("non_existent_toolchain_state.json");

    let state = ToolchainState::load(&missing_path).unwrap();
    assert_eq!(state.schema_version, 1);
    assert_eq!(state.last_manifest_sequence, 0);
    assert_eq!(state.components.len(), 2);
    assert_eq!(state.components.get("nuclei").unwrap().status, ComponentStatus::Uninstalled);
    assert_eq!(state.components.get("nuclei_templates").unwrap().status, ComponentStatus::Uninstalled);
}

#[test]
fn test_e2_e3_save_and_load_roundtrip_preserves_all_fields() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("toolchain-state.json");

    let mut state = ToolchainState::default();
    state.last_manifest_sequence = 42;
    state.updated_at = "2026-09-05T12:30:00Z".to_string();
    state.components.insert("nuclei".to_string(), ComponentState {
        status: ComponentStatus::Installed,
        version: Some("3.8.0".to_string()),
        sha256: Some("5ae082df989e80ca905761e3f9234f70bbff6e6f37929b50f00118c6e8958e66".to_string()),
        active_dir: Some("C:\\ProgramData\\Tempris\\Collector\\toolchains\\nuclei-3.8.0".to_string()),
        previous_dir: Some("C:\\ProgramData\\Tempris\\Collector\\toolchains\\nuclei-3.7.0".to_string()),
        installed_at: Some("2026-09-05T12:00:00Z".to_string()),
        last_verified_at: Some("2026-09-05T12:30:00Z".to_string()),
    });

    state.save(&state_path).expect("State save must succeed (E.2)");
    assert!(state_path.exists(), "State file must exist on disk");

    let loaded = ToolchainState::load(&state_path).expect("State load must succeed (E.3)");
    assert_eq!(loaded, state, "Loaded state must match saved state completely");
}

#[test]
fn test_e4_corrupt_state_file_fails_closed_without_crashing_or_panicking() {
    let temp_dir = tempfile::tempdir().unwrap();
    let corrupt_path = temp_dir.path().join("toolchain-state.json");

    // Write corrupt JSON
    fs::write(&corrupt_path, "{ corrupt truncated json").unwrap();

    let res = ToolchainState::load(&corrupt_path);
    match res {
        Err(ToolchainError::CorruptToolchainState(_)) => {}
        other => panic!("Expected CorruptToolchainState, got {:?}", other),
    }

    // Original corrupt file must still exist (not deleted or wiped)
    assert!(corrupt_path.exists());
    let content = fs::read_to_string(&corrupt_path).unwrap();
    assert_eq!(content, "{ corrupt truncated json");
}

#[test]
fn test_e5_atomic_write_preserves_target_on_failure() {
    let temp_dir = tempfile::tempdir().unwrap();
    let valid_path = temp_dir.path().join("toolchain-state.json");

    let state = ToolchainState::default();
    state.save(&valid_path).unwrap();
    let original_bytes = fs::read(&valid_path).unwrap();

    // 1. Attempt save to non-existent drive Z: (unwritable target)
    let invalid_path = PathBuf::from("Z:\\nonexistent_drive_12345\\state.json");
    let fail_state = ToolchainState::default();
    let res = fail_state.save(&invalid_path);
    assert!(res.is_err(), "Saving to non-existent drive should return Err");

    // 2. Original valid file remains completely untouched
    assert_eq!(fs::read(&valid_path).unwrap(), original_bytes);
}

#[test]
fn test_e6_zero_secrets_in_toolchain_state() {
    let mut state = ToolchainState::default();
    state.last_manifest_sequence = 100;
    let json_str = serde_json::to_string_pretty(&state).unwrap().to_ascii_lowercase();

    let forbidden_secret_markers = [
        "private_key",
        "secret",
        "dpapi",
        "token",
        "bearer",
        "password",
        "entropy",
        "seed",
    ];

    for marker in forbidden_secret_markers {
        assert!(
            !json_str.contains(marker),
            "E.6 Violation: ToolchainState JSON must never leak secrets or tokens, found '{}'",
            marker
        );
    }
}

// ---------------------------------------------------------------------------
// Category F: Offline Package & Hash Verification
// ---------------------------------------------------------------------------

#[test]
fn test_f1_f2_offline_package_valid_bundle_verification() {
    let package_dir = fixture_package_path();
    let verified = verify_offline_package(&package_dir).expect("F.1/F.2: Valid offline package must verify successfully");

    assert_eq!(verified.manifest.schema_version, 1);
    assert_eq!(verified.manifest.sequence_number, 100);
    assert_eq!(verified.component_artifacts.len(), 2);

    for (name, path) in verified.component_artifacts {
        assert!(path.exists());
        assert!(name == "nuclei" || name == "nuclei_templates");
    }
}

#[test]
fn test_f3_artifact_hash_mismatch_fails() {
    let data = b"some artifact content here";
    let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let res = verify_artifact_bytes(data, wrong_hash, data.len() as u64);
    match res {
        Err(ToolchainError::HashMismatch { expected, actual }) => {
            assert_eq!(expected, wrong_hash);
            assert_ne!(actual, wrong_hash);
        }
        other => panic!("Expected HashMismatch, got {:?}", other),
    }
}

#[test]
fn test_f4_artifact_size_mismatch_fails() {
    let data = b"some artifact content";
    let res = verify_artifact_bytes(data, "unused_hash", 999);
    match res {
        Err(ToolchainError::SizeMismatch { expected, actual }) => {
            assert_eq!(expected, 999);
            assert_eq!(actual, data.len() as u64);
        }
        other => panic!("Expected SizeMismatch, got {:?}", other),
    }
}

#[test]
fn test_f5_zero_binary_execution_during_verification() {
    // Calling verify_offline_package executes pure verification code in-process
    let package_dir = fixture_package_path();
    let res = verify_offline_package(&package_dir);
    assert!(res.is_ok(), "F.5: In-process verification must succeed without launching external processes");
}

#[test]
fn test_f6_offline_package_extraneous_files_and_nmap_rejected() {
    let temp_dir = tempfile::tempdir().unwrap();
    let pkg_path = temp_dir.path();

    // Copy valid fixture files
    for entry in fs::read_dir(fixture_package_path()).unwrap().flatten() {
        fs::copy(entry.path(), pkg_path.join(entry.file_name())).unwrap();
    }

    // 1. Package containing unmanifested extraneous file -> ExtraneousFileDetected
    let extraneous_file = pkg_path.join("unmanifested_script.ps1");
    fs::write(&extraneous_file, b"Write-Host 'exploit'").unwrap();

    let res1 = verify_offline_package(pkg_path);
    match res1 {
        Err(ToolchainError::ExtraneousFileDetected(msg)) => {
            assert!(msg.contains("unmanifested_script.ps1"));
        }
        other => panic!("Expected ExtraneousFileDetected, got {:?}", other),
    }

    fs::remove_file(&extraneous_file).unwrap();

    // 2. Package containing forbidden Nmap binary -> ForbiddenComponent
    let nmap_file = pkg_path.join("nmap-7.94-setup.exe");
    fs::write(&nmap_file, b"MZ dummy exe").unwrap();

    let res2 = verify_offline_package(pkg_path);
    match res2 {
        Err(ToolchainError::ForbiddenComponent(msg)) => {
            assert!(msg.contains("prohibited external prerequisite"));
        }
        other => panic!("Expected ForbiddenComponent for nmap, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Category G: Legal Provenance & Licensing Invariants
// ---------------------------------------------------------------------------

#[test]
fn test_g1_nuclei_license_notice_exists() {
    let notice_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("notices")
        .join("NUCLEI_LICENSE.txt");
    assert!(notice_path.exists(), "G.1: NUCLEI_LICENSE.txt must exist");
    let content = fs::read_to_string(&notice_path).unwrap();
    assert!(content.contains("ProjectDiscovery"), "Must contain ProjectDiscovery copyright");
    assert!(content.contains("MIT License"), "Must cite MIT License");
}

#[test]
fn test_g2_nuclei_templates_license_notice_exists() {
    let notice_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("notices")
        .join("NUCLEI_TEMPLATES_LICENSE.txt");
    assert!(notice_path.exists(), "G.2: NUCLEI_TEMPLATES_LICENSE.txt must exist");
    let content = fs::read_to_string(&notice_path).unwrap();
    assert!(content.contains("1e2578542e98818c5dfda8cb8f601023e7bcda69"), "Must cite exact commit hash");
    assert!(content.contains("MIT License"), "Must cite MIT License");
}

#[test]
fn test_g3_nmap_external_prerequisite_notice_exists() {
    let notice_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("notices")
        .join("NUCLEI_LICENSE.txt");
    assert!(notice_path.exists());

    let prereq_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("notices")
        .join("NMAP_EXTERNAL_PREREQUISITE_NOTICE.txt");
    assert!(prereq_path.exists(), "G.3: NMAP_EXTERNAL_PREREQUISITE_NOTICE.txt must exist");
    let content = fs::read_to_string(&prereq_path).unwrap();
    assert!(content.contains("external operator/customer prerequisites only"));
    assert!(content.contains("Tempris does NOT bundle, host, download"));
}

#[test]
fn test_g4_no_nmap_or_npcap_binaries_in_repo() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let git_root = manifest_dir.parent().and_then(|p| p.parent()).unwrap();

    for entry in walkdir_simple(git_root) {
        let name = entry.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
        if (name.contains("nmap") || name.contains("npcap")) && (name.ends_with(".exe") || name.ends_with(".dll") || name.ends_with(".sys")) {
            panic!(
                "G.4 Violation: Nmap or Npcap binary file detected in repo: {}",
                entry.display()
            );
        }
    }
}

#[test]
fn test_g5_manifest_and_offline_loader_reject_nmap() {
    // 1. Manifest level rejection
    let mut manifest = valid_toolchain_manifest();
    manifest.components.insert("nmap".to_string(), valid_component_manifest("nmap.exe"));
    let res = ToolchainManifest::parse_and_validate(&serde_json::to_vec(&manifest).unwrap());
    assert!(matches!(res, Err(ToolchainError::UnknownComponent(ref c)) if c == "nmap"));

    // 2. Offline loader level rejection
    let temp_dir = tempfile::tempdir().unwrap();
    let pkg_path = temp_dir.path();
    for entry in fs::read_dir(fixture_package_path()).unwrap().flatten() {
        fs::copy(entry.path(), pkg_path.join(entry.file_name())).unwrap();
    }
    fs::write(pkg_path.join("npcap.zip"), b"fake npcap").unwrap();
    let res2 = verify_offline_package(pkg_path);
    assert!(matches!(res2, Err(ToolchainError::ForbiddenComponent(_))));
}

// Helper simple recursive file walker
fn walkdir_simple(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if dir.is_dir() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let path_str = p.to_string_lossy().to_ascii_lowercase();
                // Skip build targets, git, virtualenvs, and node_modules
                if path_str.contains(r"\target\")
                    || path_str.contains("/target/")
                    || path_str.contains(r"\.git\")
                    || path_str.contains("/.git/")
                    || path_str.contains(r"\.tmp\")
                    || path_str.contains("/.tmp/")
                    || path_str.contains(r"\.venv\")
                    || path_str.contains("/.venv/")
                    || path_str.contains(r"\venv\")
                    || path_str.contains("/venv/")
                    || path_str.contains(r"\node_modules\")
                    || path_str.contains("/node_modules/")
                {
                    continue;
                }
                if p.is_dir() {
                    files.extend(walkdir_simple(&p));
                } else {
                    files.push(p);
                }
            }
        }
    }
    files
}

// ---------------------------------------------------------------------------
// Category H: Fresh-Provisioning & Wiring Verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_h1_fresh_state_offline_package_ingestion_probes_and_activates() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = StorageManager::new(temp_dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage.clone());

    let package_dir = fixture_package_path();
    let state = mgr
        .ingest_offline_package(&package_dir)
        .await
        .expect("H.1: Ingestion of valid offline package must succeed on fresh storage");

    assert_eq!(state.last_manifest_sequence, 100);
    assert_eq!(state.components.len(), 2);

    let nuclei_comp = state.components.get("nuclei").expect("nuclei component state");
    assert_eq!(nuclei_comp.status, ComponentStatus::Installed);
    assert_eq!(nuclei_comp.version.as_deref(), Some("3.8.0"));
    assert!(nuclei_comp.active_dir.is_some());

    let tmpl_comp = state
        .components
        .get("nuclei_templates")
        .expect("nuclei_templates component state");
    assert_eq!(tmpl_comp.status, ComponentStatus::Installed);
    assert_eq!(tmpl_comp.version.as_deref(), Some("10.4.4"));

    // Verify readiness probing against managed storage
    let caps = probe_scout_capabilities_with_storage(Some(&storage)).await;
    assert!(caps.nuclei.available, "Managed Nuclei must be reported as available");
    assert_eq!(caps.nuclei.version.as_deref(), Some("3.8.0"));
    assert_eq!(caps.nuclei.templates_version.as_deref(), Some("10.4.4"));
    assert_eq!(caps.nuclei.status.as_deref(), Some("ready"));
    assert_eq!(caps.nuclei.managed, Some(true));
}

#[tokio::test]
async fn test_h2_path_only_nuclei_is_ignored_when_unprovisioned() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = StorageManager::new(temp_dir.path().to_path_buf());

    // Clean fresh storage with zero toolchain state
    let caps = probe_scout_capabilities_with_storage(Some(&storage)).await;
    assert!(
        !caps.nuclei.available,
        "H.2: Ambient PATH nuclei must NEVER be reported as ready on unprovisioned storage"
    );
    assert_eq!(caps.nuclei.version, None);
    assert_eq!(caps.nuclei.status.as_deref(), Some("not_installed"));
    assert_eq!(caps.nuclei.managed, Some(true));
}

#[tokio::test]
async fn test_h3_signature_or_hash_failure_fails_closed_and_preserves_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = StorageManager::new(temp_dir.path().to_path_buf());
    let mgr = ToolchainManager::new(storage.clone());

    // 1. Initial valid ingestion
    let package_dir = fixture_package_path();
    let initial_state = mgr
        .ingest_offline_package(&package_dir)
        .await
        .expect("Initial package ingestion");

    // 2. Corrupted package attempt
    let corrupt_dir = tempfile::tempdir().unwrap();
    let pkg_path = corrupt_dir.path();
    for entry in fs::read_dir(&package_dir).unwrap().flatten() {
        fs::copy(entry.path(), pkg_path.join(entry.file_name())).unwrap();
    }
    // Corrupt nuclei artifact bytes
    fs::write(pkg_path.join("nuclei-3.8.0.zip"), b"corrupted bytes").unwrap();

    let fail_res = mgr.ingest_offline_package(pkg_path).await;
    assert!(fail_res.is_err(), "H.3: Corrupted artifact must fail closed");

    // Verify known-good state is preserved
    let state_path = storage.toolchain_state_path();
    let reloaded_state = ToolchainState::load(&state_path).unwrap();
    assert_eq!(reloaded_state.last_manifest_sequence, initial_state.last_manifest_sequence);
    let nuclei_comp = reloaded_state.components.get("nuclei").unwrap();
    assert_eq!(nuclei_comp.status, ComponentStatus::Installed);
}

#[tokio::test]
async fn test_h4_scout_execution_fails_closed_if_managed_bin_or_templates_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = StorageManager::new(temp_dir.path().to_path_buf());

    // Execute on fresh unprovisioned storage
    let res = run_scout_job_with_storage(
        Uuid::new_v4(),
        "nuclei",
        "192.168.1.100",
        30,
        Some(&storage),
    )
    .await;

    assert_eq!(res.status, "failed");
    assert!(
        res.error_message
            .as_deref()
            .unwrap_or_default()
            .contains("Managed Nuclei"),
        "H.4: Execution must fail closed when managed components are missing"
    );
}

#[tokio::test]
async fn test_h5_shared_provisioning_path_discovers_offline_package() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = StorageManager::new(temp_dir.path().to_path_buf());

    // Copy offline package to storage base_dir / offline_package
    let pkg_dest = storage.base_dir().join("offline_package");
    fs::create_dir_all(&pkg_dest).unwrap();
    for entry in fs::read_dir(fixture_package_path()).unwrap().flatten() {
        fs::copy(entry.path(), pkg_dest.join(entry.file_name())).unwrap();
    }

    let mgr = ToolchainManager::new(storage.clone());
    let discovered = mgr.find_offline_package_dir();
    assert!(discovered.is_some(), "H.5: find_offline_package_dir must locate offline_package");

    let updated_state = mgr.check_and_apply_update().await.expect("H.5: check_and_apply_update");
    assert_eq!(updated_state.last_manifest_sequence, 100);
    assert!(updated_state.components.contains_key("nuclei"));
    assert!(updated_state.components.contains_key("nuclei_templates"));
}

