use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::info;
use uuid::Uuid;

use crate::config::{validate_transport_url, CollectorConfig};
use crate::crypto::{generate_keypair, public_key_to_base64url};
use crate::storage::{CollectorState, StorageManager};

#[derive(Debug, Serialize, Deserialize)]
pub struct CollectorEnrollPayload {
    pub collector_id: Uuid,
    pub enrollment_code: String,
    pub public_key: String,
    pub platform_metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CollectorEnrollmentResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enrollment_status: String,
    pub operator_status: String,
    pub connection_status: String,
    pub status: String,
    pub public_key: Option<String>,
    pub platform_metadata: Option<HashMap<String, serde_json::Value>>,
}

pub fn collect_platform_metadata() -> HashMap<String, String> {
    let mut meta = HashMap::new();
    meta.insert("os".to_string(), std::env::consts::OS.to_string());
    meta.insert(
        "architecture".to_string(),
        std::env::consts::ARCH.to_string(),
    );

    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "windows-collector".to_string());
    meta.insert("hostname".to_string(), hostname);

    let os_version = std::env::var("OS").unwrap_or_else(|_| "Windows_NT".to_string());
    meta.insert("os_version".to_string(), os_version);

    meta.insert(
        "agent_version".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    meta
}

pub async fn enroll_collector(
    server_url: &str,
    collector_id: Uuid,
    enrollment_code: &str,
    custom_storage_dir: Option<&Path>,
) -> Result<(CollectorConfig, SigningKey)> {
    let clean_code = enrollment_code.trim();
    if clean_code.is_empty() {
        return Err(anyhow!("Enrollment code cannot be empty"));
    }

    validate_transport_url(server_url)?;

    info!("Generating local Ed25519 cryptographic keypair...");
    let (signing_key, verifying_key) = generate_keypair();
    let pubkey_b64 = public_key_to_base64url(&verifying_key);
    let platform_metadata = collect_platform_metadata();

    let payload = CollectorEnrollPayload {
        collector_id,
        enrollment_code: clean_code.to_string(),
        public_key: pubkey_b64.clone(),
        platform_metadata,
    };

    let base_url = CollectorConfig::normalize_server_url(server_url);
    let enroll_url = format!("{}/api/collectors/enroll", base_url);
    info!(
        "Submitting enrollment to '{}' for collector ID {}...",
        enroll_url, collector_id
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("Failed to build HTTP client")?;

    let response = client
        .post(&enroll_url)
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("Failed to send enrollment request to {}", enroll_url))?;

    let status = response.status();
    if !status.is_success() {
        let err_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(anyhow!(
            "Enrollment failed with HTTP {}: {}",
            status.as_u16(),
            err_body
        ));
    }

    let enroll_resp: CollectorEnrollmentResponse = response
        .json()
        .await
        .context("Failed to deserialize enrollment response from server")?;

    info!(
        "Successfully enrolled collector '{}' ({})",
        enroll_resp.name, enroll_resp.id
    );

    // Persist cleanly to V0.2 StorageManager layout (state.json + machine-scoped protected_identity.dat)
    let v02_state = CollectorState::new(
        enroll_resp.id,
        enroll_resp.name.clone(),
        base_url.to_string(),
        pubkey_b64.clone(),
        Utc::now(),
    );

    let storage_mgr = if let Some(p) = custom_storage_dir {
        if p.is_file() || p.extension().is_some() {
            StorageManager::new(p.parent().unwrap_or(Path::new(".")).to_path_buf())
        } else {
            StorageManager::new(p.to_path_buf())
        }
    } else {
        StorageManager::default_machine_storage()
    };

    // Save V0.2 state and machine-scoped identity (fails closed if persistence errors)
    storage_mgr
        .save(&v02_state, &signing_key)
        .context("Failed to persist V0.2 collector identity to secure storage")?;

    // Reload verification
    let (verified_state, verified_key) = storage_mgr
        .load()
        .context("Failed to reload-verify newly persisted collector state")?;

    if verified_state.collector_id != enroll_resp.id
        || verified_key.as_bytes() != signing_key.as_bytes()
    {
        return Err(anyhow!(
            "Identity mismatch during enrollment storage reload verification"
        ));
    }

    let config = CollectorConfig {
        server_url: base_url.to_string(),
        collector_id: Some(enroll_resp.id),
        collector_name: Some(enroll_resp.name),
        enrolled: true,
        public_key: Some(pubkey_b64),
        protected_key_blob: None,
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
    };

    info!("Saved local configuration to secure V0.2 storage (0 private keys transmitted on the wire).");

    // Attempt offline toolchain package ingestion during enrollment if present
    let toolchain_mgr = crate::toolchain::manager::ToolchainManager::new(storage_mgr.clone());
    if let Some(pkg_dir) = toolchain_mgr.find_offline_package_dir() {
        info!(
            "Discovered offline toolchain package at '{}', attempting initial provisioning...",
            pkg_dir.display()
        );
        match toolchain_mgr.ingest_offline_package(&pkg_dir).await {
            Ok(state) => {
                info!(
                    "Successfully provisioned toolchain components from offline package during enrollment: {:?}",
                    state.components.keys().collect::<Vec<_>>()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Partial readiness notice: offline toolchain package provisioning during enrollment failed: {}. Identity remains securely enrolled.",
                    e
                );
            }
        }
    }

    Ok((config, signing_key))
}
