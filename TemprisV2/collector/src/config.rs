use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[cfg(windows)]
mod dpapi {
    use anyhow::{bail, Result};
    use std::ptr::null_mut;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct DATA_BLOB {
        cbData: u32,
        pbData: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            pDataIn: *const DATA_BLOB,
            szDataDescr: *const u16,
            pOptionalEntropy: *const DATA_BLOB,
            pvReserved: *mut std::ffi::c_void,
            pPromptStruct: *mut std::ffi::c_void,
            dwFlags: u32,
            pDataOut: *mut DATA_BLOB,
        ) -> i32;

        fn CryptUnprotectData(
            pDataIn: *const DATA_BLOB,
            ppszDataDescr: *mut *mut u16,
            pOptionalEntropy: *const DATA_BLOB,
            pvReserved: *mut std::ffi::c_void,
            pPromptStruct: *mut std::ffi::c_void,
            dwFlags: u32,
            pDataOut: *mut DATA_BLOB,
        ) -> i32;

        fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let in_blob = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        let ret = unsafe {
            CryptProtectData(
                &in_blob,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ret == 0 || out_blob.pbData.is_null() {
            bail!(
                "DPAPI CryptProtectData failed with OS error: {}",
                std::io::Error::last_os_error()
            );
        }
        let out_bytes = unsafe {
            let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let vec = slice.to_vec();
            LocalFree(out_blob.pbData as *mut _);
            vec
        };
        Ok(out_bytes)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let in_blob = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };
        let ret = unsafe {
            CryptUnprotectData(
                &in_blob,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ret == 0 || out_blob.pbData.is_null() {
            bail!(
                "DPAPI CryptUnprotectData failed with OS error: {}",
                std::io::Error::last_os_error()
            );
        }
        let out_bytes = unsafe {
            let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let vec = slice.to_vec();
            LocalFree(out_blob.pbData as *mut _);
            vec
        };
        Ok(out_bytes)
    }
}

#[cfg(not(windows))]
mod dpapi {
    use anyhow::{bail, Result};

    pub fn protect(_data: &[u8]) -> Result<Vec<u8>> {
        bail!("DPAPI key protection is only available on Windows platforms");
    }

    pub fn unprotect(_data: &[u8]) -> Result<Vec<u8>> {
        bail!("DPAPI key protection is only available on Windows platforms");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    pub server_url: String,
    pub collector_id: Option<Uuid>,
    pub collector_name: Option<String>,
    pub enrolled: bool,
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_key_blob: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8000".to_string(),
            collector_id: None,
            collector_name: None,
            enrolled: false,
            public_key: None,
            protected_key_blob: None,
            created_at: None,
            updated_at: None,
        }
    }
}

pub fn is_loopback_host(host: &str) -> bool {
    let clean_host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if clean_host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.octets()[0] == 127,
            IpAddr::V6(v6) => v6.is_loopback() || v6 == Ipv6Addr::LOCALHOST,
        }
    } else {
        false
    }
}

/// Enforces the transport gate:
/// - Rejects plaintext HTTP / WS for remote endpoints.
/// - Allows plaintext HTTP / WS only for loopback development (localhost, 127.0.0.1, [::1]).
/// - Allows HTTPS / WSS unconditionally for all endpoints.
pub fn validate_transport_url(raw_url: &str) -> Result<()> {
    let clean = raw_url.trim();
    if clean.is_empty() {
        bail!("Server URL cannot be empty");
    }

    let url_to_parse = if clean.starts_with("wss://") {
        format!("https://{}", &clean[6..])
    } else if clean.starts_with("ws://") {
        format!("http://{}", &clean[5..])
    } else if !clean.contains("://") {
        format!("https://{}", clean)
    } else {
        clean.to_string()
    };

    let parsed = reqwest::Url::parse(&url_to_parse)
        .with_context(|| format!("Invalid server URL format: '{}'", clean))?;

    let original_scheme = if clean.starts_with("wss://") {
        "wss"
    } else if clean.starts_with("ws://") {
        "ws"
    } else {
        parsed.scheme()
    };

    let host = parsed.host_str().unwrap_or("");
    if host.is_empty() {
        bail!("Server URL must contain a valid host: '{}'", clean);
    }

    match original_scheme {
        "https" | "wss" => Ok(()),
        "http" | "ws" => {
            if is_loopback_host(host) {
                Ok(())
            } else {
                bail!(
                    "Plaintext transport ('{}') is strictly forbidden for remote server '{}'. Production connections must use HTTPS/WSS (plaintext http/ws is only permitted for loopback development on localhost, 127.0.0.1, or [::1]).",
                    original_scheme,
                    host
                )
            }
        }
        other => bail!("Unsupported transport scheme '{}' in URL '{}'. Must be https/wss or http/ws (loopback only).", other, clean),
    }
}

impl CollectorConfig {
    pub fn normalize_server_url(raw: &str) -> String {
        let mut base = raw.trim().trim_end_matches('/').to_string();
        if base.ends_with("/api/collectors") {
            base = base[..base.len() - "/api/collectors".len()]
                .trim_end_matches('/')
                .to_string();
        } else if base.ends_with("/api") {
            base = base[..base.len() - "/api".len()]
                .trim_end_matches('/')
                .to_string();
        }
        base
    }

    pub fn get_signing_key(&self) -> Result<Option<SigningKey>> {
        if let Some(ref blob_b64) = self.protected_key_blob {
            let encrypted_bytes = BASE64_STANDARD
                .decode(blob_b64)
                .context("Failed to decode base64 DPAPI protected key blob")?;
            let decrypted_bytes = dpapi::unprotect(&encrypted_bytes)
                .context("Failed to decrypt signing key with Windows DPAPI")?;
            if decrypted_bytes.len() != 32 {
                bail!(
                    "Decrypted DPAPI secret key seed has invalid length {}",
                    decrypted_bytes.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decrypted_bytes);
            Ok(Some(SigningKey::from_bytes(&arr)))
        } else {
            Ok(None)
        }
    }

    pub fn set_signing_key(&mut self, key: &SigningKey) -> Result<()> {
        let raw_bytes = key.as_bytes();
        let encrypted_bytes = dpapi::protect(raw_bytes)
            .context("Failed to encrypt signing key with Windows DPAPI")?;
        self.protected_key_blob = Some(BASE64_STANDARD.encode(&encrypted_bytes));
        Ok(())
    }
}

pub fn default_config_path() -> PathBuf {
    if let Some(config_dir) = dirs::data_dir() {
        config_dir
            .join("Tempris")
            .join("collector")
            .join("config.json")
    } else if let Some(home) = dirs::home_dir() {
        home.join(".tempris").join("collector").join("config.json")
    } else {
        PathBuf::from("config.json")
    }
}

pub fn load_config(custom_path: Option<&Path>) -> Result<CollectorConfig> {
    let path = custom_path
        .map(PathBuf::from)
        .unwrap_or_else(default_config_path);
    if !path.exists() {
        return Ok(CollectorConfig::default());
    }

    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config from {:?}", path))?;
    let config: CollectorConfig = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse config from {:?}", path))?;
    Ok(config)
}

pub fn save_config(config: &CollectorConfig, custom_path: Option<&Path>) -> Result<PathBuf> {
    let path = custom_path
        .map(PathBuf::from)
        .unwrap_or_else(default_config_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory {:?}", parent))?;
    }

    let json =
        serde_json::to_string_pretty(config).context("Failed to serialize config to JSON")?;
    fs::write(&path, json).with_context(|| format!("Failed to write config to {:?}", path))?;
    Ok(path)
}

pub fn reset_config(custom_path: Option<&Path>) -> Result<()> {
    let path = custom_path
        .map(PathBuf::from)
        .unwrap_or_else(default_config_path);
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("Failed to delete config file at {:?}", path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn test_transport_gate_loopback_allowed() {
        assert!(validate_transport_url("http://127.0.0.1:8000").is_ok());
        assert!(validate_transport_url("http://localhost:8000").is_ok());
        assert!(validate_transport_url("http://[::1]:8000").is_ok());
        assert!(validate_transport_url("ws://127.0.0.1:8000/api/collectors/ws").is_ok());
        assert!(validate_transport_url("ws://localhost:8000/api/collectors/ws").is_ok());
        assert!(validate_transport_url("ws://[::1]:8000/api/collectors/ws").is_ok());
    }

    #[test]
    fn test_transport_gate_remote_https_wss_allowed() {
        assert!(validate_transport_url("https://sandbox.tempris.tech/v2-assets").is_ok());
        assert!(
            validate_transport_url("wss://sandbox.tempris.tech/v2-assets/api/collectors/ws")
                .is_ok()
        );
        assert!(validate_transport_url("https://api.example.com").is_ok());
    }

    #[test]
    fn test_transport_gate_remote_plaintext_rejected() {
        let err1 = validate_transport_url("http://sandbox.tempris.tech/v2-assets");
        assert!(err1.is_err());
        assert!(err1.unwrap_err().to_string().contains("strictly forbidden"));

        let err2 = validate_transport_url("ws://sandbox.tempris.tech/v2-assets/api/collectors/ws");
        assert!(err2.is_err());
        assert!(err2.unwrap_err().to_string().contains("strictly forbidden"));

        let err3 = validate_transport_url("http://192.168.1.50:8000");
        assert!(err3.is_err());
        assert!(err3.unwrap_err().to_string().contains("strictly forbidden"));

        let err4 = validate_transport_url("ws://10.0.0.1:8000/ws");
        assert!(err4.is_err());
        assert!(err4.unwrap_err().to_string().contains("strictly forbidden"));
    }

    #[test]
    fn test_default_config_path_outside_cwd() {
        let p = default_config_path();
        assert!(
            p.is_absolute(),
            "Default config path should be absolute: {:?}",
            p
        );
        if let Ok(cwd) = std::env::current_dir() {
            assert!(
                !p.starts_with(&cwd),
                "Default config path ({:?}) must reside outside project cwd ({:?})",
                p,
                cwd
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_dpapi_protected_key_persistence() {
        let (signing_key, verifying_key) = generate_keypair();
        let raw_secret = signing_key.as_bytes();
        let raw_b64 = URL_SAFE_NO_PAD.encode(raw_secret);

        let mut config = CollectorConfig::default();
        config.collector_id = Some(Uuid::new_v4());
        config.enrolled = true;
        config
            .set_signing_key(&signing_key)
            .expect("set_signing_key with DPAPI should succeed");

        let temp_dir = std::env::temp_dir().join(format!("tempris_test_{}", Uuid::new_v4()));
        let temp_config_file = temp_dir.join("test_config.json");

        save_config(&config, Some(&temp_config_file)).expect("save_config should succeed");

        let json_contents = fs::read_to_string(&temp_config_file).expect("read temp config");
        assert!(
            !json_contents.contains("private_key_b64"),
            "Serialized JSON must NEVER contain private_key_b64 field"
        );
        assert!(
            !json_contents.contains(&raw_b64),
            "Serialized JSON must NEVER contain raw base64 secret seed"
        );
        assert!(
            json_contents.contains("protected_key_blob"),
            "Serialized JSON must contain DPAPI protected_key_blob"
        );

        let loaded = load_config(Some(&temp_config_file)).expect("load_config should succeed");
        let restored_key = loaded
            .get_signing_key()
            .expect("get_signing_key")
            .expect("key should exist");
        assert_eq!(
            restored_key.as_bytes(),
            raw_secret,
            "Decrypted key must match original secret"
        );
        assert_eq!(
            restored_key.verifying_key(),
            verifying_key,
            "Verifying key must match"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
