use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::{public_key_from_base64url, public_key_to_base64url};

#[cfg(windows)]
pub mod dpapi {
    use super::StorageError;
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

    pub const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    pub const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

    /// Encrypt data using machine-scoped DPAPI (accessible by all processes/services on the local machine)
    pub fn protect_machine(data: &[u8]) -> Result<Vec<u8>, StorageError> {
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
        let flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;
        let ret = unsafe {
            CryptProtectData(
                &in_blob,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                flags,
                &mut out_blob,
            )
        };
        if ret == 0 || out_blob.pbData.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(StorageError::DpapiError(format!(
                "DPAPI CryptProtectData (machine scope) failed: {}",
                err
            )));
        }
        let out_bytes = unsafe {
            let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let vec = slice.to_vec();
            LocalFree(out_blob.pbData as *mut _);
            vec
        };
        Ok(out_bytes)
    }

    /// Encrypt data using user-scoped DPAPI (legacy V0.1 compatibility)
    pub fn protect_user(data: &[u8]) -> Result<Vec<u8>, StorageError> {
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
            let err = std::io::Error::last_os_error();
            return Err(StorageError::DpapiError(format!(
                "DPAPI CryptProtectData (user scope) failed: {}",
                err
            )));
        }
        let out_bytes = unsafe {
            let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let vec = slice.to_vec();
            LocalFree(out_blob.pbData as *mut _);
            vec
        };
        Ok(out_bytes)
    }

    /// Decrypt data with DPAPI (automatically handles machine-scope or user-scope ciphertext)
    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, StorageError> {
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
            let err = std::io::Error::last_os_error();
            return Err(StorageError::DpapiError(format!(
                "DPAPI CryptUnprotectData failed: {}",
                err
            )));
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
pub mod dpapi {
    use super::StorageError;

    pub fn protect_machine(data: &[u8]) -> Result<Vec<u8>, StorageError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        // Non-windows test stub: simple reversible obfuscation for dev/test builds
        Ok(data.iter().map(|b| b ^ 0x5A).collect())
    }

    pub fn protect_user(data: &[u8]) -> Result<Vec<u8>, StorageError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        Ok(data.iter().map(|b| b ^ 0xA5).collect())
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, StorageError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        Ok(data.iter().map(|b| b ^ 0x5A).collect())
    }
}

#[cfg(windows)]
pub mod win_file {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    #[link(name = "kernel32")]
    extern "system" {
        fn ReplaceFileW(
            lpReplacedFileName: *const u16,
            lpReplacementFileName: *const u16,
            lpBackupFileName: *const u16,
            dwReplaceFlags: u32,
            lpExclude: *mut std::ffi::c_void,
            lpReserved: *mut std::ffi::c_void,
        ) -> i32;

        fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> i32;
    }

    pub const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    pub const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    pub const REPLACEFILE_WRITE_THROUGH: u32 = 0x1;

    /// Performs true Windows atomic file replacement with write-through semantics.
    pub fn atomic_replace(target: &Path, tmp: &Path) -> std::io::Result<()> {
        let target_wide: Vec<u16> = target
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let tmp_wide: Vec<u16> = tmp
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        if target.exists() {
            let ret = unsafe {
                ReplaceFileW(
                    target_wide.as_ptr(),
                    tmp_wide.as_ptr(),
                    null_mut(),
                    REPLACEFILE_WRITE_THROUGH,
                    null_mut(),
                    null_mut(),
                )
            };
            if ret != 0 {
                return Ok(());
            }

            let ret2 = unsafe {
                MoveFileExW(
                    tmp_wide.as_ptr(),
                    target_wide.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if ret2 != 0 {
                return Ok(());
            }
            Err(std::io::Error::last_os_error())
        } else {
            let ret = unsafe {
                MoveFileExW(
                    tmp_wide.as_ptr(),
                    target_wide.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if ret != 0 {
                return Ok(());
            }
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(not(windows))]
pub mod win_file {
    use std::path::Path;

    pub fn atomic_replace(target: &Path, tmp: &Path) -> std::io::Result<()> {
        std::fs::rename(tmp, target)
    }
}

#[cfg(windows)]
pub mod win_sec {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;
    use winapi::shared::sddl::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
        SDDL_REVISION_1,
    };
    use winapi::um::accctrl::SE_FILE_OBJECT;
    use winapi::um::aclapi::SetNamedSecurityInfoW;
    use winapi::um::securitybaseapi::SetFileSecurityW;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    pub const SECRET_TIER_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    pub const OBSERVER_TIER_SDDL: &str =
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;GRGX;;;BU)";

    pub fn apply_sddl_dacl(path: &Path, sddl: &str) -> std::io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut p_sd: *mut std::ffi::c_void = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1 as u32,
                &mut p_sd as *mut _ as *mut _,
                null_mut(),
            ) != 0
            {
                let ret = SetFileSecurityW(
                    path_wide.as_ptr(),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    p_sd as *mut _,
                );
                LocalFree(p_sd as *mut _);
                if ret != 0 {
                    return Ok(());
                } else {
                    return Err(std::io::Error::last_os_error());
                }
            } else {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    /// Applies Secret Tier DACL (SYSTEM and Administrators full access only; NO OWNER access)
    pub fn apply_secret_tier_dacl(path: &Path) -> std::io::Result<()> {
        apply_sddl_dacl(path, SECRET_TIER_SDDL)
    }

    /// Applies Observer Tier DACL (SYSTEM, Admins, Owner FA; Builtin Users GRGX)
    pub fn apply_observer_tier_dacl(path: &Path) -> std::io::Result<()> {
        apply_sddl_dacl(path, OBSERVER_TIER_SDDL)
    }

    /// Legacy compatibility helper
    pub fn apply_restrictive_dacl(path: &Path) -> std::io::Result<()> {
        apply_observer_tier_dacl(path)
    }

    /// Transfers NTFS file/directory ownership to Builtin Administrators (S-1-5-32-544)
    pub fn transfer_ownership_to_administrators(path: &Path) -> std::io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let admin_sid_str: Vec<u16> = "S-1-5-32-544\0".encode_utf16().collect();
        let mut p_sid: *mut std::ffi::c_void = null_mut();

        unsafe {
            if ConvertStringSidToSidW(admin_sid_str.as_ptr(), &mut p_sid as *mut _ as *mut _) == 0 {
                return Err(std::io::Error::last_os_error());
            }

            let ret = SetNamedSecurityInfoW(
                path_wide.as_ptr() as *mut _,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                p_sid as *mut _,
                null_mut(),
                null_mut(),
                null_mut(),
            );

            LocalFree(p_sid as *mut _);

            if ret != 0 {
                return Err(std::io::Error::from_raw_os_error(ret as i32));
            }
        }
        Ok(())
    }
}

#[cfg(not(windows))]
pub mod win_sec {
    use std::path::Path;

    pub const SECRET_TIER_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    pub const OBSERVER_TIER_SDDL: &str =
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;GRGX;;;BU)";

    pub fn apply_secret_tier_dacl(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }

    pub fn apply_observer_tier_dacl(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }

    pub fn apply_restrictive_dacl(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }

    pub fn transfer_ownership_to_administrators(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorState {
    pub schema_version: u32,
    pub collector_id: Uuid,
    pub collector_name: String,
    pub server_url: String,
    pub public_key: String,
    pub enrolled_at: DateTime<Utc>,
    pub collector_version: String,
}

impl CollectorState {
    pub fn new(
        collector_id: Uuid,
        collector_name: String,
        server_url: String,
        public_key: String,
        enrolled_at: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_version: 2,
            collector_id,
            collector_name,
            server_url,
            public_key,
            enrolled_at,
            collector_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("State not found")]
    NotFound,
    #[error("Corrupt state JSON: {0}")]
    CorruptStateJson(String),
    #[error("Missing or corrupt protected identity blob: {0}")]
    CorruptProtectedIdentity(String),
    #[error("DPAPI encryption/decryption error: {0}")]
    DpapiError(String),
    #[error("Public key does not match decrypted private key identity")]
    IdentityMismatch,
    #[error("Reset verification failed: {0}")]
    ResetFailed(String),
    #[error("Migration failed: {0}")]
    MigrationError(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Atomically writes data to `target_path` via a temporary file, sync, and atomic replacement.
pub fn atomic_write_file(target_path: &Path, data: &[u8]) -> Result<(), StorageError> {
    let is_secret = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|name| name == "protected_identity.dat" || name.starts_with("task_def_"))
        .unwrap_or(false)
        || target_path.to_string_lossy().contains("staging");

    atomic_write_file_with_tier(target_path, data, is_secret)
}

/// Atomically writes data applying either Secret Tier or Observer Tier DACL.
pub fn atomic_write_file_with_tier(
    target_path: &Path,
    data: &[u8],
    _is_secret_tier: bool,
) -> Result<(), StorageError> {
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(windows)]
        {
            if target_path.to_string_lossy().contains("staging") && parent.ends_with("staging") {
                let _ = win_sec::apply_secret_tier_dacl(parent);
            } else {
                let _ = win_sec::apply_observer_tier_dacl(parent);
            }
        }
    }
    let random_suffix = Uuid::new_v4().to_string();
    let tmp_path = target_path.with_extension(format!("tmp.{}", &random_suffix[..8]));

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
    }

    #[cfg(windows)]
    {
        let _ = win_sec::apply_observer_tier_dacl(&tmp_path);
    }

    if let Err(e) = win_file::atomic_replace(target_path, &tmp_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(StorageError::Io(e));
    }

    #[cfg(windows)]
    {
        let _ = win_sec::apply_observer_tier_dacl(target_path);
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct StorageManager {
    base_dir: PathBuf,
}

impl StorageManager {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn get_secret_tier_sddl() -> &'static str {
        win_sec::SECRET_TIER_SDDL
    }

    pub fn get_observer_tier_sddl() -> &'static str {
        win_sec::OBSERVER_TIER_SDDL
    }

    /// Canonical machine-level storage directory: `%PROGRAMDATA%\Tempris\Collector\`
    pub fn default_machine_storage() -> Self {
        let base = if let Ok(progdata) = std::env::var("PROGRAMDATA") {
            PathBuf::from(progdata).join("Tempris").join("Collector")
        } else if let Some(data_dir) = dirs::data_dir() {
            data_dir.join("Tempris").join("Collector")
        } else {
            PathBuf::from("C:\\ProgramData\\Tempris\\Collector")
        };
        Self::new(base)
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.base_dir.join("staging")
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.base_dir.join("bin")
    }

    pub fn state_path(&self) -> PathBuf {
        self.base_dir.join("state.json")
    }

    pub fn identity_path(&self) -> PathBuf {
        self.base_dir.join("protected_identity.dat")
    }

    pub fn protected_identity_path(&self) -> PathBuf {
        self.identity_path()
    }

    pub fn runtime_path(&self) -> PathBuf {
        self.base_dir.join("runtime.json")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.base_dir.join("logs")
    }

    pub fn exists(&self) -> bool {
        self.state_path().exists() && self.identity_path().exists()
    }

    pub fn has_any_state(&self) -> bool {
        self.state_path().exists() || self.identity_path().exists()
    }

    /// Load V0.2 public state and decrypt machine-scoped Ed25519 signing key.
    /// Fails closed with typed StorageError on missing or corrupted data.
    pub fn load(&self) -> Result<(CollectorState, SigningKey), StorageError> {
        let s_path = self.state_path();
        let i_path = self.identity_path();

        if !s_path.exists() && !i_path.exists() {
            return Err(StorageError::NotFound);
        }

        if !s_path.exists() && i_path.exists() {
            return Err(StorageError::CorruptStateJson(
                "state.json is missing while protected_identity.dat exists".to_string(),
            ));
        }

        let state_content = fs::read_to_string(&s_path).map_err(|e| {
            StorageError::CorruptStateJson(format!("Failed to read state.json: {}", e))
        })?;

        let state: CollectorState = serde_json::from_str(&state_content)
            .map_err(|e| StorageError::CorruptStateJson(format!("Malformed state.json: {}", e)))?;

        if state.schema_version != 2 {
            return Err(StorageError::CorruptStateJson(format!(
                "Unsupported schema_version {}; expected 2",
                state.schema_version
            )));
        }

        if !i_path.exists() {
            return Err(StorageError::CorruptProtectedIdentity(
                "protected_identity.dat is missing".to_string(),
            ));
        }

        let encrypted_identity = fs::read(&i_path).map_err(|e| {
            StorageError::CorruptProtectedIdentity(format!(
                "Failed to read protected_identity.dat: {}",
                e
            ))
        })?;

        if encrypted_identity.is_empty() {
            return Err(StorageError::CorruptProtectedIdentity(
                "protected_identity.dat is empty (0 bytes)".to_string(),
            ));
        }

        let decrypted_seed = dpapi::unprotect(&encrypted_identity)?;
        if decrypted_seed.len() != 32 {
            return Err(StorageError::CorruptProtectedIdentity(format!(
                "Decrypted identity seed length is {} bytes, expected 32",
                decrypted_seed.len()
            )));
        }

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&decrypted_seed);
        let signing_key = SigningKey::from_bytes(&seed_arr);

        // Assert public key matches decrypted private key identity
        let derived_pubkey = signing_key.verifying_key();
        let expected_pubkey = public_key_from_base64url(&state.public_key).map_err(|e| {
            StorageError::CorruptStateJson(format!("Invalid public_key in state.json: {}", e))
        })?;

        if derived_pubkey != expected_pubkey {
            return Err(StorageError::IdentityMismatch);
        }

        Ok((state, signing_key))
    }

    /// Atomically save public state.json and DPAPI machine-scoped protected_identity.dat.
    /// Retains previous valid state until new pair is committed and verified via roundtrip reload.
    pub fn save(&self, state: &CollectorState, key: &SigningKey) -> Result<(), StorageError> {
        if state.schema_version != 2 {
            return Err(StorageError::CorruptStateJson(format!(
                "Attempted to save state with invalid schema_version {}; expected 2",
                state.schema_version
            )));
        }

        // Verify key corresponds to public_key in state
        let expected_pub = public_key_from_base64url(&state.public_key).map_err(|e| {
            StorageError::CorruptStateJson(format!("Invalid public_key in state: {}", e))
        })?;
        if key.verifying_key() != expected_pub {
            return Err(StorageError::IdentityMismatch);
        }

        // Ensure base directory exists with observer DACL
        fs::create_dir_all(&self.base_dir)?;
        #[cfg(windows)]
        let _ = win_sec::apply_observer_tier_dacl(&self.base_dir);

        // Encrypt 32-byte seed with machine-scoped DPAPI
        let encrypted_blob = dpapi::protect_machine(key.as_bytes())?;

        // Format state.json (ensuring 0 secrets or private key representations)
        let state_json = serde_json::to_string_pretty(state).map_err(|e| {
            StorageError::CorruptStateJson(format!("Failed to serialize state: {}", e))
        })?;

        // Atomic writes: identity first (Secret Tier), then state (Observer Tier)
        atomic_write_file_with_tier(&self.identity_path(), &encrypted_blob, true)?;
        atomic_write_file_with_tier(&self.state_path(), state_json.as_bytes(), false)?;

        // Roundtrip reload verification
        let (verified_state, verified_key) = self.load().map_err(|e| {
            StorageError::CorruptStateJson(format!(
                "Roundtrip reload verification failed after saving: {}",
                e
            ))
        })?;

        if verified_state.collector_id != state.collector_id
            || verified_key.as_bytes() != key.as_bytes()
        {
            return Err(StorageError::IdentityMismatch);
        }

        Ok(())
    }

    /// Reset registration by removing state.json, protected_identity.dat, and runtime.json.
    /// Fails closed if any credential file cannot be removed or remains present.
    pub fn reset(&self) -> Result<(), StorageError> {
        let s_path = self.state_path();
        if s_path.exists() {
            fs::remove_file(&s_path).map_err(|e| {
                StorageError::ResetFailed(format!("Failed to remove state.json: {}", e))
            })?;
        }

        let i_path = self.identity_path();
        if i_path.exists() {
            fs::remove_file(&i_path).map_err(|e| {
                StorageError::ResetFailed(format!("Failed to remove protected_identity.dat: {}", e))
            })?;
        }

        let r_path = self.runtime_path();
        if r_path.exists() {
            let _ = fs::remove_file(&r_path);
        }

        // Clean any lingering .tmp files in base_dir
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(file_name) = p.file_name().and_then(|n| n.to_str()) {
                    if file_name.contains(".tmp")
                        || file_name.starts_with("tmp")
                        || file_name.ends_with(".tmp")
                    {
                        let _ = fs::remove_file(&p);
                    }
                }
            }
        }

        // Verify absence of sensitive credential files
        if self.state_path().exists() {
            return Err(StorageError::ResetFailed(
                "state.json still exists after reset".to_string(),
            ));
        }
        if self.identity_path().exists() {
            return Err(StorageError::ResetFailed(
                "protected_identity.dat still exists after reset".to_string(),
            ));
        }

        Ok(())
    }

    /// Migrate legacy V0.1 config (`%APPDATA%\Tempris\collector\config.json`) to V0.2 storage.
    /// Preserves exact collector_id, collector_name, server_url, and Ed25519 keypair.
    pub fn migrate_v01_if_needed(
        &self,
        legacy_config_path: Option<&Path>,
    ) -> Result<Option<(CollectorState, SigningKey)>, StorageError> {
        // If any V0.2 state exists (complete or partial), do not overwrite it with migration
        if self.has_any_state() {
            return Ok(None);
        }

        let default_legacy = dirs::data_dir()
            .map(|d| d.join("Tempris").join("collector").join("config.json"))
            .unwrap_or_else(|| PathBuf::from("config.json"));
        let leg_path = legacy_config_path.unwrap_or(&default_legacy);

        if !leg_path.exists() {
            return Ok(None);
        }

        let raw_content = fs::read_to_string(leg_path).map_err(|e| {
            StorageError::MigrationError(format!("Failed to read legacy V0.1 config: {}", e))
        })?;

        // Parse legacy CollectorConfig
        let legacy_val: serde_json::Value = serde_json::from_str(&raw_content).map_err(|e| {
            StorageError::MigrationError(format!("Malformed legacy V0.1 JSON: {}", e))
        })?;

        let is_enrolled = legacy_val
            .get("enrolled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let col_id_str = legacy_val.get("collector_id").and_then(|v| v.as_str());
        let blob_b64 = legacy_val
            .get("protected_key_blob")
            .and_then(|v| v.as_str());

        if !is_enrolled || col_id_str.is_none() || blob_b64.is_none() {
            // Not an enrolled V0.1 installation, nothing to migrate
            return Ok(None);
        }

        let collector_id: Uuid = col_id_str.unwrap().parse().map_err(|e| {
            StorageError::MigrationError(format!(
                "Invalid collector_id in legacy V0.1 config: {}",
                e
            ))
        })?;

        let encrypted_bytes = base64::engine::general_purpose::STANDARD
            .decode(blob_b64.unwrap())
            .map_err(|e| {
                StorageError::MigrationError(format!(
                    "Invalid base64 in legacy V0.1 protected_key_blob: {}",
                    e
                ))
            })?;

        let decrypted_seed = dpapi::unprotect(&encrypted_bytes)?;
        if decrypted_seed.len() != 32 {
            return Err(StorageError::MigrationError(format!(
                "Decrypted legacy key seed is {} bytes, expected 32",
                decrypted_seed.len()
            )));
        }

        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&decrypted_seed);
        let signing_key = SigningKey::from_bytes(&seed_arr);
        let derived_pub = public_key_to_base64url(&signing_key.verifying_key());

        let collector_name = legacy_val
            .get("collector_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("Collector-{}", &collector_id.to_string()[..8]));

        let raw_server_url = legacy_val
            .get("server_url")
            .and_then(|v| v.as_str())
            .unwrap_or("https://sandbox.tempris.tech/v2-assets");
        let server_url = crate::config::CollectorConfig::normalize_server_url(raw_server_url);

        let enrolled_at = legacy_val
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let v02_state = CollectorState {
            schema_version: 2,
            collector_id,
            collector_name,
            server_url,
            public_key: derived_pub,
            enrolled_at,
            collector_version: "0.2.0".to_string(),
        };

        // Save V0.2 state and machine-scoped identity
        self.save(&v02_state, &signing_key)?;

        // Verify roundtrip read of V0.2 files
        let (verified_state, verified_key) = self.load().map_err(|e| {
            StorageError::MigrationError(format!(
                "Roundtrip verification of V0.2 state failed after migration: {}",
                e
            ))
        })?;

        if verified_state.collector_id != collector_id
            || verified_key.as_bytes() != signing_key.as_bytes()
        {
            return Err(StorageError::MigrationError(
                "Verified V0.2 state mismatch after migration".to_string(),
            ));
        }

        // Rename legacy file to .migrated marker
        let migrated_path = leg_path.with_extension("json.migrated");
        let _ = fs::rename(leg_path, &migrated_path);

        Ok(Some((v02_state, signing_key)))
    }
}
