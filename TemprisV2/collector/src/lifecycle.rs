use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

/// Exact discrete reconnect backoff schedule: 1s, 2s, 5s, 10s, 30s (capped at 30s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackoffLadder {
    current_index: usize,
}

impl BackoffLadder {
    pub const LADDER: &'static [Duration] = &[
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(30),
    ];

    pub fn new() -> Self {
        Self { current_index: 0 }
    }

    pub fn current(&self) -> Duration {
        Self::LADDER[self.current_index]
    }

    /// Advances to the next backoff duration on the ladder (capping at 30s) and returns the current delay.
    pub fn next(&mut self) -> Duration {
        let dur = self.current();
        if self.current_index + 1 < Self::LADDER.len() {
            self.current_index += 1;
        }
        dur
    }

    /// Resets backoff ladder back to 1s.
    /// Strict invariant: Must ONLY be called upon successful server authentication (AUTH_SUCCESS).
    pub fn reset(&mut self) {
        self.current_index = 0;
    }

    pub fn current_step(&self) -> usize {
        self.current_index
    }

    pub fn is_max(&self) -> bool {
        self.current_index >= Self::LADDER.len() - 1
    }
}

impl Default for BackoffLadder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeStatus {
    Connecting,
    Authenticating,
    Connected,
    Offline,
    Reconnecting,
    Paused,
    Quarantined,
    Revoked,
    Error,
}

impl RuntimeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeStatus::Connecting => "CONNECTING",
            RuntimeStatus::Authenticating => "AUTHENTICATING",
            RuntimeStatus::Connected => "CONNECTED",
            RuntimeStatus::Offline => "OFFLINE",
            RuntimeStatus::Reconnecting => "RECONNECTING",
            RuntimeStatus::Paused => "PAUSED",
            RuntimeStatus::Quarantined => "QUARANTINED",
            RuntimeStatus::Revoked => "REVOKED",
            RuntimeStatus::Error => "ERROR",
        }
    }
}

impl std::fmt::Display for RuntimeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Status Snapshot (`runtime.json`)
/// Non-authoritative runtime state written atomically by the core engine for GUI consumption.
/// Strict invariant: Zero private keys, seeds, JWTs, signatures, or raw payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub schema_version: u32,
    pub collector_id: Uuid,
    pub collector_name: String,
    pub server_url: String,
    pub status: RuntimeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub jobs_verified: u64,
    pub current_activity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub collector_version: String,
}

impl RuntimeSnapshot {
    pub fn new(
        collector_id: Uuid,
        collector_name: String,
        server_url: String,
        status: RuntimeStatus,
    ) -> Self {
        Self {
            schema_version: 1,
            collector_id,
            collector_name,
            server_url,
            status,
            last_heartbeat: None,
            jobs_verified: 0,
            current_activity: "Idle".to_string(),
            error_message: None,
            updated_at: Utc::now(),
            collector_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Atomically writes the runtime snapshot to `target_path` via `.tmp` swap, flush, and atomic replacement.
    pub fn save_atomic(&self, target_path: &Path) -> std::io::Result<()> {
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(windows)]
            let _ = crate::storage::win_sec::apply_restrictive_dacl(parent);
        }

        let random_suffix = Uuid::new_v4().to_string();
        let tmp_path = target_path.with_extension(format!("tmp.{}", &random_suffix[..8]));

        let json_str = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            file.write_all(json_str.as_bytes())?;
            file.sync_all()?;
        }

        #[cfg(windows)]
        let _ = crate::storage::win_sec::apply_restrictive_dacl(&tmp_path);

        if let Err(e) = crate::storage::win_file::atomic_replace(target_path, &tmp_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        #[cfg(windows)]
        let _ = crate::storage::win_sec::apply_restrictive_dacl(target_path);

        Ok(())
    }

    /// Reads and parses `runtime.json` non-authoritatively.
    pub fn load_from(path: &Path) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_ladder_schedule() {
        let mut ladder = BackoffLadder::new();
        assert_eq!(ladder.current(), Duration::from_secs(1));
        assert_eq!(ladder.next(), Duration::from_secs(1));

        assert_eq!(ladder.current(), Duration::from_secs(2));
        assert_eq!(ladder.next(), Duration::from_secs(2));

        assert_eq!(ladder.current(), Duration::from_secs(5));
        assert_eq!(ladder.next(), Duration::from_secs(5));

        assert_eq!(ladder.current(), Duration::from_secs(10));
        assert_eq!(ladder.next(), Duration::from_secs(10));

        assert_eq!(ladder.current(), Duration::from_secs(30));
        assert_eq!(ladder.next(), Duration::from_secs(30));

        // Capped at 30s
        assert_eq!(ladder.current(), Duration::from_secs(30));
        assert_eq!(ladder.next(), Duration::from_secs(30));
        assert!(ladder.is_max());

        // Reset
        ladder.reset();
        assert_eq!(ladder.current(), Duration::from_secs(1));
        assert_eq!(ladder.current_step(), 0);
    }

    #[test]
    fn test_runtime_snapshot_serialization_and_atomic_io() {
        let temp_dir =
            std::env::temp_dir().join(format!("tempris_lifecycle_test_{}", Uuid::new_v4()));
        let runtime_file = temp_dir.join("runtime.json");

        let mut snapshot = RuntimeSnapshot::new(
            Uuid::new_v4(),
            "WinCollector-01".to_string(),
            "https://sandbox.tempris.tech/v2-assets".to_string(),
            RuntimeStatus::Connected,
        );
        snapshot.last_heartbeat = Some(Utc::now());
        snapshot.jobs_verified = 42;
        snapshot.current_activity = "Verifying target 192.168.1.100".to_string();

        snapshot
            .save_atomic(&runtime_file)
            .expect("save_atomic should succeed");
        assert!(runtime_file.exists());

        let loaded = RuntimeSnapshot::load_from(&runtime_file).expect("load_from should succeed");
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.collector_id, snapshot.collector_id);
        assert_eq!(loaded.status, RuntimeStatus::Connected);
        assert_eq!(loaded.jobs_verified, 42);
        assert_eq!(loaded.current_activity, "Verifying target 192.168.1.100");

        let raw_json = fs::read_to_string(&runtime_file).expect("read raw json");
        assert!(raw_json.contains("\"status\": \"CONNECTED\""));
        assert!(!raw_json.contains("private_key"));
        assert!(!raw_json.contains("secret"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
