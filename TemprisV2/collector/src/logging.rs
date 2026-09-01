use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
}

impl LogEntry {
    pub fn new(level: &str, message: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            level: level.to_string(),
            message: message.to_string(),
        }
    }

    pub fn format_line(&self) -> String {
        format!(
            "[{}] [{}] {}\n",
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f UTC"),
            self.level,
            self.message
        )
    }

    /// Parses a formatted log line back into a LogEntry.
    pub fn parse_line(line: &str) -> Option<Self> {
        let trimmed = line.trim();
        if !trimmed.starts_with('[') {
            return None;
        }

        let first_close = trimmed.find(']')?;
        let time_str = &trimmed[1..first_close];

        let remainder = trimmed[first_close + 1..].trim();
        if !remainder.starts_with('[') {
            return None;
        }

        let second_close = remainder.find(']')?;
        let level_str = &remainder[1..second_close];
        let msg = remainder[second_close + 1..].trim();

        let timestamp = DateTime::parse_from_str(time_str, "%Y-%m-%d %H:%M:%S%.3f UTC")
            .map(|dt| dt.with_timezone(&Utc))
            .or_else(|_| DateTime::parse_from_rfc3339(time_str).map(|dt| dt.with_timezone(&Utc)))
            .unwrap_or_else(|_| Utc::now());

        Some(LogEntry {
            timestamp,
            level: level_str.to_string(),
            message: msg.to_string(),
        })
    }
}

/// Bounded operational file logger with size-based rotation and an in-memory ring buffer.
///
/// Security & Bounds:
/// - Target file: `<logs_dir>/collector.log`
/// - Threshold: 5 MB (5 * 1024 * 1024 bytes)
/// - Max backups: 3 (`collector.log.1`, `collector.log.2`, `collector.log.3`)
/// - In-Memory Buffer: Maximum 500 lines
/// - Boundary Sanitization: Message length bounded to 512 bytes, automatic redaction of credentials/tokens.
#[derive(Debug, Clone)]
pub struct BoundedLogger {
    log_file_path: PathBuf,
    max_file_size: u64,
    max_backups: usize,
    in_memory_capacity: usize,
    buffer: Arc<Mutex<Vec<LogEntry>>>,
    file_lock: Arc<Mutex<()>>,
}

impl BoundedLogger {
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB
    pub const DEFAULT_MAX_BACKUPS: usize = 3;
    pub const DEFAULT_BUFFER_CAPACITY: usize = 500;
    pub const MAX_MESSAGE_LENGTH: usize = 512;

    pub fn new(logs_dir: PathBuf) -> Self {
        let log_file_path = logs_dir.join("collector.log");
        Self {
            log_file_path,
            max_file_size: Self::DEFAULT_MAX_FILE_SIZE,
            max_backups: Self::DEFAULT_MAX_BACKUPS,
            in_memory_capacity: Self::DEFAULT_BUFFER_CAPACITY,
            buffer: Arc::new(Mutex::new(Vec::with_capacity(
                Self::DEFAULT_BUFFER_CAPACITY,
            ))),
            file_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn with_limits(
        logs_dir: PathBuf,
        max_file_size: u64,
        max_backups: usize,
        in_memory_capacity: usize,
    ) -> Self {
        let log_file_path = logs_dir.join("collector.log");
        Self {
            log_file_path,
            max_file_size,
            max_backups,
            in_memory_capacity,
            buffer: Arc::new(Mutex::new(Vec::with_capacity(in_memory_capacity))),
            file_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn log_path(&self) -> &Path {
        &self.log_file_path
    }

    /// Sanitizes message at the logger boundary: enforces length bounds, strips CR/LF/control chars,
    /// and redacts sensitive tokens, keys, signatures, and authorization headers.
    pub fn sanitize_message(raw_msg: &str) -> String {
        // Redaction patterns
        let sensitive_keywords = [
            "bearer ",
            "authorization:",
            "private_key",
            "signing_key",
            "protected_key_blob",
            "enrollment_code",
            "signature",
            "secret",
        ];

        let mut sanitized = raw_msg.to_string();

        for kw in sensitive_keywords {
            while let Some(pos) = sanitized.to_lowercase().find(kw) {
                let end = (pos + 64).min(sanitized.len());
                sanitized.replace_range(pos..end, "[REDACTED]");
            }
        }

        // Bounded length
        if sanitized.len() > Self::MAX_MESSAGE_LENGTH {
            let mut truncated = sanitized[..Self::MAX_MESSAGE_LENGTH - 16].to_string();
            truncated.push_str("... [truncated]");
            sanitized = truncated;
        }

        // Replace all control characters (including \r, \n, \t, etc.) with space to prevent log injection
        sanitized
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    }

    /// Appends a log entry to both the in-memory ring buffer and the rotated disk file.
    pub fn log(&self, level: &str, raw_message: &str) {
        let sanitized = Self::sanitize_message(raw_message);
        let entry = LogEntry::new(level, &sanitized);

        // 1. Update in-memory ring buffer
        if let Ok(mut buf) = self.buffer.lock() {
            if buf.len() >= self.in_memory_capacity {
                buf.remove(0);
            }
            buf.push(entry.clone());
        }

        // 2. Write to disk with file locking and rotation check
        let _guard = self.file_lock.lock();
        if let Some(parent) = self.log_file_path.parent() {
            let _ = fs::create_dir_all(parent);
            #[cfg(windows)]
            let _ = crate::storage::win_sec::apply_observer_tier_dacl(parent);
        }

        // Check if rotation is needed before appending
        self.rotate_if_needed();

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file_path)
        {
            #[cfg(windows)]
            let _ = crate::storage::win_sec::apply_observer_tier_dacl(&self.log_file_path);

            let line = entry.format_line();
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }

    /// Performs size-based rotation if current `collector.log` >= `max_file_size`.
    fn rotate_if_needed(&self) {
        if let Ok(metadata) = fs::metadata(&self.log_file_path) {
            if metadata.len() >= self.max_file_size {
                self.perform_rotation();
            }
        }
    }

    /// Shifts existing backups: `log.2` -> `log.3`, `log.1` -> `log.2`, `log` -> `log.1`
    pub fn perform_rotation(&self) {
        let parent = match self.log_file_path.parent() {
            Some(p) => p,
            None => return,
        };

        // Remove the oldest backup beyond max_backups
        let oldest = parent.join(format!("collector.log.{}", self.max_backups));
        if oldest.exists() {
            let _ = fs::remove_file(&oldest);
        }

        // Shift backups down (e.g. from 2 to 3, 1 to 2)
        for i in (1..self.max_backups).rev() {
            let src = parent.join(format!("collector.log.{}", i));
            let dst = parent.join(format!("collector.log.{}", i + 1));
            if src.exists() {
                let _ = fs::rename(&src, &dst);
            }
        }

        // Move active log file to collector.log.1
        let first_backup = parent.join("collector.log.1");
        if self.log_file_path.exists() {
            let _ = fs::rename(&self.log_file_path, &first_backup);
        }
    }

    /// Returns a snapshot copy of the in-memory log buffer.
    pub fn recent_entries(&self) -> Vec<LogEntry> {
        self.buffer
            .lock()
            .map(|buf| buf.clone())
            .unwrap_or_default()
    }

    /// Reads/tails the persisted disk log file (`collector.log`) returning the most recent `max_entries`.
    pub fn tail_from_disk(log_path: &Path, max_entries: usize) -> Vec<LogEntry> {
        if !log_path.exists() {
            return Vec::new();
        }

        let file = match File::open(log_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines().flatten() {
            if let Some(entry) = LogEntry::parse_line(&line) {
                entries.push(entry);
                if entries.len() > max_entries * 2 {
                    let drain_count = entries.len() - max_entries;
                    entries.drain(0..drain_count);
                }
            }
        }

        if entries.len() > max_entries {
            let start = entries.len() - max_entries;
            entries[start..].to_vec()
        } else {
            entries
        }
    }

    /// Clears the in-memory log buffer.
    pub fn clear_buffer(&self) {
        if let Ok(mut buf) = self.buffer.lock() {
            buf.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_bounded_logger_in_memory_capacity() {
        let temp_dir = std::env::temp_dir().join(format!("tempris_logger_test_{}", Uuid::new_v4()));
        let logger = BoundedLogger::with_limits(temp_dir.clone(), 1024 * 1024, 3, 5);

        for i in 0..10 {
            logger.log("INFO", &format!("Message {}", i));
        }

        let entries = logger.recent_entries();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].message, "Message 5");
        assert_eq!(entries[4].message, "Message 9");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_bounded_logger_file_rotation() {
        let temp_dir = std::env::temp_dir().join(format!("tempris_rot_test_{}", Uuid::new_v4()));
        // Small threshold (200 bytes) to force rotation with few writes
        let logger = BoundedLogger::with_limits(temp_dir.clone(), 200, 3, 100);

        for i in 0..20 {
            logger.log(
                "INFO",
                &format!("Log entry number {:04} with padding data...", i),
            );
        }

        let active_log = temp_dir.join("collector.log");
        let backup1 = temp_dir.join("collector.log.1");
        let backup2 = temp_dir.join("collector.log.2");
        let backup3 = temp_dir.join("collector.log.3");
        let backup4 = temp_dir.join("collector.log.4");

        assert!(active_log.exists(), "Active log file should exist");
        assert!(backup1.exists(), "Backup 1 should exist");
        assert!(backup2.exists(), "Backup 2 should exist");
        assert!(backup3.exists(), "Backup 3 should exist");
        assert!(
            !backup4.exists(),
            "Backup 4 should NOT exist (max_backups=3)"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_bounded_logger_tail_and_sanitization() {
        let temp_dir = std::env::temp_dir().join(format!("tempris_tail_test_{}", Uuid::new_v4()));
        let logger = BoundedLogger::with_limits(temp_dir.clone(), 1024 * 1024, 3, 50);

        logger.log("INFO", "Normal test line 1");
        logger.log("WARN", "Sensitive secret token: Bearer eyJhbGciOi...");
        logger.log("ERROR", &format!("Very long text: {}", "A".repeat(1000)));

        let disk_entries = BoundedLogger::tail_from_disk(logger.log_path(), 10);
        assert_eq!(disk_entries.len(), 3);
        assert_eq!(disk_entries[0].message, "Normal test line 1");
        assert!(disk_entries[1].message.contains("[REDACTED]"));
        assert!(!disk_entries[1].message.contains("Bearer"));
        assert!(disk_entries[2].message.contains("[truncated]"));
        assert!(disk_entries[2].message.len() <= BoundedLogger::MAX_MESSAGE_LENGTH);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_bounded_logger_crlf_and_secret_redaction() {
        let raw = "Attacker input\r\n[2026-08-28 00:00:00 UTC] [INFO] Forged log\r\nwith signature: 123456 and enrollment_code: secretcode123";
        let sanitized = BoundedLogger::sanitize_message(raw);
        assert!(!sanitized.contains('\r'), "Must not contain CR");
        assert!(!sanitized.contains('\n'), "Must not contain LF");
        assert!(sanitized.contains("[REDACTED]"));
        assert!(!sanitized.contains("secretcode123"));
    }
}
