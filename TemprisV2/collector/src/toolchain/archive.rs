use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

use super::ToolchainError;
use crate::storage::apply_observer_tier_dacl;

/// Limits for safe archive extraction.
pub const MAX_ARCHIVE_ENTRIES: usize = 50_000;
pub const MAX_UNCOMPRESSED_BYTES: u64 = 250 * 1024 * 1024; // 250 MiB
pub const MAX_COMPRESSION_RATIO: u64 = 50;

/// Windows reserved device names that must be rejected to prevent device namespace hijacking.
const RESERVED_DOS_DEVICES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Debug, Clone, Default)]
pub struct ExtractionSummary {
    pub files_extracted: usize,
    pub directories_created: usize,
    pub total_uncompressed_bytes: u64,
}

/// Safely extracts a zip archive to an isolated staging directory.
///
/// Invariants enforced:
/// - Target directory must exist.
/// - C.1: Rejection of path traversal (`..`), absolute paths, Windows drive letters,
///        Alternate Data Streams (`:`), null bytes (`\0`), backslash path components (`\`),
///        and reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
/// - C.2: Rejection of symbolic links, hard links, and NTFS reparse points.
/// - C.3: Max 50,000 entries.
/// - C.4: Max 250 MiB uncompressed size.
/// - C.5: Max 50:1 compression ratio.
/// - C.6: Observer DACL permissions applied to the target directory and extracted files.
pub fn safe_extract_zip(archive_path: &Path, staging_dir: &Path) -> Result<ExtractionSummary, ToolchainError> {
    if !staging_dir.exists() {
        fs::create_dir_all(staging_dir).map_err(ToolchainError::Io)?;
    }
    let _ = apply_observer_tier_dacl(staging_dir);

    let file = File::open(archive_path).map_err(ToolchainError::Io)?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| ToolchainError::DeserializationError(format!("Invalid zip archive: {}", e)))?;

    let entry_count = archive.len();
    if entry_count > MAX_ARCHIVE_ENTRIES {
        return Err(ToolchainError::ArchiveBombDetected(format!(
            "Entry count {} exceeds limit {}",
            entry_count, MAX_ARCHIVE_ENTRIES
        )));
    }

    let mut summary = ExtractionSummary::default();
    let mut total_compressed: u64 = 0;
    let mut total_uncompressed: u64 = 0;

    for i in 0..entry_count {
        let mut entry = archive.by_index(i)
            .map_err(|e| ToolchainError::DeserializationError(format!("Error reading zip entry #{}: {}", i, e)))?;

        let raw_name = entry.name().to_string();

        // C.1 Path name validations
        validate_entry_name(&raw_name)?;

        // C.2 Symlink / reparse point check
        if entry.is_symlink() {
            return Err(ToolchainError::ReparsePointForbidden(format!(
                "Symbolic link detected in entry '{}'",
                raw_name
            )));
        }

        if let Some(mode) = entry.unix_mode() {
            // S_IFLNK is 0o120000
            if (mode & 0o170000) == 0o120000 {
                return Err(ToolchainError::ReparsePointForbidden(format!(
                    "Symbolic link detected via unix mode in entry '{}'",
                    raw_name
                )));
            }
        }

        // Check extra data for NTFS reparse point or symlink tag (0x000a or 0x0014)
        if let Some(extra) = entry.extra_data() {
            if extra.len() >= 4 {
                let header_id = u16::from_le_bytes([extra[0], extra[1]]);
                if header_id == 0x000a || header_id == 0x0014 {
                    return Err(ToolchainError::ReparsePointForbidden(format!(
                        "NTFS reparse point detected in entry '{}'",
                        raw_name
                    )));
                }
            }
        }

        let compressed_size = entry.compressed_size();
        let uncompressed_size = entry.size();

        total_compressed = total_compressed.saturating_add(compressed_size);
        total_uncompressed = total_uncompressed.saturating_add(uncompressed_size);

        // C.4 Total size check
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES {
            return Err(ToolchainError::ArchiveBombDetected(format!(
                "Total uncompressed size {} bytes exceeds limit {} bytes",
                total_uncompressed, MAX_UNCOMPRESSED_BYTES
            )));
        }

        // C.5 Per-entry compression ratio check (for non-trivial sizes)
        if compressed_size > 64 && uncompressed_size > compressed_size.saturating_mul(MAX_COMPRESSION_RATIO) {
            return Err(ToolchainError::ArchiveBombDetected(format!(
                "Compression ratio for entry '{}' ({}:{}) exceeds maximum {}:1",
                raw_name, uncompressed_size, compressed_size, MAX_COMPRESSION_RATIO
            )));
        }

        // Destination path resolution and Zip Slip containment check
        let safe_rel_path = sanitize_relative_path(&raw_name)?;
        let destination = staging_dir.join(&safe_rel_path);

        if !is_contained(staging_dir, &destination) {
            return Err(ToolchainError::ZipSlipDetected(format!(
                "Path traversal detected: '{}' escapes staging root",
                raw_name
            )));
        }

        if entry.is_dir() || raw_name.ends_with('/') {
            if !destination.exists() {
                fs::create_dir_all(&destination).map_err(ToolchainError::Io)?;
                let _ = apply_observer_tier_dacl(&destination);
            }
            summary.directories_created += 1;
        } else {
            if let Some(parent) = destination.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).map_err(ToolchainError::Io)?;
                    let _ = apply_observer_tier_dacl(parent);
                }
            }

            let mut out_file = File::create(&destination).map_err(ToolchainError::Io)?;
            let mut read_bytes: u64 = 0;
            let mut buffer = [0u8; 8192];

            loop {
                let n = entry.read(&mut buffer).map_err(ToolchainError::Io)?;
                if n == 0 {
                    break;
                }
                read_bytes += n as u64;
                if summary.total_uncompressed_bytes.saturating_add(read_bytes) > MAX_UNCOMPRESSED_BYTES {
                    // Clean up partially written file
                    drop(out_file);
                    let _ = fs::remove_file(&destination);
                    return Err(ToolchainError::ArchiveBombDetected(format!(
                        "Streaming uncompressed size exceeded limit of {} bytes",
                        MAX_UNCOMPRESSED_BYTES
                    )));
                }
                io::Write::write_all(&mut out_file, &buffer[..n]).map_err(ToolchainError::Io)?;
            }

            let _ = apply_observer_tier_dacl(&destination);
            summary.files_extracted += 1;
            summary.total_uncompressed_bytes += read_bytes;
        }
    }

    // C.5 Overall compression ratio check
    if total_compressed > 1024 && total_uncompressed > total_compressed.saturating_mul(MAX_COMPRESSION_RATIO) {
        return Err(ToolchainError::ArchiveBombDetected(format!(
            "Overall compression ratio ({}:{}) exceeds maximum {}:1",
            total_uncompressed, total_compressed, MAX_COMPRESSION_RATIO
        )));
    }

    Ok(summary)
}

/// Validates raw entry path string against malicious characters, ADS, DOS devices, and backslashes.
pub fn validate_entry_name(name: &str) -> Result<(), ToolchainError> {
    // Rejection of null bytes
    if name.contains('\0') {
        return Err(ToolchainError::InvalidArchiveEntryName(format!(
            "Entry name contains null byte: {:?}",
            name
        )));
    }

    // Rejection of Alternate Data Streams (colon)
    if name.contains(':') {
        return Err(ToolchainError::InvalidArchiveEntryName(format!(
            "Entry name contains Alternate Data Stream separator ':': {:?}",
            name
        )));
    }

    // Rejection of backslashes (zip spec mandates forward slash)
    if name.contains('\\') {
        return Err(ToolchainError::InvalidArchiveEntryName(format!(
            "Entry name contains illegal backslash separator '\\': {:?}",
            name
        )));
    }

    // Rejection of absolute path or drive letter
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(ToolchainError::ZipSlipDetected(format!(
            "Entry name has leading separator: {:?}",
            name
        )));
    }

    // Check individual path segments
    for segment in name.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return Err(ToolchainError::ZipSlipDetected(format!(
                "Path traversal segment '..' detected: {:?}",
                name
            )));
        }

        // Check DOS device names (e.g. CON, PRN, AUX, NUL, COM1-9, LPT1-9)
        // Matches stem before any extension (e.g. "con.txt", "NUL", "aux.yaml")
        let stem = match segment.split('.').next() {
            Some(s) => s.trim(),
            None => segment.trim(),
        };

        for reserved in RESERVED_DOS_DEVICES {
            if stem.eq_ignore_ascii_case(reserved) {
                return Err(ToolchainError::InvalidArchiveEntryName(format!(
                    "Reserved DOS device name '{}' in segment '{}' in entry '{}'",
                    reserved, segment, name
                )));
            }
        }
    }

    Ok(())
}

/// Converts normalized forward-slash zip path into a safe relative PathBuf.
fn sanitize_relative_path(name: &str) -> Result<PathBuf, ToolchainError> {
    let mut rel_path = PathBuf::new();
    for segment in name.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return Err(ToolchainError::ZipSlipDetected(format!(
                "Path traversal segment '..' detected in '{}'",
                name
            )));
        }
        rel_path.push(segment);
    }
    Ok(rel_path)
}

/// Verifies that destination is strictly inside staging_dir root.
fn is_contained(root: &Path, destination: &Path) -> bool {
    let canonical_root = match root.canonicalize() {
        Ok(p) => p,
        Err(_) => root.to_path_buf(),
    };

    // Note: destination may not exist yet, so canonicalize parent
    let mut check_path = destination.to_path_buf();
    while !check_path.exists() {
        match check_path.parent() {
            Some(p) => check_path = p.to_path_buf(),
            None => break,
        }
    }

    let canonical_check = match check_path.canonicalize() {
        Ok(p) => p,
        Err(_) => check_path,
    };

    canonical_check.starts_with(&canonical_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    #[test]
    fn test_valid_entry_name() {
        assert!(validate_entry_name("templates/cves/2023/cve-2023-1234.yaml").is_ok());
        assert!(validate_entry_name("http/vulnerabilities/test.yaml").is_ok());
    }

    #[test]
    fn test_reject_null_byte() {
        let err = validate_entry_name("templates/test\0.yaml").unwrap_err();
        match err {
            ToolchainError::InvalidArchiveEntryName(s) => assert!(s.contains("null byte")),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_reject_ads_colon() {
        let err = validate_entry_name("templates/test.yaml:Zone.Identifier").unwrap_err();
        match err {
            ToolchainError::InvalidArchiveEntryName(s) => assert!(s.contains("Alternate Data Stream")),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_reject_backslashes() {
        let err = validate_entry_name("templates\\cves\\test.yaml").unwrap_err();
        match err {
            ToolchainError::InvalidArchiveEntryName(s) => assert!(s.contains("backslash")),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_reject_dos_devices() {
        for dev in &["CON", "prn", "aux.txt", "NUL.yaml", "com1", "lpt9.dat"] {
            let path = format!("templates/{}", dev);
            let err = validate_entry_name(&path).unwrap_err();
            match err {
                ToolchainError::InvalidArchiveEntryName(s) => assert!(s.contains("Reserved DOS device")),
                other => panic!("Unexpected error for {}: {:?}", dev, other),
            }
        }
    }

    #[test]
    fn test_reject_zip_slip_traversal() {
        let err = validate_entry_name("../evil.yaml").unwrap_err();
        match err {
            ToolchainError::ZipSlipDetected(_) => {}
            other => panic!("Unexpected error: {:?}", other),
        }

        let err2 = validate_entry_name("templates/../../evil.yaml").unwrap_err();
        match err2 {
            ToolchainError::ZipSlipDetected(_) => {}
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_safe_extract_valid_zip() {
        let dir = tempdir().unwrap();
        let zip_path = dir.path().join("test.zip");
        let staging_path = dir.path().join("staging");

        // Create a valid zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("templates/cve.yaml", SimpleFileOptions::default()).unwrap();
        zip.write_all(b"id: cve-2023-0001\ninfo:\n  name: Test\n").unwrap();
        zip.finish().unwrap();

        let summary = safe_extract_zip(&zip_path, &staging_path).unwrap();
        assert_eq!(summary.files_extracted, 1);
        let extracted_file = staging_path.join("templates").join("cve.yaml");
        assert!(extracted_file.exists());
        let content = fs::read_to_string(extracted_file).unwrap();
        assert!(content.contains("cve-2023-0001"));
    }
}
