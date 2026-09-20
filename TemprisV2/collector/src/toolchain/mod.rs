pub mod archive;
pub mod discovery;
pub mod keys;
pub mod manager;
pub mod manifest;
pub mod offline;
pub mod redaction;
pub mod state;
pub mod verifier;

use thiserror::Error;

/// Hardcoded compile-time HTTPS update origin for managed toolchain updates.
/// Server/tenant requests cannot specify or override this origin.
pub const TOOLCHAIN_UPDATE_ORIGIN: &str = "https://updates.tempris.com/v1/collector-toolchain";

#[derive(Error, Debug)]
pub enum ToolchainError {
    #[error("Manifest size {size} exceeds limit of {max} bytes")]
    ManifestTooLarge { size: usize, max: usize },

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Unsupported schema version: {0}")]
    UnsupportedSchemaVersion(u32),

    #[error("Unsupported envelope format version: {0}")]
    UnsupportedFormatVersion(u32),

    #[error("Invalid release channel: {0}")]
    InvalidChannel(String),

    #[error("Invalid semver specification: {0}")]
    InvalidSemver(String),

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("Manifest contains no components")]
    EmptyComponents,

    #[error("Unknown or unauthorized component: {0}")]
    UnknownComponent(String),

    #[error("Forbidden component: {0}")]
    ForbiddenComponent(String),

    #[error("Unsupported platform: os='{os}', arch='{arch}'")]
    UnsupportedPlatform { os: String, arch: String },

    #[error("Invalid SHA-256 digest: {0}")]
    InvalidDigest(String),

    #[error("Invalid byte size for component '{component}': {size} bytes (max {max})")]
    InvalidByteSize {
        component: String,
        size: u64,
        max: u64,
    },

    #[error("Invalid entrypoint: {0}")]
    InvalidEntrypoint(String),

    #[error("Invalid verification key: {0}")]
    InvalidVerificationKey(String),

    #[error("Key ID mismatch: expected '{expected}', got '{actual}'")]
    KeyIdMismatch { expected: String, actual: String },

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Artifact size mismatch: expected {expected} bytes, got {actual} bytes")]
    SizeMismatch { expected: u64, actual: u64 },

    #[error("Artifact size limit exceeded: size {size} bytes exceeds ceiling {max} bytes")]
    ArtifactSizeExceeded { size: u64, max: u64 },

    #[error("Artifact SHA-256 mismatch: expected '{expected}', got '{actual}'")]
    HashMismatch { expected: String, actual: String },

    #[error("Artifact checksum mismatch: expected '{expected}', got '{actual}'")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Corrupt toolchain state: {0}")]
    CorruptToolchainState(String),

    #[error("Zip slip / path traversal detected: {0}")]
    ZipSlipDetected(String),

    #[error("Invalid archive entry name: {0}")]
    InvalidArchiveEntryName(String),

    #[error("Reparse point or symbolic link forbidden in archive: {0}")]
    ReparsePointForbidden(String),

    #[error("Archive bomb or excessive expansion detected: {0}")]
    ArchiveBombDetected(String),

    #[error("Pre-activation executable probe failed: {0}")]
    PreActivationCheckFailed(String),

    #[error("Post-activation health check failed: {0}")]
    HealthCheckFailed(String),

    #[error("Toolchain update already in progress")]
    UpdateAlreadyInProgress,

    #[error("Toolchain activation deferred: active SCOUT job in progress")]
    UpdateDeferredJobRunning,

    #[error("Untrusted executable path: {0}")]
    UntrustedExecutablePath(String),

    #[error("Replay detected: manifest sequence {manifest_sequence} <= current state sequence {last_sequence}")]
    ReplayDetected {
        manifest_sequence: u64,
        last_sequence: u64,
    },

    #[error("Unauthorized downgrade for '{component}': cannot downgrade from '{current_version}' to '{candidate_version}' without emergency rollback")]
    UnauthorizedDowngrade {
        component: String,
        current_version: String,
        candidate_version: String,
    },

    #[error("Offline package directory not found: {0}")]
    PackageNotFound(String),

    #[error("Missing toolchain-manifest.json: {0}")]
    MissingManifestFile(String),

    #[error("Missing component artifact: {0}")]
    MissingComponentArtifact(String),

    #[error("Extraneous unmanifested file detected in offline package: {0}")]
    ExtraneousFileDetected(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
