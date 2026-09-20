use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};

use super::keys::{get_verification_key, TOOLCHAIN_RELEASE_KEY_ID};
use super::manifest::{ToolchainEnvelope, ToolchainManifest, MAX_MANIFEST_RAW_BYTES};
use super::ToolchainError;

/// Verifies a canonical signed envelope and returns the validated manifest.
/// Strictly enforces the order of operations:
/// 1. Envelope format and size validation.
/// 2. Raw-byte Ed25519 signature verification against the compiled-in public key BEFORE deserializing the manifest.
/// 3. Structural deserialization and constraint validation of the manifest payload.
pub fn verify_envelope(envelope_raw: &[u8]) -> Result<ToolchainManifest, ToolchainError> {
    if envelope_raw.len() > MAX_MANIFEST_RAW_BYTES * 2 {
        return Err(ToolchainError::ManifestTooLarge {
            size: envelope_raw.len(),
            max: MAX_MANIFEST_RAW_BYTES * 2,
        });
    }

    let envelope_str = std::str::from_utf8(envelope_raw)
        .map_err(|e| ToolchainError::DeserializationError(format!("Invalid envelope UTF-8: {}", e)))?;

    let envelope: ToolchainEnvelope = serde_json::from_str(envelope_str)
        .map_err(|e| ToolchainError::DeserializationError(format!("Corrupt envelope JSON: {}", e)))?;

    if envelope.format_version != 1 {
        return Err(ToolchainError::UnsupportedFormatVersion(envelope.format_version));
    }

    if envelope.key_id != TOOLCHAIN_RELEASE_KEY_ID {
        return Err(ToolchainError::KeyIdMismatch {
            expected: TOOLCHAIN_RELEASE_KEY_ID.to_string(),
            actual: envelope.key_id,
        });
    }

    let sig_bytes = hex::decode(&envelope.signature)
        .map_err(|e| ToolchainError::SignatureVerificationFailed(format!("Invalid signature hex: {}", e)))?;

    if sig_bytes.len() != 64 {
        return Err(ToolchainError::SignatureVerificationFailed(format!(
            "Signature length must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let verifying_key = get_verification_key()?;

    // CRITICAL: Raw byte signature verification before any manifest JSON parsing
    verifying_key
        .verify_strict(envelope.manifest_raw.as_bytes(), &signature)
        .map_err(|e| ToolchainError::SignatureVerificationFailed(format!("Ed25519 verification failed: {}", e)))?;

    // Deserialization occurs only after signature has been cryptographically validated
    let manifest = ToolchainManifest::parse_and_validate(envelope.manifest_raw.as_bytes())?;
    Ok(manifest)
}

/// Verifies that artifact bytes match the expected SHA-256 digest and byte size.
pub fn verify_artifact_bytes(
    data: &[u8],
    expected_sha256: &str,
    expected_byte_size: u64,
) -> Result<(), ToolchainError> {
    let actual_size = data.len() as u64;
    if actual_size != expected_byte_size {
        return Err(ToolchainError::SizeMismatch {
            expected: expected_byte_size,
            actual: actual_size,
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual_hash = hex::encode(hasher.finalize());

    if actual_hash != expected_sha256.to_ascii_lowercase() {
        return Err(ToolchainError::HashMismatch {
            expected: expected_sha256.to_string(),
            actual: actual_hash,
        });
    }

    Ok(())
}
