use ed25519_dalek::VerifyingKey;

use super::ToolchainError;

pub const TOOLCHAIN_RELEASE_KEY_ID: &str = "tempris-toolchain-release-v1";

pub const TOOLCHAIN_RELEASE_PUBLIC_KEY: [u8; 32] = [
    0xba, 0xdd, 0xe3, 0xab, 0x19, 0x9e, 0x12, 0xf9,
    0xd8, 0x37, 0x36, 0xf8, 0xe6, 0x68, 0x48, 0xcc,
    0x6d, 0xf9, 0xce, 0x1c, 0x12, 0x49, 0xa9, 0x1c,
    0xca, 0xf8, 0x56, 0xfd, 0x14, 0x14, 0x74, 0xc3,
];

/// Returns the compiled-in release public verification key.
/// Zero private keys or signing logic exist in the Collector runtime.
pub fn get_verification_key() -> Result<VerifyingKey, ToolchainError> {
    VerifyingKey::from_bytes(&TOOLCHAIN_RELEASE_PUBLIC_KEY)
        .map_err(|e| ToolchainError::InvalidVerificationKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_public_key_is_valid() {
        let vk = get_verification_key();
        assert!(vk.is_ok(), "Embedded public key must be valid 32-byte Ed25519 point");
    }
}
