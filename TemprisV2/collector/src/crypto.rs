use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use uuid::Uuid;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(bytes)
}

pub fn public_key_to_base64url(verifying_key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())
}

pub fn public_key_from_base64url(s: &str) -> Result<VerifyingKey> {
    let clean = s.trim();
    let bytes = if clean.len() == 64 {
        hex::decode(clean).map_err(|e| anyhow!("Invalid hex: {}", e))?
    } else {
        URL_SAFE_NO_PAD
            .decode(clean)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(clean))
            .map_err(|e| anyhow!("Invalid base64 public key: {}", e))?
    };

    if bytes.len() != 32 {
        return Err(anyhow!("Expected 32-byte public key, got {}", bytes.len()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow!("Invalid Ed25519 public key: {}", e))
}

pub fn build_canonical_challenge_bytes(
    collector_id: &Uuid,
    nonce: &str,
    expires_at: &str,
) -> Vec<u8> {
    let canonical_id = collector_id.to_string().to_lowercase();
    let msg = format!(
        "TEMPRIS-COLLECTOR-AUTH-V1\ncollector_id={}\nnonce={}\nexpires_at={}",
        canonical_id, nonce, expires_at
    );
    msg.into_bytes()
}

pub fn sign_canonical_challenge(
    signing_key: &SigningKey,
    collector_id: &Uuid,
    nonce: &str,
    expires_at: &str,
) -> String {
    let canonical_bytes = build_canonical_challenge_bytes(collector_id, nonce, expires_at);
    let signature = signing_key.sign(&canonical_bytes);
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

pub fn verify_signature(verifying_key: &VerifyingKey, message: &[u8], signature_str: &str) -> bool {
    let clean = signature_str.trim();
    let sig_bytes = if clean.len() == 128 {
        match hex::decode(clean) {
            Ok(b) => b,
            Err(_) => return false,
        }
    } else {
        match URL_SAFE_NO_PAD
            .decode(clean)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(clean))
        {
            Ok(b) => b,
            Err(_) => return false,
        }
    };

    if sig_bytes.len() != 64 {
        return false;
    }

    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    verifying_key.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_and_signing() {
        let (signing_key, verifying_key) = generate_keypair();
        let pub_b64 = public_key_to_base64url(&verifying_key);
        let parsed_pub = public_key_from_base64url(&pub_b64).unwrap();
        assert_eq!(verifying_key, parsed_pub);

        let col_id = Uuid::new_v4();
        let nonce = "test-nonce-1234567890abcdef";
        let expires_at = "2026-08-28T12:00:30Z";

        let canonical_bytes = build_canonical_challenge_bytes(&col_id, nonce, expires_at);
        let expected_msg = format!(
            "TEMPRIS-COLLECTOR-AUTH-V1\ncollector_id={}\nnonce={}\nexpires_at={}",
            col_id.to_string().to_lowercase(),
            nonce,
            expires_at
        );
        assert_eq!(canonical_bytes, expected_msg.as_bytes());

        let sig = sign_canonical_challenge(&signing_key, &col_id, nonce, expires_at);
        assert!(verify_signature(&verifying_key, &canonical_bytes, &sig));
    }
}
