use tempris_collector::crypto::{
    build_canonical_challenge_bytes, generate_keypair, public_key_from_base64url,
    public_key_to_base64url, sign_canonical_challenge, verify_signature,
};
use uuid::Uuid;

#[test]
fn test_canonical_challenge_string_format() {
    let collector_id = Uuid::parse_str("C0A80101-0000-0000-0000-000000000001").unwrap();
    let nonce = "4A7B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D";
    let expires_at = "2026-08-28T12:00:30Z";

    let canonical_bytes = build_canonical_challenge_bytes(&collector_id, nonce, expires_at);
    let canonical_str = String::from_utf8(canonical_bytes).unwrap();

    let expected = "TEMPRIS-COLLECTOR-AUTH-V1\ncollector_id=c0a80101-0000-0000-0000-000000000001\nnonce=4A7B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D\nexpires_at=2026-08-28T12:00:30Z";
    assert_eq!(canonical_str, expected);
}

#[test]
fn test_ed25519_sign_and_verify_cycle() {
    let (signing_key, verifying_key) = generate_keypair();
    let collector_id = Uuid::new_v4();
    let nonce = "nonce_1234567890abcdefghijklmnopqrstuvwxyz";
    let expires_at = "2026-08-28T14:30:00Z";

    let canonical_bytes = build_canonical_challenge_bytes(&collector_id, nonce, expires_at);
    let signature_b64 = sign_canonical_challenge(&signing_key, &collector_id, nonce, expires_at);

    // Verify with own key
    assert!(verify_signature(
        &verifying_key,
        &canonical_bytes,
        &signature_b64
    ));

    // Wrong message fails
    let tampered_bytes = build_canonical_challenge_bytes(&Uuid::new_v4(), nonce, expires_at);
    assert!(!verify_signature(
        &verifying_key,
        &tampered_bytes,
        &signature_b64
    ));

    // Wrong public key fails
    let (_other_signing, other_verifying) = generate_keypair();
    assert!(!verify_signature(
        &other_verifying,
        &canonical_bytes,
        &signature_b64
    ));
}

#[test]
fn test_public_key_serialization_roundtrip() {
    let (_signing_key, verifying_key) = generate_keypair();
    let b64 = public_key_to_base64url(&verifying_key);
    let parsed = public_key_from_base64url(&b64).unwrap();
    assert_eq!(verifying_key, parsed);
}
