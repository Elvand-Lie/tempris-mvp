# backend/app/collector_crypto.py
import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def generate_enrollment_code() -> Tuple[str, str, datetime]:
    """
    Generates a one-time enrollment code and its SHA-256 hash with 15-minute expiration.
    Returns (raw_code, sha256_hash, expires_at).
    """
    raw_code = f"col_enc_{secrets.token_urlsafe(24)}"
    code_hash = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc).replace(microsecond=0)
    # Add 15 minutes
    from datetime import timedelta
    expires_at = expires_at + timedelta(minutes=15)
    return raw_code, code_hash, expires_at

def generate_auth_challenge() -> Tuple[str, str, datetime]:
    """
    Generates a 32-byte base64url-no-padding nonce and 30-second UTC RFC3339 expiry.
    Returns (nonce, expires_at_str, expires_at_dt).
    """
    random_bytes = secrets.token_bytes(32)
    nonce = base64.urlsafe_b64encode(random_bytes).decode("utf-8").rstrip("=")

    from datetime import timedelta
    expires_at_dt = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=30)
    # Server-provided UTC RFC3339 ending in Z
    expires_at_str = expires_at_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return nonce, expires_at_str, expires_at_dt

def parse_ed25519_public_key(pub_key_str: str) -> ed25519.Ed25519PublicKey:
    """
    Parses a 32-byte Ed25519 public key from base64, base64url, or hex encoding.
    """
    raw_bytes = None
    pub_key_clean = pub_key_str.strip()

    if len(pub_key_clean) == 64:
        try:
            raw_bytes = bytes.fromhex(pub_key_clean)
        except ValueError:
            pass

    if raw_bytes is None:
        padded = pub_key_clean + "=" * ((4 - len(pub_key_clean) % 4) % 4)
        try:
            raw_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            try:
                raw_bytes = base64.b64decode(padded)
            except Exception:
                raise ValueError("Invalid public key encoding; must be 32 bytes in base64, base64url, or hex.")

    if len(raw_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be exactly 32 bytes, got {len(raw_bytes)}")

    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)

def normalize_ed25519_public_key(pub_key_str: str) -> str:
    """
    Validates and normalizes Ed25519 public key to base64url-no-padding string for storage.
    """
    key = parse_ed25519_public_key(pub_key_str)
    raw_bytes = key.public_bytes_raw()
    return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")

def build_canonical_challenge_bytes(collector_id: str | uuid.UUID, nonce: str, expires_at: str) -> bytes:
    """
    Constructs the exact canonical UTF-8 challenge string with LF separators and no trailing LF:
    TEMPRIS-COLLECTOR-AUTH-V1
    collector_id=<lowercase canonical uuid>
    nonce=<base64url-no-padding>
    expires_at=<server-provided UTC RFC3339 ending in Z>
    """
    canonical_id = str(collector_id).lower()
    msg = f"TEMPRIS-COLLECTOR-AUTH-V1\ncollector_id={canonical_id}\nnonce={nonce}\nexpires_at={expires_at}"
    return msg.encode("utf-8")

def verify_ed25519_signature(public_key_str: str, signature_str: str, message_bytes: bytes) -> bool:
    """
    Verifies an Ed25519 signature over message bytes.
    Accepts signature in base64, base64url, or hex (64 raw bytes).
    """
    try:
        pub_key = parse_ed25519_public_key(public_key_str)
    except Exception:
        return False

    sig_clean = signature_str.strip()
    sig_bytes = None

    if len(sig_clean) == 128:
        try:
            sig_bytes = bytes.fromhex(sig_clean)
        except ValueError:
            pass

    if sig_bytes is None:
        padded = sig_clean + "=" * ((4 - len(sig_clean) % 4) % 4)
        try:
            sig_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            try:
                sig_bytes = base64.b64decode(padded)
            except Exception:
                return False

    if len(sig_bytes) != 64:
        return False

    try:
        pub_key.verify(sig_bytes, message_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
