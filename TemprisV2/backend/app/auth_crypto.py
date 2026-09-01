# backend/app/auth_crypto.py
import hashlib
import hmac
import secrets
from typing import Tuple, Optional

# Fixed dummy salt and hash for timing equivalence on unknown username
DUMMY_SALT = bytes.fromhex("e0a4f291bc8491736481029485720194")
DUMMY_HASH = bytes.fromhex("00" * 32)

def parse_scrypt_hash(hash_str: str) -> Tuple[int, int, int, int, bytes, bytes]:
    """
    Parses and validates a stored scrypt password hash string.
    Supported formats:
      - scrypt$N$r$p$salt_hex$hash_hex (e.g. scrypt$16384$8$1$<32+ hex chars>$<64 hex chars>)
      - scrypt$salt_hex$hash_hex (defaults N=16384, r=8, p=1, dklen=32)
      - salt_hex:hash_hex
      - salt_hex$hash_hex

    Enforces:
      - Pinned scrypt parameters: N=16384, r=8, p=1, dklen=32
      - Salt length >= 16 bytes (>= 32 hex chars)
      - Hash length == 32 bytes (64 hex chars)
    """
    if not isinstance(hash_str, str) or not hash_str.strip():
        raise ValueError("Admin password hash cannot be empty.")

    cleaned = hash_str.strip()

    if cleaned.startswith("scrypt$"):
        parts = cleaned.split("$")
        if len(parts) == 6:
            try:
                n = int(parts[1])
                r = int(parts[2])
                p = int(parts[3])
            except ValueError:
                raise ValueError("Scrypt cost parameters (N, r, p) must be integers.")
            try:
                salt = bytes.fromhex(parts[4])
                expected_hash = bytes.fromhex(parts[5])
            except ValueError:
                raise ValueError("Scrypt salt and hash must be valid hexadecimal strings.")
        elif len(parts) == 3:
            n, r, p = 16384, 8, 1
            try:
                salt = bytes.fromhex(parts[1])
                expected_hash = bytes.fromhex(parts[2])
            except ValueError:
                raise ValueError("Scrypt salt and hash must be valid hexadecimal strings.")
        else:
            raise ValueError("Invalid scrypt format. Expected 'scrypt$N$r$p$salt$hash' or 'scrypt$salt$hash'.")
    elif ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) != 2:
            raise ValueError("Invalid colon-delimited format. Expected 'salt:hash'.")
        n, r, p = 16384, 8, 1
        try:
            salt = bytes.fromhex(parts[0])
            expected_hash = bytes.fromhex(parts[1])
        except ValueError:
            raise ValueError("Scrypt salt and hash must be valid hexadecimal strings.")
    elif "$" in cleaned:
        parts = cleaned.split("$")
        if len(parts) != 2:
            raise ValueError("Invalid dollar-delimited format. Expected 'salt$hash'.")
        n, r, p = 16384, 8, 1
        try:
            salt = bytes.fromhex(parts[0])
            expected_hash = bytes.fromhex(parts[1])
        except ValueError:
            raise ValueError("Scrypt salt and hash must be valid hexadecimal strings.")
    else:
        raise ValueError("Unrecognized password hash format.")

    if n != 16384 or r != 8 or p != 1:
        raise ValueError(
            f"Invalid scrypt parameters: N={n}, r={r}, p={p}. Required: N=16384, r=8, p=1, dklen=32."
        )
    if len(salt) < 16:
        raise ValueError(
            f"Scrypt salt must be at least 16 bytes (32 hex characters). Got {len(salt)} bytes."
        )
    if len(expected_hash) != 32:
        raise ValueError(
            f"Scrypt hash must be exactly 32 bytes (64 hex characters). Got {len(expected_hash)} bytes."
        )

    return n, r, p, 32, salt, expected_hash

def generate_scrypt_hash(password: str, salt: bytes = None) -> str:
    """Generates a canonical scrypt hash string: scrypt$16384$8$1$<salt_hex>$<hash_hex>."""
    if salt is None:
        salt = secrets.token_bytes(16)
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32
    )
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"

def compute_dummy_scrypt(password_attempt: str) -> bool:
    """
    Executes a timing-equivalent scrypt computation using fixed dummy salt and hash.
    Always returns False.
    """
    derived = hashlib.scrypt(
        password_attempt.encode("utf-8") if isinstance(password_attempt, str) else b"",
        salt=DUMMY_SALT,
        n=16384,
        r=8,
        p=1,
        dklen=32
    )
    hmac.compare_digest(derived, DUMMY_HASH)
    return False

def verify_password_scrypt(password_attempt: str, stored_hash: Optional[str] = None) -> bool:
    """
    Verifies a password attempt against a stored scrypt hash string.
    If stored_hash is None, empty, or invalid, executes compute_dummy_scrypt
    to prevent timing enumeration side channels.
    """
    if not isinstance(password_attempt, str) or not stored_hash or not isinstance(stored_hash, str) or not stored_hash.strip():
        return compute_dummy_scrypt(password_attempt if isinstance(password_attempt, str) else "")

    try:
        n, r, p, dklen, salt, expected = parse_scrypt_hash(stored_hash)
    except Exception:
        return compute_dummy_scrypt(password_attempt)

    derived = hashlib.scrypt(
        password_attempt.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen
    )

    return hmac.compare_digest(derived, expected)

