# backend/tests/test_auth_crypto.py
import hashlib
import time
import uuid
import pytest
from starlette.testclient import TestClient

from app.auth_crypto import (
    compute_dummy_scrypt,
    verify_password_scrypt,
    generate_scrypt_hash,
    parse_scrypt_hash,
    DUMMY_SALT,
    DUMMY_HASH,
)
from app.db import get_db_connection
from tests.conftest import TENANT_A, TEST_PASSWORD_HASH

def test_compute_dummy_scrypt_always_returns_false():
    assert compute_dummy_scrypt("my-password-123") is False
    assert compute_dummy_scrypt("") is False
    assert compute_dummy_scrypt(None) is False
    assert compute_dummy_scrypt("a" * 500) is False

def test_verify_password_scrypt_valid_and_invalid_passwords():
    raw_password = "SecurePassword2026!"
    hash_str = generate_scrypt_hash(raw_password)

    # Valid matching password
    assert verify_password_scrypt(raw_password, hash_str) is True

    # Incorrect password
    assert verify_password_scrypt("WrongPassword2026!", hash_str) is False
    assert verify_password_scrypt("", hash_str) is False

def test_verify_password_scrypt_missing_or_malformed_hash_executes_dummy_scrypt(monkeypatch):
    scrypt_invocations = []
    original_scrypt = hashlib.scrypt

    def tracked_scrypt(*args, **kwargs):
        scrypt_invocations.append((args, kwargs))
        return original_scrypt(*args, **kwargs)

    monkeypatch.setattr("hashlib.scrypt", tracked_scrypt)

    # None hash (pending user)
    assert verify_password_scrypt("some-pass", None) is False
    assert len(scrypt_invocations) == 1
    assert scrypt_invocations[-1][1]["salt"] == DUMMY_SALT
    assert scrypt_invocations[-1][1]["n"] == 16384
    assert scrypt_invocations[-1][1]["r"] == 8
    assert scrypt_invocations[-1][1]["p"] == 1
    assert scrypt_invocations[-1][1]["dklen"] == 32

    # Empty string hash
    assert verify_password_scrypt("some-pass", "") is False
    assert len(scrypt_invocations) == 2
    assert scrypt_invocations[-1][1]["salt"] == DUMMY_SALT

    # Whitespace only hash
    assert verify_password_scrypt("some-pass", "   ") is False
    assert len(scrypt_invocations) == 3
    assert scrypt_invocations[-1][1]["salt"] == DUMMY_SALT

    # Corrupt/malformed hash
    assert verify_password_scrypt("some-pass", "invalid_scrypt$string") is False
    assert len(scrypt_invocations) == 4
    assert scrypt_invocations[-1][1]["salt"] == DUMMY_SALT

def test_login_endpoint_scrypt_execution_for_unknown_pending_and_disabled_users(
    client: TestClient,
    monkeypatch
):
    scrypt_calls = []
    original_scrypt = hashlib.scrypt

    def tracked_scrypt(*args, **kwargs):
        scrypt_calls.append((args, kwargs))
        return original_scrypt(*args, **kwargs)

    monkeypatch.setattr("hashlib.scrypt", tracked_scrypt)

    pending_email = f"pending-{uuid.uuid4().hex[:8]}@example.com"
    disabled_email = f"disabled-{uuid.uuid4().hex[:8]}@example.com"

    # Insert pending and disabled users into database
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES
                    (gen_random_uuid(), %s, 'Pending User', NULL, 'pending', FALSE),
                    (gen_random_uuid(), %s, 'Disabled User', %s, 'disabled', FALSE)
                ON CONFLICT ((LOWER(email))) DO NOTHING;
            """, (pending_email, disabled_email, TEST_PASSWORD_HASH))
        conn.commit()

    # 1. Unknown user login attempt -> 401 + scrypt computed
    scrypt_calls.clear()
    unknown_resp = client.post(
        "/api/auth/login",
        json={"email": "nonexistent@example.com", "password": "password123"}
    )
    assert unknown_resp.status_code == 401
    assert unknown_resp.json()["detail"] == "Invalid email or password"
    assert len(scrypt_calls) == 1
    assert scrypt_calls[0][1]["salt"] == DUMMY_SALT

    # 2. Pending user login attempt -> 401 + scrypt computed
    scrypt_calls.clear()
    pending_resp = client.post(
        "/api/auth/login",
        json={"email": pending_email, "password": "password123"}
    )
    assert pending_resp.status_code == 401
    assert pending_resp.json()["detail"] == "Invalid email or password"
    assert len(scrypt_calls) == 1
    assert scrypt_calls[0][1]["salt"] == DUMMY_SALT

    # 3. Disabled user login attempt -> 401 + scrypt computed
    scrypt_calls.clear()
    disabled_resp = client.post(
        "/api/auth/login",
        json={"email": disabled_email, "password": "password123"}
    )
    assert disabled_resp.status_code == 401
    assert disabled_resp.json()["detail"] == "Invalid email or password"
    assert len(scrypt_calls) == 1
    assert scrypt_calls[0][1]["salt"] == DUMMY_SALT
