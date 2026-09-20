# backend/tests/test_auth_login.py
import uuid
import time
import importlib
import pytest
import jwt
import hashlib
from starlette.testclient import TestClient
from app.config import (
    JWT_SECRET,
    JWT_ALGORITHM,
)
from app.auth_crypto import (
    parse_scrypt_hash,
    generate_scrypt_hash,
)
from tests.conftest import TENANT_A
from app.db import get_db_connection


def _fixture_user_id(email: str) -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s);", (email,))
            row = cur.fetchone()
    assert row is not None, f"fixture user {email} missing"
    return str(row["id"])

def test_parse_scrypt_hash_validation_rules():
    # Valid canonical hash
    valid_hash = generate_scrypt_hash("my-secret-password")
    n, r, p, dklen, salt, exp = parse_scrypt_hash(valid_hash)
    assert n == 16384
    assert r == 8
    assert p == 1
    assert dklen == 32
    assert len(salt) >= 16
    assert len(exp) == 32

    # Malformed empty hash
    with pytest.raises(ValueError, match="cannot be empty"):
        parse_scrypt_hash("")

    # Non-integer cost params
    with pytest.raises(ValueError, match="must be integers"):
        parse_scrypt_hash("scrypt$bad$8$1$0123456789abcdef0123456789abcdef$" + ("0" * 64))

    # Disallowed scrypt parameters (e.g. weak N=1024)
    with pytest.raises(ValueError, match="Invalid scrypt parameters"):
        parse_scrypt_hash("scrypt$1024$8$1$0123456789abcdef0123456789abcdef$0000000000000000000000000000000000000000000000000000000000000000")

    # Short salt (< 16 bytes = 32 hex chars)
    with pytest.raises(ValueError, match="[Ss]crypt salt must be at least 16 bytes"):
        parse_scrypt_hash("scrypt$16384$8$1$0123456789abcdef$0000000000000000000000000000000000000000000000000000000000000000")

    # Short hash length != 32 bytes (64 hex chars)
    with pytest.raises(ValueError, match="[Ss]crypt hash must be exactly 32 bytes"):
        parse_scrypt_hash("scrypt$16384$8$1$0123456789abcdef0123456789abcdef$00000000")

def test_login_success_and_jwt_claims(client: TestClient):
    resp = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "tempris-admin-2026",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 3600

    token = data["token"]
    now_before = int(time.time()) - 5

    # Decode and verify claims
    decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    assert decoded["tenant_id"] == str(TENANT_A)
    # sub = user UUID (PRD Ch.5 decision; email is a display/lookup attribute)
    assert decoded["sub"] == str(_fixture_user_id("admin"))
    assert decoded["role"] == "admin"
    assert isinstance(decoded["iat"], int)
    assert isinstance(decoded["exp"], int)
    assert decoded["exp"] - decoded["iat"] == 3600
    assert decoded["iat"] >= now_before

    # Verify that minted token can authenticate to protected endpoints
    auth_headers = {"Authorization": f"Bearer {token}"}
    assets_resp = client.get("/api/assets", headers=auth_headers)
    assert assets_resp.status_code == 200

    collectors_resp = client.get("/api/collectors", headers=auth_headers)
    assert collectors_resp.status_code == 200

def test_login_invalid_password_returns_generic_401(client: TestClient):
    resp = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "wrong-password",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"

def test_login_unknown_username_returns_generic_401(client: TestClient):
    resp = client.post(
        "/api/auth/login",
        json={
            "username": "non_existent_admin",
            "password": "tempris-admin-2026",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"

def test_login_empty_or_missing_inputs_fail_validation_422(client: TestClient):
    from app.routes.auth import login_rate_guard
    login_rate_guard.reset()

    # Empty username
    resp = client.post(
        "/api/auth/login",
        json={"username": "", "password": "tempris-admin-2026"},
    )
    assert resp.status_code == 422

    # Empty password
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": ""},
    )
    assert resp.status_code == 422

    # Both empty
    resp = client.post(
        "/api/auth/login",
        json={"username": "", "password": ""},
    )
    assert resp.status_code == 422

    # Missing username
    resp = client.post(
        "/api/auth/login",
        json={"password": "tempris-admin-2026"},
    )
    assert resp.status_code == 422

    # Missing password
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin"},
    )
    assert resp.status_code == 422

def test_login_oversized_inputs_fail_validation_422(client: TestClient):
    from app.routes.auth import login_rate_guard
    login_rate_guard.reset()

    # Oversized username (> 128 characters)
    oversized_username = "a" * 129
    resp = client.post(
        "/api/auth/login",
        json={"username": oversized_username, "password": "tempris-admin-2026"},
    )
    assert resp.status_code == 422

    # Oversized password (> 1024 characters)
    oversized_password = "p" * 1025
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": oversized_password},
    )
    assert resp.status_code == 422

    # Max valid bounds (username 128, password 1024) pass schema validation
    # (returns 401 due to non-matching credentials, not 422 validation error)
    resp = client.post(
        "/api/auth/login",
        json={"username": "a" * 128, "password": "p" * 1024},
    )
    assert resp.status_code == 401

class FakeClock:
    def __init__(self, initial_time: float = 1000.0):
        self.current_time = initial_time

    def __call__(self) -> float:
        return self.current_time

    def advance(self, seconds: float):
        self.current_time += seconds

def test_login_rate_guard_unit_controllable_clock():
    from app.routes.auth import LoginRateGuard

    clock = FakeClock(1000.0)
    guard = LoginRateGuard(max_attempts=5, window_seconds=60.0, clock=clock)

    # 5 attempts within window are allowed
    for _ in range(5):
        assert guard.check_and_record("client-1") is True
        clock.advance(5.0)

    # 6th attempt within 60s is blocked
    assert guard.check_and_record("client-1") is False

    # Different client is not blocked
    assert guard.check_and_record("client-2") is True

    # Advance clock past 60s window
    clock.advance(60.0)
    assert guard.check_and_record("client-1") is True

def test_login_endpoint_rate_guard_integration_controllable_clock(client: TestClient):
    from app.routes.auth import login_rate_guard

    clock = FakeClock(2000.0)
    login_rate_guard.reset()
    login_rate_guard.clock = clock

    try:
        # First 5 attempts return 401 (invalid credentials)
        for i in range(5):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": f"wrong-pass-{i}"},
            )
            assert resp.status_code == 401
            clock.advance(2.0)

        # 6th attempt within window is rate limited (429)
        rate_limited_resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong-pass-6"},
        )
        assert rate_limited_resp.status_code == 429
        assert "Too many login attempts" in rate_limited_resp.json()["detail"]

        # Advance clock past window (60s)
        clock.advance(61.0)

        # 7th attempt is allowed through again
        allowed_resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong-pass-7"},
        )
        assert allowed_resp.status_code == 401
    finally:
        login_rate_guard.reset()
        login_rate_guard.clock = time.time

def test_login_rate_guard_concurrent_threads_deterministic_admission():
    """
    Deterministic concurrent regression test:
    Proves that with max_attempts=1, exactly one caller is admitted among
    simultaneous threads using threading.Barrier synchronization, and that
    the critical section inside check_and_record is strictly serialized
    (max_active == 1) under GIL-releasing clock operations.
    """
    import threading
    import time
    from app.routes.auth import LoginRateGuard

    active_entrants = 0
    max_active = 0
    tracker_lock = threading.Lock()

    def instrumented_clock() -> float:
        nonlocal active_entrants, max_active
        with tracker_lock:
            active_entrants += 1
            if active_entrants > max_active:
                max_active = active_entrants
        time.sleep(0.002)
        with tracker_lock:
            active_entrants -= 1
        return 5000.0

    guard = LoginRateGuard(max_attempts=1, window_seconds=60.0, clock=instrumented_clock)

    num_threads = 12
    barrier = threading.Barrier(num_threads)
    results = []
    results_lock = threading.Lock()

    def worker():
        barrier.wait()
        admitted = guard.check_and_record("concurrent-client-ip")
        with results_lock:
            results.append(admitted)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == num_threads
    # Serialization verification: maximum simultaneous entrants in guarded clock path must be 1
    assert max_active == 1
    # Exactly one thread is admitted (True), remaining (num_threads - 1) are rejected (False)
    assert results.count(True) == 1
    assert results.count(False) == num_threads - 1
    # Exactly one timestamp stored in guard
    assert len(guard._attempts["concurrent-client-ip"]) == 1

def test_login_rate_guard_prunes_stale_and_empty_client_buckets():
    """
    Proves that stale/expired client buckets are pruned and deleted from _attempts
    so memory keys do not accumulate over time.
    """
    from app.routes.auth import LoginRateGuard

    clock = FakeClock(1000.0)
    guard = LoginRateGuard(max_attempts=5, window_seconds=60.0, clock=clock)

    # Client A and Client B make attempts at t=1000
    assert guard.check_and_record("client-a") is True
    assert guard.check_and_record("client-b") is True
    assert "client-a" in guard._attempts
    assert "client-b" in guard._attempts

    # Advance clock past 60s window to t=1070
    clock.advance(70.0)

    # Client C makes an attempt at t=1070; should prune stale client-a and client-b buckets
    assert guard.check_and_record("client-c") is True

    # client-a and client-b should be deleted from _attempts
    assert "client-a" not in guard._attempts
    assert "client-b" not in guard._attempts
    assert "client-c" in guard._attempts
    assert len(guard._attempts) == 1

    # Advance clock again to t=1150 and Client C makes another attempt
    clock.advance(80.0)
    assert guard.check_and_record("client-c") is True
    assert len(guard._attempts) == 1
    assert len(guard._attempts["client-c"]) == 1


