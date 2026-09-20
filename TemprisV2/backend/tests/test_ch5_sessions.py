# backend/tests/test_ch5_sessions.py
"""
Chapter 5 platform hardening — persisted sessions / per-token revocation
(PRD-000 Ch.5 Target architecture item 2; migration 024).

Covers:
  * login mints the session-bound token shape: sub = user UUID, jti claim,
    persisted user_sessions row keyed by sha256(jti), expiry aligned to 3600s
  * per-request verification resolves the session (AuthContext.session_id)
  * logout revokes exactly the caller's session — the OTHER session of the
    same user keeps working (per-token, not coarse)
  * sessions list / revoke-by-id (self-owned, tenant-scoped, no oracle)
  * fail-closed: unknown jti, expired session, sub/session mismatch
  * legacy transition shape (no jti, create_test_token) still verifies and
    logout is a no-op for it
"""
import hashlib
import time
import uuid

import jwt
import pytest
from starlette.testclient import TestClient

from app.auth import get_auth_context
from app.config import JWT_SECRET
from app.db import get_db_connection
from tests.conftest import TENANT_A, TEST_PASSWORD, TEST_PASSWORD_HASH


def _create_user_with_membership(email: str, role: str = "admin", tenant_id=TENANT_A) -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (id, email, full_name, password_hash, status, is_platform_admin)
                VALUES (gen_random_uuid(), %s, 'Ch5 Session User', %s, 'active', FALSE)
                RETURNING id;
                """,
                (email, TEST_PASSWORD_HASH)
            )
            user_id = cur.fetchone()["id"]
            cur.execute(
                """
                INSERT INTO tenant_memberships (id, tenant_id, user_id, role, status)
                VALUES (gen_random_uuid(), %s, %s, %s, 'active');
                """,
                (str(tenant_id), str(user_id), role)
            )
        conn.commit()
    return str(user_id)


def _insert_session(user_id: str, tenant_id, jti: str, *, expires_in_seconds: int = 3600,
                    issued_ago_seconds: int = 0) -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO user_sessions (user_id, tenant_id, jti_hash, issued_at, expires_at)
                VALUES (
                    %s, %s, %s,
                    now() - (%s || ' seconds')::interval,
                    now() + (%s || ' seconds')::interval
                )
                RETURNING id;
                """,
                (user_id, str(tenant_id), hashlib.sha256(jti.encode()).hexdigest(),
                 str(issued_ago_seconds), str(expires_in_seconds))
            )
            session_id = str(cur.fetchone()["id"])
        conn.commit()
    return session_id


def _mint_session_token(user_id: str, tenant_id, role: str, jti: str, *, sub: str = None,
                        iat: int = None, lifetime: int = 3600) -> str:
    now_ts = int(time.time()) if iat is None else iat
    payload = {
        "tenant_id": str(tenant_id),
        "sub": sub if sub is not None else user_id,
        "role": role,
        "iat": now_ts,
        "exp": now_ts + lifetime,
        "jti": jti,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _login(client: TestClient, email: str):
    resp = client.post("/api/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert resp.status_code == 200
    return resp.json()["token"]


def test_login_persists_session_and_mints_session_bound_claims(client: TestClient):
    email = f"ch5-sess-{uuid.uuid4().hex[:8]}@tempris.com"
    user_id = _create_user_with_membership(email)

    token = _login(client, email)
    decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

    assert decoded["sub"] == user_id  # token identity is the user UUID now
    jti = decoded.get("jti")
    assert isinstance(jti, str) and jti
    assert decoded["exp"] - decoded["iat"] == 3600

    # The session row persists, keyed by sha256(jti) — raw jti never stored.
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, tenant_id, issued_at, expires_at, revoked_at
                FROM user_sessions WHERE jti_hash = %s;
                """,
                (hashlib.sha256(jti.encode()).hexdigest(),)
            )
            row = cur.fetchone()
    assert row is not None
    assert str(row["user_id"]) == user_id
    assert str(row["tenant_id"]) == str(TENANT_A)
    assert row["revoked_at"] is None
    assert (row["expires_at"] - row["issued_at"]).total_seconds() == 3600


def test_auth_context_resolves_session_and_reports_it():
    email = f"ch5-ctx-{uuid.uuid4().hex[:8]}@tempris.com"
    user_id = _create_user_with_membership(email)
    jti = str(uuid.uuid4())
    _insert_session(user_id, TENANT_A, jti)
    token = _mint_session_token(user_id, TENANT_A, "admin", jti)

    ctx = get_auth_context(authorization=f"Bearer {token}")
    assert ctx.actor_id == user_id
    assert str(ctx.user_id) == user_id
    assert ctx.session_id is not None

    # Legacy shape verifies through the transition path, with no session.
    legacy_token = jwt.encode(
        {
            "tenant_id": str(TENANT_A), "sub": email, "role": "admin",
            "iat": int(time.time()), "exp": int(time.time()) + 3600,
        },
        JWT_SECRET, algorithm="HS256"
    )
    legacy_ctx = get_auth_context(authorization=f"Bearer {legacy_token}")
    assert str(legacy_ctx.user_id) == user_id
    assert legacy_ctx.session_id is None


def test_logout_revokes_only_current_session(client: TestClient):
    """THE per-token revocation contract: revoking session A leaves session B
    of the same user fully working."""
    email = f"ch5-pertoken-{uuid.uuid4().hex[:8]}@tempris.com"
    user_id = _create_user_with_membership(email)

    token_a = _login(client, email)
    token_b = _login(client, email)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    assert client.get("/api/assets", headers=headers_a).status_code == 200
    assert client.get("/api/assets", headers=headers_b).status_code == 200

    logout = client.post("/api/auth/logout", headers=headers_a)
    assert logout.status_code == 200
    assert logout.json() == {"status": "logged_out", "session_revoked": True}

    # Session A is dead...
    assert client.get("/api/assets", headers=headers_a).status_code == 401
    # ...session B of the SAME user is untouched.
    assert client.get("/api/assets", headers=headers_b).status_code == 200

    # A revoked token cannot log itself out again.
    assert client.post("/api/auth/logout", headers=headers_a).status_code == 401


def test_sessions_list_marks_current_and_hides_revoked(client: TestClient):
    email = f"ch5-list-{uuid.uuid4().hex[:8]}@tempris.com"
    user_id = _create_user_with_membership(email)

    token_a = _login(client, email)
    token_b = _login(client, email)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    listed = client.get("/api/auth/sessions", headers=headers_a)
    assert listed.status_code == 200
    sessions = listed.json()["sessions"]
    assert len(sessions) == 2
    assert sum(1 for s in sessions if s["current"]) == 1
    current_ids = {s["id"] for s in sessions if s["current"]}
    ctx_a = get_auth_context(authorization=f"Bearer {token_a}")
    assert current_ids == {str(ctx_a.session_id)}

    client.post("/api/auth/logout", headers=headers_b)
    listed_after = client.get("/api/auth/sessions", headers=headers_a)
    assert listed_after.status_code == 200
    assert len(listed_after.json()["sessions"]) == 1


def test_revoke_specific_session_by_id(client: TestClient):
    email = f"ch5-revoke-{uuid.uuid4().hex[:8]}@tempris.com"
    user_id = _create_user_with_membership(email)

    token_a = _login(client, email)
    token_b = _login(client, email)
    headers_b = {"Authorization": f"Bearer {token_b}"}

    ctx_a = get_auth_context(authorization=f"Bearer {token_a}")
    target_id = str(ctx_a.session_id)

    revoked = client.delete(f"/api/auth/sessions/{target_id}", headers=headers_b)
    assert revoked.status_code == 200
    assert revoked.json()["session_id"] == target_id

    # Revoked session's token is dead; the revoking session survives.
    assert client.get("/api/assets", headers={"Authorization": f"Bearer {token_a}"}).status_code == 401
    assert client.get("/api/assets", headers=headers_b).status_code == 200

    # Second revoke of the same session: identical 404, no existence oracle.
    again = client.delete(f"/api/auth/sessions/{target_id}", headers=headers_b)
    assert again.status_code == 404

    # Another user's session id is the same 404 (ownership scoped).
    other_email = f"ch5-revoke2-{uuid.uuid4().hex[:8]}@tempris.com"
    _create_user_with_membership(other_email)
    other_token = _login(client, other_email)
    foreign = client.delete(f"/api/auth/sessions/{target_id}", headers={"Authorization": f"Bearer {other_token}"})
    assert foreign.status_code == 404


def test_logout_with_legacy_token_revokes_nothing(client: TestClient):
    from app.auth import create_test_token
    legacy_headers = {
        "Authorization": f"Bearer {create_test_token(str(TENANT_A), actor_id='admin-a', role='admin')}"
    }

    resp = client.post("/api/auth/logout", headers=legacy_headers)
    assert resp.status_code == 200
    assert resp.json() == {"status": "logged_out", "session_revoked": False}
    # Nothing was revoked: the legacy token still authenticates.
    assert client.get("/api/assets", headers=legacy_headers).status_code == 200


def test_token_with_unknown_jti_is_rejected():
    email = f"ch5-ghost-{uuid.uuid4().hex[:8]}@tempris.com"
    user_id = _create_user_with_membership(email)
    token = _mint_session_token(user_id, TENANT_A, "admin", str(uuid.uuid4()))  # no session row
    with pytest.raises(Exception) as excinfo:
        get_auth_context(authorization=f"Bearer {token}")
    assert getattr(excinfo.value, "status_code", None) == 401


def test_sub_session_mismatch_is_rejected():
    email = f"ch5-mismatch-{uuid.uuid4().hex[:8]}@tempris.com"
    user_id = _create_user_with_membership(email)
    jti = str(uuid.uuid4())
    _insert_session(user_id, TENANT_A, jti)
    token = _mint_session_token(user_id, TENANT_A, "admin", jti, sub="f0000000-0000-4000-8000-00000000000f")
    with pytest.raises(Exception) as excinfo:
        get_auth_context(authorization=f"Bearer {token}")
    assert getattr(excinfo.value, "status_code", None) == 401


def test_expired_session_is_rejected_even_with_valid_token():
    email = f"ch5-expired-{uuid.uuid4().hex[:8]}@tempris.com"
    user_id = _create_user_with_membership(email)
    jti = str(uuid.uuid4())
    # Token itself is valid for another hour; the persisted session already
    # expired (issued 2h ago, expired 1h ago — satisfies the lifetime CHECK).
    _insert_session(user_id, TENANT_A, jti, expires_in_seconds=-3600, issued_ago_seconds=7200)
    token = _mint_session_token(user_id, TENANT_A, "admin", jti)
    with pytest.raises(Exception) as excinfo:
        get_auth_context(authorization=f"Bearer {token}")
    assert getattr(excinfo.value, "status_code", None) == 401


def test_logout_requires_authentication(client: TestClient):
    assert client.post("/api/auth/logout").status_code == 401
    assert client.get("/api/auth/sessions").status_code == 401
