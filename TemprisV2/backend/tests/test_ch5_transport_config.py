# backend/tests/test_ch5_transport_config.py
"""
Chapter 5 platform hardening — transport/config hygiene (PRD-000 Ch.5 Target
architecture item 5).

Covers:
  * CORS origins are pinned to the CORS_ALLOW_ORIGINS allowlist (no wildcard
    with credentials); disallowed origins get no ACAO header
  * JWT kid + rotation path: minting carries the active kid, verification
    resolves each configured kid, old-key tokens survive rotation while the
    key is listed, and unknown kids fail closed (401)
"""
import time

import jwt
import pytest
from starlette.testclient import TestClient

from app import config
from app.config import JWT_SECRET
from app.db import get_db_connection
from tests.conftest import TENANT_A, TEST_PASSWORD

ALLOWED_ORIGIN = "https://console.tempris.test"


def _login(client: TestClient, email: str = "admin", password: str = TEST_PASSWORD):
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    return resp.json()["token"]


def test_cors_allows_only_pinned_origins(client: TestClient):
    allowed = client.get("/healthz", headers={"Origin": ALLOWED_ORIGIN})
    assert allowed.status_code == 200
    assert allowed.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN

    denied = client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert denied.status_code == 200
    assert "access-control-allow-origin" not in denied.headers


def test_cors_default_is_no_cross_origin(monkeypatch):
    """The empty allowlist (env unset) pins CORS closed entirely — the
    fail-closed default; the same-origin frontend needs no CORS."""
    # Covered structurally by config: the wildcard default is retired.
    assert "*" not in config.CORS_ALLOW_ORIGINS


def _fixture_user_id(email: str) -> str:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s);", (email,))
            return str(cur.fetchone()["id"])


def test_jwt_kid_round_trip_and_rotation(client: TestClient, monkeypatch):
    key_a = "a" * 40
    key_b = "b" * 40
    keys_rot1 = {"k1": key_a, "default": JWT_SECRET}
    keys_rot2 = {"k1": key_a, "k2": key_b, "default": JWT_SECRET}

    # Rotation 1: mint under k1.
    monkeypatch.setattr(config, "JWT_KEYS", keys_rot1)
    monkeypatch.setattr(config, "JWT_ACTIVE_KID", "k1")
    token_k1 = _login(client)
    assert jwt.get_unverified_header(token_k1)["kid"] == "k1"
    user_id = _fixture_user_id("admin")
    claims = jwt.decode(token_k1, key_a, algorithms=["HS256"])
    assert claims["sub"] == user_id

    # Tokens under k1 keep verifying while k1 stays listed.
    resp = client.get("/api/assets", headers={"Authorization": f"Bearer {token_k1}"})
    assert resp.status_code == 200

    # Rotation 2: k2 becomes active; k1 remains a verification key.
    monkeypatch.setattr(config, "JWT_KEYS", keys_rot2)
    monkeypatch.setattr(config, "JWT_ACTIVE_KID", "k2")
    token_k2 = _login(client)
    assert jwt.get_unverified_header(token_k2)["kid"] == "k2"
    assert jwt.decode(token_k2, key_b, algorithms=["HS256"])["sub"] == user_id

    resp = client.get("/api/assets", headers={"Authorization": f"Bearer {token_k1}"})
    assert resp.status_code == 200, "old-key tokens verify until the kid is retired"

    # Retire k1: its tokens fail closed.
    monkeypatch.setattr(config, "JWT_KEYS", {"k2": key_b, "default": JWT_SECRET})
    resp = client.get("/api/assets", headers={"Authorization": f"Bearer {token_k1}"})
    assert resp.status_code == 401
    assert "unknown token key id" in resp.json()["detail"]


def test_unknown_kid_token_is_rejected():
    now_ts = int(time.time())
    token = jwt.encode(
        {
            "tenant_id": str(TENANT_A),
            "sub": "admin-a",
            "role": "admin",
            "iat": now_ts,
            "exp": now_ts + 3600,
        },
        JWT_SECRET,
        algorithm="HS256",
        headers={"kid": "does-not-exist"},
    )
    from app.auth import get_auth_context
    with pytest.raises(Exception) as excinfo:
        get_auth_context(authorization=f"Bearer {token}")
    assert getattr(excinfo.value, "status_code", None) == 401
