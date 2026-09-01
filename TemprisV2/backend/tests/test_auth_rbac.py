# backend/tests/test_auth_rbac.py
import uuid
import pytest
import jwt
from starlette.testclient import TestClient
from app.config import JWT_SECRET, JWT_ALGORITHM
from app.auth import create_test_token

def test_startup_fails_closed_without_required_env_or_disallowed_algorithm(monkeypatch):
    import importlib
    import os
    import app.config

    # Prevent load_dotenv from re-reading .env during the test
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: None)

    orig_db = os.environ.get("DATABASE_URL")
    orig_secret = os.environ.get("JWT_SECRET")
    orig_alg = os.environ.get("JWT_ALGORITHM", "HS256")

    # Missing DATABASE_URL fails closed
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        importlib.reload(app.config)

    if orig_db:
        monkeypatch.setenv("DATABASE_URL", orig_db)

    # Missing JWT_SECRET fails closed
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        importlib.reload(app.config)

    # Empty JWT_SECRET fails closed
    monkeypatch.setenv("JWT_SECRET", "   ")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        importlib.reload(app.config)

    # Placeholder JWT_SECRET (e.g. <jwt_secret>) fails closed
    monkeypatch.setenv("JWT_SECRET", "<jwt_secret>")
    with pytest.raises(RuntimeError, match="placeholder"):
        importlib.reload(app.config)

    # Short JWT_SECRET (< 32 UTF-8 bytes) fails closed
    monkeypatch.setenv("JWT_SECRET", "short-secret-less-than-32-bytes")
    with pytest.raises(RuntimeError, match="32 UTF-8 bytes"):
        importlib.reload(app.config)

    if orig_secret:
        monkeypatch.setenv("JWT_SECRET", orig_secret)

    # Disallowed algorithm (e.g. 'none' or 'RS256') fails closed
    monkeypatch.setenv("JWT_ALGORITHM", "none")
    with pytest.raises(RuntimeError, match="JWT_ALGORITHM"):
        importlib.reload(app.config)

    # Restore valid test configuration
    monkeypatch.setenv("JWT_ALGORITHM", orig_alg)
    importlib.reload(app.config)

def test_missing_auth_header_returns_401(client: TestClient):
    resp = client.get("/api/assets")
    assert resp.status_code == 401
    assert "Missing Authorization header" in resp.json()["detail"]

def test_invalid_token_format_returns_401(client: TestClient):
    resp = client.get("/api/assets", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp.status_code == 401

def test_tampered_signature_returns_401(client: TestClient):
    token = create_test_token(tenant_id=str(uuid.uuid4()))
    tampered_token = token[:-5] + "aaaaa"
    resp = client.get("/api/assets", headers={"Authorization": f"Bearer {tampered_token}"})
    assert resp.status_code == 401

def test_invalid_role_claim_returns_401(client: TestClient):
    import time
    now_ts = int(time.time())
    payload = {
        "tenant_id": str(uuid.uuid4()),
        "sub": "bad-user",
        "role": "hacker",
        "iat": now_ts,
        "exp": now_ts + 3600,
    }
    bad_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    resp = client.get("/api/assets", headers={"Authorization": f"Bearer {bad_token}"})
    assert resp.status_code == 401
    assert "Invalid role claim" in resp.json()["detail"]

def test_missing_required_jwt_claims_returns_401(client: TestClient):
    import time
    now_ts = int(time.time())
    valid_payload = {
        "tenant_id": str(uuid.uuid4()),
        "sub": "valid-user",
        "role": "admin",
        "iat": now_ts,
        "exp": now_ts + 3600,
    }

    # Test missing each required claim individually
    for missing_claim in ["tenant_id", "sub", "role", "iat", "exp"]:
        payload = dict(valid_payload)
        del payload[missing_claim]
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        resp = client.get("/api/assets", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
        assert "missing required claims" in resp.json()["detail"].lower() or "invalid or expired token" in resp.json()["detail"].lower()

def test_invalid_token_lifetime_returns_401(client: TestClient):
    import time
    now_ts = int(time.time())

    # Token with 7200 seconds lifetime (intended is 3600)
    payload_too_long = {
        "tenant_id": str(uuid.uuid4()),
        "sub": "valid-user",
        "role": "admin",
        "iat": now_ts,
        "exp": now_ts + 7200,
    }
    token_too_long = jwt.encode(payload_too_long, JWT_SECRET, algorithm="HS256")
    resp = client.get("/api/assets", headers={"Authorization": f"Bearer {token_too_long}"})
    assert resp.status_code == 401
    assert "3600 seconds" in resp.json()["detail"]

    # Token with 1800 seconds lifetime
    payload_too_short = {
        "tenant_id": str(uuid.uuid4()),
        "sub": "valid-user",
        "role": "admin",
        "iat": now_ts,
        "exp": now_ts + 1800,
    }
    token_too_short = jwt.encode(payload_too_short, JWT_SECRET, algorithm="HS256")
    resp = client.get("/api/assets", headers={"Authorization": f"Bearer {token_too_short}"})
    assert resp.status_code == 401
    assert "3600 seconds" in resp.json()["detail"]

def test_client_injected_tenant_id_in_body_is_ignored(client: TestClient, auth_headers_tenant_a_admin):
    # Pass a spoofed tenant_id in body; server must strictly use JWT tenant_id
    spoofed_tenant = str(uuid.uuid4())
    resp = client.post(
        "/api/assets",
        json={
            "tenant_id": spoofed_tenant,
            "name": "Production Database",
            "asset_type": "database",
            "target_type": "ip",
            "target_value": "10.0.0.99",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["tenant_id"] == "11111111-1111-1111-1111-111111111111"
    assert data["tenant_id"] != spoofed_tenant

def test_collector_rbac_enforcement(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst
):
    # Analyst cannot create collector (403 Forbidden)
    analyst_create = client.post(
        "/api/collectors",
        json={"name": "Analyst Attempted Collector"},
        headers=auth_headers_tenant_a_analyst
    )
    assert analyst_create.status_code == 403

    # Admin can create collector (201 Created)
    admin_create = client.post(
        "/api/collectors",
        json={"name": "Admin Authorized Collector"},
        headers=auth_headers_tenant_a_admin
    )
    assert admin_create.status_code == 201

def test_runtime_startup_succeeds_without_admin_bootstrap_env():
    """
    Subprocess regression test:
    Proves that `import app.main` succeeds with valid runtime DB/JWT configuration
    when ADMIN_USERNAME, ADMIN_TENANT_ID, and ADMIN_PASSWORD_HASH are absent from the environment.
    """
    import os
    import sys
    import subprocess
    from pathlib import Path

    backend_dir = str(Path(__file__).resolve().parent.parent)
    env = os.environ.copy()
    env.pop("ADMIN_USERNAME", None)
    env.pop("ADMIN_TENANT_ID", None)
    env.pop("ADMIN_PASSWORD_HASH", None)
    env["PYTHONPATH"] = backend_dir

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import app.main, app.config; "
            "assert not hasattr(app.config, 'ADMIN_USERNAME'); "
            "assert not hasattr(app.config, 'ADMIN_TENANT_ID'); "
            "assert not hasattr(app.config, 'ADMIN_PASSWORD_HASH'); "
            "print('STARTUP_OK')",
        ],
        cwd=backend_dir,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Import failed with stderr: {result.stderr}"
    assert "STARTUP_OK" in result.stdout
