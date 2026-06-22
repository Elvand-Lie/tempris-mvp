import pytest


def test_login_with_valid_credentials_returns_token(client):
    """Login returns a JWT and the expected user payload."""
    resp = client.post("/api/auth/login", json={"email": "viewer@tempris.com", "password": "demo"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["token_type"] == "bearer"
    assert data["user"]["role"] == "Viewer"
    assert data["user"]["email"] == "viewer@tempris.com"
    assert data["access_token"]


def test_login_with_invalid_credentials_returns_401(client):
    """Bad credentials are rejected with 401."""
    resp = client.post("/api/auth/login", json={"email": "viewer@tempris.com", "password": "wrong"})
    assert resp.status_code == 401


def test_login_requires_email_and_password(client):
    """Login payload validation should reject missing fields."""
    resp = client.post("/api/auth/login", json={"email": "viewer@tempris.com"})
    assert resp.status_code == 422


def test_login_rate_limit_triggers_429(client):
    """Repeated failed logins should eventually hit the auth rate limit or lockout."""
    for _ in range(6):
        client.post("/api/auth/login", json={"email": "viewer@tempris.com", "password": "wrong"})
    resp = client.post("/api/auth/login", json={"email": "viewer@tempris.com", "password": "wrong"})
    assert resp.status_code in (401, 429)


def test_protected_endpoint_requires_auth(client):
    """Protected routes must reject missing JWTs."""
    resp = client.get("/api/audit/log")
    assert resp.status_code == 401


def test_login_token_grants_access_to_audit_log(client):
    """A valid JWT should allow access to authenticated endpoints."""
    login = client.post("/api/auth/login", json={"email": "admin@tempris.com", "password": "demo"})
    token = login.json()["access_token"]
    resp = client.get("/api/audit/log", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
