import pytest


def test_security_headers_present(client, viewer_headers):
    """Responses should include the expected security headers."""
    resp = client.get("/api/audit/log", headers=viewer_headers)
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers
    assert "Permissions-Policy" in resp.headers


def test_server_fingerprint_headers_are_stripped(client, viewer_headers):
    """Server fingerprint headers should not leak."""
    resp = client.get("/api/audit/log", headers=viewer_headers)
    assert resp.status_code == 200
    assert "server" not in {k.lower() for k in resp.headers.keys()}
    assert "x-powered-by" not in {k.lower() for k in resp.headers.keys()}


def test_cors_preflight_allows_configured_origin(client):
    """CORS should allow configured origins."""
    resp = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200, f"CORS preflight rejected: {resp.status_code}"
    # Verify CORS headers are actually present
    assert "access-control-allow-origin" in {k.lower() for k in resp.headers.keys()}, \
        "CORS response missing Access-Control-Allow-Origin header"


def test_rate_limit_auth_endpoint(client):
    """Auth endpoint should enforce its per-IP rate limit under burst traffic."""
    statuses = []
    for _ in range(7):
        r = client.post("/api/auth/login", json={"email": "ratelimit-test@tempris.com", "password": "wrong"})
        statuses.append(r.status_code)
    assert 429 in statuses, \
        f"Auth rate limit never triggered after 7 requests: {statuses}"


def test_rate_limit_scanner_endpoint(client, admin_headers):
    """Scanner endpoint should be rate limited separately from other APIs."""
    statuses = []
    for _ in range(12):
        r = client.post("/api/scanner/scan", headers=admin_headers, json={"target": "example.com", "scan_type": "quick"})
        statuses.append(r.status_code)
    # Must see 429 at some point — scanner limit is 10/min
    assert 429 in statuses, \
        f"Scanner rate limit never triggered after 12 requests: {statuses}"


def test_health_endpoint_skips_rate_limit(client):
    """Health endpoint should remain available under the middleware."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "Tempris API running"
