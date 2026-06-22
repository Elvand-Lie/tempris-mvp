from unittest.mock import AsyncMock


def test_get_matrix_requires_auth(client):
    """MITRE matrix should require authentication."""
    assert client.get("/api/strike/matrix").status_code == 401


def test_get_available_techniques(client, viewer_headers):
    """Technique catalog should be visible to authenticated users."""
    resp = client.get("/api/strike/techniques", headers=viewer_headers)
    assert resp.status_code == 200
    assert "available" in resp.json()


def test_create_authorization_requires_privileged_role(client, viewer_headers):
    """Viewer should not be able to create strike authorizations."""
    resp = client.post(
        "/api/strike/authorizations",
        headers=viewer_headers,
        json={"target_name": "example.com", "target_ip": "203.0.113.10", "techniques": ["T1595"], "rules_of_engagement": "non-destructive", "authorized_by": "viewer@tempris.com"},
    )
    assert resp.status_code == 403


def test_create_authorization_and_list(client, admin_headers):
    """Admin can create and list strike authorizations."""
    create = client.post(
        "/api/strike/authorizations",
        headers=admin_headers,
        json={"target_name": "example.com", "target_ip": "203.0.113.10", "techniques": ["T1595"], "rules_of_engagement": "non-destructive", "authorized_by": "admin@tempris.com"},
    )
    assert create.status_code == 200
    auth_id = create.json()["id"]

    listing = client.get("/api/strike/authorizations", headers=admin_headers)
    assert listing.status_code == 200
    assert any(item["id"] == auth_id for item in listing.json())


def test_sign_authorization_requires_admin(client, viewer_headers):
    """Viewer should not be able to sign strike authorizations."""
    resp = client.post("/api/strike/authorizations/AUTH-DOES-NOT-EXIST/sign", headers=viewer_headers)
    assert resp.status_code == 403


def test_quick_scan_blocks_internal_targets(client, admin_headers):
    """Quick scan must block internal targets via SSRF protection."""
    resp = client.post(
        "/api/strike/quick-scan",
        headers=admin_headers,
        json={"target": "127.0.0.1"},
    )
    assert resp.status_code == 403


def test_run_simulation_requires_signed_authorization(client, admin_headers):
    """Simulation should reject unsigned authorizations."""
    create = client.post(
        "/api/strike/authorizations",
        headers=admin_headers,
        json={"target_name": "example.com", "target_ip": "203.0.113.10", "techniques": ["T1595"], "rules_of_engagement": "non-destructive", "authorized_by": "admin@tempris.com"},
    )
    auth_id = create.json()["id"]
    resp = client.post(
        "/api/strike/simulations",
        headers=admin_headers,
        json={"authorization_id": auth_id},
    )
    assert resp.status_code == 403, \
        f"Unsigned authorization should be rejected with 403, got {resp.status_code}"


def test_scanner_blocks_internal_ips(client, admin_headers):
    """Scanner must block private and loopback targets."""
    resp = client.post(
        "/api/scanner/scan",
        headers=admin_headers,
        json={"target": "127.0.0.1", "scan_type": "quick"},
    )
    assert resp.status_code == 403


def test_scanner_requires_privileged_role(client, viewer_headers):
    """Viewer should not be able to run scans."""
    resp = client.post(
        "/api/scanner/scan",
        headers=viewer_headers,
        json={"target": "example.com", "scan_type": "quick"},
    )
    assert resp.status_code == 403


def test_scout_stats_and_findings(client, viewer_headers):
    """Scout should expose vulnerability summaries to authenticated users."""
    findings = client.get("/api/scout/findings", headers=viewer_headers)
    assert findings.status_code == 200
    assert findings.json()["data"]
    stats = client.get("/api/scout/stats", headers=viewer_headers)
    assert stats.status_code == 200


def test_grc_dashboard_and_signoff(client, admin_headers, viewer_headers):
    """GRC should support state, TES, controls, and signoffs."""
    state = client.get("/api/grc/state", headers=viewer_headers)
    assert state.status_code == 200
    assert "toggles" in state.json()

    controls = client.get("/api/grc/controls", headers=viewer_headers)
    assert controls.status_code == 200

    tes = client.get("/api/grc/tes-score", headers=viewer_headers)
    assert tes.status_code == 200

    signoff = client.post(
        "/api/grc/signoff/A.2.2",
        headers=admin_headers,
        json={"signoff_type": "pic", "signed": True, "notes": "approved"},
    )
    assert signoff.status_code == 200
