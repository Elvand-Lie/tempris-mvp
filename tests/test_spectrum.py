import pytest


def test_get_findings_returns_paged_results(client, superadmin_headers):
    """Findings endpoint should return KEV findings with TES data."""
    resp = client.get("/api/spectrum/findings", headers=superadmin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["meta"]["total"] >= 2
    assert data["data"]
    assert "tes_score" in data["data"][0]


def test_get_findings_requires_auth(client):
    """Findings endpoint must require authentication."""
    resp = client.get("/api/spectrum/findings")
    assert resp.status_code == 401


def test_get_findings_supports_filters(client, superadmin_headers):
    """Findings endpoint should filter by priority and decision state."""
    resp = client.get("/api/spectrum/findings?priority=P0&decision=pending", headers=superadmin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert all(item["priority"] == "P0" for item in data["data"])


def test_record_edip_decision_requires_privileged_role(client, viewer_headers):
    """Viewer should not be able to write EDIP decisions."""
    resp = client.post(
        "/api/spectrum/findings/F-1/edip",
        headers=viewer_headers,
        json={"decision": "patch", "rationale": "urgent"},
    )
    assert resp.status_code == 403


def test_record_edip_decision_creates_record(client, admin_headers):
    """Admin can persist an EDIP decision for a finding."""
    findings = client.get("/api/spectrum/findings", headers=admin_headers).json()["data"]
    finding_id = findings[0]["id"]
    resp = client.post(
        f"/api/spectrum/findings/{finding_id}/edip",
        headers=admin_headers,
        json={"decision": "patch", "rationale": "critical exposure"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_id"] == finding_id
    assert body["decision"] == "patch"


def test_record_edip_decision_returns_404_for_unknown_finding(client, admin_headers):
    """Unknown findings should return 404."""
    resp = client.post(
        "/api/spectrum/findings/NOPE/edip",
        headers=admin_headers,
        json={"decision": "patch", "rationale": "missing"},
    )
    assert resp.status_code == 404


def test_calculate_tes_returns_breakdown(client, viewer_headers):
    """TES calculation endpoint should return the breakdown fields."""
    resp = client.post(
        "/api/spectrum/calculate-tes",
        headers=viewer_headers,
        json={
            "cvss": 9.0,
            "exploitability": 8.0,
            "business_impact": 7.0,
            "asset_criticality": 6.0,
            "threat_actor_activity": 5.0,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_score"] > 0
    assert data["cvss_component"] == 3.15


def test_calculate_tes_rejects_bad_input(client, viewer_headers):
    """TES calculation endpoint should validate its payload."""
    resp = client.post(
        "/api/spectrum/calculate-tes",
        headers=viewer_headers,
        json={"cvss": 9.0},
    )
    assert resp.status_code == 422
