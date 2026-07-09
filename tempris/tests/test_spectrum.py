import pytest


@pytest.fixture(autouse=True)
def seed_spectrum_findings(db):
    """Provide stable finding rows for SPECTRUM/SCOUT endpoint tests."""
    from models import Finding

    db.add_all([
        Finding(
            id="F-TEST-001",
            cve="CVE-2026-48907",
            title="Critical Unauthenticated RCE in Joomla JCE",
            vendor="Joomla",
            product="JCE",
            cvss=9.8,
            priority="P0",
            status="unmitigated",
            cisa_kev=True,
            ransomware=False,
            date_added="2026-06-29T12:00:00Z",
            short_description="Test v51 finding",
            required_action="Patch JCE",
            raw_inputs={
                "cvss": 9.8,
                "exploitability": 10.0,
                "business_impact": 10.0,
                "asset_criticality": 10.0,
                "threat_actor_activity": 10.0,
            },
            sss_data={"scoring": {"TES_effective": 10.0}, "fim_bypass": True, "fim_bypass_note": "Memory integrity monitoring required."},
            source="kev",
        ),
        Finding(
            id="F-TEST-002",
            cve="CVE-2026-00002",
            title="High test vulnerability",
            vendor="TestVendor",
            product="TestProduct",
            cvss=7.5,
            priority="P1",
            status="unmitigated",
            cisa_kev=False,
            ransomware=False,
            date_added="2026-06-29T12:00:00Z",
            short_description="Second test finding",
            required_action="Investigate",
            raw_inputs={
                "cvss": 7.5,
                "exploitability": 8.0,
                "business_impact": 7.0,
                "asset_criticality": 6.0,
                "threat_actor_activity": 5.0,
            },
            source="cve",
        ),
    ])
    db.add(Finding(
        id="F-TEST-SSS",
        cve="SSS-2026-BLFLAW-IDOR-001",
        title="Business Logic Flaw - IDOR",
        vendor="Web Application",
        product="Authorization Logic",
        cvss=8.0,
        priority="P0",
        status="unmitigated",
        cisa_kev=False,
        ransomware=False,
        date_added="2026-07-06T00:00:00Z",
        short_description="Non-CVE business logic flaw",
        required_action="Enforce object-level authorization",
        raw_inputs={
            "cvss": 8.0,
            "exploitability": 1.0,
            "business_impact": 1.0,
            "asset_criticality": 1.0,
            "threat_actor_activity": 1.0,
        },
        sss_data={"type": "NON_CVE_SSS", "scoring": {"base_severity": 8.0, "AGM": 1.2, "DRF": 1.1, "TEF": 1.2, "TES_effective": 1.0}},
        source="sss",
    ))
    db.commit()


def test_get_findings_returns_paged_results(client, superadmin_headers):
    """Findings endpoint should return KEV findings with TES data."""
    resp = client.get("/api/spectrum/findings", headers=superadmin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["meta"]["total"] >= 2
    assert data["data"]
    assert "tes_score" in data["data"][0]


def test_get_findings_strips_internal_tes_fields(client, superadmin_headers):
    """Findings API must not expose internal scoring inputs or breakdowns."""
    resp = client.get("/api/spectrum/findings", headers=superadmin_headers)
    assert resp.status_code == 200
    finding = resp.json()["data"][0]
    for forbidden in ("raw_inputs", "sss_data", "tes_breakdown"):
        assert forbidden not in finding

def test_get_findings_exposes_public_fim_bypass_advisory(client, superadmin_headers):
    """FIM-bypass advisory should be public without exposing internal SSS data."""
    resp = client.get("/api/spectrum/findings", headers=superadmin_headers)
    assert resp.status_code == 200
    finding = resp.json()["data"][0]
    assert finding["fim_bypass"] is True
    assert finding["fim_bypass_note"] == "Memory integrity monitoring required."
    assert "sss_data" not in finding


def test_scout_findings_strip_internal_fields(client, superadmin_headers):
    """SCOUT browser should not leak SPECTRUM internal scoring fields."""
    resp = client.get("/api/scout/findings", headers=superadmin_headers)
    assert resp.status_code == 200
    finding = resp.json()["data"][0]
    for forbidden in ("raw_inputs", "sss_data"):
        assert forbidden not in finding


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
        json={"decision": "mitigate", "rationale": "urgent"},
    )
    assert resp.status_code == 403


def test_record_edip_decision_creates_record(client, admin_headers):
    """Admin can persist an EDIP decision for a finding."""
    findings = client.get("/api/spectrum/findings", headers=admin_headers).json()["data"]
    finding_id = findings[0]["id"]
    resp = client.post(
        f"/api/spectrum/findings/{finding_id}/edip",
        headers=admin_headers,
        json={"decision": "mitigate", "rationale": "critical exposure"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_id"] == finding_id
    assert body["decision"] == "mitigate"


def test_record_edip_decision_returns_404_for_unknown_finding(client, admin_headers):
    """Unknown findings should return 404."""
    resp = client.post(
        "/api/spectrum/findings/NOPE/edip",
        headers=admin_headers,
        json={"decision": "mitigate", "rationale": "missing"},
    )
    assert resp.status_code == 404


def test_calculate_tes_returns_public_result_only(client, admin_headers):
    """TES calculation endpoint should not return component breakdown fields."""
    resp = client.post(
        "/api/spectrum/calculate-tes",
        headers=admin_headers,
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
    assert data["tes_score"] > 0
    assert data["decision"] in ("ESCALATE", "PATCH", "INVESTIGATE", "DEFER")
    assert "cvss_component" not in data


def test_calculate_tes_requires_privileged_role(client, viewer_headers):
    """Viewer should not be able to probe the TES calculator."""
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
    assert resp.status_code == 403


def test_calculate_tes_rejects_bad_input(client, admin_headers):
    """TES calculation endpoint should validate its payload."""
    resp = client.post(
        "/api/spectrum/calculate-tes",
        headers=admin_headers,
        json={"cvss": 9.0},
    )
    assert resp.status_code == 422



def test_record_edip_decision_rejects_invalid_enum(client, admin_headers):
    findings = client.get("/api/spectrum/findings", headers=admin_headers).json()["data"]
    resp = client.post(
        f"/api/spectrum/findings/{findings[0]['id']}/edip",
        headers=admin_headers,
        json={"decision": "patch", "rationale": "old enum"},
    )
    assert resp.status_code == 400


def test_get_findings_calculates_non_cve_sss_tes(client, superadmin_headers):
    resp = client.get("/api/spectrum/findings?search=SSS-2026-BLFLAW", headers=superadmin_headers)
    assert resp.status_code == 200
    finding = resp.json()["data"][0]
    assert finding["severity"] == {"score": 8.0, "label": "High", "source": "SSS"}
    assert finding["tes_score"] == 10.0
    assert finding["tes_priority"] == "P0"
    assert finding["tes_decision"] == "ESCALATE"
    assert "sss_data" not in finding
