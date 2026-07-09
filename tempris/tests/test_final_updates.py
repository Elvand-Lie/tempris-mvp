def test_v54_final_pack_seeds_and_exposes_public_context(client, admin_headers, db):
    from models import Finding
    from scripts.seed_findings import seed_v54_final_findings

    seed_v54_final_findings(db, set())
    db.commit()

    assert db.query(Finding).filter(Finding.cve == "CVE-2026-45659").first().ransomware is True
    assert db.query(Finding).filter(Finding.cve == "SSS-2026-NHI-DEPLOY-001").first() is not None

    resp = client.get("/api/spectrum/findings?search=RustDuck", headers=admin_headers)
    assert resp.status_code == 200
    finding = resp.json()["data"][0]
    assert finding["tes_decision"] == "COMPENSATING_CONTROL"
    assert finding["patch_available"] is False
    assert "raw_inputs" not in finding
    assert "sss_data" not in finding


def test_blflaw_intake_creates_finding_and_tacf_metadata(client, admin_headers, db):
    from models import AuditLog, Finding

    resp = client.post(
        "/api/edip/intake/blflaw",
        headers=admin_headers,
        json={
            "finding_id": "SSS-2026-BLFLAW-TEST-001",
            "finding_type": "BLFLAW",
            "title": "Tenant boundary bypass",
            "description": "Cross-tenant access through a valid object ID.",
            "affected_ecosystem": "Customer Portal",
            "attack_vectors": ["IDOR"],
            "base_severity": 8.0,
            "agm": 1.2,
            "drf": 1.1,
            "tef": 1.1,
            "patch_available": True,
            "recommended_action": "Enforce object-level authorization",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_type"] == "BLFLAW"
    assert body["tes_score"] > 9
    assert db.query(Finding).filter(Finding.cve == "SSS-2026-BLFLAW-TEST-001").first() is not None

    audit = db.query(AuditLog).filter(AuditLog.action == "AUTO_EDIP_INTAKE").first()
    assert audit is not None
    assert audit.metadata_["agent_identity"] == "tempris-edip-intake"
    assert audit.metadata_["under_policy_control"] is True


def test_surge_acceptance_promotes_submission_to_spectrum_finding(client, admin_headers, db):
    from models import Finding, SurgeSubmission

    submit = client.post(
        "/api/surge/submit",
        headers=admin_headers,
        json={"title": "Stored XSS in report preview", "severity": "high", "description": "Researcher report summary."},
    )
    assert submit.status_code == 200
    submission_id = submit.json()["id"]

    triage = client.post(
        f"/api/surge/submissions/{submission_id}/triage",
        headers=admin_headers,
        json={"status": "accepted", "edip_decision": "mitigate", "bounty_amount": 100.0},
    )
    assert triage.status_code == 200
    promoted = triage.json()
    assert promoted["finding_id"]

    row = db.query(SurgeSubmission).filter(SurgeSubmission.id == submission_id).first()
    finding = db.query(Finding).filter(Finding.id == row.finding_id).first()
    assert finding is not None
    assert finding.source == "surge"
    assert finding.sss_data["type"] == "SURGE"


def test_tes_probe_detection_blocks_near_variant_requests(client, admin_headers):
    statuses = []
    for i in range(6):
        resp = client.post(
            "/api/spectrum/calculate-tes",
            headers=admin_headers,
            json={
                "cvss": 8.0 + (i * 0.1),
                "exploitability": 8.0,
                "business_impact": 7.0,
                "asset_criticality": 6.0,
                "threat_actor_activity": 5.0,
            },
        )
        statuses.append(resp.status_code)
    assert statuses[-1] == 429
