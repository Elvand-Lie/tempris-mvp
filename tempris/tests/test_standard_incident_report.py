def test_mas_trm_incident_report_generates_and_persists(client, admin_headers, db):
    from models import IncidentReport

    resp = client.post(
        "/api/standard/mas-trm/incident-report",
        headers=admin_headers,
        json={},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"].startswith("DRAFT")
    assert "PENDING SUBMISSION TO MAS" in data["status"]
    assert data["threat_landscape"]["total_kev_findings"] >= 0
    assert data["notification_deadline"] > data["generated_at"]

    stored = db.query(IncidentReport).filter(IncidentReport.report_id == data["report_id"]).first()
    assert stored is not None
    assert stored.payload["report_id"] == data["report_id"]

    latest = client.get("/api/standard/mas-trm/incident-reports/latest", headers=admin_headers)
    assert latest.status_code == 200
    assert latest.json()["report_id"] == data["report_id"]

    history = client.get("/api/standard/mas-trm/incident-reports?limit=10", headers=admin_headers)
    assert history.status_code == 200
    assert history.json()["total"] == 1
    assert history.json()["data"][0]["report_id"] == data["report_id"]

    from services.ai_context import build_full_context
    ctx = build_full_context(db)
    assert ctx["structured"]["latest_incident_report"]["report_id"] == data["report_id"]
