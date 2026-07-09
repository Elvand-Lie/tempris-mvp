import io


def test_get_frameworks_requires_auth(client):
    """Framework listing should require authentication."""
    assert client.get("/api/standard/frameworks").status_code == 401


def test_get_frameworks_returns_list(client, viewer_headers):
    """Framework listing should return all configured frameworks."""
    resp = client.get("/api/standard/frameworks", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert any(item["id"] == "mas_trm_2024" for item in data)


def test_update_control_status_rbac(client, viewer_headers):
    """Viewer must not be able to update control status."""
    resp = client.put(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-11.1.1",
        headers=viewer_headers,
        json={"status": "compliant"},
    )
    assert resp.status_code == 403


def test_update_control_status_happy_path(client, admin_headers):
    """Admin can update a framework control status."""
    resp = client.put(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-11.1.1",
        headers=admin_headers,
        json={"status": "compliant"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "updated"


def test_update_control_status_validation(client, admin_headers):
    """Invalid status values should be rejected."""
    resp = client.put(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-11.1.1",
        headers=admin_headers,
        json={"status": "broken"},
    )
    assert resp.status_code == 400


def test_evidence_upload_requires_valid_file_type(client, admin_headers):
    """Evidence upload should reject unsupported file extensions before any write."""
    upload = client.post(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-11.1.1/evidence",
        headers=admin_headers,
        files={"file": ("evidence.exe", io.BytesIO(b"payload"), "application/octet-stream")},
    )
    assert upload.status_code == 400


def test_evidence_list_requires_auth(client):
    """Evidence listing should require authentication."""
    assert client.get("/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-11.1.1/evidence").status_code == 401


def test_get_asset_list_and_crud(client, admin_headers, viewer_headers):
    """Assets should support list/create/update/delete with RBAC."""
    create = client.post(
        "/api/assets",
        headers=admin_headers,
        json={"name": "Core Server", "asset_type": "server", "criticality": "critical"},
    )
    assert create.status_code == 200
    asset_id = create.json()["id"]

    listing = client.get("/api/assets", headers=viewer_headers)
    assert listing.status_code == 200
    assert listing.json()["data"]

    update = client.put(
        f"/api/assets/{asset_id}",
        headers=admin_headers,
        json={"notes": "updated"},
    )
    assert update.status_code == 200

    delete = client.delete(f"/api/assets/{asset_id}", headers=admin_headers)
    assert delete.status_code == 200


def test_assets_validation(client, admin_headers):
    """Asset creation should validate required fields."""
    resp = client.post("/api/assets", headers=admin_headers, json={"asset_type": "server"})
    assert resp.status_code == 422


def test_get_asset_stats_requires_auth(client):
    """Asset stats should require authentication."""
    assert client.get("/api/assets/stats").status_code == 401


def test_take_tes_snapshot_and_dashboard(client, viewer_headers):
    """Synthesis should return dashboard data and allow snapshot creation."""
    dashboard = client.get("/api/synthesis/dashboard", headers=viewer_headers)
    assert dashboard.status_code == 200
    assert "aggregate_tes" in dashboard.json()

    snapshot = client.post("/api/synthesis/tes-snapshot", headers=viewer_headers)
    assert snapshot.status_code == 200
    assert snapshot.json()["status"] == "snapshot_taken"


def test_evidence_list_and_download_reject_viewer_role(client, viewer_headers, db):
    from models import ControlEvidence
    ev = ControlEvidence(
        framework_id="mas_trm_2024",
        control_id="MAS-TRM-11.1.1",
        filename="evidence.txt",
        uploaded_by="admin@tempris.com",
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    ev_id = ev.id

    listing = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-11.1.1/evidence",
        headers=viewer_headers,
    )
    assert listing.status_code == 403

    download = client.get(
        f"/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-11.1.1/evidence/{ev_id}/download",
        headers=viewer_headers,
    )
    assert download.status_code == 403
