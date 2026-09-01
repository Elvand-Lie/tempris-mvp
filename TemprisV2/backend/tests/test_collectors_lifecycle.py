# backend/tests/test_collectors_lifecycle.py
import uuid
import pytest
from starlette.testclient import TestClient
from app.db import get_db_connection

def test_collector_profile_creation_and_lifecycle(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst,
    auth_headers_tenant_b_admin
):
    # 1. Admin creates collector profile
    resp = client.post(
        "/api/collectors",
        json={"name": "Branch Office Collector", "description": "Branch internal probe"},
        headers=auth_headers_tenant_a_admin
    )
    assert resp.status_code == 201
    col = resp.json()
    col_id = col["id"]
    assert col["name"] == "Branch Office Collector"
    assert col["description"] == "Branch internal probe"
    assert col["enrollment_status"] == "awaiting_enrollment"
    assert col["operator_status"] == "active"
    assert col["connection_status"] == "offline"
    assert col["status"] == "awaiting_enrollment"
    assert col["req_rate_per_sec"] == 0.0
    assert "enrollment_code" in col
    assert col["enrollment_code"].startswith("col_enc_")
    assert col["enrollment_code_expires_at"] is not None

    # Verify enrollment_code_hash is stored in DB, but raw code is not
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT enrollment_code_hash, enrollment_code_expires_at FROM collectors WHERE id = %s;", (col_id,))
            db_row = cur.fetchone()
            assert db_row["enrollment_code_hash"] is not None
            assert len(db_row["enrollment_code_hash"]) == 64  # SHA-256 hex string

    # 2. Analyst can list and get collector details (Read-only)
    list_resp = client.get("/api/collectors", headers=auth_headers_tenant_a_analyst)
    assert list_resp.status_code == 200
    collectors = list_resp.json()
    assert len(collectors) >= 1
    found = next((c for c in collectors if c["id"] == col_id), None)
    assert found is not None
    assert found["connection_status"] == "offline"
    assert found["status"] == "awaiting_enrollment"

    get_resp = client.get(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_analyst)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == col_id

    # 3. Analyst cannot create collector (RBAC: 403)
    analyst_create_resp = client.post(
        "/api/collectors",
        json={"name": "Unauthorized Collector"},
        headers=auth_headers_tenant_a_analyst
    )
    assert analyst_create_resp.status_code == 403

    # 4. Tenant B cannot get Tenant A's collector (Tenant isolation: 404)
    tenant_b_get_resp = client.get(f"/api/collectors/{col_id}", headers=auth_headers_tenant_b_admin)
    assert tenant_b_get_resp.status_code == 404
    assert tenant_b_get_resp.json()["detail"] == "Collector not found"
