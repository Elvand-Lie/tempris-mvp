# backend/tests/test_scan_authorization.py
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from starlette.testclient import TestClient
from app.db import get_db_connection

def test_scan_authorization_lifecycle_and_rbac(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst,
    auth_headers_tenant_b_admin
):
    # 1. Create active asset
    create_resp = client.post(
        "/api/assets",
        json={
            "name": "Auth Lifecycle Srv",
            "asset_type": "server",
            "target_type": "domain",
            "target_value": "auth-test.example.com",
            "network_scope": "internet",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert create_resp.status_code == 201
    asset_id = create_resp.json()["id"]

    # 2. GET /api/assets/{id}/scan-authorization when none exists returns 200 with null
    get_auth_resp = client.get(f"/api/assets/{asset_id}/scan-authorization", headers=auth_headers_tenant_a_analyst)
    assert get_auth_resp.status_code == 200
    assert get_auth_resp.json() is None

    # 3. GET /api/assets/{id}/scan-authorization for non-existent asset returns 404
    fake_id = str(uuid.uuid4())
    assert client.get(f"/api/assets/{fake_id}/scan-authorization", headers=auth_headers_tenant_a_admin).status_code == 404

    # 4. Analyst requests scan authorization -> 201 Created
    req_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/request",
        json={"request_reason": "Quarterly penetration test"},
        headers=auth_headers_tenant_a_analyst
    )
    assert req_resp.status_code == 201
    auth_data = req_resp.json()
    assert auth_data["status"] == "pending"
    assert auth_data["requested_by"] == "analyst-a"
    assert auth_data["request_reason"] == "Quarterly penetration test"
    assert auth_data["target_type"] == "domain"
    assert auth_data["normalized_target"] == "auth-test.example.com"
    assert auth_data["network_scope"] == "internet"

    # 5. RBAC: Analyst cannot approve or revoke (403 Forbidden)
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    approve_by_analyst = client.post(
        f"/api/assets/{asset_id}/scan-authorization/approve",
        json={"expires_at": future_expiry},
        headers=auth_headers_tenant_a_analyst
    )
    assert approve_by_analyst.status_code == 403

    revoke_by_analyst = client.post(
        f"/api/assets/{asset_id}/scan-authorization/revoke",
        json={"revocation_reason": "Unauthorized attempt"},
        headers=auth_headers_tenant_a_analyst
    )
    assert revoke_by_analyst.status_code == 403

    # 6. Expiry validation: Past or missing expiry returns 422 Unprocessable Entity
    past_expiry = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    bad_expiry_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/approve",
        json={"expires_at": past_expiry},
        headers=auth_headers_tenant_a_admin
    )
    assert bad_expiry_resp.status_code == 422

    missing_expiry_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/approve",
        json={},
        headers=auth_headers_tenant_a_admin
    )
    assert missing_expiry_resp.status_code == 422

    # 7. Admin approves authorization with valid future expiry -> 200 OK
    approve_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/approve",
        json={"expires_at": future_expiry},
        headers=auth_headers_tenant_a_admin
    )
    assert approve_resp.status_code == 200
    approved_data = approve_resp.json()
    assert approved_data["status"] == "approved"
    assert approved_data["approved_by"] == "admin-a"
    assert approved_data["approved_at"] is not None
    assert approved_data["expires_at"] is not None

    # 8. Cross-tenant isolation: Tenant B cannot access or modify Tenant A authorization
    assert client.get(f"/api/assets/{asset_id}/scan-authorization", headers=auth_headers_tenant_b_admin).status_code == 404
    assert client.post(
        f"/api/assets/{asset_id}/scan-authorization/request",
        json={"request_reason": "Cross-tenant attack"},
        headers=auth_headers_tenant_b_admin
    ).status_code == 404
    assert client.post(
        f"/api/assets/{asset_id}/scan-authorization/approve",
        json={"expires_at": future_expiry},
        headers=auth_headers_tenant_b_admin
    ).status_code == 404
    assert client.post(
        f"/api/assets/{asset_id}/scan-authorization/revoke",
        json={"revocation_reason": "Cross-tenant revoke"},
        headers=auth_headers_tenant_b_admin
    ).status_code == 404

    # 9. Admin revokes authorization -> 200 OK
    revoke_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/revoke",
        json={"revocation_reason": "Scope changed prematurely"},
        headers=auth_headers_tenant_a_admin
    )
    assert revoke_resp.status_code == 200
    revoked_data = revoke_resp.json()
    assert revoked_data["status"] == "revoked"
    assert revoked_data["revoked_by"] == "admin-a"
    assert revoked_data["revocation_reason"] == "Scope changed prematurely"

    # 10. Audit log check: verify events scan_authorization.requested, approved, revoked
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_name FROM audit_events WHERE asset_id = %s ORDER BY created_at ASC;",
                (asset_id,)
            )
            events = [r["event_name"] for r in cur.fetchall()]
            assert "scan_authorization.requested" in events
            assert "scan_authorization.approved" in events
            assert "scan_authorization.revoked" in events

def test_decommissioned_asset_rejects_authorization_operations(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    create_resp = client.post(
        "/api/assets",
        json={
            "name": "Decom Auth Test Srv",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "192.168.100.10",
            "network_scope": "internal",
            "environment": "staging",
            "criticality": "low"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_id = create_resp.json()["id"]

    # Decommission asset
    client.post(f"/api/assets/{asset_id}/decommission", headers=auth_headers_tenant_a_admin)

    # Request on decommissioned asset -> 400 Bad Request
    req_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/request",
        json={"request_reason": "Test"},
        headers=auth_headers_tenant_a_admin
    )
    assert req_resp.status_code == 400

    # Approve on decommissioned asset -> 400 Bad Request
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    appr_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/approve",
        json={"expires_at": future_expiry},
        headers=auth_headers_tenant_a_admin
    )
    assert appr_resp.status_code == 400

def test_scan_authorization_elapsed_expiry_returns_effective_expired_status(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    create_resp = client.post(
        "/api/assets",
        json={
            "name": "Expired Auth Test Asset",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.10.10.10",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "high"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_id = create_resp.json()["id"]

    # Insert approved authorization with elapsed expiry
    past_expiry = datetime.now(timezone.utc) - timedelta(days=2)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO asset_scan_authorizations (
                    id, tenant_id, asset_id, target_type, normalized_target,
                    network_scope, status, requested_by, approved_by, approved_at, expires_at
                ) VALUES (
                    gen_random_uuid(), '11111111-1111-1111-1111-111111111111', %s, 'ip', '10.10.10.10',
                    'internal', 'approved', 'admin-a', 'admin-a', now(), %s
                );
                """,
                (asset_id, past_expiry)
            )
        conn.commit()

    # Read authorization via API -> effective status must be 'expired'
    auth_resp = client.get(f"/api/assets/{asset_id}/scan-authorization", headers=auth_headers_tenant_a_admin)
    assert auth_resp.status_code == 200
    data = auth_resp.json()
    assert data["status"] == "expired"

def test_approve_pending_authorization_scoped_and_fails_on_concurrent_modification(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst
):
    create_resp = client.post(
        "/api/assets",
        json={
            "name": "Pending Auth Scoping Srv",
            "asset_type": "server",
            "target_type": "domain",
            "target_value": "pending-scope.example.com",
            "network_scope": "internet",
            "environment": "staging",
            "criticality": "medium"
        },
        headers=auth_headers_tenant_a_admin
    )
    asset_id = create_resp.json()["id"]

    # Request authorization -> status is pending
    req_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/request",
        json={"request_reason": "Audit"},
        headers=auth_headers_tenant_a_analyst
    )
    assert req_resp.status_code == 201

    # Approve pending authorization
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    appr_resp = client.post(
        f"/api/assets/{asset_id}/scan-authorization/approve",
        json={"expires_at": future_expiry},
        headers=auth_headers_tenant_a_admin
    )
    assert appr_resp.status_code == 200
    assert appr_resp.json()["status"] == "approved"
