# backend/tests/test_collector_delete.py
import base64
import uuid
import pytest
from starlette.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.auth import create_test_token
from app.db import get_db_connection
from app.collector_registry import collector_registry, CollectorSession

def _create_and_enroll_collector(client: TestClient, headers: dict, name: str = "Test Revoked Collector") -> str:
    create_resp = client.post(
        "/api/collectors",
        json={"name": name, "description": "For deletion test"},
        headers=headers
    )
    assert create_resp.status_code == 201
    col_id = create_resp.json()["id"]
    code = create_resp.json()["enrollment_code"]

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_resp = client.post(
        "/api/collectors/enroll",
        json={
            "collector_id": col_id,
            "enrollment_code": code,
            "public_key": pub_key_b64,
            "platform_metadata": {
                "os": "windows",
                "architecture": "x86_64",
                "hostname": "test-host-01",
                "version": "0.2.0"
            }
        }
    )
    assert enroll_resp.status_code == 200
    return col_id


def test_collector_delete_role_rbac_denial(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst
):
    """Analyst receives 403 on DELETE; unauthenticated receives 401."""
    col_id = _create_and_enroll_collector(client, auth_headers_tenant_a_admin)

    # Revoke it first
    revoke_resp = client.post(f"/api/collectors/{col_id}/revoke", headers=auth_headers_tenant_a_admin)
    assert revoke_resp.status_code == 200

    # Analyst attempt -> 403 Forbidden
    analyst_del = client.delete(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_analyst)
    assert analyst_del.status_code == 403

    # Unauthenticated attempt -> 401 Unauthorized
    unauth_del = client.delete(f"/api/collectors/{col_id}")
    assert unauth_del.status_code == 401


def test_collector_delete_cross_tenant_and_not_found_404(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_b_admin
):
    """Cross-tenant deletion returns 404 (zero existence disclosure); non-existent returns 404."""
    # Tenant A creates and revokes collector
    col_a_id = _create_and_enroll_collector(client, auth_headers_tenant_a_admin, name="Tenant A Target")
    revoke_resp = client.post(f"/api/collectors/{col_a_id}/revoke", headers=auth_headers_tenant_a_admin)
    assert revoke_resp.status_code == 200

    # Tenant B attempts to DELETE Tenant A collector -> 404 Not Found
    b_del = client.delete(f"/api/collectors/{col_a_id}", headers=auth_headers_tenant_b_admin)
    assert b_del.status_code == 404
    assert b_del.json()["detail"] == "Collector not found"

    # Non-existent UUID -> 404 Not Found
    fake_id = uuid.uuid4()
    not_found_del = client.delete(f"/api/collectors/{fake_id}", headers=auth_headers_tenant_a_admin)
    assert not_found_del.status_code == 404
    assert not_found_del.json()["detail"] == "Collector not found"


def test_collector_delete_non_revoked_states_rejected_409(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    """Deleting collector in awaiting_enrollment, active, paused, or quarantined status returns 409."""
    # 1. Awaiting enrollment (operator_status='active', enrollment_status='awaiting_enrollment')
    create_resp = client.post(
        "/api/collectors",
        json={"name": "Awaiting Enrollment Collector"},
        headers=auth_headers_tenant_a_admin
    )
    col_id_awaiting = create_resp.json()["id"]
    del_awaiting = client.delete(f"/api/collectors/{col_id_awaiting}", headers=auth_headers_tenant_a_admin)
    assert del_awaiting.status_code == 409
    assert "must be revoked" in del_awaiting.json()["detail"]

    # 2. Enrolled and active
    col_id_active = _create_and_enroll_collector(client, auth_headers_tenant_a_admin, name="Active Collector")
    del_active = client.delete(f"/api/collectors/{col_id_active}", headers=auth_headers_tenant_a_admin)
    assert del_active.status_code == 409
    assert "must be revoked" in del_active.json()["detail"]

    # 3. Paused
    pause_resp = client.post(f"/api/collectors/{col_id_active}/pause", headers=auth_headers_tenant_a_admin)
    assert pause_resp.status_code == 200
    del_paused = client.delete(f"/api/collectors/{col_id_active}", headers=auth_headers_tenant_a_admin)
    assert del_paused.status_code == 409
    assert "must be revoked" in del_paused.json()["detail"]

    # 4. Quarantined
    quar_resp = client.post(f"/api/collectors/{col_id_active}/quarantine", headers=auth_headers_tenant_a_admin)
    assert quar_resp.status_code == 200
    del_quar = client.delete(f"/api/collectors/{col_id_active}", headers=auth_headers_tenant_a_admin)
    assert del_quar.status_code == 409
    assert "must be revoked" in del_quar.json()["detail"]


def test_collector_delete_live_session_rejected_409(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    """Deleting revoked collector while active WebSocket session exists in registry returns 409."""
    col_id = _create_and_enroll_collector(client, auth_headers_tenant_a_admin, name="Live Session Collector")
    cid = uuid.UUID(col_id)
    tenant_id = uuid.UUID("11111111-1111-1111-1111-111111111111")

    # Manually register a mock live session in collector_registry
    mock_session = CollectorSession(
        collector_id=cid,
        tenant_id=tenant_id,
        operator_status="revoked"
    )
    collector_registry._sessions[cid] = mock_session

    try:
        # Revoke in DB
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE collectors SET operator_status = 'revoked' WHERE id = %s;", (col_id,))
            conn.commit()

        # Attempt DELETE while live session is registered -> 409
        del_resp = client.delete(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
        assert del_resp.status_code == 409
        assert "active live session" in del_resp.json()["detail"]
    finally:
        collector_registry._sessions.pop(cid, None)


def test_collector_delete_referenced_by_active_or_historical_asset_rejected_409(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    """Deleting revoked collector referenced by active or decommissioned assets returns 409."""
    col_id = _create_and_enroll_collector(client, auth_headers_tenant_a_admin, name="Referenced Collector")

    # 1. Create active asset routed to this collector
    asset_resp = client.post(
        "/api/assets",
        json={
            "name": "Collector Asset",
            "asset_type": "server",
            "target_type": "ip",
            "target_value": "10.50.1.100",
            "network_scope": "internal",
            "environment": "production",
            "criticality": "high",
            "collector_id": col_id
        },
        headers=auth_headers_tenant_a_admin
    )
    assert asset_resp.status_code == 201
    asset_id = asset_resp.json()["id"]

    # Revoke the collector
    revoke_resp = client.post(f"/api/collectors/{col_id}/revoke", headers=auth_headers_tenant_a_admin)
    assert revoke_resp.status_code == 200

    # Attempt DELETE -> 409 Conflict due to active asset reference
    del_active_ref = client.delete(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
    assert del_active_ref.status_code == 409
    assert "referenced by 1 asset(s)" in del_active_ref.json()["detail"]

    # Decommission the asset (making it historical reference)
    decom_resp = client.post(f"/api/assets/{asset_id}/decommission", headers=auth_headers_tenant_a_admin)
    assert decom_resp.status_code == 200

    # Attempt DELETE -> still 409 Conflict due to historical/decommissioned asset reference
    del_hist_ref = client.delete(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
    assert del_hist_ref.status_code == 409
    assert "referenced by 1 asset(s)" in del_hist_ref.json()["detail"]


def test_collector_delete_success_204_repeated_404_and_audit_retention(
    client: TestClient,
    auth_headers_tenant_a_admin
):
    """
    Revoked, unreferenced collector profile is deleted returning 204.
    Repeated delete returns 404.
    Audit history is retained and new collector.deleted audit event is sanitized.
    """
    col_id = _create_and_enroll_collector(client, auth_headers_tenant_a_admin, name="Clean Deletion Collector")

    # Revoke collector
    revoke_resp = client.post(f"/api/collectors/{col_id}/revoke", headers=auth_headers_tenant_a_admin)
    assert revoke_resp.status_code == 200

    # Execute DELETE -> 204 No Content
    del_resp = client.delete(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
    assert del_resp.status_code == 204

    # 1. Verify collector is completely removed from database
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM collectors WHERE id = %s;", (col_id,))
            assert cur.fetchone() is None

    # 2. Repeated delete returns 404 Not Found
    repeat_del = client.delete(f"/api/collectors/{col_id}", headers=auth_headers_tenant_a_admin)
    assert repeat_del.status_code == 404
    assert repeat_del.json()["detail"] == "Collector not found"

    # 3. Verify audit history is preserved and collector.deleted audit row exists and is sanitized
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT event_name, details
                FROM audit_events
                WHERE details->>'collector_id' = %s
                ORDER BY created_at ASC;
                """,
                (col_id,)
            )
            audit_rows = cur.fetchall()
            event_names = [r["event_name"] for r in audit_rows]
            assert "collector.created" in event_names
            assert "collector.enrolled" in event_names
            assert "collector.revoked" in event_names
            assert "collector.deleted" in event_names

            # Inspect collector.deleted details
            del_event = next(r for r in audit_rows if r["event_name"] == "collector.deleted")
            details = del_event["details"]
            assert details["collector_id"] == col_id
            assert details["name"] == "Clean Deletion Collector"
            assert details.get("hostname") == "test-host-01"
            assert details.get("os") == "windows"

            # Strict zero secret / key leakage check
            assert "public_key" not in details
            assert "enrollment_code" not in details
            assert "enrollment_code_hash" not in details
            assert "secret" not in str(details).lower()
            assert "key" not in details
