# backend/tests/test_collector_operator_lifecycle.py
import base64
import uuid
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.collector_crypto import build_canonical_challenge_bytes

def test_operator_security_lifecycle_and_rbac(
    client: TestClient,
    auth_headers_tenant_a_admin,
    auth_headers_tenant_a_analyst
):
    # 1. Create and enroll collector
    create_resp = client.post("/api/collectors", json={"name": "Operator Lifecycle Collector"}, headers=auth_headers_tenant_a_admin)
    assert create_resp.status_code == 201
    col_id = create_resp.json()["id"]
    code = create_resp.json()["enrollment_code"]

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_b64 = base64.urlsafe_b64encode(priv_key.public_key().public_bytes_raw()).decode().rstrip("=")

    enroll_resp = client.post("/api/collectors/enroll", json={"collector_id": col_id, "enrollment_code": code, "public_key": pub_key_b64})
    assert enroll_resp.status_code == 200

    # 2. Analyst attempts mutations -> 403 Forbidden
    for action in ["pause", "resume", "quarantine", "release", "revoke"]:
        r = client.post(f"/api/collectors/{col_id}/{action}", headers=auth_headers_tenant_a_analyst)
        assert r.status_code == 403, f"Action {action} should require Admin/Superadmin"

    # 3. Admin Pause
    pause_resp = client.post(f"/api/collectors/{col_id}/pause", headers=auth_headers_tenant_a_admin)
    assert pause_resp.status_code == 200
    assert pause_resp.json()["operator_status"] == "paused"
    assert pause_resp.json()["status"] == "paused"

    # 4. Admin Resume
    resume_resp = client.post(f"/api/collectors/{col_id}/resume", headers=auth_headers_tenant_a_admin)
    assert resume_resp.status_code == 200
    assert resume_resp.json()["operator_status"] == "active"
    assert resume_resp.json()["status"] == "offline"

    # 5. Admin Quarantine
    quar_resp = client.post(f"/api/collectors/{col_id}/quarantine", headers=auth_headers_tenant_a_admin)
    assert quar_resp.status_code == 200
    assert quar_resp.json()["operator_status"] == "quarantined"
    assert quar_resp.json()["status"] == "quarantined"

    # Cannot resume directly from quarantine
    invalid_resume = client.post(f"/api/collectors/{col_id}/resume", headers=auth_headers_tenant_a_admin)
    assert invalid_resume.status_code == 400

    # 6. Admin Release from Quarantine
    release_resp = client.post(f"/api/collectors/{col_id}/release", headers=auth_headers_tenant_a_admin)
    assert release_resp.status_code == 200
    assert release_resp.json()["operator_status"] == "active"

    # Release on already active collector returns 400
    dup_release = client.post(f"/api/collectors/{col_id}/release", headers=auth_headers_tenant_a_admin)
    assert dup_release.status_code == 400

    # 7. Admin Revoke
    revoke_resp = client.post(f"/api/collectors/{col_id}/revoke", headers=auth_headers_tenant_a_admin)
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["operator_status"] == "revoked"
    assert revoke_resp.json()["status"] == "revoked"

    # Revoked collector cannot be paused/resumed/quarantined
    for action in ["pause", "resume", "quarantine"]:
        r = client.post(f"/api/collectors/{col_id}/{action}", headers=auth_headers_tenant_a_admin)
        assert r.status_code == 400
