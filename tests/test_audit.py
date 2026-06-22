import hashlib


def test_audit_log_requires_auth(client):
    """Audit log listing must require authentication."""
    resp = client.get("/api/audit/log")
    assert resp.status_code == 401


def test_audit_log_lists_entries(client, superadmin_headers, db):
    """Audit log listing should return stored entries."""
    from models import AuditLog
    db.add(AuditLog(user_email="sherie@tempris.com", action="A1", module="TEST", detail="one", hash="h1"))
    db.commit()
    resp = client.get("/api/audit/log", headers=superadmin_headers)
    assert resp.status_code == 200
    assert resp.json()


def test_audit_integrity_detects_tamper(client, superadmin_headers, db):
    """Tampering with an audit log entry should break verification."""
    from models import AuditLog
    first = AuditLog(user_email="sherie@tempris.com", action="A1", module="TEST", detail="one", hash="h1")
    second = AuditLog(user_email="sherie@tempris.com", action="A2", module="TEST", detail="two", hash="h2")
    db.add_all([first, second])
    db.commit()
    second.detail = "tampered"
    db.commit()
    resp = client.get("/api/audit/verify", headers=superadmin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["intact"] is False or body["status"] == "TAMPERED"


def test_audit_post_requires_admin_role(client, viewer_headers):
    """Viewer should not be allowed to write audit entries directly."""
    resp = client.post("/api/audit/log", headers=viewer_headers, json={"action": "X", "module": "Y", "detail": "z"})
    assert resp.status_code == 403


def test_audit_post_creates_hash_chain_entry(client, admin_headers):
    """Admin can append to the audit log and receive a hash payload."""
    resp = client.post(
        "/api/audit/log",
        headers=admin_headers,
        json={"user": "admin@tempris.com", "action": "TEST_ACTION", "module": "TEST", "detail": "payload"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["hash"]
    assert body["action"] == "TEST_ACTION"


def test_audit_verify_empty_log_is_intact(client, superadmin_headers):
    """Empty audit log should verify cleanly."""
    resp = client.get("/api/audit/verify", headers=superadmin_headers)
    assert resp.status_code == 200
    assert resp.json()["intact"] is True
