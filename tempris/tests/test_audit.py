import hashlib
from datetime import datetime, timezone


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


def test_audit_log_supports_paging_sort_and_filters(client, superadmin_headers, db):
    """Audit log query mode should support server-side paging, sorting, and module filters."""
    from models import AuditLog
    db.add_all([
        AuditLog(user_email="beta@tempris.com", action="Z_ACTION", module="GRC", detail="later", hash="h1"),
        AuditLog(user_email="alpha@tempris.com", action="A_ACTION", module="STANDARD", detail="earlier", hash="h2"),
    ])
    db.commit()

    resp = client.get(
        "/api/audit/log?limit=1&offset=0&sort_by=action&order=asc&module=STANDARD",
        headers=superadmin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["data"][0]["action"] == "A_ACTION"


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

    verify = client.get("/api/audit/verify", headers=admin_headers)
    assert verify.status_code == 200
    assert verify.json()["intact"] is True


def test_audit_verify_empty_log_is_intact(client, superadmin_headers):
    """Empty audit log should verify cleanly."""
    resp = client.get("/api/audit/verify", headers=superadmin_headers)
    assert resp.status_code == 200
    assert resp.json()["intact"] is True


def test_audit_post_uses_authenticated_actor_and_request_ip(client, admin_headers):
    resp = client.post(
        "/api/audit/log",
        headers={**admin_headers, "X-Real-IP": "203.0.113.55"},
        json={"user": "attacker@tempris.com", "action": "SPOOF", "module": "AUDIT", "detail": "try", "ip_address": "10.0.0.9"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"] == "admin@tempris.com"
    assert body["ip_address"] != "203.0.113.55"
    assert body["ip_address"] != "10.0.0.9"


def test_audit_integrity_detects_actor_tamper(client, admin_headers, db):
    resp = client.post(
        "/api/audit/log",
        headers=admin_headers,
        json={"action": "SIGNED", "module": "AUDIT", "detail": "original"},
    )
    assert resp.status_code == 200

    from models import AuditLog
    row = db.query(AuditLog).first()
    row.user_email = "forged@tempris.com"
    db.commit()

    verify = client.get("/api/audit/verify", headers=admin_headers)
    assert verify.status_code == 200
    assert verify.json()["intact"] is False


def test_audit_recompute_requires_admin(client, viewer_headers):
    resp = client.get("/api/audit/verify?recompute=true", headers=viewer_headers)
    assert resp.status_code == 403

def test_audit_verify_accepts_legacy_hash_payload(client, admin_headers, db):
    """Production rows before TACF metadata used action+detail+timestamp hashes."""
    from models import AuditLog

    ts = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    legacy_payload = f"LEGACY_ACTIONlegacy detail{ts.isoformat()}"
    legacy_hash = hashlib.sha256(f"0{legacy_payload}".encode()).hexdigest()
    db.add(AuditLog(
        timestamp=ts,
        user_email="legacy@tempris.com",
        action="LEGACY_ACTION",
        module="AUDIT",
        detail="legacy detail",
        hash=legacy_hash,
    ))
    db.commit()

    resp = client.get("/api/audit/verify", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["intact"] is True
