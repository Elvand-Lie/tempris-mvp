import pytest
import os
import sys
from fastapi.testclient import TestClient
from passlib.hash import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.database import Base, get_db
import services.database
from models import Finding, FindingStatusHistory, FindingControl, AuditLog
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_blflaw.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

@pytest.fixture(autouse=True)
def setup_db(monkeypatch):
    from middleware.rate_limit import _Bucket
    monkeypatch.setattr(_Bucket, "consume", lambda self: True)

    app.dependency_overrides[get_db] = override_get_db
    old_engine = services.database.engine
    services.database.engine = engine
    old_session_local = services.database.SessionLocal
    services.database.SessionLocal = TestingSessionLocal

    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    db.query(Finding).delete()
    db.query(FindingStatusHistory).delete()
    db.query(FindingControl).delete()
    db.query(AuditLog).delete()
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_blflaw.db"):
        try:
            os.remove("./test_blflaw.db")
        except Exception:
            pass

def test_blflaw_lifecycle_and_security_rules():
    from routers.auth import USERS
    USERS["analyst_a@tempris.com"] = {
        "password": bcrypt.hash("pwd_a"),
        "role": "Analyst",
        "name": "Analyst A",
        "tenant_id": "tenantA"
    }
    USERS["analyst_b@tempris.com"] = {
        "password": bcrypt.hash("pwd_b"),
        "role": "Analyst",
        "name": "Analyst B",
        "tenant_id": "tenantB"
    }
    USERS["user_a@tempris.com"] = {
        "password": bcrypt.hash("pwd_user"),
        "role": "User",
        "name": "User A",
        "tenant_id": "tenantA"
    }

    client = TestClient(app)

    # Login analyst A
    resp_login_a = client.post("/api/auth/login", json={"email": "analyst_a@tempris.com", "password": "pwd_a"})
    headers_a = {"Authorization": f"Bearer {resp_login_a.json()['access_token']}"}

    # Login analyst B
    resp_login_b = client.post("/api/auth/login", json={"email": "analyst_b@tempris.com", "password": "pwd_b"})
    headers_b = {"Authorization": f"Bearer {resp_login_b.json()['access_token']}"}

    # Login user A
    resp_login_u = client.post("/api/auth/login", json={"email": "user_a@tempris.com", "password": "pwd_user"})
    headers_u = {"Authorization": f"Bearer {resp_login_u.json()['access_token']}"}

    # 1. Reject unapproved flaw types
    bad_intake = {
        "title": "SQL Injection",
        "description": "SQL injection in search parameter",
        "flaw_type": "SQLI",
        "severity": "high",
        "asset_id": "ASSET-001"
    }
    resp_bad = client.post("/api/blflaw/intake", json=bad_intake, headers=headers_a)
    assert resp_bad.status_code == 422
    assert "Invalid flaw_type" in resp_bad.json()["detail"]

    # 2. Accept approved flaw types + compensating controls (no-patch compensating-control handling)
    good_intake = {
        "title": "IDOR on profile update",
        "description": "User can update other profiles by modifying account ID parameter.",
        "flaw_type": "IDOR",
        "severity": "high",
        "asset_id": "ASSET-001",
        "flow_steps": ["1. Login", "2. Change ID", "3. Submit"],
        "compensating_controls": [
            {"title": "Request Signature Validation", "description": "Verify hash of ID parameter."}
        ]
    }
    resp_good = client.post("/api/blflaw/intake", json=good_intake, headers=headers_a)
    assert resp_good.status_code == 200
    flaw_id = resp_good.json()["id"]

    # Verify compensating control in FindingControl table
    db = TestingSessionLocal()
    ctrl = db.query(FindingControl).filter(FindingControl.finding_id == flaw_id).first()
    assert ctrl is not None
    assert ctrl.title == "Request Signature Validation"
    assert ctrl.layer_type == "compensating"
    db.close()

    # 3. Tenant Isolation: Analyst B cannot view or transition Flaw A
    resp_view_b = client.get("/api/blflaw", headers=headers_b)
    assert len(resp_view_b.json()) == 0

    resp_trans_b = client.post(f"/api/blflaw/{flaw_id}/transition", json={"new_status": "TRIAGED"}, headers=headers_b)
    assert resp_trans_b.status_code == 403

    # 4. Role restrictions: User A (role User) cannot transition Flaw A
    resp_trans_u = client.post(f"/api/blflaw/{flaw_id}/transition", json={"new_status": "TRIAGED"}, headers=headers_u)
    assert resp_trans_u.status_code == 403

    # 5. Invalid transition fails (OPEN -> RESOLVED is illegal, must go through TRIAGED and MITIGATION_PLANNED)
    resp_illegal = client.post(f"/api/blflaw/{flaw_id}/transition", json={"new_status": "RESOLVED"}, headers=headers_a)
    assert resp_illegal.status_code == 409
    assert "Illegal transition" in resp_illegal.json()["detail"]

    # 6. Success transition lifecycle (OPEN -> TRIAGED -> MITIGATION_PLANNED -> RESOLVED -> VERIFIED)
    for next_status in ["TRIAGED", "MITIGATION_PLANNED", "RESOLVED", "VERIFIED"]:
        resp_ok = client.post(f"/api/blflaw/{flaw_id}/transition", json={"new_status": next_status, "notes": f"Moved to {next_status}"}, headers=headers_a)
        assert resp_ok.status_code == 200
        assert resp_ok.json()["current_status"] == next_status
