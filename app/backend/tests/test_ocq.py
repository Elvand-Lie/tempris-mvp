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
from models import OperationsChangeTicket, AuditLog
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_ocq.db"
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
    db.query(OperationsChangeTicket).delete()
    db.query(AuditLog).delete()
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_ocq.db"):
        try:
            os.remove("./test_ocq.db")
        except Exception:
            pass

def test_ocq_ticket_flow_and_two_man_rule():
    from routers.auth import USERS
    USERS["user_a@tempris.com"] = {
        "password": bcrypt.hash("pwd_a"),
        "role": "Admin",
        "name": "User A",
        "tenant_id": "tenantA"
    }
    USERS["user_b@tempris.com"] = {
        "password": bcrypt.hash("pwd_b"),
        "role": "Admin",
        "name": "User B",
        "tenant_id": "tenantA"
    }

    client = TestClient(app)
    
    # 1. Login User A
    resp_login_a = client.post("/api/auth/login", json={"email": "user_a@tempris.com", "password": "pwd_a"})
    token_a = resp_login_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 2. Login User B
    resp_login_b = client.post("/api/auth/login", json={"email": "user_b@tempris.com", "password": "pwd_b"})
    token_b = resp_login_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Create change ticket
    ticket_data = {
        "title": "Upgrade PostgreSQL to v16",
        "description": "Perform database upgrade during maintenance window.",
        "runbook_reference": "RB-992",
        "backup_required": True,
        "rollback_plan": "Restore snapshot."
    }
    resp_create = client.post("/api/ocq/tickets", json=ticket_data, headers=headers_a)
    assert resp_create.status_code == 200
    ticket_id = resp_create.json()["id"]

    # Try to approve before preflight (fails)
    resp_app_fail = client.post(f"/api/ocq/tickets/{ticket_id}/approve", headers=headers_b)
    assert resp_app_fail.status_code == 400
    assert "preflight check" in resp_app_fail.json()["detail"]

    # Run preflight check
    resp_pre = client.post(f"/api/ocq/tickets/{ticket_id}/preflight", headers=headers_a)
    assert resp_pre.status_code == 200
    assert resp_pre.json()["status"] == "success"

    # Try to approve own ticket (fails due to two-man rule)
    resp_app_own = client.post(f"/api/ocq/tickets/{ticket_id}/approve", headers=headers_a)
    assert resp_app_own.status_code == 400
    assert "Two-man rule" in resp_app_own.json()["detail"]

    # Approve via User B (succeeds)
    resp_app_ok = client.post(f"/api/ocq/tickets/{ticket_id}/approve", headers=headers_b)
    assert resp_app_ok.status_code == 200
    assert resp_app_ok.json()["status"] == "APPROVED"

    # Execute
    exec_data = {
        "evidence_path": "s3://tempris-ops/upgrade.log",
        "post_verification_template": "All services verified online."
    }
    resp_exec = client.post(f"/api/ocq/tickets/{ticket_id}/execute", json=exec_data, headers=headers_a)
    assert resp_exec.status_code == 200
    assert resp_exec.json()["status"] == "EXECUTED"
