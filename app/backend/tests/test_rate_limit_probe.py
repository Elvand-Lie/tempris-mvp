import pytest
import os
import sys
import time
from fastapi.testclient import TestClient
from passlib.hash import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.database import Base, get_db
import services.database
from models import AuditLog
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_rate_limit_probe.db"
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
    # Do NOT monkeypatch rate limiter consume so we can test the middleware!
    # Instead, we will simulate client IPs or bypass IP limits by using separate IPs/endpoints if needed, 
    # but wait, the default IP limit is 100/min, so we won't exceed it with 6 requests!
    # So we do not need to mock bucket consume!
    
    app.dependency_overrides[get_db] = override_get_db
    old_engine = services.database.engine
    services.database.engine = engine
    old_session_local = services.database.SessionLocal
    services.database.SessionLocal = TestingSessionLocal

    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    db.query(AuditLog).delete()
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_rate_limit_probe.db"):
        try:
            os.remove("./test_rate_limit_probe.db")
        except Exception:
            pass

def test_structured_probe_detection():
    from routers.auth import USERS
    USERS["probe_user@tempris.com"] = {
        "password": bcrypt.hash("pwd_probe"),
        "role": "Admin",
        "name": "Probe User",
        "tenant_id": "tenantA"
    }

    client = TestClient(app)
    
    # Login
    resp_login = client.post("/api/auth/login", json={"email": "probe_user@tempris.com", "password": "pwd_probe"})
    token = resp_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Reset probe windows
    from middleware.rate_limit import _probe_windows
    _probe_windows.clear()

    # Generate 6 requests with at least 4 variants of payloads (rounding)
    payloads = [
        {"agm": 0.1, "drf": 0.5, "tef": 0.2},
        {"agm": 0.2, "drf": 0.5, "tef": 0.2},
        {"agm": 0.3, "drf": 0.5, "tef": 0.2},
        {"agm": 0.4, "drf": 0.5, "tef": 0.2},
        {"agm": 0.5, "drf": 0.5, "tef": 0.2},
        {"agm": 0.6, "drf": 0.5, "tef": 0.2}
    ]

    blocked = False
    for i, p in enumerate(payloads):
        # We call an endpoint starting with /api/spectrum (e.g. /api/spectrum/findings/relationships)
        # using POST so it triggers the structured probe filter
        resp = client.post("/api/spectrum/findings/relationships", json={
            "source_id": f"F-SRC-{i}",
            "target_id": f"F-TGT-{i}",
            "relationship_type": "CHAIN",
            "metadata_": p
        }, headers=headers)
        
        if resp.status_code == 429 and resp.headers.get("X-Tempris-Block") == "PROBE_DETECTION":
            blocked = True
            break
            
    assert blocked is True
    
    # Check that audit log has been updated
    db = TestingSessionLocal()
    audit = db.query(AuditLog).filter(AuditLog.action == "STRUCTURED_PROBE_DETECTED").first()
    assert audit.user_email == "system:rate_limiter"
    assert "probe_user@tempris.com" in audit.detail
    db.close()
