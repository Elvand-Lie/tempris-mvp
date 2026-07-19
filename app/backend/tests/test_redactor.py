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
from models import Finding
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_redactor.db"
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
    
    # Seed a finding with tenant_id set
    finding = Finding(
        id="F-9999",
        cve="CVE-2026-9999",
        title="Test Finding",
        vendor="Test Vendor",
        product="Test Product",
        cvss=5.0,
        priority="P2",
        status="unmitigated",
        source="kev",
        tenant_id="tempris",
        raw_inputs={
            "cvss": 5.0,
            "exploitability": 5.0,
            "business_impact": 5.0,
            "asset_criticality": 5.0,
            "threat_actor_activity": 5.0
        }
    )
    db.add(finding)
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_redactor.db"):
        try:
            os.remove("./test_redactor.db")
        except Exception:
            pass

def test_global_redactor_strips_private_fields():
    # Seed user in USERS registry
    from routers.auth import USERS
    USERS["redact_test@tempris.com"] = {
        "password": bcrypt.hash("secure_pwd_123"),
        "role": "Admin",
        "name": "Redact User",
        "tenant_id": "tempris"
    }

    client = TestClient(app)
    
    # 1. Login to get token
    login_data = {
        "email": "redact_test@tempris.com",
        "password": "secure_pwd_123"
    }
    resp_login = client.post("/api/auth/login", json=login_data)
    assert resp_login.status_code == 200
    token = resp_login.json()["access_token"]
    
    # 2. Get findings
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/spectrum/findings", headers=headers)
    assert resp.status_code == 200
    findings = resp.json()["data"]
    
    assert len(findings) > 0
    # Check that no private keys exist in any returned finding
    from services.redactor import PRIVATE_KEYS
    for f in findings:
        for key in PRIVATE_KEYS:
            assert key not in f
            assert key.upper() not in f
            assert key.lower() not in f
            
        # Verify allowlisted properties exist
        assert "id" in f
        assert "cve" in f
        assert "tes_score" in f
        assert "tes_decision" in f


def test_global_redactor_strips_scoring_keys_case_insensitively():
    from services.redactor import redact_private_fields

    result = redact_private_fields({
        "agm": 1.1,
        "DRF": 0.8,
        "TeF": 0.6,
        "nested": {"AGM": 1.2, "safe": "kept"},
    })

    assert result == {"nested": {"safe": "kept"}}
