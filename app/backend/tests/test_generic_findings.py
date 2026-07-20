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
from models import Finding, FindingRelationship, FindingSource, FindingDisputedClaim, FindingControl
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_generic_findings.db"
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
    
    # Seed findings
    f1 = Finding(
        id="F-1", cve="CVE-2026-0001", title="F1", vendor="V1", cvss=9.0, priority="P0", tenant_id="tenantA", source="kev"
    )
    f2 = Finding(
        id="F-2", cve="CVE-2026-0002", title="F2", vendor="V2", cvss=8.0, priority="P1", tenant_id="tenantA", source="kev"
    )
    f_other = Finding(
        id="F-OTHER", cve="CVE-2026-0003", title="FOther", vendor="VO", cvss=7.0, priority="P1", tenant_id="tenantB", source="kev"
    )
    db.add(f1)
    db.add(f2)
    db.add(f_other)
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_generic_findings.db"):
        try:
            os.remove("./test_generic_findings.db")
        except Exception:
            pass

def test_generic_findings_endpoints():
    from routers.auth import USERS
    USERS["user_a@tempris.com"] = {
        "password": bcrypt.hash("pwd_a"),
        "role": "Analyst",
        "name": "User A",
        "tenant_id": "tenantA"
    }

    client = TestClient(app)
    
    # Login
    resp_login = client.post("/api/auth/login", json={"email": "user_a@tempris.com", "password": "pwd_a"})
    assert resp_login.status_code == 200
    token = resp_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create Relationship
    rel_data = {
        "source_id": "F-1",
        "target_id": "F-2",
        "relationship_type": "CHAIN",
        "metadata_": {"order": 1}
    }
    resp_rel = client.post("/api/spectrum/findings/relationships", json=rel_data, headers=headers)
    assert resp_rel.status_code == 200
    assert resp_rel.json()["source_id"] == "F-1"

    # 2. Prevent cross-tenant relationship creation
    bad_rel_data = {
        "source_id": "F-1",
        "target_id": "F-OTHER",
        "relationship_type": "CHAIN"
    }
    resp_bad = client.post("/api/spectrum/findings/relationships", json=bad_rel_data, headers=headers)
    assert resp_bad.status_code == 404

    # 3. Add Source Freshness
    source_data = {
        "source_id": "SRC-99",
        "publisher": "GovTech",
        "retrieved_at": "2026-07-16T12:00:00",
        "last_verified_at": "2026-07-16T12:00:00",
        "verification_state": "CONFIRMED",
        "expiry_date": "2027-07-16T12:00:00",
        "analyst_notes": "Verified source."
    }
    resp_src = client.post("/api/spectrum/findings/F-1/sources", json=source_data, headers=headers)
    assert resp_src.status_code == 200
    assert resp_src.json()["publisher"] == "GovTech"

    # Get Sources
    resp_get_src = client.get("/api/spectrum/findings/F-1/sources", headers=headers)
    assert resp_get_src.status_code == 200
    assert len(resp_get_src.json()) == 1

    # 4. Add Disputed Claim (evidence state)
    claim_data = {
        "source": "Vendor Advisory",
        "claim_details": "Vendor disputes the CVSS score severity.",
        "disagreement_text": "Claiming score should be 5.0.",
        "verification_state": "DISPUTED"
    }
    resp_claim = client.post("/api/spectrum/findings/F-1/disputed-claims", json=claim_data, headers=headers)
    assert resp_claim.status_code == 200
    assert resp_claim.json()["source"] == "Vendor Advisory"

    # Verify finding verification state updated to DISPUTED
    db = TestingSessionLocal()
    finding = db.query(Finding).filter(Finding.id == "F-1").first()
    assert finding.verification == "DISPUTED"
    db.close()

    # 5. Add Remediation Control
    control_data = {
        "title": "Nginx WAF Filter",
        "description": "Block JCE exploit payload",
        "layer_type": "network",
        "priority": "P0",
        "status": "compliant"
    }
    resp_ctrl = client.post("/api/spectrum/findings/F-1/controls", json=control_data, headers=headers)
    assert resp_ctrl.status_code == 200
    assert resp_ctrl.json()["title"] == "Nginx WAF Filter"

    # Get Controls
    resp_get_ctrl = client.get("/api/spectrum/findings/F-1/controls", headers=headers)
    assert resp_get_ctrl.status_code == 200
    assert len(resp_get_ctrl.json()) == 1
