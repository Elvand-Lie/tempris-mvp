import pytest
import os
import sys
import json
from fastapi.testclient import TestClient
from passlib.hash import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.database import Base, get_db
import services.database
from models import Finding, FindingRelationship, FindingSource, FindingControl
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_threats.db"
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
    db.query(FindingRelationship).delete()
    db.query(FindingSource).delete()
    db.query(FindingControl).delete()
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_threats.db"):
        try:
            os.remove("./test_threats.db")
        except Exception:
            pass

def test_threat_pack_importer_and_rollback():
    from routers.auth import USERS
    USERS["threat_admin@tempris.com"] = {
        "password": bcrypt.hash("pwd_admin"),
        "role": "Admin",
        "name": "Threat Admin",
        "tenant_id": "tempris"
    }

    client = TestClient(app)
    
    # Login Admin
    resp_login = client.post("/api/auth/login", json={"email": "threat_admin@tempris.com", "password": "pwd_admin"})
    assert resp_login.status_code == 200
    token = resp_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Load JCE fixture data
    with open("fixtures/threat_packs/jce.json", "r") as f:
        pack_data = json.load(f)

    # 1. Dry Run Import
    resp_dry = client.post("/api/threats/import?dry_run=true", json=pack_data, headers=headers)
    assert resp_dry.status_code == 200
    assert resp_dry.json()["status"] == "dry_run_success"
    assert resp_dry.json()["findings_to_import"] == 1

    # Verify no findings in DB
    db = TestingSessionLocal()
    assert db.query(Finding).count() == 0
    db.close()

    # 2. Real Import
    resp_real = client.post("/api/threats/import?dry_run=false", json=pack_data, headers=headers)
    assert resp_real.status_code == 200
    assert resp_real.json()["status"] == "success"
    assert resp_real.json()["imported_findings"] == 1

    # Verify finding, source, control in DB
    db = TestingSessionLocal()
    f_db = db.query(Finding).filter(Finding.id == "F-JCE-01").first()
    assert f_db is not None
    assert f_db.cve == "CVE-2026-48907"
    assert f_db.priority == "P0"

    src_db = db.query(FindingSource).filter(FindingSource.finding_id == "F-JCE-01").all()
    assert len(src_db) == 1
    assert src_db[0].source_id == "SRC-JCE-01"

    ctrl_db = db.query(FindingControl).filter(FindingControl.finding_id == "F-JCE-01").all()
    assert len(ctrl_db) == 1
    assert ctrl_db[0].title == "Nginx JCE WAF Filtering Rule"
    db.close()

    # 3. Idempotent Import (Deduplication check)
    resp_re_import = client.post("/api/threats/import?dry_run=false", json=pack_data, headers=headers)
    assert resp_re_import.status_code == 200
    assert resp_re_import.json()["imported_findings"] == 0  # Deduplicated and skipped/updated

    # 4. Rollback Threat Pack
    resp_rollback = client.post("/api/threats/rollback?pack_name=jce&version=1.0.0", headers=headers)
    assert resp_rollback.status_code == 200
    assert resp_rollback.json()["status"] == "success"
    assert resp_rollback.json()["deleted_records"] == 1

    # Verify deleted from DB
    db = TestingSessionLocal()
    assert db.query(Finding).count() == 0
    assert db.query(FindingSource).count() == 0
    assert db.query(FindingControl).count() == 0
    db.close()
