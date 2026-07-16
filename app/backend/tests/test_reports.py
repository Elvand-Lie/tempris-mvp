import pytest
import os
import sys
import json
import csv
from fastapi.testclient import TestClient
from passlib.hash import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.database import Base, get_db
import services.database
from models import GeneratedReport, Finding, ControlEvidence, AuditLog
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_reports.db"
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
    db.query(GeneratedReport).delete()
    db.query(Finding).delete()
    db.query(ControlEvidence).delete()
    db.query(AuditLog).delete()
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_reports.db"):
        try:
            os.remove("./test_reports.db")
        except Exception:
            pass

def test_reporting_pipeline_and_isolation():
    from routers.auth import USERS
    USERS["reporter_a@tempris.com"] = {
        "password": bcrypt.hash("pwd_a"),
        "role": "Admin",
        "name": "Reporter A",
        "tenant_id": "tenantA"
    }
    USERS["reporter_b@tempris.com"] = {
        "password": bcrypt.hash("pwd_b"),
        "role": "Admin",
        "name": "Reporter B",
        "tenant_id": "tenantB"
    }

    client = TestClient(app)
    
    # Login Reporter A
    resp_login_a = client.post("/api/auth/login", json={"email": "reporter_a@tempris.com", "password": "pwd_a"})
    headers_a = {"Authorization": f"Bearer {resp_login_a.json()['access_token']}"}

    # Login Reporter B
    resp_login_b = client.post("/api/auth/login", json={"email": "reporter_b@tempris.com", "password": "pwd_b"})
    headers_b = {"Authorization": f"Bearer {resp_login_b.json()['access_token']}"}

    # Seed findings & evidence for tenant A and tenant B
    db = TestingSessionLocal()
    f_a = Finding(
        id="F-A1", tenant_id="tenantA", title="Tenant A Finding", vendor="V", product="P",
        cvss=7.5, priority="P1", status="unmitigated", short_description="Desc",
        raw_inputs={"agm": 0.8, "drf": 0.5, "tef": 0.3}
    )
    f_b = Finding(
        id="F-B1", tenant_id="tenantB", title="Tenant B Finding", vendor="V", product="P",
        cvss=8.0, priority="P1", status="unmitigated", short_description="Desc"
    )
    db.add(f_a)
    db.add(f_b)
    
    e_a = ControlEvidence(id=1, tenant_id="tenantA", framework_id="ISO42001", control_id="A.1", filename="ev_a.txt", file_path="/tmp/a.txt")
    e_b = ControlEvidence(id=2, tenant_id="tenantB", framework_id="ISO42001", control_id="A.1", filename="ev_b.txt", file_path="/tmp/b.txt")
    db.add(e_a)
    db.add(e_b)
    
    db.commit()
    db.close()

    # 1. Anomaly check: Reporter A attempts to register report referencing Tenant B's finding -> 400
    register_data_bad = {
        "id": "R-100",
        "report_type": "risk",
        "generator_version": "v1.0",
        "source_finding_ids": ["F-B1"],
        "content_hash": "abc",
        "artifact_location": "/tmp/a.csv"
    }
    resp_reg_bad = client.post("/api/reports/register", json=register_data_bad, headers=headers_a)
    assert resp_reg_bad.status_code == 400
    assert "belongs to a different tenant" in resp_reg_bad.json()["detail"]

    # 2. Reporter A generates report referencing Tenant A finding & evidence -> 200
    gen_data = {
        "report_type": "risk",
        "source_finding_ids": ["F-A1"],
        "source_evidence_ids": ["1"],
        "framework_configuration": {"engagement_id": "ENG-101"}
    }
    resp_gen = client.post("/api/reports/generate", json=gen_data, headers=headers_a)
    assert resp_gen.status_code == 200
    report_manifest = resp_gen.json()["manifest"]
    assert report_manifest["tenant_id"] == "tenantA"
    assert report_manifest["engagement_id"] == "ENG-101"
    
    # 3. Verify file output exists and does NOT leak scoring internals (agm, drf, tef)
    csv_file = report_manifest["artifact_location"]
    assert os.path.exists(csv_file)
    with open(csv_file, "r") as f_csv:
        content = f_csv.read()
        assert "agm" not in content
        assert "drf" not in content
        assert "tef" not in content
        assert "Tenant A Finding" in content
        
    # Clean up generated report file
    if os.path.exists(csv_file):
        try:
            os.remove(csv_file)
        except Exception:
            pass

    # 4. Generate combined client report package (REPORT-C08)
    combined_data = {
        "report_type": "combined",
        "source_finding_ids": ["F-A1"],
        "source_evidence_ids": ["1"],
        "framework_configuration": {"engagement_id": "ENG-101"}
    }
    resp_comb = client.post("/api/reports/generate", json=combined_data, headers=headers_a)
    assert resp_comb.status_code == 200
    comb_manifest = resp_comb.json()["manifest"]
    assert comb_manifest["report_type"] == "combined"
    
    comb_file = comb_manifest["artifact_location"]
    assert os.path.exists(comb_file)
    with open(comb_file, "r") as f_json:
        comb_json_data = json.load(f_json)
        
    assert "sub_reports" in comb_json_data
    assert "risk" in comb_json_data["sub_reports"]
    assert "gap" in comb_json_data["sub_reports"]
    
    # Verify sub-report files exist
    risk_sub_path = comb_json_data["sub_reports"]["risk"]["path"]
    gap_sub_path = comb_json_data["sub_reports"]["gap"]["path"]
    assert os.path.exists(risk_sub_path)
    assert os.path.exists(gap_sub_path)
    
    # Clean up files
    for p in (risk_sub_path, gap_sub_path, comb_file):
        if os.path.exists(p):
            os.remove(p)

    # 5. Verify PDF generation is blocked (documented limitation)
    pdf_data = {
        "report_type": "pdf",
        "source_finding_ids": ["F-A1"],
        "source_evidence_ids": ["1"],
        "framework_configuration": {"engagement_id": "ENG-101"}
    }
    resp_pdf = client.post("/api/reports/generate", json=pdf_data, headers=headers_a)
    assert resp_pdf.status_code == 400
    assert "PDF_GENERATION_BLOCKED" in resp_pdf.json()["detail"]
