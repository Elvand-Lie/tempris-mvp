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
from models import PartnerOnboarding, Finding, Asset
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_partner.db"
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
    db.query(PartnerOnboarding).delete()
    db.query(Finding).delete()
    db.query(Asset).delete()
    
    # Seed standard initial data for testing
    a1 = Asset(id="old-asset", tenant_id="sandbox_partner_tenant", name="Old Asset")
    f1 = Finding(id="old-finding", tenant_id="sandbox_partner_tenant", finding_type="vulnerability", title="Old Finding")
    db.add(a1)
    db.add(f1)
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_partner.db"):
        try:
            os.remove("./test_partner.db")
        except Exception:
            pass

def test_partner_onboarding_and_sandbox_reset(monkeypatch):
    from routers.auth import USERS
    USERS["partner_admin@tempris.com"] = {
        "password": bcrypt.hash("pwd_partner"),
        "role": "Admin",
        "name": "Partner Admin",
        "tenant_id": "sandbox_partner_tenant"
    }
    USERS["partner_analyst@tempris.com"] = {
        "password": bcrypt.hash("pwd_analyst"),
        "role": "Analyst",
        "name": "Partner Analyst",
        "tenant_id": "sandbox_partner_tenant"
    }
    USERS["other_admin@tempris.com"] = {
        "password": bcrypt.hash("pwd_other"),
        "role": "Admin",
        "name": "Other Admin",
        "tenant_id": "other_tenant"
    }

    client = TestClient(app)
    
    # 1. Login Partner Admin
    resp_login = client.post("/api/auth/login", json={"email": "partner_admin@tempris.com", "password": "pwd_partner"})
    assert resp_login.status_code == 200
    token_p = resp_login.json()["access_token"]
    headers_p = {"Authorization": f"Bearer {token_p}"}

    # Onboard
    onboard_data = {
        "license_verified": True,
        "agreements_signed": True,
        "attendees": ["John Doe", "Jane Smith"],
        "provisioning_status": "completed",
        "role_assigned": "partner-admin",
        "attendance_checkins": ["Day 1", "Day 2"],
        "module_checkpoints": {"module_1": "pass", "module_2": "pass"},
        "pilot_evidence_submitted": True,
        "assessment_result": "PASS_WITH_HONORS",
        "certification_number": "CERT-2026-9921",
        "expiry_date": "2027-07-16T18:00:00Z",
        "renewal_status": "active",
        "release_notes_acknowledged": True
    }
    resp_onboard = client.post("/api/partner/onboard", json=onboard_data, headers=headers_p)
    assert resp_onboard.status_code == 200
    assert resp_onboard.json()["license_verified"] is True
    assert resp_onboard.json()["partner_id"] == "sandbox_partner_tenant"

    # 2. Verify Tenancy Scoping
    resp_login_o = client.post("/api/auth/login", json={"email": "other_admin@tempris.com", "password": "pwd_other"})
    token_o = resp_login_o.json()["access_token"]
    headers_o = {"Authorization": f"Bearer {token_o}"}

    resp_get_o = client.get("/api/partner/onboard/sandbox_partner_tenant", headers=headers_o)
    assert resp_get_o.status_code == 403

    # Partner Admin can see it
    resp_get_p = client.get("/api/partner/onboard/sandbox_partner_tenant", headers=headers_p)
    assert resp_get_p.status_code == 200

    # 3. Sandbox Reset constraints checks
    monkeypatch.setenv("SANDBOX_RESET_ENABLED", "true")
    monkeypatch.setenv("ENVIRONMENT", "training")

    # A. Partner Analyst cannot reset (Analyst role blocked, must be Admin/Superadmin)
    resp_login_analyst = client.post("/api/auth/login", json={"email": "partner_analyst@tempris.com", "password": "pwd_analyst"})
    token_analyst = resp_login_analyst.json()["access_token"]
    headers_analyst = {"Authorization": f"Bearer {token_analyst}"}
    
    resp_reset_analyst = client.post("/api/partner/sandbox-reset", headers=headers_analyst)
    assert resp_reset_analyst.status_code == 403

    # B. Non-sandbox tenant Admin cannot reset (designation check fails)
    resp_reset_other = client.post("/api/partner/sandbox-reset", headers=headers_o)
    assert resp_reset_other.status_code == 400
    assert "Tenant is not authoritatively designated" in resp_reset_other.json()["detail"]

    # C. Production environment rejects reset
    monkeypatch.setenv("ENVIRONMENT", "production")
    resp_reset_prod = client.post("/api/partner/sandbox-reset", headers=headers_p)
    assert resp_reset_prod.status_code == 400
    assert "Sandbox reset is only allowed in training or demo environments" in resp_reset_prod.json()["detail"]

    # D. Test environment (alone) rejects reset
    monkeypatch.setenv("ENVIRONMENT", "test")
    resp_reset_test = client.post("/api/partner/sandbox-reset", headers=headers_p)
    assert resp_reset_test.status_code == 400
    assert "Sandbox reset is only allowed in training or demo environments" in resp_reset_test.json()["detail"]

    # E. Feature flag disabled rejects reset (even in training env)
    monkeypatch.setenv("ENVIRONMENT", "training")
    monkeypatch.setenv("SANDBOX_RESET_ENABLED", "false")
    resp_reset_ff = client.post("/api/partner/sandbox-reset", headers=headers_p)
    assert resp_reset_ff.status_code == 400
    assert "Sandbox reset feature flag is disabled" in resp_reset_ff.json()["detail"]
    
    # Restore environment for success path
    monkeypatch.setenv("ENVIRONMENT", "training")
    monkeypatch.setenv("SANDBOX_RESET_ENABLED", "true")

    # F. Tenant merely named sandbox-* is rejected without authoritative designation
    USERS["sandbox_fake_tenant@tempris.com"] = {
        "password": bcrypt.hash("pwd_fake"),
        "role": "Admin",
        "name": "Fake Tenant Admin",
        "tenant_id": "sandbox_fake_tenant"
    }
    resp_login_fake = client.post("/api/auth/login", json={"email": "sandbox_fake_tenant@tempris.com", "password": "pwd_fake"})
    token_fake = resp_login_fake.json()["access_token"]
    headers_fake = {"Authorization": f"Bearer {token_fake}"}
    resp_reset_fake = client.post("/api/partner/sandbox-reset", headers=headers_fake)
    assert resp_reset_fake.status_code == 400
    assert "Tenant is not authoritatively designated" in resp_reset_fake.json()["detail"]

    # G. partner-admin cannot reset a different sandbox
    resp_reset_diff = client.post("/api/partner/sandbox-reset?target_tenant_id=tenanta", headers=headers_p)
    assert resp_reset_diff.status_code == 403
    assert "cannot reset another tenant" in resp_reset_diff.json()["detail"]

    # H. Ordinary admin cannot reset another tenant
    USERS["ordinary_admin@tempris.com"] = {
        "password": bcrypt.hash("pwd_ord"),
        "role": "Admin",
        "name": "Ordinary Admin",
        "tenant_id": "tenantA"
    }
    resp_login_ord = client.post("/api/auth/login", json={"email": "ordinary_admin@tempris.com", "password": "pwd_ord"})
    token_ord = resp_login_ord.json()["access_token"]
    headers_ord = {"Authorization": f"Bearer {token_ord}"}
    resp_reset_cross = client.post("/api/partner/sandbox-reset?target_tenant_id=tenantB", headers=headers_ord)
    assert resp_reset_cross.status_code == 403

    # I. Internal superadmin reset is explicitly audited and can target another sandbox
    USERS["internal_superadmin@tempris.com"] = {
        "password": bcrypt.hash("pwd_super"),
        "role": "Superadmin",
        "name": "Internal Superadmin",
        "tenant_id": "tempris"
    }
    resp_login_super = client.post("/api/auth/login", json={"email": "internal_superadmin@tempris.com", "password": "pwd_super"})
    token_super = resp_login_super.json()["access_token"]
    headers_super = {"Authorization": f"Bearer {token_super}"}
    
    # Preseed asset for tenantB to verify reset
    db = TestingSessionLocal()
    db.add(Asset(id="old-asset-b", tenant_id="tenantb", name="Old B"))
    db.commit()
    db.close()

    resp_reset_super = client.post("/api/partner/sandbox-reset?target_tenant_id=tenantb", headers=headers_super)
    assert resp_reset_super.status_code == 200

    # Verify tenantb was indeed reset
    db = TestingSessionLocal()
    assets_b = db.query(Asset).filter(Asset.tenant_id == "tenantb").all()
    assert len(assets_b) == 1
    assert assets_b[0].id == "ASSET-tenantb-1"

    # Verify audit contains details and target tenant
    from models import AuditLog
    audit_entry_super = db.query(AuditLog).filter(AuditLog.action == "SANDBOX_RESET", AuditLog.tenant_id == "tempris").first()
    assert audit_entry_super is not None
    assert "tenantb" in audit_entry_super.detail
    db.close()
    
    # J. Authorized sandbox admin can reset own sandbox
    resp_reset = client.post("/api/partner/sandbox-reset", headers=headers_p)
    assert resp_reset.status_code == 200
    assert "Sandbox database reset" in resp_reset.json()["message"]

    db = TestingSessionLocal()
    assets = db.query(Asset).filter(Asset.tenant_id == "sandbox_partner_tenant").all()
    findings = db.query(Finding).filter(Finding.tenant_id == "sandbox_partner_tenant").all()
    
    assert len(assets) == 1
    assert assets[0].id == "ASSET-sandbox_partner_tenant-1"
    assert assets[0].name == "Core Web Portal (Sandbox)"
    
    assert len(findings) == 1
    assert findings[0].id == "F-sandbox_partner_tenant-1"
    assert findings[0].cve == "CVE-2026-9901"
    
    # K. Verify audit contains no credentials or scoring internals
    audit_entry = db.query(AuditLog).filter(AuditLog.action == "SANDBOX_RESET", AuditLog.tenant_id == "sandbox_partner_tenant").first()
    assert audit_entry is not None
    assert "detail" in audit_entry.__dict__
    assert "password" not in audit_entry.detail
    assert "agm" not in audit_entry.detail
    
    db.close()
