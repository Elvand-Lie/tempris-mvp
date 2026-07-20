import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
import sys
import os
import time
import ipaddress
import hmac
import hashlib
from concurrent.futures import ThreadPoolExecutor

# Adjust sys.path to run tests from the correct backend directory context
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure test environment variables before importing modules
os.environ["ENVIRONMENT"] = "test"
os.environ["AUDIT_HMAC_KEY"] = "test_audit_hmac_secret_key_12345678"
os.environ["TEMPRIS_TRUSTED_PROXY_CIDRS"] = "192.168.1.0/24,10.0.0.0/16"


from services.database import Base, get_db
from index import app
from models import AuditLog
from routers.audit import (
    verify_audit_integrity,
    append_to_audit_log_db,
    AuditEntry,
    get_audit_hmac_key,
    _compute_v2_hmac,
    seed_audit_log,
)
from routers.auth import create_access_token

# Use a temporary SQLite database for isolated test fixtures
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_audit.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function", autouse=True)
def setup_db():
    from routers.auth import USERS
    old_users = dict(USERS)
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    # Seed the legacy records to test legacy boundary validation
    seed_audit_log(db)
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    
    from routers.auth import USERS
    USERS.clear()
    USERS.update(old_users)
    
    if os.path.exists("./test_audit.db"):
        try:
            os.remove("./test_audit.db")
        except PermissionError:
            pass

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

client = TestClient(app)


def get_token(email: str, role: str):
    from routers.auth import USERS, create_test_session
    if email not in USERS:
        USERS[email] = {"role": role, "tenant_id": "tempris"}
    db = TestingSessionLocal()
    token = create_test_session(db, email)
    db.close()
    return token

# 1. Actor and IP Spoofing Prevention
def test_actor_and_ip_override():
    token = get_token("admin@tempris.com", "Admin")
    # Request from testclient (which is trusted by test rule)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": "192.168.1.100",  # Under trusted proxy range
    }
    payload = {
        "user": "hacker@evil.com",
        "action": "AUTO_TEST_ACTION",
        "module": "EDIP",
        "detail": "Attempting to spoof audit trail",
        "ip_address": "8.8.8.8",
        "metadata": {
            "agent_identity": "test",
            "authority_granted": "test",
            "tool_used": "test",
            "evidence_generated": "test",
            "revocation_path": "test",
            "under_policy_control": True
        }
    }
    response = client.post("/api/audit/log", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["user"] == "admin@tempris.com"  # Spoofer user rejected
    assert data["ip_address"] == "192.168.1.100"  # Spoofer IP rejected, trusted header used

# 2. Sequential context isolation
def test_sequential_requests_isolation():
    token1 = get_token("user1@tempris.com", "Admin")
    token2 = get_token("user2@tempris.com", "Admin")
    
    payload = {
        "action": "TEST_ACTION",
        "module": "SYSTEM",
        "detail": "Sequential check"
    }
    
    res1 = client.post("/api/audit/log", json=payload, headers={"Authorization": f"Bearer {token1}"})
    assert res1.status_code == 200
    assert res1.json()["user"] == "user1@tempris.com"
    
    res2 = client.post("/api/audit/log", json=payload, headers={"Authorization": f"Bearer {token2}"})
    assert res2.status_code == 200
    assert res2.json()["user"] == "user2@tempris.com"

# 3. Concurrent requests isolation
def test_concurrent_requests_isolation():
    emails = [f"user{i}@tempris.com" for i in range(10)]
    tokens = [get_token(email, "Admin") for email in emails]
    
    def fire_request(token):
        res = client.post(
            "/api/audit/log",
            json={"action": "CONCURRENT_ACTION", "module": "SYSTEM", "detail": "Concurrent check"},
            headers={"Authorization": f"Bearer {token}"}
        )
        return res
        
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fire_request, tokens))
        
    for res, email in zip(results, emails):
        assert res.status_code == 200
        assert res.json()["user"] == email

# 4. CIDR Trusted and Untrusted Proxies + Invalid IP format handling
def test_cidr_proxies_validation():
    token = get_token("admin@tempris.com", "Admin")
    
    # CASE A: Request from loopback, Forwarded header from trusted CIDR (192.168.1.5)
    res_trusted = client.post(
        "/api/audit/log",
        json={"action": "TEST_ACTION", "module": "SYSTEM", "detail": "Check trusted proxy"},
        headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "192.168.1.5"}
    )
    assert res_trusted.status_code == 200
    assert res_trusted.json()["ip_address"] == "192.168.1.5"
    
    # CASE B: Request from loopback, Forwarded header has invalid IP address format (malformed)
    res_malformed = client.post(
        "/api/audit/log",
        json={"action": "TEST_ACTION", "module": "SYSTEM", "detail": "Check invalid format"},
        headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "not-an-ip-address"}
    )
    assert res_malformed.status_code == 200
    # Must fallback to peer address safely
    assert res_malformed.json()["ip_address"] == "testclient"

# 5. New records cannot downgrade to legacy hash format
def test_downgrade_prevention(setup_db):
    db = setup_db
    token = get_token("admin@tempris.com", "Admin")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Append a current-version record.
    res1 = client.post("/api/audit/log", json={"action": "V3_EVENT", "module": "SYSTEM", "detail": "Valid v3"}, headers=headers)
    assert res1.status_code == 200
    assert res1.json()["hash"].startswith("v3:")
    
    # Let's verify untouched chain is intact
    res_verify = client.get("/api/audit/verify", headers=headers)
    assert res_verify.json()["intact"] is True
    
    # Append a legacy record after v3; verification must reject the downgrade.
    last_v3 = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last_v3.hash
    
    # Compute legacy plain SHA-256 digest
    legacy_payload = f"LEGACY_ACTIONDetail"
    legacy_hash = hashlib.sha256(f"{prev_hash}{legacy_payload}".encode()).hexdigest()
    
    downgraded_record = AuditLog(
        timestamp=datetime.now(timezone.utc),
        user_email="admin@tempris.com",
        action="LEGACY_ACTION",
        module="SYSTEM",
        detail="Detail",
        ip_address="127.0.0.1",
        metadata_={},
        hash=legacy_hash
    )
    db.add(downgraded_record)
    db.commit()
    
    # Verification must fail because of the downgrade check
    res_verify = client.get("/api/audit/verify", headers=headers)
    assert res_verify.json()["intact"] is False
    assert res_verify.json()["status"] == "TAMPERED"

# 6. A plain SHA-256 digest cannot validate a v3 record.
def test_plain_sha256_cannot_validate_v3(setup_db):
    db = setup_db
    token = get_token("admin@tempris.com", "Admin")
    headers = {"Authorization": f"Bearer {token}"}
    
    res = client.post("/api/audit/log", json={"action": "V3_EVENT", "module": "SYSTEM", "detail": "Valid v3"}, headers=headers)
    assert res.status_code == 200
    
    # Direct database tampering: replace HMAC hash with plain SHA-256
    v3_record = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    v3_record.hash = f"v3:primary:{hashlib.sha256(b'forged').hexdigest()[:52]}"
    db.commit()
    
    # Verification must fail because key is checked via HMAC
    res_verify = client.get("/api/audit/verify", headers=headers)
    assert res_verify.json()["intact"] is False

# 7. Internal system action service principal enforcement
def test_internal_events_principal_check(setup_db):
    db = setup_db
    # Case A: Append with correct service principal format (system:xxx)
    valid_entry = AuditEntry(
        user="system:test_scheduler",
        action="INTERNAL_RUN",
        module="SYSTEM",
        detail="Cron run completed"
    )
    result = append_to_audit_log_db(db, valid_entry)
    assert result["user"] == "system:test_scheduler"
    assert result["ip_address"] == "internal"  # No 127.0.0.1 fabrication
    
    # Case B: Append with invalid service principal (unauthorized / fake user)
    invalid_entry = AuditEntry(
        user="fake_system",
        action="INTERNAL_RUN",
        module="SYSTEM",
        detail="Fake"
    )
    with pytest.raises(ValueError) as excinfo:
        append_to_audit_log_db(db, invalid_entry)
    assert "Internal events must provide an explicit service principal" in str(excinfo.value)

# 8. Seed database idempotency
def test_seed_database_idempotency(setup_db):
    db = setup_db
    # Clear all log database rows
    db.query(AuditLog).delete()
    db.commit()
    
    # First seed on fresh database
    seed_audit_log(db)
    count1 = db.query(AuditLog).count()
    assert count1 > 0
    
    # Second seed on existing seed database
    seed_audit_log(db)
    count2 = db.query(AuditLog).count()
    assert count1 == count2  # No duplicate seed entries created

# 9. No key leaks in logs/responses
def test_no_secrets_in_responses():
    token = get_token("admin@tempris.com", "Admin")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test GET log
    response = client.get("/api/audit/log", headers=headers)
    assert response.status_code == 200
    
    # Check that secrets are not inside response payload
    res_str = response.text.lower()
    assert "hmac" not in res_str
    assert "secret" not in res_str
    assert "key" not in res_str


# 10. Legitimate complete-chain verification passes
def test_legitimate_chain_verification_passes(setup_db):
    db = setup_db
    token = get_token("admin@tempris.com", "Admin")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Add multiple v2 records to legacy database
    for i in range(5):
        res = client.post(
            "/api/audit/log",
            json={"action": f"V2_EVENT_{i}", "module": "SYSTEM", "detail": f"Detail {i}"},
            headers=headers
        )
        assert res.status_code == 200
        
    # Walk and verify the mixed legacy/v2 chain
    res_verify = client.get("/api/audit/verify", headers=headers)
    assert res_verify.status_code == 200
    assert res_verify.json()["intact"] is True
    assert res_verify.json()["status"] == "verified"


def test_audit_tenant_spoofing_prevention(setup_db):
    from routers.auth import USERS
    USERS["userA@tempris.com"] = {"role": "Admin", "tenant_id": "tenantA"}
    
    # Authenticate as userA
    token = get_token("userA@tempris.com", "Admin")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Attempt to spoof tenantB via body payload
    payload = {
        "user": "spoofed@evil.com",
        "action": "TEST_SPOOF",
        "module": "SYSTEM",
        "detail": "detail trying to spoof",
        "metadata": {
            "tenant_id": "tenantB",
            "user": "hacker"
        }
    }
    
    resp = client.post("/api/audit/log", json=payload, headers=headers)
    assert resp.status_code == 200
    
    # Verify DB entry remained strictly tenantA scoped
    db = TestingSessionLocal()
    audit_entry = db.query(AuditLog).filter(AuditLog.action == "TEST_SPOOF").first()
    assert audit_entry is not None
    assert audit_entry.tenant_id == "tenantA"
    assert audit_entry.user_email == "userA@tempris.com"
    db.close()
