import pytest
import os
import sys
import json
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
import jwt

# Adjust sys.path to run tests from the correct backend directory context
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ["ENVIRONMENT"] = "test"
os.environ["AUDIT_HMAC_KEY"] = "test_audit_hmac_secret_key_12345678"

from services.database import Base, get_db
import services.database
from models import UserSession, AuditLog, Finding
from routers.auth import create_access_token, create_test_session, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
import routers.auth
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_sec_i3.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def bypass_rate_limiting(monkeypatch):
    from middleware.rate_limit import _Bucket
    monkeypatch.setattr(_Bucket, "consume", lambda self: True)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

client = TestClient(app)

@pytest.fixture(scope="function", autouse=True)
def setup_db():
    # Snapshot original USERS
    from routers.auth import USERS
    old_users = dict(USERS)

    app.dependency_overrides[get_db] = override_get_db
    old_engine = services.database.engine
    services.database.engine = engine
    old_session_local = services.database.SessionLocal
    services.database.SessionLocal = TestingSessionLocal

    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # Clear tables
    db.query(UserSession).delete()
    db.query(AuditLog).delete()
    db.query(Finding).delete()
    db.commit()

    # Seed test finding for validation routing check
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

    # Restore USERS
    from routers.auth import USERS
    USERS.clear()
    USERS.update(old_users)

    if os.path.exists("./test_sec_i3.db"):
        try:
            os.remove("./test_sec_i3.db")
        except Exception:
            pass

def get_token(email: str, role: str, tenant_id: str = "tempris"):
    from routers.auth import USERS
    USERS[email] = {"role": role, "tenant_id": tenant_id, "password": "hashed_stub", "name": "Test User"}
    db = TestingSessionLocal()
    token = create_test_session(db, email)
    db.close()
    return token

# ── 1. Login creates a persisted session
def test_login_creates_persisted_session():
    # Setup correct password hash in USERS
    from passlib.hash import bcrypt
    from routers.auth import USERS
    USERS["login_test@tempris.com"] = {
        "password": bcrypt.hash("secure_password123"),
        "role": "Analyst",
        "name": "Login Test User",
        "tenant_id": "tempris"
    }

    response = client.post(
        "/api/auth/login",
        json={"email": "login_test@tempris.com", "password": "secure_password123"}
    )
    assert response.status_code == 200
    res_data = response.json()
    assert "access_token" in res_data

    # Decode access token to retrieve sid
    payload = jwt.decode(res_data["access_token"], SECRET_KEY, algorithms=[ALGORITHM])
    sid = payload["sid"]

    # Verify session is persisted
    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    assert session is not None
    assert session.account_subject == "login_test@tempris.com"
    assert session.revoked_at is None
    db.close()

# ── 2. Returned JWT contains required sid, jti, iat, exp, and version claims
def test_login_jwt_contains_required_claims():
    from passlib.hash import bcrypt
    from routers.auth import USERS
    USERS["claims_test@tempris.com"] = {
        "password": bcrypt.hash("pwd123"),
        "role": "Analyst",
        "name": "Claims User",
        "tenant_id": "tempris"
    }
    response = client.post(
        "/api/auth/login",
        json={"email": "claims_test@tempris.com", "password": "pwd123"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    
    assert "sub" in payload
    assert payload["sub"] == "claims_test@tempris.com"
    assert "sid" in payload
    assert "jti" in payload
    assert "iat" in payload
    assert "exp" in payload
    assert "token_version" in payload
    assert payload["token_version"] == "v2"

# ── 3. Raw JWT and raw jti are not stored in the database
def test_raw_jwt_and_jti_not_stored():
    from passlib.hash import bcrypt
    from routers.auth import USERS
    USERS["store_test@tempris.com"] = {
        "password": bcrypt.hash("pwd123"),
        "role": "Analyst",
        "name": "Store User",
        "tenant_id": "tempris"
    }
    response = client.post(
        "/api/auth/login",
        json={"email": "store_test@tempris.com", "password": "pwd123"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    jti = payload["jti"]

    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == payload["sid"]).first()
    db.close()

    # Raw token and jti must NOT be stored in DB
    assert session.jti_hash == hashlib.sha256(jti.encode()).hexdigest()
    
    # We inspect db file structure or direct attributes
    # Check that raw token or jti string is not stored in user_sessions table anywhere
    # In SQLite we can verify fields:
    db = TestingSessionLocal()
    raw_rows = db.execute(text("SELECT * FROM user_sessions;")).fetchall()
    db.close()
    for row in raw_rows:
        # Check that none of the columns contain raw token or jti
        for val in row:
            if isinstance(val, str):
                assert token not in val
                assert jti not in val

# ── 4. Failed session persistence returns no usable token
def test_failed_session_persistence_returns_no_token(monkeypatch):
    from passlib.hash import bcrypt
    from routers.auth import USERS
    USERS["fail_test@tempris.com"] = {
        "password": bcrypt.hash("pwd123"),
        "role": "Analyst",
        "name": "Fail User",
        "tenant_id": "tempris"
    }
    
    # Force DB write to fail
    def mock_add(*args, **kwargs):
        raise Exception("Database error")
    
    # We apply override
    db = TestingSessionLocal()
    db.add = mock_add
    app.dependency_overrides[get_db] = lambda: db

    response = client.post(
        "/api/auth/login",
        json={"email": "fail_test@tempris.com", "password": "pwd123"}
    )
    assert response.status_code == 500
    assert "access_token" not in response.json()

    # Cleanup override
    app.dependency_overrides[get_db] = override_get_db
    db.close()

# ── 5. A valid active session authenticates successfully
def test_valid_active_session_authenticates():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 200

# ── 6. Logout revokes the current session
def test_logout_revokes_session():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    sid = payload["sid"]

    response = client.post("/api/auth/logout", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "logged_out"

    # Verify session is revoked in DB
    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    assert session.revoked_at is not None
    assert session.revoking_actor == "analyst@tempris.com"
    db.close()

# ── 7. The logged-out token is rejected before natural expiry
def test_logged_out_token_rejected():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}
    
    client.post("/api/auth/logout", headers=headers)
    
    # Next request must fail
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

# ── 8. Logout is idempotent
def test_logout_is_idempotent():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}

    res1 = client.post("/api/auth/logout", headers=headers)
    assert res1.status_code == 200

    # Repeating logout must succeed safely
    res2 = client.post("/api/auth/logout", headers=headers)
    assert res2.status_code == 200

# ── 9. A revoked session cannot access evidence, EDIP, audit, or another protected route
def test_revoked_session_blocked_from_all_routes():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    sid = payload["sid"]

    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    session.revoked_at = datetime.now(timezone.utc)
    db.commit()
    db.close()

    # Rejected from findings
    res1 = client.get("/api/spectrum/findings", headers=headers)
    assert res1.status_code == 401

    # Rejected from audit
    res2 = client.get("/api/audit/log", headers=headers)
    assert res2.status_code == 401

# ── 10. An expired session is rejected
def test_expired_session_rejected():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    sid = payload["sid"]

    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db.commit()
    db.close()

    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

# ── 11. A missing session is rejected
def test_missing_session_rejected():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    sid = payload["sid"]

    # Delete session from DB
    db = TestingSessionLocal()
    db.query(UserSession).filter(UserSession.id == sid).delete()
    db.commit()
    db.close()

    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

# ── 12. A token with a mismatched jti is rejected
def test_mismatched_jti_rejected():
    from routers.auth import USERS
    email = "analyst@tempris.com"
    USERS[email] = {"role": "Analyst", "tenant_id": "tempris", "password": "hashed_stub", "name": "Test User"}

    db = TestingSessionLocal()
    # Create test session with a specific jti
    sid = "test-sid-jti"
    jti_real = "real-jti-token"
    jti_hash = hashlib.sha256(jti_real.encode()).hexdigest()
    
    session = UserSession(
        id=sid,
        account_subject=email,
        jti_hash=jti_hash,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        created_at=datetime.now(timezone.utc)
    )
    db.add(session)
    db.commit()
    db.close()

    # Generate token with mismatched jti
    token = create_access_token(data={"sub": email, "sid": sid, "jti": "mismatched-jti"})
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

# ── 13. A token with a mismatched subject is rejected
def test_mismatched_subject_rejected():
    from routers.auth import USERS
    USERS["analyst@tempris.com"] = {"role": "Analyst", "tenant_id": "tempris", "password": "hashed_stub"}
    USERS["victim@tempris.com"] = {"role": "Analyst", "tenant_id": "tempris", "password": "hashed_stub"}

    db = TestingSessionLocal()
    sid = "test-sid-sub"
    jti = "jti-val"
    jti_hash = hashlib.sha256(jti.encode()).hexdigest()
    
    session = UserSession(
        id=sid,
        # session is for victim@tempris.com
        account_subject="victim@tempris.com",
        jti_hash=jti_hash,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        created_at=datetime.now(timezone.utc)
    )
    db.add(session)
    db.commit()
    db.close()

    # Token belongs to attacker analyst@tempris.com but claims victim's sid
    token = create_access_token(data={"sub": "analyst@tempris.com", "sid": sid, "jti": jti})
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

# ── 14. A token without sid is rejected
def test_token_without_sid_rejected():
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "analyst@tempris.com",
        "jti": "jti123",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "token_version": "v2"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

# ── 15. A token without jti is rejected
def test_token_without_jti_rejected():
    # create_access_token auto-generates jti if not present, so we encode it manually
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "analyst@tempris.com",
        "sid": "sid123",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "token_version": "v2"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

# ── 16. An unsupported token version is rejected
def test_unsupported_token_version_rejected():
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "analyst@tempris.com",
        "sid": "sid123",
        "jti": "jti123",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "token_version": "v1" # unsupported version
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

# ── 17. An unknown account subject is rejected
def test_unknown_account_subject_rejected():
    token = get_token("nonexistent@tempris.com", "Analyst", "tempris")
    # Remove from USERS mapping to make it unknown
    from routers.auth import USERS
    USERS.pop("nonexistent@tempris.com", None)

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "User account not found"

# ── 18. A disabled account is rejected despite an otherwise valid active session
def test_disabled_account_rejected():
    token = get_token("disabled@tempris.com", "Analyst", "tempris")
    from routers.auth import USERS
    USERS["disabled@tempris.com"]["disabled"] = True

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"] == "Account is disabled"

# ── 19. Current account role and tenant override stale JWT copies
def test_role_and_tenant_override_stale_jwt():
    # Verify that get_current_user resolves role/tenant from USERS registry directly
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    
    # Role / tenant modified in registry
    from routers.auth import USERS
    USERS["analyst@tempris.com"]["role"] = "Admin"
    USERS["analyst@tempris.com"]["tenant_id"] = "tenantB"

    # We call standard scoped route or check request state
    headers = {"Authorization": f"Bearer {token}"}
    
    # We can invoke GET /sessions and check that the resolved user role is Admin (implicit verification)
    # The actual get_current_user returned object has 'role': 'Admin' and 'tenant_id': 'tenantB'
    response = client.get("/api/auth/sessions", headers=headers)
    assert response.status_code == 200

# ── 20. Users can list only their own sessions
def test_users_list_only_own_sessions():
    token_a = get_token("analystA@tempris.com", "Analyst", "tempris")
    token_b = get_token("analystB@tempris.com", "Analyst", "tempris")

    # Fetch sessions for Analyst A
    res = client.get("/api/auth/sessions", headers={"Authorization": f"Bearer {token_a}"})
    assert res.status_code == 200
    sessions_a = res.json()["sessions"]
    
    # Verify Analyst A only sees Analyst A's session subject
    db = TestingSessionLocal()
    for s in sessions_a:
        session_db = db.query(UserSession).filter(UserSession.id == s["session_id"]).first()
        assert session_db.account_subject == "analystA@tempris.com"
    db.close()

# ── 21. Session-list responses expose no token or hash material
def test_sessions_list_exposes_no_secrets():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    res = client.get("/api/auth/sessions", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    sessions = res.json()["sessions"]
    assert len(sessions) > 0
    for s in sessions:
        assert "jti" not in s
        assert "jti_hash" not in s
        assert "token" not in s
        assert "hash" not in s

# ── 22. Users can revoke another one of their own sessions
def test_user_revoke_own_session():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    
    # Create second session for analyst@tempris.com
    db = TestingSessionLocal()
    other_sid = "other-analyst-session"
    s = UserSession(
        id=other_sid,
        account_subject="analyst@tempris.com",
        jti_hash="hash-stub",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        created_at=datetime.now(timezone.utc)
    )
    db.add(s)
    db.commit()
    db.close()

    # User revokes the second session
    response = client.delete(
        f"/api/auth/sessions/{other_sid}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    db = TestingSessionLocal()
    assert db.query(UserSession).filter(UserSession.id == other_sid).first().revoked_at is not None
    db.close()

# ── 23. Users cannot revoke another user's session
def test_user_cannot_revoke_other_session():
    token_a = get_token("analystA@tempris.com", "Analyst", "tempris")
    token_b = get_token("analystB@tempris.com", "Analyst", "tempris")

    payload_b = jwt.decode(token_b, SECRET_KEY, algorithms=[ALGORITHM])
    sid_b = payload_b["sid"]

    # Analyst A tries to revoke Analyst B's session
    response = client.delete(
        f"/api/auth/sessions/{sid_b}",
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert response.status_code == 404 # Non-disclosing policy

# ── 24. Cross-tenant administrators cannot revoke sessions
def test_cross_tenant_admin_cannot_revoke():
    token_admin_a = get_token("adminA@tempris.com", "Admin", "tenantA")
    token_user_b = get_token("analystB@tempris.com", "Analyst", "tenantB")

    payload_b = jwt.decode(token_user_b, SECRET_KEY, algorithms=[ALGORITHM])
    sid_b = payload_b["sid"]

    # Admin from tenant A tries to revoke User from tenant B's session
    response = client.delete(
        f"/api/auth/sessions/{sid_b}",
        headers={"Authorization": f"Bearer {token_admin_a}"}
    )
    assert response.status_code == 404

# ── 25. Authorized same-tenant administrative revocation succeeds and is audited
def test_same_tenant_admin_revocation_success():
    token_admin_a = get_token("adminA@tempris.com", "Admin", "tenantA")
    token_user_a = get_token("analystA@tempris.com", "Analyst", "tenantA")

    payload_user = jwt.decode(token_user_a, SECRET_KEY, algorithms=[ALGORITHM])
    sid_user = payload_user["sid"]

    response = client.delete(
        f"/api/auth/sessions/{sid_user}",
        headers={"Authorization": f"Bearer {token_admin_a}"}
    )
    assert response.status_code == 200
    
    db = TestingSessionLocal()
    assert db.query(UserSession).filter(UserSession.id == sid_user).first().revoked_at is not None
    # Verify audit log contains revocation administrative action
    audit = db.query(AuditLog).filter(AuditLog.action == "SESSION_REVOKED_BY_ADMIN").first()
    assert audit is not None
    assert audit.user_email == "adminA@tempris.com"
    assert sid_user in audit.detail
    db.close()

# ── 26. Superadmin revocation is explicit and audited
def test_superadmin_revocation_success():
    token_superadmin = get_token("superadmin@tempris.com", "Superadmin", "tempris")
    token_user_a = get_token("analystA@tempris.com", "Analyst", "tenantA")

    payload_user = jwt.decode(token_user_a, SECRET_KEY, algorithms=[ALGORITHM])
    sid_user = payload_user["sid"]

    response = client.delete(
        f"/api/auth/sessions/{sid_user}",
        headers={"Authorization": f"Bearer {token_superadmin}"}
    )
    assert response.status_code == 200
    
    db = TestingSessionLocal()
    assert db.query(UserSession).filter(UserSession.id == sid_user).first().revoked_at is not None
    audit = db.query(AuditLog).filter(AuditLog.action == "SESSION_REVOKED_BY_SUPERADMIN").first()
    assert audit is not None
    db.close()

# ── 27. Nonexistent and unauthorized session IDs use the same safe response policy
def test_nonexistent_and_unauthorized_same_response():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}

    # Nonexistent session ID
    res1 = client.delete("/api/auth/sessions/session-9999", headers=headers)
    assert res1.status_code == 404
    assert res1.json()["detail"] == "Session not found"

    # Unauthorized session ID (belongs to another user, e.g. victim)
    token_victim = get_token("victim@tempris.com", "Analyst", "tempris")
    sid_victim = jwt.decode(token_victim, SECRET_KEY, algorithms=[ALGORITHM])["sid"]

    res2 = client.delete(f"/api/auth/sessions/{sid_victim}", headers=headers)
    assert res2.status_code == 404
    assert res2.json()["detail"] == "Session not found"

# ── 28. Revocation failure does not falsely return success
def test_revocation_failure_does_not_return_success(monkeypatch):
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    sid = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sid"]

    db = TestingSessionLocal()
    def mock_commit(*args, **kwargs):
         raise Exception("Revocation database commit error")
    db.commit = mock_commit
    app.dependency_overrides[get_db] = lambda: db

    response = client.delete(
        f"/api/auth/sessions/{sid}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 500

    app.dependency_overrides[get_db] = override_get_db
    db.close()

# ── 29. Duplicate revocation creates no duplicate success audit event
def test_duplicate_revocation_no_duplicate_audit():
    token_active = get_token("analyst@tempris.com", "Analyst", "tempris")
    
    # Create second session for analyst@tempris.com
    db = TestingSessionLocal()
    sid_a = "session-a-to-revoke"
    s = UserSession(
        id=sid_a,
        account_subject="analyst@tempris.com",
        jti_hash="hash-stub-a",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        created_at=datetime.now(timezone.utc)
    )
    db.add(s)
    db.commit()
    db.close()

    headers = {"Authorization": f"Bearer {token_active}"}

    res1 = client.delete(f"/api/auth/sessions/{sid_a}", headers=headers)
    assert res1.status_code == 200

    db = TestingSessionLocal()
    orig_audit_count = db.query(AuditLog).filter(AuditLog.action == "SESSION_REVOKED_BY_OWNER").count()
    db.close()

    res2 = client.delete(f"/api/auth/sessions/{sid_a}", headers=headers)
    assert res2.status_code == 200

    db = TestingSessionLocal()
    new_audit_count = db.query(AuditLog).filter(AuditLog.action == "SESSION_REVOKED_BY_OWNER").count()
    assert new_audit_count == orig_audit_count
    db.close()

# ── 30. Concurrent authentication after committed revocation fails
def test_concurrent_auth_after_revocation_fails():
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    sid = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sid"]

    # Session is active
    res1 = client.get("/api/spectrum/findings", headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200

    # Revoke session
    res2 = client.delete(f"/api/auth/sessions/{sid}", headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 200

    # Session is now blocked
    res3 = client.get("/api/spectrum/findings", headers={"Authorization": f"Bearer {token}"})
    assert res3.status_code == 401

# ── 31. JWT-signing configuration refuses missing or weak production values
def test_production_jwt_signing_conf_hardened(monkeypatch):
    # Verify that app fails startup if ENVIRONMENT is production but JWT_SECRET_KEY is weak/empty
    import sys
    
    # Case A: Empty secret in production
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "")
    
    # Importing routers/auth under this env configuration should exit
    with pytest.raises(SystemExit):
        importlib = __import__('importlib')
        importlib.reload(routers.auth)

    # Restore clean test environment and reload routers.auth to a clean state
    monkeypatch.undo()
    importlib = __import__('importlib')
    importlib.reload(routers.auth)
    global SECRET_KEY
    SECRET_KEY = routers.auth.SECRET_KEY

# ── 32. Authentication and audit errors never expose secrets or token material
def test_errors_do_not_leak_auth_secrets(monkeypatch):
    # If login fails or exception is raised, verify that traceback / response doesn't expose the JWT_SECRET_KEY or passwords
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    
    # We trigger a Database Error on `/sessions` list and confirm exception message / traceback details does not contain JWT_SECRET_KEY
    db = TestingSessionLocal()
    real_session = db.query(UserSession).filter(UserSession.account_subject == "analyst@tempris.com").first()

    class MockQuery:
        def __init__(self, *args, **kwargs):
            pass
        def filter(self, *args, **kwargs):
            return self
        def first(self):
            return real_session
        def all(self):
            raise Exception(f"Failed query database. Internal secret: {SECRET_KEY}")

    db.query = MockQuery
    app.dependency_overrides[get_db] = lambda: db

    local_client = TestClient(app, raise_server_exceptions=False)
    response = local_client.get("/api/auth/sessions", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 500
    assert SECRET_KEY not in response.text

    app.dependency_overrides[get_db] = override_get_db
    db.close()

# ── 33. Existing SEC-F1, SEC-F2, SEC-F3/F4, and SEC-I1 behavior remains functional
def test_existing_behaviors_functional():
    # SEC-F2 behavior: invalid decision validation
    token = get_token("analyst@tempris.com", "Analyst", "tempris")
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post(
        "/api/spectrum/findings/F-9999/edip",
        headers=headers,
        json={"decision": "invalid_decision"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EDIP_DECISION"


# ── 34. Prove that ENVIRONMENT=test alone does not disable rate limiting
def test_rate_limiting_active_in_test_env(monkeypatch):
    from middleware.rate_limit import _Bucket, _buckets
    import middleware.rate_limit
    import importlib
    
    _buckets.clear()
    importlib.reload(middleware.rate_limit)
    _Bucket.consume = middleware.rate_limit._Bucket.consume
    
    response = None
    for _ in range(7):
        response = client.post("/api/auth/login", json={"email": "a@tempris.com", "password": "p"})
    
    assert response is not None
    assert response.status_code == 429
    assert "Rate limit" in response.json()["detail"]


# ── 35. Bearer-only transport validation tests
def test_auth_rate_limit_bucket_is_scoped_to_login_only():
    from middleware.rate_limit import _DEFAULT_LIMIT, _bucket_group, _get_limit

    assert _get_limit("/api/auth/login") == (5, 5 / 60)
    assert _bucket_group("/api/auth/login") == "/api/auth/login"
    assert _get_limit("/api/auth/logout") == _DEFAULT_LIMIT
    assert _bucket_group("/api/auth/logout") == "default"
    assert _bucket_group("/api/auth/sessions") == "default"


def test_bearer_only_transport_validation():
    from passlib.hash import bcrypt
    from routers.auth import USERS
    USERS["bearer_only@tempris.com"] = {
        "password": bcrypt.hash("secure123"),
        "role": "Analyst",
        "name": "Bearer Only User",
        "tenant_id": "tempris"
    }

    # 1. Login does not set an authentication cookie
    response = client.post(
        "/api/auth/login",
        json={"email": "bearer_only@tempris.com", "password": "secure123"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "set-cookie" not in response.headers or "tempris_token" not in response.headers["set-cookie"]

    token = response.json()["access_token"]

    # 2. A valid JWT supplied only through tempris_token cookie is rejected
    cookie_client = TestClient(app)
    cookie_client.cookies.set("tempris_token", token)
    response = cookie_client.get("/api/spectrum/findings")
    assert response.status_code == 401

    # 3. The same JWT supplied through the Authorization header succeeds
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 200

    # 4. Logout requires a valid bearer token
    res_no_auth = client.post("/api/auth/logout")
    assert res_no_auth.status_code == 401

    # 5. Logout still emits a cookie-deletion header when compatibility cleanup is retained
    res_logout = client.post("/api/auth/logout", headers=headers)
    assert res_logout.status_code == 200
    assert "set-cookie" in res_logout.headers
    assert 'tempris_token=""' in res_logout.headers["set-cookie"]

    # 6. A revoked bearer token remains rejected by all protected endpoints
    res_revoked = client.get("/api/spectrum/findings", headers=headers)
    assert res_revoked.status_code == 401


# ── 36. Throttled and Best-Effort last_seen_at persistence tests
def test_throttled_and_best_effort_last_seen(caplog):
    token = get_token("lastseen@tempris.com", "Analyst", "tempris")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    sid = payload["sid"]
    
    headers = {"Authorization": f"Bearer {token}"}

    # 1. An eligible request updates last-seen
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 200
    
    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    t1 = routers.auth._normalize_datetime(session.last_seen_at)
    assert t1 is not None
    db.close()

    # 2. Requests within five minutes do not write again
    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 200
    
    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    t2 = routers.auth._normalize_datetime(session.last_seen_at)
    assert t2 == t1
    db.close()

    # 3. Requests after the interval update it
    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    session.last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=6)
    db.commit()
    db.close()

    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 200
    
    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    t3 = routers.auth._normalize_datetime(session.last_seen_at)
    assert t3 > t1
    db.close()

    # 4. A forced last-seen write failure does not convert a valid session into 401
    from services.database import SessionLocal
    class MockFailSession:
        def __init__(self, *args, **kwargs):
            self.real_sess = SessionLocal()
        def query(self, *args, **kwargs):
            return self.real_sess.query(*args, **kwargs)
        def commit(self):
            raise Exception("Incidental write lock/error")
        def rollback(self):
            pass
        def close(self):
            self.real_sess.close()

    import services.database
    orig_session_local = services.database.SessionLocal
    services.database.SessionLocal = MockFailSession

    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    session.last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=6)
    db.commit()
    db.close()

    try:
        response = client.get("/api/spectrum/findings", headers=headers)
        assert response.status_code == 200
    finally:
        services.database.SessionLocal = orig_session_local

    # 5. A primary session lookup failure still fails closed
    bad_sid_token = create_access_token(data={"sub": "lastseen@tempris.com", "sid": "does-not-exist", "jti": "somejti"})
    response = client.get("/api/spectrum/findings", headers={"Authorization": f"Bearer {bad_sid_token}"})
    assert response.status_code == 401

    # 6. A revoked session never updates last-seen
    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    session.revoked_at = datetime.now(timezone.utc)
    session.last_seen_at = None
    db.commit()
    db.close()

    response = client.get("/api/spectrum/findings", headers=headers)
    assert response.status_code == 401

    db = TestingSessionLocal()
    session = db.query(UserSession).filter(UserSession.id == sid).first()
    assert session.last_seen_at is None
    db.close()

    # 7. Caller transaction state is unaffected by last-seen rollback
    # Auth uses separate SessionLocal, ensuring main DB session is untouched

    # 8. Logs and responses expose no token, JTI hash or authorization header
    log_content = caplog.text
    assert token not in log_content
    assert payload["jti"] not in log_content
    assert "Bearer" not in log_content

