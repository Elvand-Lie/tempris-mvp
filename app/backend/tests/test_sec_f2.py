import pytest
import os
import sys
import json
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Adjust sys.path to run tests from the correct backend directory context
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ["ENVIRONMENT"] = "test"
os.environ["AUDIT_HMAC_KEY"] = "test_audit_hmac_secret_key_12345678"

from services.database import Base, get_db
import services.database
from models import Finding, EdipDecision, AuditLog
from routers.auth import create_access_token
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_edip_sec_f2.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

client = TestClient(app)

@pytest.fixture(scope="function", autouse=True)
def setup_db(monkeypatch):
    # Snapshot original USERS
    from routers.auth import USERS
    old_users = dict(USERS)

    import middleware.rate_limit
    monkeypatch.setattr(middleware.rate_limit, "detect_probe_attempt", lambda *args, **kwargs: False)

    app.dependency_overrides[get_db] = override_get_db
    old_engine = services.database.engine
    services.database.engine = engine
    old_session_local = services.database.SessionLocal
    services.database.SessionLocal = TestingSessionLocal

    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # Clean tables
    db.query(Finding).delete()
    db.query(EdipDecision).delete()
    db.query(AuditLog).delete()
    db.commit()

    # Seed test findings
    finding1 = Finding(
        id="F-1234",
        tenant_id="tenantA",
        cve="CVE-2026-9999",
        title="Test KEV Finding",
        vendor="Test Vendor",
        product="Test Product",
        cvss=9.8,
        priority="P0",
        status="unmitigated",
        source="kev",
        cisa_kev=True,
        raw_inputs={
            "cvss": 9.8,
            "exploitability": 8.0,
            "business_impact": 8.0,
            "asset_criticality": 9.0,
            "threat_actor_activity": 7.0
        }
    )
    finding2 = Finding(
        id="F-5678",
        tenant_id="tenantA",
        cve="CVE-2026-8888",
        title="Another KEV Finding",
        vendor="Test Vendor 2",
        product="Test Product 2",
        cvss=7.5,
        priority="P1",
        status="unmitigated",
        source="kev",
        raw_inputs={
            "cvss": 7.5,
            "exploitability": 6.0,
            "business_impact": 5.0,
            "asset_criticality": 5.0,
            "threat_actor_activity": 4.0
        }
    )
    db.add(finding1)
    db.add(finding2)
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

    if os.path.exists("./test_edip_sec_f2.db"):
        try:
            os.remove("./test_edip_sec_f2.db")
        except Exception:
            pass

def get_token(email: str, role: str, tenant_id: str = "tempris"):
    from routers.auth import USERS, create_test_session
    USERS[email] = {"role": role, "tenant_id": tenant_id, "password": "hashed_stub", "name": "Test User"}
    db = TestingSessionLocal()
    token = create_test_session(db, email)
    db.close()
    return token

# ── 1. Every documented valid decision is accepted in an allowed state
def test_valid_decisions_accepted():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}

    valid_decisions = ["mitigate", "accept", "transfer", "ignore"]
    db = TestingSessionLocal()

    for idx, decision in enumerate(valid_decisions):
        finding_id = f"F-VALID-{idx}"
        # Seed fresh finding
        f = Finding(
            id=finding_id,
            tenant_id="tenantA",
            cve=f"CVE-2026-000{idx}",
            title=f"Valid {decision} Finding",
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
        db.add(f)
        db.commit()

        response = client.post(
            f"/api/spectrum/findings/{finding_id}/edip",
            headers=headers,
            json={"decision": decision, "rationale": "Valid test decision"}
        )
        assert response.status_code == 200
        assert response.json()["decision"] == decision
        
        # Verify persistence and status synchronization
        db.refresh(f)
        assert f.status == decision
        
        ed = db.query(EdipDecision).filter(EdipDecision.finding_id == finding_id).first()
        assert ed is not None
        assert ed.decision == decision

    db.close()

# ── 2. An unsupported decision returns 422, not 500
def test_unsupported_decision_returns_422():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "escalate", "rationale": "Invalid decision"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EDIP_DECISION"

# ── 3. A missing decision returns 422
def test_missing_decision_returns_422():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"rationale": "Missing decision"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EDIP_DECISION"

# ── 4. null returns 422
def test_null_decision_returns_422():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": None, "rationale": "Null decision"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EDIP_DECISION"

# ── 5. Empty and whitespace-only values return 422
def test_empty_whitespace_decision_returns_422():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    for val in ["", "   ", "\n", "\t"]:
        response = client.post(
            "/api/spectrum/findings/F-1234/edip",
            headers=headers,
            json={"decision": val, "rationale": "Empty decision"}
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "INVALID_EDIP_DECISION"

# ── 6. Wrong JSON types return 422
def test_wrong_json_types_returns_422():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    for val in [123, True, ["mitigate"], {"val": "mitigate"}]:
        response = client.post(
            "/api/spectrum/findings/F-1234/edip",
            headers=headers,
            json={"decision": val, "rationale": "Invalid type"}
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "INVALID_EDIP_DECISION"

# ── 7. Overlong input returns 422
def test_overlong_input_returns_422():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate" * 10, "rationale": "Overlong decision"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EDIP_DECISION"

    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "a" * 2001}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EDIP_DECISION"

# ── 8. Case and whitespace behavior matches the documented contract
def test_case_and_whitespace_behavior():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "  Mitigate  ", "rationale": "Case test"}
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "mitigate"

# ── 9. A valid decision in an illegal state returns 409
def test_valid_decision_in_illegal_state_returns_409():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1. Transition to terminal state 'ignore'
    res1 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "ignore", "rationale": "Terminal state"}
    )
    assert res1.status_code == 200

    # 2. Try transitioning from 'ignore' to 'mitigate'
    res2 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Reopen attempts"}
    )
    assert res2.status_code == 409
    assert res2.json()["error"]["code"] == "INVALID_STATE_TRANSITION"

# ── 10. Invalid input causes no database mutation
def test_invalid_input_causes_no_mutation():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    db = TestingSessionLocal()
    orig_dec_count = db.query(EdipDecision).count()
    orig_audit_count = db.query(AuditLog).count()
    db.close()

    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "invalid", "rationale": "No mutation"}
    )
    assert response.status_code == 422

    db = TestingSessionLocal()
    assert db.query(EdipDecision).count() == orig_dec_count
    assert db.query(AuditLog).count() == orig_audit_count
    db.close()

# ── 11. Illegal transitions cause no database mutation
def test_illegal_transitions_cause_no_mutation():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Set to terminal ignore
    client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "ignore", "rationale": "Terminal"}
    )

    db = TestingSessionLocal()
    orig_status = db.query(Finding).filter(Finding.id == "F-1234").first().status
    orig_dec = db.query(EdipDecision).filter(EdipDecision.finding_id == "F-1234").first().decision
    db.close()

    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Illegal"}
    )
    assert response.status_code == 409

    db = TestingSessionLocal()
    assert db.query(Finding).filter(Finding.id == "F-1234").first().status == orig_status
    assert db.query(EdipDecision).filter(EdipDecision.finding_id == "F-1234").first().decision == orig_dec
    db.close()

# ── 12. Forced flush failure rolls back all related changes
def test_forced_flush_failure_rolls_back(monkeypatch):
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}

    db = TestingSessionLocal()
    original_flush = db.flush
    def mock_flush(*args, **kwargs):
        raise Exception("Simulated database flush failure")
    
    db.flush = mock_flush
    app.dependency_overrides[get_db] = lambda: db

    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Flush error test"}
    )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "TRANSACTION_FAILED"

    # Reset overrides to query the DB safely
    app.dependency_overrides[get_db] = override_get_db
    db.close()

    db_check = TestingSessionLocal()
    finding = db_check.query(Finding).filter(Finding.id == "F-1234").first()
    assert finding.status == "unmitigated"
    assert db_check.query(EdipDecision).filter(EdipDecision.finding_id == "F-1234").first() is None
    assert db_check.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").first() is None
    db_check.close()

# ── 13. Forced commit failure rolls back all related changes
def test_forced_commit_failure_rolls_back(monkeypatch):
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}

    db = TestingSessionLocal()
    def mock_commit(*args, **kwargs):
        raise Exception("Simulated database commit failure")
    
    db.commit = mock_commit
    app.dependency_overrides[get_db] = lambda: db

    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Commit error test"}
    )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "TRANSACTION_FAILED"

    app.dependency_overrides[get_db] = override_get_db
    db.close()

    db_check = TestingSessionLocal()
    finding = db_check.query(Finding).filter(Finding.id == "F-1234").first()
    assert finding.status == "unmitigated"
    assert db_check.query(EdipDecision).filter(EdipDecision.finding_id == "F-1234").first() is None
    assert db_check.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").first() is None
    db_check.close()

# ── 14. A failed operation creates no success audit event
def test_failed_operation_creates_no_success_audit():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}

    # Transition failure (409)
    client.post("/api/spectrum/findings/F-1234/edip", headers=headers, json={"decision": "ignore", "rationale": "Terminal"})
    
    db = TestingSessionLocal()
    orig_audit_count = db.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").count()
    db.close()

    res = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Illegal reopen"}
    )
    assert res.status_code == 409

    db = TestingSessionLocal()
    assert db.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").count() == orig_audit_count
    db.close()

# ── 15. A successful operation records the correct actor, tenant, target and outcome
def test_successful_operation_records_correct_details():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Audited mitigation"}
    )
    assert response.status_code == 200

    db = TestingSessionLocal()
    audit = db.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").first()
    assert audit is not None
    assert audit.user_email == "analyst@tempris.com"
    assert "Applied 'mitigate' to F-1234" in audit.detail
    db.close()

# ── 16. Unauthorized users cannot modify the decision
def test_unauthorized_users_blocked():
    token = get_token("viewer@tempris.com", "Viewer", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Unauthorized"}
    )
    assert response.status_code == 403

# ── 17. Cross-tenant users cannot modify the decision
def test_cross_tenant_users_blocked():
    token_a = get_token("analystA@tempris.com", "Analyst", "tenantA")
    token_b = get_token("analystB@tempris.com", "Analyst", "tenantB")

    # 1. Tenant A records a decision
    res1 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"decision": "mitigate", "rationale": "Tenant A decision"}
    )
    assert res1.status_code == 200

    # 2. Tenant B tries to overwrite/modify it -> should return 404 safely concealing
    res2 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers={"Authorization": f"Bearer {token_b}"},
        json={"decision": "accept", "rationale": "Tenant B modification"}
    )
    assert res2.status_code == 404

# ── 18. Missing and concealed records follow the established safe response policy
def test_missing_and_concealed_records():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Missing finding ID F-9999
    response = client.post(
        "/api/spectrum/findings/F-9999/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Concealed"}
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"

# ── 19. Repeating a decision follows the selected idempotency policy
def test_idempotent_success():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}

    # 1st attempt
    res1 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Idempotent"}
    )
    assert res1.status_code == 200

    db = TestingSessionLocal()
    orig_dec_id = db.query(EdipDecision).filter(EdipDecision.finding_id == "F-1234").first().id
    orig_audit_count = db.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").count()
    db.close()

    # 2nd attempt
    res2 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Idempotent"}
    )
    assert res2.status_code == 200

    db = TestingSessionLocal()
    assert db.query(EdipDecision).filter(EdipDecision.finding_id == "F-1234").first().id == orig_dec_id
    assert db.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").count() == orig_audit_count
    db.close()

# ── 20. Retrying does not duplicate audit, history, report or notification records
def test_retry_no_duplicate_records():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}

    res1 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "No duplicates"}
    )
    assert res1.status_code == 200

    db = TestingSessionLocal()
    orig_audit_count = db.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").count()
    db.close()

    res2 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "No duplicates"}
    )
    assert res2.status_code == 200

    db = TestingSessionLocal()
    assert db.query(AuditLog).filter(AuditLog.action == "EDIP_DECISION").count() == orig_audit_count
    db.close()

# ── 21. Database and exception details never appear in responses
def test_database_exceptions_sanitized(monkeypatch):
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}

    db = TestingSessionLocal()
    def mock_commit(*args, **kwargs):
        raise Exception("OperationalError: (sqlite3.OperationalError) database is locked")
    db.commit = mock_commit
    app.dependency_overrides[get_db] = lambda: db

    response = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Database lock"}
    )
    assert response.status_code == 500
    # Confirm SQL specifics are hidden
    assert "sqlite3.OperationalError" not in response.text
    assert "database is locked" not in response.text
    assert response.json()["error"]["code"] == "TRANSACTION_FAILED"

    app.dependency_overrides[get_db] = override_get_db
    db.close()

# ── 22. Existing legitimate EDIP behavior remains functional
def test_legitimate_edip_behavior_functional():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Retrieve findings list, ensure auto classification and persisted overlay still work
    res1 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "rationale": "Legacy behavior"}
    )
    assert res1.status_code == 200

    res2 = client.get("/api/spectrum/findings", headers=headers)
    assert res2.status_code == 200
    findings = res2.json()["data"]
    test_finding = next((f for f in findings if f["id"] == "F-1234"), None)
    assert test_finding is not None
    assert test_finding["edip_decision"] == "mitigate"
    assert test_finding["edip_rationale"] == "Legacy behavior"
    assert test_finding["auto_classification"]["decision"] == "fix"  # CVSS 9.8 critical

# ── 23. Regression test: invalid decision types or structure do not return HTTP 500
def test_regression_invalid_decision_fixed():
    token = get_token("analyst@tempris.com", "Analyst", "tenantA")
    headers = {"Authorization": f"Bearer {token}"}

    # Case 1: overlong input
    res1 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "A" * 100, "rationale": "Overlong"}
    )
    assert res1.status_code == 422
    assert res1.json()["error"]["code"] == "INVALID_EDIP_DECISION"

    # Case 2: unexpected additional keys
    res2 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json={"decision": "mitigate", "evil_key": "injected"}
    )
    assert res2.status_code == 422
    assert res2.json()["error"]["code"] == "INVALID_EDIP_DECISION"

    # Case 3: wrong JSON structure (array instead of object)
    res3 = client.post(
        "/api/spectrum/findings/F-1234/edip",
        headers=headers,
        json=[{"decision": "mitigate"}]
    )
    assert res3.status_code == 422
    assert res3.json()["error"]["code"] == "INVALID_EDIP_DECISION"
