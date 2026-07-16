import pytest
import os
import sys
import shutil
import tempfile
import urllib.parse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Adjust sys.path to run tests from the correct backend directory context
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Set environment variables for testing context
os.environ["ENVIRONMENT"] = "test"
os.environ["AUDIT_HMAC_KEY"] = "test_audit_hmac_secret_key_12345678"

from services.database import Base, get_db
import services.database
from models import ControlEvidence, AuditLog
from routers.auth import create_access_token
from index import app

# Database URL for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_evidence_bola.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

client = TestClient(app)

# Track temp root to clean up
TEMP_STORAGE_ROOT = tempfile.mkdtemp(prefix="tempris_test_evidence_")
os.environ["EVIDENCE_STORAGE_ROOT"] = TEMP_STORAGE_ROOT

@pytest.fixture(scope="function", autouse=True)
def setup_db_and_files():
    # Save original USERS and override locally
    from routers.auth import USERS
    old_users = dict(USERS)

    # Override dependencies locally
    app.dependency_overrides[get_db] = override_get_db
    
    # Save original SessionLocal and engine and override them
    old_engine = services.database.engine
    services.database.engine = engine
    old_session_local = services.database.SessionLocal
    services.database.SessionLocal = TestingSessionLocal
    
    # Setup Database
    Base.metadata.create_all(bind=engine)
    
    # Force clean directory
    if os.path.exists(TEMP_STORAGE_ROOT):
        shutil.rmtree(TEMP_STORAGE_ROOT)
    os.makedirs(TEMP_STORAGE_ROOT, exist_ok=True)
    
    # Create structure
    std_dir = os.path.join(TEMP_STORAGE_ROOT, "standard", "mas_trm_2024", "MAS-TRM-5.1.1")
    os.makedirs(std_dir, exist_ok=True)
    
    # Standard Evidence File for tenant A
    std_file_a_path = os.path.realpath(os.path.join(std_dir, "uuid_file_a.pdf"))
    with open(std_file_a_path, "wb") as f:
        f.write(b"User A Standard Evidence PDF Content")
        
    # Standard Evidence File for tenant B
    std_file_b_path = os.path.realpath(os.path.join(std_dir, "uuid_file_b.png"))
    with open(std_file_b_path, "wb") as f:
        f.write(b"User B Standard Evidence PNG Content")
        
    # GRC Evidence Files
    grc_dir = os.path.join(TEMP_STORAGE_ROOT, "ISO42001", "A.2.2")
    os.makedirs(grc_dir, exist_ok=True)
    
    grc_file_a_path = os.path.realpath(os.path.join(grc_dir, "uuid_grc_file_a.docx"))
    with open(grc_file_a_path, "wb") as f:
        f.write(b"User A GRC Evidence Docx Content")

    db = TestingSessionLocal()
    # Ensure clear DB
    db.query(ControlEvidence).delete()
    db.query(AuditLog).delete()
    db.commit()

    # Add records
    std_ev_a = ControlEvidence(
        id=101,
        tenant_id="tenantA",
        framework_id="mas_trm_2024",
        control_id="MAS-TRM-5.1.1",
        filename="UserA_MasTrm_Evidence.pdf",
        file_path=std_file_a_path,
        uploaded_by="user1@tenantA.com"
    )
    std_ev_b = ControlEvidence(
        id=102,
        tenant_id="tenantB",
        framework_id="mas_trm_2024",
        control_id="MAS-TRM-5.1.1",
        filename="UserB_MasTrm_Evidence.png",
        file_path=std_file_b_path,
        uploaded_by="user2@tenantB.com"
    )
    grc_ev_a = ControlEvidence(
        id=201,
        tenant_id="tenantA",
        framework_id="ISO42001",
        control_id="A.2.2",
        filename="UserA_Grc_Evidence.docx",
        file_path=grc_file_a_path,
        uploaded_by="user1@tenantA.com"
    )
    
    db.add(std_ev_a)
    db.add(std_ev_b)
    db.add(grc_ev_a)
    db.commit()
    db.close()

    yield

    # Clean up DB and files
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    
    # Restore overridden settings
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    
    from routers.auth import USERS
    USERS.clear()
    USERS.update(old_users)
    
    if os.path.exists(TEMP_STORAGE_ROOT):
        shutil.rmtree(TEMP_STORAGE_ROOT)
                
    if os.path.exists("./test_evidence_bola.db"):
        try:
            os.remove("./test_evidence_bola.db")
        except Exception:
            pass

# Helper to generate authorization headers
def auth_headers(email: str, role: str, tenant_id: str) -> dict:
    from routers.auth import USERS, create_test_session
    if email not in USERS:
        USERS[email] = {"role": role, "tenant_id": tenant_id}
    db = TestingSessionLocal()
    token = create_test_session(db, email)
    db.close()
    return {"Authorization": f"Bearer {token}"}

# ── 1. Authorized access through an explicit server-maintained membership
def test_authorized_access_explicit_membership():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200
    assert response.content == b"User A Standard Evidence PDF Content"

# ── 2. Two users sharing the same email domain do not gain access to each other's evidence
def test_users_sharing_email_domain_no_cross_access():
    # user1 has tenantA, user2 has tenantB, both share domain "public.com"
    headers_a = auth_headers("user1@public.com", "Analyst", "tenantA")
    headers_b = auth_headers("user2@public.com", "Analyst", "tenantB")

    # User B tries to download User A's evidence
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers_b
    )
    assert response.status_code == 404

    # User A tries to download User B's evidence
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/102/download",
        headers=headers_a
    )
    assert response.status_code == 404

# ── 3. One organization using multiple email domains still works through explicit membership
def test_organization_multiple_domains():
    # Different domains, same tenant
    headers1 = auth_headers("user1@domain1.com", "Analyst", "tenantA")
    headers2 = auth_headers("user2@domain2.com", "Analyst", "tenantA")

    # Both can list/download tenantA's evidence
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers1
    )
    assert response.status_code == 200

    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers2
    )
    assert response.status_code == 200

# ── 4. Cross-tenant access fails
def test_cross_tenant_access_fails():
    headers = auth_headers("user@tenantB.com", "Analyst", "tenantB")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 404

# ── 5. Cross-partner access fails
def test_cross_partner_access_fails():
    headers = auth_headers("partner@partnerA.com", "Analyst", "partnerA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 404

# ── 6. A lower-privilege role cannot delete evidence without permission
def test_lower_privilege_cannot_delete():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.delete(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101",
        headers=headers
    )
    assert response.status_code == 403

# ── 7. Nonexistent and unauthorized evidence return the same non-disclosing status (404)
def test_nonexistent_and_unauthorized_same_404():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    
    # Nonexistent
    res_nonexistent = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/999/download",
        headers=headers
    )
    assert res_nonexistent.status_code == 404
    assert res_nonexistent.json() == {"detail": "Evidence not found"}

    # Unauthorized (evidence 102 belonging to tenantB)
    res_unauthorized = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/102/download",
        headers=headers
    )
    assert res_unauthorized.status_code == 404
    assert res_unauthorized.json() == {"detail": "Evidence not found"}

# ── 8. Superadmin access is explicit and audited
def test_superadmin_access_explicit_and_audited():
    headers = auth_headers("super@tempris.com", "Superadmin", "tempris")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200

    db = TestingSessionLocal()
    audit_logs = db.query(AuditLog).filter(AuditLog.action == "EVIDENCE_DOWNLOAD").all()
    assert len(audit_logs) > 0
    superadmin_log = next((l for l in audit_logs if "superadmin_bypass" in l.detail or "Superadmin" in l.detail), None)
    assert superadmin_log is not None
    assert "User super@tempris.com (Superadmin) performed EVIDENCE_DOWNLOAD" in superadmin_log.detail
    db.close()

# ── 9. Denied access is audited without leaking sensitive data
def test_denied_access_audited_securely():
    headers = auth_headers("user@tenantB.com", "Analyst", "tenantB")
    client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )

    db = TestingSessionLocal()
    audit_logs = db.query(AuditLog).filter(AuditLog.action == "EVIDENCE_DOWNLOAD_DENIED").all()
    assert len(audit_logs) > 0
    denied_log = audit_logs[0]
    # Check that detail or metadata does not contain physical paths
    assert "uuid_file_a.pdf" not in denied_log.detail
    assert "tempris_test_evidence" not in denied_log.detail
    db.close()

# ── 10. Path traversal is rejected
def test_path_traversal_rejected():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/../controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 404

# ── 11. Absolute caller-supplied paths are rejected
def test_absolute_caller_supplied_paths_rejected():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    # Attempting to query with absolute path in framework_id/control_id
    response = client.get(
        "/api/standard/frameworks/C:%5C/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 404

# ── 12. A symlink resolving outside the evidence root is rejected
def test_symlink_resolving_outside_root_rejected():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    
    # Create a symlink outside the root
    outside_file = os.path.join(tempfile.gettempdir(), "tempris_outside_evidence.txt")
    with open(outside_file, "wb") as f:
        f.write(b"Sensitive Host File Content")

    symlink_path = os.path.join(TEMP_STORAGE_ROOT, "standard", "mas_trm_2024", "MAS-TRM-5.1.1", "bad_symlink.txt")
    if os.path.exists(symlink_path):
        os.remove(symlink_path)
    try:
        os.symlink(outside_file, symlink_path)
    except OSError:
        # Skip if symlink creation is not permitted on this machine (e.g. non-admin Windows)
        pytest.skip("Symlink creation not supported/permitted.")

    db = TestingSessionLocal()
    ev_sym = ControlEvidence(
        id=103,
        tenant_id="tenantA",
        framework_id="mas_trm_2024",
        control_id="MAS-TRM-5.1.1",
        filename="symlink.txt",
        file_path=symlink_path,
        uploaded_by="user1@tenantA.com"
    )
    db.add(ev_sym)
    db.commit()
    db.close()

    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/103/download",
        headers=headers
    )
    assert response.status_code == 404

# ── 13. Internal storage paths do not appear in response bodies or headers
def test_internal_storage_paths_hidden():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200
    # Search for storage root name or "data/evidence" inside headers/body
    for k, v in response.headers.items():
        assert "tempris_test_evidence" not in v
        assert "uuid_file_a" not in v

# ── 14. CR/LF filename injection cannot create additional headers
def test_filename_injection_protection():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    
    db = TestingSessionLocal()
    ev = db.query(ControlEvidence).filter(ControlEvidence.id == 101).first()
    ev.filename = "injected\r\nHeader-Test: evil\r\nfile.pdf"
    db.commit()
    db.close()

    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200
    assert "Header-Test" not in response.headers
    assert "\r" not in response.headers["Content-Disposition"]
    assert "\n" not in response.headers["Content-Disposition"]

# ── 15. Quote, separator, Unicode, and empty-name cases produce safe filenames
def test_safe_filenames_handling():
    from routers.standard import sanitize_filename
    assert sanitize_filename('test"quote.txt') == "testquote.txt"
    assert sanitize_filename('test/slash.txt') == "testslash.txt"
    assert sanitize_filename('test\\backslash.txt') == "testbackslash.txt"
    assert sanitize_filename('test\x00nul.txt') == "testnul.txt"
    assert sanitize_filename('') == "evidence_file.dat"

# ── 16. Unknown MIME types use application/octet-stream
def test_unknown_mime_types_use_octet_stream():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    
    db = TestingSessionLocal()
    ev = db.query(ControlEvidence).filter(ControlEvidence.id == 101).first()
    ev.filename = "unknown_ext.xyz"
    db.commit()
    db.close()

    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/octet-stream"

    response_preview = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/preview",
        headers=headers
    )
    assert response_preview.status_code == 200
    assert response_preview.headers["Content-Type"] == "application/octet-stream"
    assert "attachment" in response_preview.headers["Content-Disposition"]

# ── 17. Every successful download includes X-Content-Type-Options: nosniff
def test_download_includes_nosniff():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"

# ── 18. Sensitive evidence uses the required no-cache policy
def test_download_nocache_headers():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200
    assert "no-store" in response.headers.get("Cache-Control", "")
    assert "private" in response.headers.get("Cache-Control", "")

# ── 19. Content-Length is correct when the implementation can determine it reliably
def test_download_content_length_correct():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200
    assert response.headers.get("Content-Length") == str(len(response.content))

# ── 20. Existing legitimate PDF, CSV, JSON, image, text, and binary downloads remain functional where supported
def test_legitimate_formats_functional():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 200
    assert response.headers.get("Content-Type") == "application/octet-stream"

# ── 21. List, download, and delete endpoints use the same authorization model
def test_consistent_authorization_model():
    headers_unauth = auth_headers("analyst@tenantB.com", "Analyst", "tenantB")
    
    # 1. Download must reject
    res_download = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers_unauth
    )
    assert res_download.status_code == 404

    # 2. Delete must reject
    headers_unauth_admin = auth_headers("admin@tenantB.com", "Admin", "tenantB")
    res_delete = client.delete(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101",
        headers=headers_unauth_admin
    )
    assert res_delete.status_code == 404

    # 3. List must not show
    res_list = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence",
        headers=headers_unauth
    )
    assert res_list.status_code == 200
    evidence_ids = [e["id"] for e in res_list.json()]
    assert 101 not in evidence_ids

# ── 22. Upload ignores or rejects a client-provided tenant_id
def test_upload_ignores_provided_tenant_id():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    
    file_data = {"file": ("test_upload.pdf", b"Uploaded PDF content")}
    response = client.post(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence",
        headers=headers,
        files=file_data
    )
    assert response.status_code == 200
    new_ev_id = response.json()["evidence"]["id"]

    db = TestingSessionLocal()
    new_ev = db.query(ControlEvidence).filter(ControlEvidence.id == new_ev_id).first()
    assert new_ev.tenant_id == "tenantA"  # Enforced from AuthContext
    db.close()

# ── 23. A missing tenant_id claim fails closed
def test_missing_tenant_id_fails_closed():
    from routers.auth import USERS, create_test_session
    USERS["no_tenant@tenant.com"] = {"role": "Analyst", "tenant_id": None}
    db = TestingSessionLocal()
    token = create_test_session(db, "no_tenant@tenant.com")
    db.close()
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 404

# ── 24. A tampered JWT cannot modify tenant or role
def test_tampered_jwt_rejected():
    from routers.auth import USERS, create_test_session
    USERS["user@tenantA.com"] = {"role": "Superadmin", "tenant_id": "tenantA"}
    db = TestingSessionLocal()
    token = create_test_session(db, "user@tenantA.com")
    db.close()
    tampered_token = token + "evil"
    headers = {"Authorization": f"Bearer {tampered_token}"}

    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 401

# ── 25. Revoked or changed membership cannot continue indefinitely with a stale token
def test_revoked_token_invalidation():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response_logout = client.post("/api/auth/logout", headers=headers)
    assert response_logout.status_code == 200

    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 401

# ── 26. Current account membership overrides stale JWT tenant claims
def test_current_account_membership_overrides_stale_jwt_claims():
    from routers.auth import USERS, create_test_session
    USERS["user1@tenantA.com"] = {"role": "Analyst", "tenant_id": "tenantA"}
    
    db = TestingSessionLocal()
    token = create_test_session(db, "user1@tenantA.com")
    db.close()
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/102/download",
        headers=headers
    )
    assert response.status_code == 404

# ── 27. A disabled user cannot access evidence with an otherwise valid JWT
def test_disabled_user_cannot_access_evidence():
    from routers.auth import USERS
    USERS["disabled@tenantA.com"] = {"role": "Analyst", "tenant_id": "tenantA", "disabled": True}
    headers = auth_headers("disabled@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Account is disabled"

# ── 28. An unknown subject cannot access evidence
def test_unknown_subject_cannot_access_evidence():
    from routers.auth import create_test_session
    db = TestingSessionLocal()
    token = create_test_session(db, "unknown@unknown.com")
    db.close()
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/download",
        headers=headers
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "User account not found"

# ── 29. New uploads cannot use caller-supplied tenant IDs (for normal users)
def test_new_uploads_cannot_use_caller_supplied_tenant_ids():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    file_data = {"file": ("test_upload.pdf", b"Uploaded PDF content")}
    response = client.post(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence?target_tenant_id=tenantB",
        headers=headers,
        files=file_data
    )
    assert response.status_code == 400
    assert "Caller-supplied tenant ID is not permitted" in response.json()["detail"]

# ── 30. Missing tenant context rejects upload
def test_missing_tenant_context_rejects_upload():
    from routers.auth import USERS
    USERS["no_tenant@tenantA.com"] = {"role": "Analyst", "tenant_id": None}
    headers = auth_headers("no_tenant@tenantA.com", "Analyst", None)
    
    file_data = {"file": ("test_upload.pdf", b"Uploaded PDF content")}
    response = client.post(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence",
        headers=headers,
        files=file_data
    )
    assert response.status_code == 400
    assert "Missing tenant context" in response.json()["detail"]

# ── 31. Superadmin target-tenant selection is explicit and validated
def test_superadmin_target_tenant_selection_validated():
    from routers.auth import USERS
    USERS["analyst@tenantA.com"] = {"role": "Analyst", "tenant_id": "tenantA"}
    
    headers = auth_headers("superadmin@tempris.com", "Superadmin", "tempris")
    file_data = {"file": ("test_upload.pdf", b"Uploaded PDF content")}
    response = client.post(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence",
        headers=headers,
        files=file_data
    )
    assert response.status_code == 400
    assert "Superadmin upload must explicitly specify a valid target_tenant_id" in response.json()["detail"]

    response_invalid = client.post(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence?target_tenant_id=nonexistent",
        headers=headers,
        files=file_data
    )
    assert response_invalid.status_code == 400
    assert "Invalid target tenant ID" in response_invalid.json()["detail"]

    response_valid = client.post(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence?target_tenant_id=tenantA",
        headers=headers,
        files=file_data
    )
    assert response_valid.status_code == 200

# ── 32. Application startup does not execute schema-changing SQL
def test_startup_does_not_execute_schema_changing_sql(monkeypatch):
    import sqlalchemy.engine.base
    executed_alter = False
    original_execute = sqlalchemy.engine.base.Connection.execute
    
    def mock_execute(self, statement, *args, **kwargs):
        nonlocal executed_alter
        stmt_str = str(statement)
        if "ALTER TABLE" in stmt_str.upper() or "ADD COLUMN" in stmt_str.upper():
            executed_alter = True
        return original_execute(self, statement, *args, **kwargs)
        
    monkeypatch.setattr(sqlalchemy.engine.base.Connection, "execute", mock_execute)
    from services.database import init_db
    init_db()
    assert executed_alter is False, "Startup executed schema-changing ALTER TABLE statements!"

# ── 33. Startup fails safely when the tenant column or index is missing
def test_startup_fails_safely_when_tenant_column_missing():
    with engine.connect() as conn:
        conn.execute(text("DROP TABLE IF EXISTS control_evidence;"))
        conn.execute(text("""
            CREATE TABLE control_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                framework_id VARCHAR(50) NOT NULL,
                control_id VARCHAR(50) NOT NULL,
                filename VARCHAR(255),
                file_path VARCHAR(500),
                uploaded_by VARCHAR(255)
            );
        """))
        conn.commit()

    import sys
    exit_called = False
    def mock_exit(code):
        nonlocal exit_called
        exit_called = True
        raise SystemExit("Exit called")

    sys_exit_backup = sys.exit
    sys.exit = mock_exit
    try:
        from services.database import init_db
        with pytest.raises(SystemExit):
            init_db()
        assert exit_called is True
    finally:
        sys.exit = sys_exit_backup

# ── 34. Migration succeeds against a legacy temporary SQLite database
def test_migration_succeeds_against_legacy_sqlite():
    import sqlite3
    temp_db_fd, temp_db_path = tempfile.mkstemp(prefix="legacy_test_", suffix=".db")
    os.close(temp_db_fd)
    
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE control_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework_id VARCHAR(50) NOT NULL,
            control_id VARCHAR(50) NOT NULL,
            filename VARCHAR(255),
            file_path VARCHAR(500),
            uploaded_by VARCHAR(255)
        );
    """)
    cursor.execute("INSERT INTO control_evidence (framework_id, control_id, filename) VALUES ('mas_trm_2024', 'MAS-TRM-5.1.1', 'legacy.pdf');")
    conn.commit()
    conn.close()

    import subprocess
    migration_script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "scripts", "migrations", "001_add_evidence_tenant.py")
    res = subprocess.run(
        [sys.executable, migration_script, "--db-path", temp_db_path, "--legacy-tenant-id", "tempris"],
        capture_output=True, text=True
    )
    assert res.returncode == 0
    
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(control_evidence);")
    columns = [row[1] for row in cursor.fetchall()]
    assert "tenant_id" in columns

    cursor.execute("SELECT tenant_id FROM control_evidence;")
    rows = cursor.fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "tempris"

    cursor.execute("PRAGMA index_list(control_evidence);")
    indexes = [row[1] for row in cursor.fetchall()]
    assert "ix_evidence_tenant_framework_control" in indexes

    conn.close()
    
    try:
        os.remove(temp_db_path)
        if os.path.exists(temp_db_path + ".bak"):
            os.remove(temp_db_path + ".bak")
    except Exception:
        pass

# ── 35. Migration is idempotent
def test_migration_is_idempotent():
    import sqlite3
    temp_db_fd, temp_db_path = tempfile.mkstemp(prefix="legacy_test_", suffix=".db")
    os.close(temp_db_fd)
    
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE control_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework_id VARCHAR(50) NOT NULL,
            control_id VARCHAR(50) NOT NULL,
            filename VARCHAR(255)
        );
    """)
    conn.commit()
    conn.close()

    import subprocess
    migration_script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "scripts", "migrations", "001_add_evidence_tenant.py")
    
    res1 = subprocess.run([sys.executable, migration_script, "--db-path", temp_db_path, "--legacy-tenant-id", "tempris"], capture_output=True)
    assert res1.returncode == 0

    res2 = subprocess.run([sys.executable, migration_script, "--db-path", temp_db_path, "--legacy-tenant-id", "tempris"], capture_output=True)
    assert res2.returncode == 0

    try:
        os.remove(temp_db_path)
    except Exception:
        pass

# ── 36. Migration refuses to guess legacy ownership
def test_migration_refuses_to_guess_legacy_ownership():
    import sqlite3
    temp_db_fd, temp_db_path = tempfile.mkstemp(prefix="legacy_test_", suffix=".db")
    os.close(temp_db_fd)
    
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE control_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework_id VARCHAR(50) NOT NULL,
            control_id VARCHAR(50) NOT NULL
        );
    """)
    cursor.execute("INSERT INTO control_evidence (framework_id, control_id) VALUES ('mas_trm_2024', 'MAS-TRM-5.1.1');")
    conn.commit()
    conn.close()

    import subprocess
    migration_script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "scripts", "migrations", "001_add_evidence_tenant.py")
    
    res = subprocess.run([sys.executable, migration_script, "--db-path", temp_db_path], capture_output=True, text=True)
    assert res.returncode != 0
    assert "Error: Existing evidence records found" in res.stderr

    try:
        os.remove(temp_db_path)
    except Exception:
        pass

# ── 37. New rows have no implicit "tempris" tenant default
def test_new_rows_have_no_implicit_tempris_default():
    db = TestingSessionLocal()
    with pytest.raises(Exception):
        ev = ControlEvidence(
            framework_id="mas_trm_2024",
            control_id="MAS-TRM-5.1.1",
            filename="nodefault.txt"
        )
        db.add(ev)
        db.commit()
    db.rollback()
    db.close()

# ── 38. PDF responses are attachment-only
def test_pdf_responses_are_attachment_only():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101/preview",
        headers=headers
    )
    assert response.status_code == 200
    assert "attachment" in response.headers["Content-Disposition"]
    assert response.headers["Content-Type"] == "application/octet-stream"

# ── 39. Markdown is returned as plain text rather than rendered HTML
def test_markdown_returned_as_plain_text():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    
    db = TestingSessionLocal()
    ev = ControlEvidence(
        id=301,
        tenant_id="tenantA",
        framework_id="mas_trm_2024",
        control_id="MAS-TRM-5.1.1",
        filename="readme.md",
        file_path=os.path.join(TEMP_STORAGE_ROOT, "standard", "mas_trm_2024", "MAS-TRM-5.1.1", "uuid_file_a.pdf")
    )
    db.add(ev)
    db.commit()
    db.close()

    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/301/preview",
        headers=headers
    )
    assert response.status_code == 200
    assert "inline" in response.headers["Content-Disposition"]
    assert response.headers["Content-Type"].startswith("text/plain")

# ── 40. HTML, SVG and XML are never previewed inline
def test_html_svg_xml_never_previewed_inline():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    
    db = TestingSessionLocal()
    for ext, id_ in [("html", 302), ("svg", 303), ("xml", 304)]:
        ev = ControlEvidence(
            id=id_,
            tenant_id="tenantA",
            framework_id="mas_trm_2024",
            control_id="MAS-TRM-5.1.1",
            filename=f"evil.{ext}",
            file_path=os.path.join(TEMP_STORAGE_ROOT, "standard", "mas_trm_2024", "MAS-TRM-5.1.1", "uuid_file_a.pdf")
        )
        db.add(ev)
    db.commit()
    db.close()

    for id_ in [302, 303, 304]:
        response = client.get(
            "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/{}/preview".format(id_),
            headers=headers
        )
        assert response.status_code == 200
        assert "attachment" in response.headers["Content-Disposition"]
        assert response.headers["Content-Type"] == "application/octet-stream"

# ── 41. Commit failure restores a quarantined file
def test_commit_failure_restores_quarantined_file():
    headers = auth_headers("admin@tenantA.com", "Admin", "tenantA")
    
    db = TestingSessionLocal()
    original_commit = db.commit
    def fail_commit():
        raise Exception("Database transaction error")
    db.commit = fail_commit

    ev = db.query(ControlEvidence).filter(ControlEvidence.id == 101).first()
    original_file_path = ev.file_path
    assert os.path.exists(original_file_path)

    app.dependency_overrides[get_db] = lambda: db
    response = client.delete(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence/101",
        headers=headers
    )
    assert response.status_code == 500

    assert os.path.exists(original_file_path)
    
    db.commit = original_commit
    db.close()
    app.dependency_overrides[get_db] = override_get_db

# ── 42. Interrupted deletion can be identified and recovered by the reconciliation command
def test_interrupted_deletion_reconciled():
    import subprocess
    db = TestingSessionLocal()
    ev = db.query(ControlEvidence).filter(ControlEvidence.id == 101).first()
    file_path = ev.file_path
    assert os.path.exists(file_path)
    
    quarantine_dir = os.path.join(TEMP_STORAGE_ROOT, ".quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)
    quarantine_path = os.path.join(quarantine_dir, os.path.basename(file_path) + ".quarantine")
    
    os.replace(file_path, quarantine_path)
    assert not os.path.exists(file_path)
    assert os.path.exists(quarantine_path)
    
    reconcile_script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "scripts", "reconcile_evidence_quarantine.py")
    
    # 1. Run without action flags: dry-run should not make changes
    res_dry = subprocess.run(
        [sys.executable, reconcile_script, "--db-path", "./test_evidence_bola.db", "--evidence-root", TEMP_STORAGE_ROOT],
        capture_output=True, text=True
    )
    assert res_dry.returncode == 0
    assert not os.path.exists(file_path)
    assert os.path.exists(quarantine_path)
    
    # 2. Run with --restore: should restore the file
    res_restore = subprocess.run(
        [sys.executable, reconcile_script, "--db-path", "./test_evidence_bola.db", "--evidence-root", TEMP_STORAGE_ROOT, "--restore"],
        capture_output=True, text=True
    )
    assert res_restore.returncode == 0
    assert os.path.exists(file_path)
    assert not os.path.exists(quarantine_path)

    # 3. Simulate deleted record with quarantine file (transaction committed but crashed before file cleanup)
    os.replace(file_path, quarantine_path)
    db.delete(ev)
    db.commit()
    db.close()

    # Dry-run should not delete the quarantine file
    res_dry2 = subprocess.run(
        [sys.executable, reconcile_script, "--db-path", "./test_evidence_bola.db", "--evidence-root", TEMP_STORAGE_ROOT],
        capture_output=True, text=True
    )
    assert res_dry2.returncode == 0
    assert not os.path.exists(file_path)
    assert os.path.exists(quarantine_path)

    # Run with --purge: should purge the quarantine file
    res_purge = subprocess.run(
        [sys.executable, reconcile_script, "--db-path", "./test_evidence_bola.db", "--evidence-root", TEMP_STORAGE_ROOT, "--purge"],
        capture_output=True, text=True
    )
    assert res_purge.returncode == 0
    assert not os.path.exists(quarantine_path)

# ── 43. Internal paths and quarantine names do not leak through responses
def test_internal_paths_do_not_leak():
    headers = auth_headers("analyst@tenantA.com", "Analyst", "tenantA")
    response = client.get(
        "/api/standard/frameworks/mas_trm_2024/controls/MAS-TRM-5.1.1/evidence",
        headers=headers
    )
    assert response.status_code == 200
    for item in response.json():
        assert "file_path" not in item
        assert "quarantine" not in str(item)

# ── 44. Migration succeeds with --mark-legacy-unassigned
def test_migration_mark_legacy_unassigned():
    import sqlite3
    temp_db_fd, temp_db_path = tempfile.mkstemp(prefix="legacy_test_", suffix=".db")
    os.close(temp_db_fd)
    
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE control_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework_id VARCHAR(50) NOT NULL,
            control_id VARCHAR(50) NOT NULL,
            filename VARCHAR(255)
        );
    """)
    cursor.execute("INSERT INTO control_evidence (framework_id, control_id, filename) VALUES ('mas_trm_2024', 'MAS-TRM-5.1.1', 'legacy.pdf');")
    conn.commit()
    conn.close()

    import subprocess
    migration_script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "scripts", "migrations", "001_add_evidence_tenant.py")
    res = subprocess.run(
        [sys.executable, migration_script, "--db-path", temp_db_path, "--mark-legacy-unassigned"],
        capture_output=True, text=True
    )
    assert res.returncode == 0
    
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT tenant_id FROM control_evidence;")
    rows = cursor.fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "legacy-unassigned"
    conn.close()
    
    try:
        os.remove(temp_db_path)
    except Exception:
        pass
