import pytest
from fastapi.testclient import TestClient
from passlib.hash import bcrypt

from index import app
import middleware.rate_limit as rate_limit
from models import AuditLog, Finding, SurgeResearcher, SurgeSubmission
from routers import auth
from services.database import Base, SessionLocal, engine


PASSWORD = "vdp-hardening-test-password"
STAFF_EMAIL = "vdp.staff@tempris.test"
OUTSIDER_EMAIL = "customer.admin@example.test"


@pytest.fixture(autouse=True)
def vdp_state(monkeypatch):
    rate_limit._buckets.clear()
    monkeypatch.setattr(rate_limit._Bucket, "consume", lambda self: True)
    Base.metadata.create_all(bind=engine)
    auth.USERS[STAFF_EMAIL] = {
        "password": bcrypt.hash(PASSWORD),
        "role": "Analyst",
        "name": "VDP Staff",
        "tenant_id": "tempris",
    }
    auth.USERS[OUTSIDER_EMAIL] = {
        "password": bcrypt.hash(PASSWORD),
        "role": "Admin",
        "name": "Customer Admin",
        "tenant_id": "customer-tenant",
    }
    db = SessionLocal()
    db.query(SurgeSubmission).delete()
    auth._login_attempts.pop(STAFF_EMAIL, None)
    auth._login_attempts.pop(OUTSIDER_EMAIL, None)
    db.query(SurgeResearcher).delete()
    db.query(Finding).filter(Finding.source == "surge").delete()
    db.query(AuditLog).filter(AuditLog.action == "VDP_SUBMISSION_RECEIVED").delete()
    db.commit()
    db.close()
    yield
    auth.USERS.pop(STAFF_EMAIL, None)
    auth.USERS.pop(OUTSIDER_EMAIL, None)


def _headers(client: TestClient, email: str) -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _valid_report() -> dict:
    return {
        "email": "researcher@example.test",
        "recognition_name": "researcher-handle",
        "title": "Authorisation bypass in tenant export",
        "severity": "high",
        "description": "A tenant user can request another tenant export by changing the resource identifier.",
        "affected_url": "https://sandbox.tempris.tech/api/example",
        "safe_harbor_ack": True,
        "privacy_ack": True,
        "website": "",
    }


def test_public_vdp_intake_is_validated_confidential_and_audited():
    client = TestClient(app)

    missing_ack = _valid_report()
    missing_ack["privacy_ack"] = False
    assert client.post("/api/surge/public/submit", json=missing_ack).status_code == 400

    unsafe_url = _valid_report()
    unsafe_url["affected_url"] = "javascript:alert(1)"
    assert client.post("/api/surge/public/submit", json=unsafe_url).status_code == 400

    honeypot = _valid_report()
    honeypot["website"] = "spam.example"
    accepted_bot = client.post("/api/surge/public/submit", json=honeypot)
    assert accepted_bot.status_code == 202
    assert "tracking_id" not in accepted_bot.json()

    accepted = client.post("/api/surge/public/submit", json=_valid_report())
    assert accepted.status_code == 202
    body = accepted.json()
    assert body["status"] == "received"
    assert body["tracking_id"].startswith("S-")
    assert "email" not in body
    assert "description" not in body

    db = SessionLocal()
    try:
        submission = db.query(SurgeSubmission).filter(SurgeSubmission.id == body["tracking_id"]).one()
        researcher = db.query(SurgeResearcher).filter(SurgeResearcher.id == submission.researcher_id).one()
        audit = db.query(AuditLog).filter(AuditLog.action == "VDP_SUBMISSION_RECEIVED").one()
        assert researcher.email == "researcher@example.test"
        assert submission.status == "submitted"
        assert submission.attachments == []
        assert "researcher@example.test" not in audit.detail
        assert _valid_report()["title"] not in audit.detail
    finally:
        db.close()


def test_vdp_queue_is_restricted_to_tempris_staff_and_acceptance_creates_tenant_finding():
    client = TestClient(app)
    tracking_id = client.post("/api/surge/public/submit", json=_valid_report()).json()["tracking_id"]
    outsider = _headers(client, OUTSIDER_EMAIL)
    staff = _headers(client, STAFF_EMAIL)

    assert client.get("/api/surge/submissions", headers=outsider).status_code == 403
    queue = client.get("/api/surge/submissions", headers=staff)
    assert queue.status_code == 200
    assert queue.json()["data"][0]["id"] == tracking_id
    assert queue.json()["data"][0]["researcher"] == {
        "handle": "researcher-handle",
        "email": "researcher@example.test",
    }

    triaged = client.post(
        f"/api/surge/submissions/{tracking_id}/triage",
        headers=staff,
        json={"status": "accepted", "edip_decision": "mitigate"},
    )
    assert triaged.status_code == 200
    finding_id = triaged.json()["finding_id"]

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).one()
        assert finding.tenant_id == "tempris"
        assert finding.source == "surge"
    finally:
        db.close()


def test_vdp_is_canonical_and_security_txt_is_rfc_9116_scoped():
    client = TestClient(app)
    redirect = client.get("/security", follow_redirects=False)
    assert redirect.status_code == 308
    assert redirect.headers["location"] == "/vdp"

    policy = client.get("/vdp")
    assert policy.status_code == 200
    assert "/extensions/tempris-modules.js?v=20260810a" in policy.text

    security_txt = client.get("/.well-known/security.txt")
    assert security_txt.status_code == 200
    assert security_txt.headers["content-type"].startswith("text/plain")
    assert "Contact: https://sandbox.tempris.tech/vdp#submit" in security_txt.text
    assert "Policy: https://sandbox.tempris.tech/vdp" in security_txt.text
    assert "Canonical: https://sandbox.tempris.tech/.well-known/security.txt" in security_txt.text
    assert "Canonical: https://tempris.tech/.well-known/security.txt" not in security_txt.text
    assert "Expires: 2027-06-30T00:00:00Z" in security_txt.text
