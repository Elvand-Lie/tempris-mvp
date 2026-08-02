from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from passlib.hash import bcrypt

from index import app
from models import AuditLog, Finding, TenantPackage
from routers import auth
from services.database import Base, SessionLocal, engine


PASSWORD = "isolated-researcher-test-password"
RESEARCHER_EMAIL = "researcher.test@tempris.test"
ANALYST_EMAIL = "analyst.other@tempris.test"
RESEARCHER_TENANT = "bug-bounty-test"
OTHER_TENANT = "tenant-operational-test"


@pytest.fixture(autouse=True)
def researcher_state(monkeypatch):
    from middleware.rate_limit import _Bucket

    monkeypatch.setattr(_Bucket, "consume", lambda self: True)
    Base.metadata.create_all(bind=engine)
    auth.USERS[RESEARCHER_EMAIL] = {
        "password": bcrypt.hash(PASSWORD),
        "role": "Researcher",
        "name": "Security Researcher",
        "tenant_id": RESEARCHER_TENANT,
    }
    auth.USERS[ANALYST_EMAIL] = {
        "password": bcrypt.hash(PASSWORD),
        "role": "Analyst",
        "name": "Security Analyst",
        "tenant_id": OTHER_TENANT,
    }
    db = SessionLocal()
    db.query(TenantPackage).filter(
        TenantPackage.tenant_id.in_([RESEARCHER_TENANT, OTHER_TENANT])
    ).delete(synchronize_session=False)
    db.query(Finding).filter(
        Finding.tenant_id.in_([RESEARCHER_TENANT, OTHER_TENANT])
    ).delete(synchronize_session=False)
    db.query(AuditLog).filter(
        AuditLog.tenant_id.in_([RESEARCHER_TENANT, OTHER_TENANT])
    ).delete(synchronize_session=False)
    db.commit()
    db.close()
    yield
    auth.USERS.pop(RESEARCHER_EMAIL, None)
    auth.USERS.pop(ANALYST_EMAIL, None)


def login(client: TestClient, email: str) -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200
    return {
        "Authorization": f"Bearer {response.json()['access_token']}",
        "user": response.json()["user"],
    }


def test_researcher_has_one_isolated_write_capability_and_no_module_access():
    client = TestClient(app)
    login_result = login(client, RESEARCHER_EMAIL)
    headers = {"Authorization": login_result["Authorization"]}
    assert login_result["user"]["role"] == "Researcher"


    package = client.get("/api/packages/current", headers=headers)
    assert package.status_code == 200
    assert package.json()["role"] == "Researcher"
    assert package.json()["tenant_id"] == RESEARCHER_TENANT
    assert package.json()["effective_modules"] == []
    assert package.json()["can_manage"] is False
    assert package.json()["can_submit_sss"] is True
    assert package.json()["can_manage_sss"] is False

    created = client.post(
        "/api/edip/intake/sss",
        headers=headers,
        json={
            "class": "BLFLAW",
            "subtype": "IDOR",
            "title": "Researcher isolated authorization test",
            "description": "Synthetic bug-bounty test finding with no operational impact.",
            "affected_ecosystem": "Bug bounty sandbox",
            "base_severity": 4.0,
            "source_tool": "Authorized researcher test",
        },
    )
    assert created.status_code == 200
    finding_id = created.json()["id"]

    listed = client.get("/api/edip/intake/sss", headers=headers)
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["data"]] == [finding_id]

    blocked = [
        client.get("/api/scout/findings", headers=headers),
        client.get("/api/audit/log", headers=headers),
        client.get("/api/standard/frameworks", headers=headers),
        client.put(
            "/api/packages/current",
            headers=headers,
            json={"package_code": "DOMINATE", "module_overrides": {}},
        ),
        client.put(
            f"/api/edip/intake/sss/{finding_id}",
            headers=headers,
            json={"patch_available": True},
        ),
        client.post(
            f"/api/edip/intake/sss/{finding_id}/resolve",
            headers=headers,
            json={"resolution_notes": "Researcher must not resolve findings."},
        ),
    ]
    assert [response.status_code for response in blocked] == [403] * len(blocked)
    assert all(
        response.json()["detail"]
        == "Researcher users can create and view isolated SSS test findings only."
        for response in blocked
    )

    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).one()
        assert finding.tenant_id == RESEARCHER_TENANT
        audit = db.query(AuditLog).filter(
            AuditLog.tenant_id == RESEARCHER_TENANT,
            AuditLog.action == "AUTO_EDIP_INTAKE",
        ).one()
        assert audit.user_email == RESEARCHER_EMAIL
    finally:
        db.close()

    logout = client.post("/api/auth/logout", headers=headers)
    assert logout.status_code == 200


def test_researcher_findings_are_not_visible_to_operational_tenant():
    client = TestClient(app)
    researcher = login(client, RESEARCHER_EMAIL)
    analyst = login(client, ANALYST_EMAIL)
    created = client.post(
        "/api/edip/intake/sss",
        headers={"Authorization": researcher["Authorization"]},
        json={
            "class": "BLFLAW",
            "subtype": "IDOR",
            "title": "Tenant boundary test",
            "description": "Synthetic researcher-only tenant record.",
        },
    )
    assert created.status_code == 200

    operational = client.get(
        "/api/edip/intake/sss",
        headers={"Authorization": analyst["Authorization"]},
    )
    assert operational.status_code == 200
    assert created.json()["id"] not in {row["id"] for row in operational.json()["data"]}


def test_frontend_forces_researchers_into_the_sss_workspace():
    root = Path(__file__).resolve().parents[2] / "frontend"
    bootstrap = (root / "extensions" / "tempris-bootstrap.js").read_text(encoding="utf-8")
    modules = (root / "extensions" / "tempris-modules.js").read_text(encoding="utf-8")

    assert "user?.role === 'Researcher'" in bootstrap
    assert "window.location.replace('/sss-intake')" in bootstrap
    assert "currentUserRole() === 'Researcher'" in modules
    assert "window.location.pathname !== '/sss-intake'" in modules
    assert 'can_manage_sss' in modules
    assert 'a[href="/audit"]' in modules