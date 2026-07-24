import pytest
from fastapi.testclient import TestClient
from passlib.hash import bcrypt

from index import app
from models import AuditLog, Finding, TenantPackage
from routers import auth
from services.database import Base, SessionLocal, engine


TENANT = "tenant-production-workflows"
PASSWORD = "production-workflow-test-password"
ACCOUNTS = {
    "pkg.admin@tempris.test": "Admin",
    "pkg.analyst@tempris.test": "Analyst",
    "pkg.viewer@tempris.test": "Viewer",
    "other.analyst@tempris.test": "Analyst",
}


@pytest.fixture(autouse=True)
def workflow_state(monkeypatch):
    from middleware.rate_limit import _Bucket

    monkeypatch.setattr(_Bucket, "consume", lambda self: True)
    Base.metadata.create_all(bind=engine)
    for email, role in ACCOUNTS.items():
        auth.USERS[email] = {
            "password": bcrypt.hash(PASSWORD),
            "role": role,
            "name": role,
            "tenant_id": "tenant-other" if email.startswith("other.") else TENANT,
        }
    db = SessionLocal()
    db.query(TenantPackage).filter(TenantPackage.tenant_id.in_([TENANT, "tenant-other"])).delete()
    db.query(Finding).filter(Finding.tenant_id.in_([TENANT, "tenant-other"])).delete()
    db.query(AuditLog).filter(AuditLog.tenant_id.in_([TENANT, "tenant-other"])).delete()
    db.commit()
    db.close()
    yield
    for email in ACCOUNTS:
        auth.USERS.pop(email, None)


def headers(client: TestClient, email: str) -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_packages_are_persisted_audited_and_enforced_by_backend():
    client = TestClient(app)
    admin = headers(client, "pkg.admin@tempris.test")
    analyst = headers(client, "pkg.analyst@tempris.test")

    default = client.get("/api/packages/current", headers=admin)
    assert default.status_code == 200
    assert default.json()["package_code"] == "DOMINATE"
    assert default.json()["configured"] is False
    assert set(default.json()["effective_modules"]) == set(default.json()["modules"])

    forbidden = client.put(
        "/api/packages/current",
        headers=analyst,
        json={"package_code": "DETECT", "module_overrides": {}},
    )
    assert forbidden.status_code == 403

    saved = client.put(
        "/api/packages/current",
        headers=admin,
        json={"package_code": "DETECT", "module_overrides": {"CISO": True}},
    )
    assert saved.status_code == 200
    assert saved.json()["configured"] is True
    assert "CISO" in saved.json()["effective_modules"]
    assert "STRIKE" not in saved.json()["effective_modules"]

    allowed = client.get("/api/synthesis/dashboard", headers=analyst)
    assert allowed.status_code == 200
    blocked = client.get("/api/strike/matrix", headers=analyst)
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == {
        "code": "MODULE_NOT_ENTITLED",
        "module": "STRIKE",
        "package": "DETECT",
    }

    db = SessionLocal()
    try:
        row = db.query(TenantPackage).filter(TenantPackage.tenant_id == TENANT).one()
        assert row.package_code == "DETECT"
        audit = db.query(AuditLog).filter(
            AuditLog.tenant_id == TENANT,
            AuditLog.action == "TENANT_PACKAGE_UPDATED",
        ).one()
        assert audit.module == "PACKAGES"
    finally:
        db.close()


def test_sss_business_logic_intake_update_resolve_and_tenant_scope():
    client = TestClient(app)
    analyst = headers(client, "pkg.analyst@tempris.test")
    viewer = headers(client, "pkg.viewer@tempris.test")
    other = headers(client, "other.analyst@tempris.test")

    invalid = client.post(
        "/api/edip/intake/sss",
        headers=analyst,
        json={"class": "BLFLAW", "title": "Missing subtype", "description": "Invalid"},
    )
    assert invalid.status_code == 422

    created = client.post(
        "/api/edip/intake/sss",
        headers=analyst,
        json={
            "class": "BLFLAW",
            "subtype": "IDOR",
            "title": "Cross-tenant invoice access",
            "description": "User A can retrieve User B invoice by changing the object identifier.",
            "affected_ecosystem": "Billing Portal",
            "base_severity": 8.4,
            "source_tool": "Manual Pentest",
            "pii_exposed": True,
            "patch_available": False,
        },
    )
    assert created.status_code == 200
    body = created.json()
    finding_id = body["id"]
    assert body["subtype"] == "IDOR"
    assert body["source_tool"] == "Manual Pentest"
    assert body["pii_exposed"] is True
    assert body["status"] == "unmitigated"

    listed = client.get("/api/edip/intake/sss", headers=viewer)
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["data"]] == [finding_id]
    assert client.put(
        f"/api/edip/intake/sss/{finding_id}", headers=viewer, json={"patch_available": True}
    ).status_code == 403
    assert client.put(
        f"/api/edip/intake/sss/{finding_id}", headers=other, json={"patch_available": True}
    ).status_code == 404

    updated = client.put(
        f"/api/edip/intake/sss/{finding_id}",
        headers=analyst,
        json={
            "patch_available": True,
            "compensating_controls": ["Object ownership validation"],
            "compensating_control_notes": "Server-side authorization added to every invoice lookup.",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["patch_available"] is True
    assert updated.json()["compensating_controls"] == ["Object ownership validation"]

    resolved = client.post(
        f"/api/edip/intake/sss/{finding_id}/resolve",
        headers=analyst,
        json={"resolution_notes": "Verified with cross-account regression tests."},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"
    duplicate = client.post(
        f"/api/edip/intake/sss/{finding_id}/resolve",
        headers=analyst,
        json={"resolution_notes": "Resolve again"},
    )
    assert duplicate.status_code == 409
