import pytest
from fastapi.testclient import TestClient
from passlib.hash import bcrypt

from index import app
from models import AuditLog, Tenant, TenantPackage
from routers import auth
from services.database import Base, SessionLocal, engine


PASSWORD = "tenant-admin-test-password"
PLATFORM_ADMIN = "tenant.platform@tempris.test"
CUSTOMER_ADMIN = "tenant.customer.admin@tempris.test"
CUSTOMER_ANALYST = "tenant.customer.analyst@tempris.test"
PLATFORM_REGULAR_ADMIN = "tenant.regular@tempris.test"
TENANT_A = "tenant-admin-a"
TENANT_B = "tenant-admin-b"


@pytest.fixture(autouse=True)
def tenant_admin_state(monkeypatch):
    from middleware.rate_limit import _Bucket

    monkeypatch.setattr(_Bucket, "consume", lambda self: True)
    Base.metadata.create_all(bind=engine)
    accounts = {
        PLATFORM_ADMIN: ("Superadmin", "tempris"),
        CUSTOMER_ADMIN: ("Superadmin", TENANT_A),
        CUSTOMER_ANALYST: ("Analyst", TENANT_A),
        PLATFORM_REGULAR_ADMIN: ("Admin", "tempris"),
    }
    for email, (role, tenant_id) in accounts.items():
        auth.USERS[email] = {
            "password": bcrypt.hash(PASSWORD),
            "role": role,
            "name": role,
            "tenant_id": tenant_id,
        }

    db = SessionLocal()
    db.query(TenantPackage).filter(TenantPackage.tenant_id.in_([TENANT_A, TENANT_B])).delete(
        synchronize_session=False
    )
    db.query(Tenant).filter(Tenant.id.in_([TENANT_A, TENANT_B])).delete(synchronize_session=False)
    db.add_all([
        Tenant(id=TENANT_A, display_name="Customer Alpha", tenant_type="customer"),
        Tenant(id=TENANT_B, display_name="Customer Beta", tenant_type="customer"),
    ])
    if db.query(Tenant).filter(Tenant.id == "tempris").first() is None:
        db.add(Tenant(id="tempris", display_name="Tempris Platform", tenant_type="platform"))
    db.commit()
    db.close()
    yield
    for email in accounts:
        auth.USERS.pop(email, None)
    db = SessionLocal()
    db.query(TenantPackage).filter(TenantPackage.tenant_id.in_([TENANT_A, TENANT_B])).delete(
        synchronize_session=False
    )
    db.query(Tenant).filter(Tenant.id.in_([TENANT_A, TENANT_B])).delete(synchronize_session=False)
    db.commit()
    db.close()


def headers(client: TestClient, email: str) -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_only_platform_superadmin_can_enumerate_and_target_tenants():
    client = TestClient(app)
    platform = headers(client, PLATFORM_ADMIN)
    customer = headers(client, CUSTOMER_ADMIN)
    regular = headers(client, PLATFORM_REGULAR_ADMIN)

    response = client.get("/api/tenants?q=Alpha&limit=10", headers=platform)
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["tenant_id"] == TENANT_A
    assert "email" not in str(response.json()).lower()

    assert client.get("/api/tenants", headers=customer).status_code == 403
    assert client.get("/api/tenants", headers=regular).status_code == 403
    assert client.get(f"/api/tenants/{TENANT_B}", headers=customer).status_code == 403


def test_detail_explains_defaults_provenance_and_non_impersonation():
    client = TestClient(app)
    response = client.get(f"/api/tenants/{TENANT_A}", headers=headers(client, PLATFORM_ADMIN))
    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] is False
    assert payload["version"] == 0
    assert payload["package_code"] == "DOMINATE"
    assert payload["selection_changes_session"] is False
    assert all(item["source"] == "package" for item in payload["module_access"])
    assert any(item["code"] == "ADMIN_TARGET_ONLY" for item in payload["constraints"])


def test_targeted_update_is_isolated_audited_versioned_and_immediately_enforced():
    client = TestClient(app)
    platform = headers(client, PLATFORM_ADMIN)
    analyst = headers(client, CUSTOMER_ANALYST)

    saved = client.put(
        f"/api/tenants/{TENANT_A}/entitlements",
        headers=platform,
        json={"package_code": "DETECT", "module_overrides": {"CISO": True}, "expected_version": 0},
    )
    assert saved.status_code == 200
    assert saved.json()["version"] == 1
    assert saved.json()["package_code"] == "DETECT"
    assert "CISO" in saved.json()["effective_modules"]
    assert next(item for item in saved.json()["module_access"] if item["module"] == "CISO")["source"] == "override_enabled"

    untouched = client.get(f"/api/tenants/{TENANT_B}", headers=platform).json()
    assert untouched["configured"] is False
    assert untouched["package_code"] == "DOMINATE"

    blocked = client.get("/api/strike/matrix", headers=analyst)
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "MODULE_NOT_ENTITLED"

    db = SessionLocal()
    try:
        row = db.query(TenantPackage).filter(TenantPackage.tenant_id == TENANT_A).one()
        assert row.version == 1
        audit = db.query(AuditLog).filter(
            AuditLog.tenant_id == "tempris",
            AuditLog.action == "TENANT_ENTITLEMENTS_UPDATED",
        ).order_by(AuditLog.id.desc()).first()
        assert audit is not None
        assert audit.module == "TENANT_ADMIN"
        assert audit.metadata_["target_tenant_id"] == TENANT_A
        assert audit.metadata_["before"]["version"] == 0
        assert audit.metadata_["after"]["version"] == 1
    finally:
        db.close()


def test_stale_update_fails_without_overwriting_current_policy():
    client = TestClient(app)
    platform = headers(client, PLATFORM_ADMIN)
    first = client.put(
        f"/api/tenants/{TENANT_A}/entitlements",
        headers=platform,
        json={"package_code": "DETECT", "module_overrides": {}, "expected_version": 0},
    )
    assert first.status_code == 200

    stale = client.put(
        f"/api/tenants/{TENANT_A}/entitlements",
        headers=platform,
        json={"package_code": "RESPOND", "module_overrides": {}, "expected_version": 0},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "STALE_TENANT_CONFIGURATION"
    current = client.get(f"/api/tenants/{TENANT_A}", headers=platform).json()
    assert current["package_code"] == "DETECT"
    assert current["version"] == 1


def test_unknown_unsafe_and_invalid_updates_fail_closed():
    client = TestClient(app)
    platform = headers(client, PLATFORM_ADMIN)
    assert client.get("/api/tenants/not-registered", headers=platform).status_code == 404
    assert client.get("/api/tenants/..%2Ftempris", headers=platform).status_code in {404, 422}
    invalid = client.put(
        f"/api/tenants/{TENANT_A}/entitlements",
        headers=platform,
        json={"package_code": "INVENTED", "module_overrides": {}, "expected_version": 0},
    )
    assert invalid.status_code == 422
    extra = client.put(
        f"/api/tenants/{TENANT_A}/entitlements",
        headers=platform,
        json={"package_code": "DETECT", "module_overrides": {}, "expected_version": 0, "impersonate": True},
    )
    assert extra.status_code == 422


def test_audit_failure_rolls_back_entitlement_change(monkeypatch):
    import routers.tenants as tenant_router

    client = TestClient(app, raise_server_exceptions=False)
    platform = headers(client, PLATFORM_ADMIN)

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(tenant_router, "append_to_audit_log_db", fail_audit)
    response = client.put(
        f"/api/tenants/{TENANT_A}/entitlements",
        headers=platform,
        json={"package_code": "DETECT", "module_overrides": {}, "expected_version": 0},
    )
    assert response.status_code == 500
    db = SessionLocal()
    try:
        assert db.query(TenantPackage).filter(TenantPackage.tenant_id == TENANT_A).first() is None
    finally:
        db.close()
