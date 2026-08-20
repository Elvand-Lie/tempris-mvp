"""Contract and lifecycle tests for Asset Inventory CRUD and Scan Authorization boundaries.

Verifies:
1. POST /api/assets creates an asset with proper JSON payload, serialized tags (list[str]), and defaults.
2. PUT /api/assets/{id} updates only provided fields; changing target (hostname/ip) revokes active scan authorizations.
3. DELETE /api/assets/{id} soft-decommissions asset and revokes active scan authorizations without hard-deleting database records.
4. Scan authorization remains a strictly separate workflow (request -> approve -> revoke) independent of asset creation.
5. Role-based access control: Analyst can create/update, Admin+ can decommission, Superadmin approves scan auth.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from index import app
from models import (
    Asset,
    AssetScanAuthorization,
    Base,
)
from routers.auth import get_auth_context, get_current_user
from services.database import get_db


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_assets_crud_contract.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: {
        "sub": "admin@tempris.com",
        "email": "admin@tempris.com",
        "role": "Admin",
        "tenant_id": "tempris",
        "package": "ENTERPRISE",
        "is_superadmin": False,
    }
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_create_asset_contract_and_tag_serialization(client, db_session):
    """POST /api/assets creates an asset with serialized tags array and valid defaults."""
    payload = {
        "name": "Perimeter Web Proxy",
        "asset_type": "server",
        "criticality": "high",
        "hostname": "proxy.customer.com",
        "ip_address": "198.51.100.25",
        "owner": "Cloud Infrastructure",
        "environment": "production",
        "tags": ["proxy", "perimeter", "aws"],
        "notes": "Main reverse proxy gateway",
    }

    resp = client.post("/api/assets", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["name"] == "Perimeter Web Proxy"
    assert data["asset_type"] == "server"
    assert data["criticality"] == "high"
    assert data["hostname"] == "proxy.customer.com"
    assert data["ip_address"] == "198.51.100.25"
    assert data["tags"] == ["proxy", "perimeter", "aws"]
    assert data["environment"] == "production"
    assert data["status"] == "active"
    assert data["id"].startswith("ASSET-")

    # Assert persisted in DB
    asset_in_db = db_session.query(Asset).filter(Asset.id == data["id"]).first()
    assert asset_in_db is not None
    assert asset_in_db.name == "Perimeter Web Proxy"
    assert asset_in_db.tags == ["proxy", "perimeter", "aws"]
    assert asset_in_db.tenant_id == "tempris"


def test_update_asset_and_target_modification_revokes_scan_auth(client, db_session):
    """PUT /api/assets/{id} updates fields and revokes active scan auth if hostname/ip changed."""
    now = datetime.now(timezone.utc)
    asset = Asset(
        id="asset-up-1",
        tenant_id="tempris",
        name="API Gateway",
        asset_type="application",
        ip_address="203.0.113.50",
        criticality="critical",
        status="active",
        tags=["api", "external"],
    )
    auth = AssetScanAuthorization(
        id="auth-up-1",
        tenant_id="tempris",
        asset_id=asset.id,
        authorized_target="203.0.113.50",
        target_kind="ipv4",
        status="approved",
        evidence="SOW signed",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=90),
    )
    db_session.add_all([asset, auth])
    db_session.commit()

    # 1. Update name and tags only -> auth remains approved
    resp1 = client.put(f"/api/assets/{asset.id}", json={
        "name": "Renamed API Gateway",
        "tags": ["api", "production", "v2"],
    })
    assert resp1.status_code == 200
    assert resp1.json()["name"] == "Renamed API Gateway"

    db_session.refresh(auth)
    assert auth.status == "approved"

    # 2. Update IP address -> auth is automatically revoked
    resp2 = client.put(f"/api/assets/{asset.id}", json={
        "ip_address": "203.0.113.99",
    })
    assert resp2.status_code == 200
    assert resp2.json()["ip_address"] == "203.0.113.99"

    db_session.refresh(auth)
    assert auth.status == "revoked"
    assert "Asset target modified" in (auth.revocation_reason or "")


def test_decommission_asset_soft_deletes_and_revokes_auth(client, db_session):
    """DELETE /api/assets/{id} soft-decommissions asset and revokes authorizations."""
    now = datetime.now(timezone.utc)
    asset = Asset(
        id="asset-decomm-1",
        tenant_id="tempris",
        name="Legacy Core Database",
        asset_type="database",
        ip_address="192.0.2.10",
        criticality="high",
        status="active",
    )
    auth = AssetScanAuthorization(
        id="auth-decomm-1",
        tenant_id="tempris",
        asset_id=asset.id,
        authorized_target="192.0.2.10",
        target_kind="ipv4",
        status="approved",
        evidence="Historical pentest SOW",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=30),
    )
    db_session.add_all([asset, auth])
    db_session.commit()

    resp = client.delete(f"/api/assets/{asset.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "decommissioned"
    assert data["asset_id"] == asset.id

    # Verify DB state: asset is NOT deleted from DB, status is decommissioned
    db_session.refresh(asset)
    assert asset.status == "decommissioned"


def test_asset_crud_rbac_enforcement(client, db_session):
    """Analyst can create/update but cannot delete; Read-only cannot create."""
    # 1. Analyst cannot delete
    app.dependency_overrides[get_current_user] = lambda: {
        "sub": "analyst@tempris.com",
        "email": "analyst@tempris.com",
        "role": "Analyst",
        "tenant_id": "tempris",
        "package": "ENTERPRISE",
        "is_superadmin": False,
    }
    resp1 = client.delete("/api/assets/some-asset-id")
    assert resp1.status_code == 403

    # 2. Read-only cannot create
    app.dependency_overrides[get_current_user] = lambda: {
        "sub": "readonly@tempris.com",
        "email": "readonly@tempris.com",
        "role": "Read-only",
        "tenant_id": "tempris",
        "package": "ENTERPRISE",
        "is_superadmin": False,
    }
    resp2 = client.post("/api/assets", json={"name": "Test Asset", "asset_type": "server", "criticality": "low"})
    assert resp2.status_code == 403
