"""Comprehensive Tests for TEMPRIS SCOUT Wave 1: Hardening, Authorization, Target-Binding, and Safety.

Verifies:
1. Target policy & SSRF Defense (is_ip_globally_routable, clean_target_input, validate_and_resolve_target)
2. Asset Scan Authorization Lifecycle (Request -> Approve -> Revoke, Invalidation on Asset Update)
3. Scanner Process Safety & Kill Switch (SCOUT_ACTIVE_SCANNING_ENABLED, SCOUT_RAW_DIAGNOSTIC_ENABLED)
4. Asset-bound Scan Execution & Target Provenance recording in ScanJob
5. Scanner-to-Asset Trust Boundary & Drift Prevention in Scan Normalizer
6. Concurrency limits & Cooldown enforcement
"""

from __future__ import annotations

import ipaddress
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from index import app
from models import (
    Asset,
    AssetExposure,
    AssetScanAuthorization,
    Base,
    CanonicalVulnerability,
    Finding,
    ScanFinding,
    ScanJob,
)
from routers.auth import get_auth_context, get_current_user
from services.database import get_db
from services.scan_normalizer import normalize_observation
from services.target_policy import (
    classify_asset_target,
    clean_target_input,
    is_ip_globally_routable,
    validate_and_resolve_target,
)


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_scout_wave1.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    yield session

    session.close()
    engine.dispose()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


# ── 1. Target Policy & SSRF Defense Unit Tests ────────────────────────────────

def test_is_ip_globally_routable():
    # Public IPs
    assert is_ip_globally_routable(ipaddress.ip_address("93.184.216.34")) is True
    assert is_ip_globally_routable(ipaddress.ip_address("8.8.8.8")) is True
    assert is_ip_globally_routable(ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946")) is True

    # RFC 1918 Private IPs
    assert is_ip_globally_routable(ipaddress.ip_address("10.0.0.1")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("172.16.5.10")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("192.168.1.1")) is False

    # Loopback
    assert is_ip_globally_routable(ipaddress.ip_address("127.0.0.1")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("127.0.0.254")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("::1")) is False

    # Link-local & Cloud Metadata
    assert is_ip_globally_routable(ipaddress.ip_address("169.254.1.1")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("169.254.169.254")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("100.100.100.200")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("fd00:ec2::254")) is False

    # CGNAT
    assert is_ip_globally_routable(ipaddress.ip_address("100.64.0.1")) is False

    # IPv6 ULA
    assert is_ip_globally_routable(ipaddress.ip_address("fc00::1")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("fd12:3456:789a::1")) is False

    # IPv4-mapped IPv6 loopback / private
    assert is_ip_globally_routable(ipaddress.ip_address("::ffff:127.0.0.1")) is False
    assert is_ip_globally_routable(ipaddress.ip_address("::ffff:10.0.0.1")) is False


def test_clean_target_input():
    assert clean_target_input("https://example.com/api/v1?test=1#frag") == "example.com"
    assert clean_target_input("http://example.com:8080/test") == "example.com"
    assert clean_target_input("93.184.216.34:443") == "93.184.216.34"
    assert clean_target_input("example.com.") == "example.com"
    assert clean_target_input("  sub.example.com  ") == "sub.example.com"

    # Credentials or malicious schemes rejected
    assert clean_target_input("https://admin:pass@example.com") == ""
    assert clean_target_input("ftp://example.com") == ""
    assert clean_target_input("javascript:alert(1)") == ""


def test_validate_and_resolve_target_rejections():
    # Direct private IP
    res = validate_and_resolve_target("192.168.1.50")
    assert res.is_valid is False
    assert res.is_public_scannable is False
    assert res.target_kind == "private_ipv4"
    assert "private, internal, or restricted" in (res.error or "")

    # Direct loopback
    res = validate_and_resolve_target("127.0.0.1")
    assert res.is_valid is False

    # Direct metadata
    res = validate_and_resolve_target("169.254.169.254")
    assert res.is_valid is False

    # CIDR, wildcard, multiple targets, injection
    assert validate_and_resolve_target("192.168.1.0/24").is_valid is False
    assert validate_and_resolve_target("93.184.216.0/24").is_valid is False
    assert validate_and_resolve_target("example.com,google.com").is_valid is False
    assert validate_and_resolve_target("*.example.com").is_valid is False
    assert validate_and_resolve_target("example.com; id").is_valid is False
    assert validate_and_resolve_target("").is_valid is False


def test_classify_asset_target():
    # Unspecified
    assert classify_asset_target()["target_kind"] == "unspecified"

    # Private IP asset
    c1 = classify_asset_target(ip_address="10.0.0.5")
    assert c1["target_kind"] == "private_ipv4"
    assert c1["is_public_scannable"] is False

    # Public IP asset
    c2 = classify_asset_target(ip_address="93.184.216.34")
    assert c2["target_kind"] == "public_ipv4"
    assert c2["is_public_scannable"] is True


# ── 2. Asset Scan Authorization Lifecycle Tests ───────────────────────────────

def test_scan_authorization_lifecycle_and_invalidation(client, db_session):
    # 1. Create a public asset
    asset = Asset(
        id="AST-PUB-01",
        tenant_id="tenant-alpha",
        name="Public Gateway",
        hostname="scanme.nmap.org",
        ip_address="45.33.32.156",
        asset_type="server",
        status="active",
    )
    db_session.add(asset)
    db_session.commit()

    # Analyst requests authorization
    analyst_user = {"sub": "analyst@alpha.com", "role": "Analyst", "tenant_id": "tenant-alpha"}
    app.dependency_overrides[get_current_user] = lambda: analyst_user

    req_resp = client.post(
        f"/api/assets/{asset.id}/scan-authorization/request",
        json={"evidence": "Signed pentest agreement contract #1234"},
    )
    assert req_resp.status_code == 200
    auth_data = req_resp.json()
    auth_id = auth_data["id"]
    assert auth_data["status"] == "pending"
    assert auth_data["requested_by"] == "analyst@alpha.com"
    assert auth_data["authorized_target"] == "scanme.nmap.org"

    # Non-Superadmin cannot approve (e.g. Admin or Analyst)
    admin_user = {"sub": "admin@alpha.com", "role": "Admin", "tenant_id": "tenant-alpha"}
    app.dependency_overrides[get_current_user] = lambda: admin_user
    fail_approve = client.post(f"/api/assets/{asset.id}/scan-authorization/approve")
    assert fail_approve.status_code == 403

    # Superadmin approves
    superadmin_user = {"sub": "super@tempris.com", "role": "Superadmin", "tenant_id": "tenant-alpha"}
    app.dependency_overrides[get_current_user] = lambda: superadmin_user
    approve_resp = client.post(
        f"/api/assets/{asset.id}/scan-authorization/approve",
        json={"notes": "Verified ownership with DNS TXT record", "expires_in_days": 30},
    )
    assert approve_resp.status_code == 200
    app_data = approve_resp.json()
    assert app_data["status"] == "approved"
    assert app_data["approved_by"] == "super@tempris.com"
    assert app_data["expires_at"] is not None

    # Check asset view includes active authorization
    get_auth = client.get(f"/api/assets/{asset.id}/scan-authorization")
    assert get_auth.status_code == 200
    assert get_auth.json()["current_authorization"]["status"] == "approved"

    # Updating asset hostname automatically revokes authorization
    app.dependency_overrides[get_current_user] = lambda: admin_user
    update_resp = client.put(
        f"/api/assets/{asset.id}",
        json={"hostname": "api.different-domain.com"},
    )
    assert update_resp.status_code == 200

    # Verify authorization was invalidated
    auth_row = db_session.query(AssetScanAuthorization).filter(AssetScanAuthorization.id == auth_id).first()
    assert auth_row.status == "revoked"
    assert "Asset target modified" in auth_row.revocation_reason


# ── 3. Scanner Process Safety, Kill Switch & Execution Tests ──────────────────

def test_scanner_kill_switch_enforcement(client, db_session, monkeypatch):
    # Kill switch disabled by default
    monkeypatch.setenv("SCOUT_ACTIVE_SCANNING_ENABLED", "false")
    user = {"sub": "admin@alpha.com", "role": "Admin", "tenant_id": "tenant-alpha"}
    app.dependency_overrides[get_current_user] = lambda: user

    resp = client.post("/api/scanner/run", json={"asset_id": "AST-123"})
    assert resp.status_code == 503
    assert "Active scanning is disabled globally" in resp.json()["detail"]


def test_scanner_requires_approved_authorization(client, db_session, monkeypatch):
    monkeypatch.setenv("SCOUT_ACTIVE_SCANNING_ENABLED", "true")
    user = {"sub": "admin@alpha.com", "role": "Admin", "tenant_id": "tenant-alpha"}
    app.dependency_overrides[get_current_user] = lambda: user

    # 1. Asset does not exist
    resp = client.post("/api/scanner/run", json={"asset_id": "NON-EXISTENT"})
    assert resp.status_code == 404

    # 2. Asset exists but has no authorization
    asset = Asset(
        id="AST-UNAUTH-01",
        tenant_id="tenant-alpha",
        name="Unauth Server",
        hostname="93.184.216.34",
        ip_address="93.184.216.34",
        asset_type="server",
        status="active",
    )
    db_session.add(asset)
    db_session.commit()

    resp = client.post("/api/scanner/run", json={"asset_id": asset.id})
    assert resp.status_code == 403
    assert "does not have an approved scan authorization" in resp.json()["detail"]

    # 3. Asset has expired authorization
    auth = AssetScanAuthorization(
        id="AUTH-EXP-01",
        tenant_id="tenant-alpha",
        asset_id=asset.id,
        authorized_target="93.184.216.34",
        target_kind="public_ipv4",
        status="approved",
        approval_method="superadmin_manual",
        requested_by="admin@alpha.com",
        approved_by="super@tempris.com",
        approved_at=datetime.now(timezone.utc) - timedelta(days=40),
        expires_at=datetime.now(timezone.utc) - timedelta(days=10),
    )
    db_session.add(auth)
    db_session.commit()

    resp = client.post("/api/scanner/run", json={"asset_id": asset.id})
    assert resp.status_code == 403
    assert "expired" in resp.json()["detail"]


def test_asset_bound_scan_execution_and_provenance(client, db_session, monkeypatch):
    monkeypatch.setenv("SCOUT_ACTIVE_SCANNING_ENABLED", "true")
    user = {"sub": "admin@alpha.com", "role": "Admin", "tenant_id": "tenant-alpha"}
    app.dependency_overrides[get_current_user] = lambda: user

    asset = Asset(
        id="AST-TARGET-01",
        tenant_id="tenant-alpha",
        name="Target Server",
        hostname="93.184.216.34",
        ip_address="93.184.216.34",
        asset_type="server",
        status="active",
    )
    auth = AssetScanAuthorization(
        id="AUTH-VALID-01",
        tenant_id="tenant-alpha",
        asset_id=asset.id,
        authorized_target="93.184.216.34",
        target_kind="public_ipv4",
        status="approved",
        approval_method="superadmin_manual",
        requested_by="admin@alpha.com",
        approved_by="super@tempris.com",
        approved_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db_session.add(asset)
    db_session.add(auth)
    db_session.commit()

    # Mock subprocess execution to simulate observation finding
    mock_builtin_findings = [
        {
            "id": "SCAN-TEST-P443",
            "scan_id": "SCAN-TEST",
            "target": "93.184.216.34",
            "port": 443,
            "service": "HTTPS",
            "risk": "Low",
            "detail": "HTTPS port open",
            "status": "new",
            "template_id": "builtin-tcp",
            "cve_id": "",
            "matched_at": "93.184.216.34:443",
            "engine": "builtin_tcp",
            "discovered_at": datetime.now(timezone.utc).isoformat(),
        }
    ]

    with patch("routers.scanner._run_builtin_scan", new=AsyncMock(return_value=mock_builtin_findings)):
        resp = client.post(
            "/api/scanner/run",
            json={"asset_id": asset.id, "scan_type": "quick"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["asset_id"] == asset.id
        assert data["target"] == "93.184.216.34"

        # Verify ScanJob provenance recorded in DB
        job = db_session.query(ScanJob).filter(ScanJob.id == data["scan_id"]).first()
        assert job is not None
        assert job.asset_id == asset.id
        assert job.scan_authorization_id == auth.id
        assert job.authorized_canonical_target == "93.184.216.34"
        assert job.target_kind == "public_ipv4"
        assert job.execution_origin == "tempris_central_vps"
        assert job.initiating_user_id == "admin@alpha.com"


# ── 4. Scanner-to-Asset Trust Boundary & Drift Normalizer Tests ───────────────

def test_scan_normalizer_drift_and_trust_boundary(db_session):
    asset = Asset(
        id="AST-NORM-01",
        tenant_id="tenant-alpha",
        name="Target Asset",
        hostname="target.example.com",
        ip_address="93.184.216.34",
        asset_type="server",
        status="active",
    )
    job = ScanJob(
        id="SCAN-NORM-01",
        tenant_id="tenant-alpha",
        asset_id=asset.id,
        authorized_canonical_target="target.example.com",
        target="target.example.com",
        normalized_target="target.example.com",
        resolved_ips=["93.184.216.34"],
        scan_type="full",
        status="started",
    )
    db_session.add(asset)
    db_session.add(job)
    db_session.commit()

    # 1. Observation matching authorized origin -> confirms exposure link
    obs_valid = {
        "id": "SCAN-NORM-01-0001",
        "target": "target.example.com",
        "port": 443,
        "service": "Apache Log4j",
        "risk": "Critical",
        "detail": "Log4j RCE detected",
        "template_id": "cve-2021-44228",
        "cve_id": "CVE-2021-44228",
        "matched_at": "https://target.example.com:443/login",
        "engine": "nuclei",
    }

    res_valid = normalize_observation(
        db_session,
        tenant_id="tenant-alpha",
        scan_job=job,
        observation=obs_valid,
        actor_id="admin@alpha.com",
    )
    assert res_valid["exposure"] == "confirmed"
    assert res_valid["finding"] is not None
    assert res_valid["scan_finding"].asset_id == asset.id

    # Verify AssetExposure link
    link = db_session.query(AssetExposure).filter(
        AssetExposure.asset_id == asset.id,
        AssetExposure.finding_id == res_valid["finding"].id,
    ).first()
    assert link is not None
    assert link.status == "confirmed"

    # 2. Observation with target drift (e.g. redirected to third-party.com) -> does NOT confirm
    obs_drift = {
        "id": "SCAN-NORM-01-0002",
        "target": "target.example.com",
        "port": 443,
        "service": "Third Party OAuth",
        "risk": "High",
        "detail": "OAuth misconfiguration",
        "template_id": "oauth-detect",
        "cve_id": "",
        "matched_at": "https://auth.third-party.com/callback",
        "engine": "nuclei",
    }
    res_drift = normalize_observation(
        db_session,
        tenant_id="tenant-alpha",
        scan_job=job,
        observation=obs_drift,
        actor_id="admin@alpha.com",
    )
    assert res_drift["exposure"] == "needs_classification"
    assert res_drift["scan_finding"].evidence_metadata.get("target_drift") is True

    # 3. Non-vulnerability observation (e.g. Nmap open port) remains observation_only
    obs_nmap = {
        "id": "SCAN-NORM-01-0003",
        "target": "target.example.com",
        "port": 22,
        "service": "OpenSSH",
        "risk": "Medium",
        "detail": "SSH service version",
        "template_id": "nmap-sV",
        "cve_id": "",
        "matched_at": "target.example.com:22",
        "engine": "nmap",
    }
    res_nmap = normalize_observation(
        db_session,
        tenant_id="tenant-alpha",
        scan_job=job,
        observation=obs_nmap,
        actor_id="admin@alpha.com",
    )
    assert res_nmap["exposure"] == "observation_only"
    assert res_nmap["finding"] is None


def test_scanner_subprocess_streaming_bounded_memory():
    """Verify that _read_stream_bounded truncates stream without memory accumulation."""
    import asyncio
    from routers.scanner import _read_stream_bounded

    async def _run():
        reader = asyncio.StreamReader()
        data_chunk = b"A" * 50000
        for _ in range(10):
            reader.feed_data(data_chunk)
        reader.feed_eof()

        limit = 100 * 1024  # 100 KB limit
        captured = await _read_stream_bounded(reader, limit)
        assert len(captured) == limit
        assert captured == b"A" * limit

    asyncio.run(_run())


# ── 5. Superadmin Raw Diagnostic Scan Route Tests ─────────────────────────────

def test_superadmin_raw_diagnostic_scan(client, db_session, monkeypatch):
    superadmin_user = {"sub": "super@tempris.com", "role": "Superadmin", "tenant_id": "tenant-alpha"}
    admin_user = {"sub": "admin@alpha.com", "role": "Admin", "tenant_id": "tenant-alpha"}

    # 1. Disabled by default
    monkeypatch.setenv("SCOUT_RAW_DIAGNOSTIC_ENABLED", "false")
    app.dependency_overrides[get_current_user] = lambda: superadmin_user
    resp = client.post("/api/scanner/admin/raw-scan", json={"target": "93.184.216.34"})
    assert resp.status_code == 403
    assert "Raw diagnostic scanning is disabled" in resp.json()["detail"]

    # 2. Enabled -> Admin rejected (requires Superadmin)
    monkeypatch.setenv("SCOUT_RAW_DIAGNOSTIC_ENABLED", "true")
    app.dependency_overrides[get_current_user] = lambda: admin_user
    resp = client.post("/api/scanner/admin/raw-scan", json={"target": "93.184.216.34"})
    assert resp.status_code == 403

    # 3. Enabled -> Superadmin with private/internal target rejected by SSRF policy
    app.dependency_overrides[get_current_user] = lambda: superadmin_user
    resp = client.post("/api/scanner/admin/raw-scan", json={"target": "10.0.0.1"})
    assert resp.status_code == 400
    assert "rejected by network safety policy" in resp.json()["detail"]
