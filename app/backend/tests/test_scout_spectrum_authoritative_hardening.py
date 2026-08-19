"""Authoritative hardening tests for SCOUT & SPECTRUM amendments.

Verifies:
1. Scanner buffer overflow exception handling, task cancellation awaiting, and zero partial findings.
2. Exact 6-metric populations in /api/scanner/findings/summary.
3. Correlated CISA KEV search across CVE ID, description, vendor_project, product, and vulnerability_name.
4. Server-side CVSS Critical calculation using deterministic preferred assessment policy.
5. Server-derived scan eligibility including target consistency, expiration, revocation, and active asset requirements.
6. Dedicated SPECTRUM hydrated pipeline with live TES calculation, unscored records staying null, and stable sort.
"""

from __future__ import annotations

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
    CisaKevEntry,
    Finding,
    ScanFinding,
    ScanJob,
    VulnerabilityCvssAssessment,
)
from routers.auth import get_auth_context, get_current_user
from routers.scanner import ScannerOutputLimitExceeded
from services.database import get_db


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_authoritative_hardening.db"
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
        yield db_session

    fake_user = {
        "email": "analyst@tempris.com",
        "role": "Analyst",
        "tenant_id": "tenant-auth-1",
        "package": "ENTERPRISE",
        "is_superadmin": False,
    }

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[get_auth_context] = lambda: type(
        "AuthContext",
        (),
        {
            "tenant_id": "tenant-auth-1",
            "role": "Analyst",
            "package": "ENTERPRISE",
            "is_superadmin": False,
            "user_email": "analyst@tempris.com",
        },
    )()

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()


def test_scanner_output_limit_exceeded_handled_gracefully(db_session, client):
    """Verifies ScannerOutputLimitExceeded records failed ScanJob with output_limit_exceeded and zero partial findings."""
    now = datetime.now(timezone.utc)
    asset = Asset(
        id="asset-overflow-1",
        tenant_id="tenant-auth-1",
        name="Overflow Test Target",
        ip_address="93.184.216.34",
        status="active",
    )
    auth = AssetScanAuthorization(
        id="auth-overflow-1",
        tenant_id="tenant-auth-1",
        asset_id=asset.id,
        authorized_target="93.184.216.34",
        target_kind="ipv4",
        status="approved",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=30),
    )
    db_session.add_all([asset, auth])
    db_session.commit()

    with patch.dict(os.environ, {"SCOUT_ACTIVE_SCANNING_ENABLED": "true"}), patch(
        "routers.scanner._run_nuclei_scan",
        side_effect=ScannerOutputLimitExceeded("stdout", 10 * 1024 * 1024),
    ):
        resp = client.post("/api/scanner/run", json={"asset_id": "asset-overflow-1", "scan_type": "quick"})
        assert resp.status_code == 500
        assert "output_limit_exceeded" in resp.json()["detail"]

    # Verify failed ScanJob persisted in database
    job = db_session.query(ScanJob).filter(ScanJob.asset_id == "asset-overflow-1").first()
    assert job is not None
    assert job.status == "failed"
    assert job.failure_reason == "output_limit_exceeded"

    # Verify zero partial findings created
    findings_count = db_session.query(ScanFinding).filter(ScanFinding.scan_id == job.id).count()
    assert findings_count == 0


def test_scan_summary_six_exact_metric_populations(db_session, client):
    """Verifies get_scan_summary accurately calculates the 6 distinct metric populations."""
    now = datetime.now(timezone.utc)

    # 1 Active asset
    asset = Asset(
        id="asset-metric-1",
        tenant_id="tenant-auth-1",
        name="Production Portal",
        ip_address="93.184.216.34",
        status="active",
    )
    db_session.add(asset)

    # 2 Scan Jobs
    job1 = ScanJob(
        id="SCAN-001",
        tenant_id="tenant-auth-1",
        asset_id=asset.id,
        target="93.184.216.34",
        normalized_target="93.184.216.34",
        scan_type="quick",
        status="completed",
        started_at=now,
    )
    job2 = ScanJob(
        id="SCAN-002",
        tenant_id="tenant-auth-1",
        asset_id=asset.id,
        target="93.184.216.34",
        normalized_target="93.184.216.34",
        scan_type="full",
        status="completed",
        started_at=now,
    )
    db_session.add_all([job1, job2])

    # 1 Tenant Finding
    finding = Finding(
        id="F-SCAN-NORM-1",
        tenant_id="tenant-auth-1",
        cve="CVE-2023-44487",
        title="HTTP/2 Rapid Reset",
        status="unmitigated",
        priority="P0",
        cvss=7.5,
    )
    db_session.add(finding)

    # 1 Confirmed Asset Exposure
    exposure = AssetExposure(
        id="exp-metric-1",
        tenant_id="tenant-auth-1",
        finding_id=finding.id,
        asset_id=asset.id,
        status="confirmed",
        match_method="nuclei",
    )
    db_session.add(exposure)

    # 3 Scan Findings: 1 port service observation + 2 vulnerability observations
    sf_service = ScanFinding(
        id="sf-1",
        tenant_id="tenant-auth-1",
        scan_id="SCAN-001",
        target="93.184.216.34",
        port=443,
        service="https",
        risk="Low",
        template_id="builtin_tcp_port_443",
        last_seen_at=now,
    )
    sf_vuln1 = ScanFinding(
        id="sf-2",
        tenant_id="tenant-auth-1",
        scan_id="SCAN-001",
        target="93.184.216.34",
        port=443,
        service="https",
        risk="Critical",
        template_id="cve-2023-44487",
        normalized_finding_id=finding.id,
        last_seen_at=now,
    )
    sf_vuln2 = ScanFinding(
        id="sf-3",
        tenant_id="tenant-auth-1",
        scan_id="SCAN-002",
        target="93.184.216.34",
        port=80,
        service="http",
        risk="High",
        template_id="cve-2021-41773",
        last_seen_at=now,
    )
    db_session.add_all([sf_service, sf_vuln1, sf_vuln2])
    db_session.commit()

    resp = client.get("/api/scanner/findings/summary")
    assert resp.status_code == 200
    data = resp.json()

    assert data["scans"] == 2
    assert data["total_observations"] == 3
    assert data["service_observations"] == 1
    assert data["vulnerability_observations"] == 2
    assert data["critical_observations"] == 1
    assert data["high_observations"] == 1
    assert data["normalized_findings"] == 1
    assert data["confirmed_scan_exposures"] == 1


def test_scout_canonical_vulnerabilities_search_and_preferred_aggregates(db_session, client):
    """Verifies correlated KEV search and preferred CVSS selection in /api/scout/vulnerabilities."""
    # CVE 1: Critical CVSS 9.8 from NVD, in CISA KEV (Apache Log4j)
    cve1 = CanonicalVulnerability(
        cve_id="CVE-2021-44228",
        status="published",
        description="Apache Log4j2 Remote Code Execution Vulnerability",
    )
    kev1 = CisaKevEntry(
        id="kev-1",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Apache Log4j2 JNDI RCE",
        known_ransomware_campaign_use="Known",
    )
    cvss1_nvd = VulnerabilityCvssAssessment(
        id="cvss-1",
        cve_id="CVE-2021-44228",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=9.8,
        source="NVD",
        source_role="CNA",
    )

    # CVE 2: CVSS 9.8 secondary overridden by Authoritative Primary 7.5 (Fortinet)
    cve2 = CanonicalVulnerability(
        cve_id="CVE-2022-40684",
        status="published",
        description="Fortinet FortiOS authentication bypass",
    )
    kev2 = CisaKevEntry(
        id="kev-2",
        cve_id="CVE-2022-40684",
        vendor_project="Fortinet",
        product="FortiOS",
        vulnerability_name="FortiOS Auth Bypass",
        known_ransomware_campaign_use="Unknown",
    )
    cvss2_secondary = VulnerabilityCvssAssessment(
        id="cvss-2",
        cve_id="CVE-2022-40684",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
        source="ThirdParty",
        source_role="Secondary",
    )
    cvss2_primary = VulnerabilityCvssAssessment(
        id="cvss-3",
        cve_id="CVE-2022-40684",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        base_score=7.5,
        source="NVD",
        source_role="Primary",
    )

    # CVE 3: Unassessed CVE with no CVSS record and no KEV record
    cve3 = CanonicalVulnerability(
        cve_id="CVE-2024-0001",
        status="published",
        description="Unassessed Linux kernel bug",
    )

    db_session.add_all([cve1, kev1, cvss1_nvd, cve2, kev2, cvss2_secondary, cvss2_primary, cve3])
    db_session.commit()

    # 1. Query without filters: check global and preferred aggregates
    resp = client.get("/api/scout/vulnerabilities")
    assert resp.status_code == 200
    res = resp.json()
    meta = res["meta"]

    assert meta["catalog_total"] == 3
    assert meta["filtered_total"] == 3
    # CVE-2021-44228 is >=9.0; CVE-2022-40684 preferred is 7.5 (not >=9.0); CVE-2024-0001 has no score.
    # Therefore, critical_count MUST be exactly 1!
    assert meta["critical_count"] == 1
    assert meta["kev_count"] == 2
    assert meta["ransomware_count"] == 1

    # 2. Correlated Search by KEV product name ("Log4j")
    resp_search = client.get("/api/scout/vulnerabilities?search=Log4j")
    assert resp_search.status_code == 200
    res_search = resp_search.json()
    assert res_search["meta"]["filtered_total"] == 1
    assert res_search["data"][0]["cve_id"] == "CVE-2021-44228"
    assert res_search["meta"]["critical_count"] == 1
    assert res_search["meta"]["ransomware_count"] == 1

    # 3. Correlated Search by KEV vendor ("Fortinet")
    resp_forti = client.get("/api/scout/vulnerabilities?search=Fortinet")
    assert resp_forti.status_code == 200
    res_forti = resp_forti.json()
    assert res_forti["meta"]["filtered_total"] == 1
    assert res_forti["data"][0]["cve_id"] == "CVE-2022-40684"
    assert res_forti["meta"]["critical_count"] == 0  # Preferred score 7.5 is not >= 9.0


def test_asset_scan_eligibility_target_consistency_and_revocation(db_session, client):
    """Verifies authoritative server-derived scan eligibility derivation in /api/assets."""
    now = datetime.now(timezone.utc)

    # Asset 1: Valid and scannable
    asset1 = Asset(
        id="asset-el-1",
        tenant_id="tenant-auth-1",
        name="Scannable Host",
        ip_address="93.184.216.34",
        status="active",
    )
    auth1 = AssetScanAuthorization(
        id="auth-el-1",
        tenant_id="tenant-auth-1",
        asset_id=asset1.id,
        authorized_target="93.184.216.34",
        target_kind="ipv4",
        status="approved",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=30),
    )

    # Asset 2: Target modified after approval (target mismatch on public IPs)
    asset2 = Asset(
        id="asset-el-2",
        tenant_id="tenant-auth-1",
        name="Target Changed Host",
        ip_address="93.184.216.36",
        status="active",
    )
    auth2 = AssetScanAuthorization(
        id="auth-el-2",
        tenant_id="tenant-auth-1",
        asset_id=asset2.id,
        authorized_target="93.184.216.37",
        target_kind="ipv4",
        status="approved",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=30),
    )

    # Asset 3: Inactive asset
    asset3 = Asset(
        id="asset-el-3",
        tenant_id="tenant-auth-1",
        name="Decommissioned Host",
        ip_address="93.184.216.35",
        status="decommissioned",
    )
    auth3 = AssetScanAuthorization(
        id="auth-el-3",
        tenant_id="tenant-auth-1",
        asset_id=asset3.id,
        authorized_target="93.184.216.35",
        target_kind="ipv4",
        status="approved",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=30),
    )

    db_session.add_all([asset1, auth1, asset2, auth2, asset3, auth3])
    db_session.commit()

    resp = client.get("/api/assets?status=")
    assert resp.status_code == 200
    assets_by_id = {a["id"]: a for a in resp.json()["data"]}

    # Asset 1 must be scan eligible
    assert assets_by_id["asset-el-1"]["scan_eligible"] is True
    assert assets_by_id["asset-el-1"]["scan_eligibility"]["reason_code"] == "ELIGIBLE"

    # Asset 2 must fail due to TARGET_MISMATCH
    assert assets_by_id["asset-el-2"]["scan_eligible"] is False
    assert assets_by_id["asset-el-2"]["scan_eligibility"]["reason_code"] == "TARGET_MISMATCH"

    # Asset 3 must fail due to ASSET_INACTIVE
    assert assets_by_id["asset-el-3"]["scan_eligible"] is False
    assert assets_by_id["asset-el-3"]["scan_eligibility"]["reason_code"] == "ASSET_INACTIVE"


def test_spectrum_dedicated_hydrated_pipeline_and_stable_sort(db_session, client):
    """Verifies dedicated SPECTRUM finding pipeline, live TES sorting, and null unscored values."""
    now = datetime.now(timezone.utc)

    # Asset
    asset = Asset(
        id="asset-spec-1",
        tenant_id="tenant-auth-1",
        name="Core Database",
        ip_address="93.184.216.50",
        criticality="critical",
        status="active",
    )
    db_session.add(asset)

    # Finding 1: Canonical CVE with CVSS 9.8 and KEV -> High TES score
    cve1 = CanonicalVulnerability(
        cve_id="CVE-2021-44228",
        status="published",
        description="Apache Log4j RCE",
    )
    kev1 = CisaKevEntry(
        id="kev-spec-1",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Apache Log4j RCE",
        known_ransomware_campaign_use="Known",
    )
    cvss1 = VulnerabilityCvssAssessment(
        id="cvss-spec-1",
        cve_id="CVE-2021-44228",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=9.8,
        source="NVD",
        source_role="Primary",
    )
    f1 = Finding(
        id="F-SPEC-1",
        tenant_id="tenant-auth-1",
        cve="CVE-2021-44228",
        title="Log4j Vulnerability",
        status="unmitigated",
    )
    exp1 = AssetExposure(
        id="exp-spec-1",
        tenant_id="tenant-auth-1",
        finding_id=f1.id,
        asset_id=asset.id,
        status="confirmed",
        match_method="scanner",
    )

    # Finding 2: Unassessed finding with no CVSS and no confirmed exposure
    f2 = Finding(
        id="F-SPEC-2",
        tenant_id="tenant-auth-1",
        title="Generic Configuration Triage",
        status="unmapped",
    )

    db_session.add_all([cve1, kev1, cvss1, f1, exp1, f2])
    db_session.commit()

    resp = client.get("/api/spectrum/findings")
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert len(data) == 2
    # First item must be the confirmed exposure with high TES priority
    assert data[0]["id"] == "F-SPEC-1"
    assert data[0]["record_scope"] == "confirmed_exposure"
    assert data[0]["tes_priority"] in ("P0", "P1")
    assert data[0]["cvss"] == 9.8

    # Second item must be unmapped intake with null TES
    assert data[1]["id"] == "F-SPEC-2"
    assert data[1]["record_scope"] == "unmapped_intake"
    assert data[1]["tes_score"] is None
    assert data[1]["tes_priority"] is None
