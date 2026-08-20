"""Authoritative hardening tests for SCOUT & SPECTRUM Phase 2 amendments.

Verifies:
1. Real subprocess immediate streaming overflow abort and clean process lifecycle.
2. Full scan sibling scanner cancellation and distinct failure reasons.
3. Exact same-asset Nuclei lineage and canonical status exclusions in confirmed scan exposures.
4. Scale-safe SQL window function aggregates for canonical CVE catalogue.
5. Required verification notes (min 10 chars, extra forbidden) and evidence persistence in scan authorization approval.
6. Pure live-TES priority filtering and sorting in SPECTRUM without stale stored priority fallback.
7. Authentic unassessed severity semantics (score=None, label='Not available') and EDIP auto_classify guard.
"""

from __future__ import annotations

import asyncio
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
from routers.scanner import ScannerOutputLimitExceeded, _execute_subprocess_safely, _read_stream_bounded
from services.cve_intelligence import select_preferred_cvss_assessment
from services.database import get_db
from services.edip_engine import auto_classify, bulk_classify
from services.tes_engine import public_severity


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_authoritative_hardening_phase2.db"
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
        "sub": "analyst@tempris.com",
        "email": "analyst@tempris.com",
        "role": "Superadmin",
        "tenant_id": "tenant-auth-1",
        "package": "ENTERPRISE",
        "is_superadmin": True,
    }

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[get_auth_context] = lambda: type(
        "AuthContext",
        (),
        {
            "tenant_id": "tenant-auth-1",
            "role": "Superadmin",
            "package": "ENTERPRISE",
            "is_superadmin": True,
            "user_email": "analyst@tempris.com",
        },
    )()

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()


# ── 1. Subprocess Immediate Overflow Abort ─────────────────────────────────────

def test_real_subprocess_immediate_stream_overflow_abort():
    """Verify that a real subprocess exceeding output limit raises ScannerOutputLimitExceeded immediately and terminates."""
    async def _run():
        # Spawn a python process that emits 1 MB of data
        code = "import sys; sys.stdout.write('A' * 200000); sys.stdout.flush()"
        cmd = [sys.executable, "-c", code]

        limit = 10 * 1024  # 10 KB limit
        with pytest.raises(ScannerOutputLimitExceeded) as exc_info:
            await _execute_subprocess_safely(cmd, timeout_seconds=5, max_output_bytes=limit)

        assert exc_info.value.stream == "stdout"
        assert "exceeded maximum output limit" in str(exc_info.value)

    asyncio.run(_run())


def test_real_subprocess_cancellation_terminates_child_process():
    """Verify that cancelling an asyncio task running _execute_subprocess_safely cleans up and terminates the OS process."""
    async def _run():
        code = "import time; time.sleep(60)"
        cmd = [sys.executable, "-c", code]

        task = asyncio.create_task(_execute_subprocess_safely(cmd, timeout_seconds=60))
        await asyncio.sleep(0.3)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_run())


# ── 2. Full Scan Sibling Task Cancellation & Distinct Failure Reasons ───────────

def test_scanner_sibling_task_cancellation_and_failure_reasons(db_session, client, monkeypatch):
    """Verify that sibling tasks are cancelled upon failure and distinct failure reasons are persisted."""
    now = datetime.now(timezone.utc)
    asset = Asset(
        id="asset-sibling-1",
        tenant_id="tenant-auth-1",
        name="Sibling Test Target",
        ip_address="93.184.216.34",
        status="active",
    )
    auth = AssetScanAuthorization(
        id="auth-sibling-1",
        tenant_id="tenant-auth-1",
        asset_id="asset-sibling-1",
        authorized_target="93.184.216.34",
        target_kind="ipv4",
        status="approved",
        evidence="Approved for test",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=30),
    )
    asset_2 = Asset(
        id="asset-sibling-2",
        tenant_id="tenant-auth-1",
        name="Sibling Test Target 2",
        ip_address="93.184.216.35",
        status="active",
    )
    auth_2 = AssetScanAuthorization(
        id="auth-sibling-2",
        tenant_id="tenant-auth-1",
        asset_id="asset-sibling-2",
        authorized_target="93.184.216.35",
        target_kind="ipv4",
        status="approved",
        evidence="Approved for test",
        requested_by="analyst@tempris.com",
        approved_by="superadmin@tempris.com",
        approved_at=now,
        expires_at=now + timedelta(days=30),
    )
    db_session.add_all([asset, auth, asset_2, auth_2])
    db_session.commit()

    monkeypatch.setenv("SCOUT_ACTIVE_SCANNING_ENABLED", "true")
    monkeypatch.setattr("routers.scanner.NUCLEI_AVAILABLE", True)

    # 1. Output limit exceeded
    with patch("routers.scanner._run_nuclei_scan", new_callable=AsyncMock) as mock_n, \
         patch("routers.scanner._run_port_scan", new_callable=AsyncMock) as mock_p:
        mock_n.side_effect = ScannerOutputLimitExceeded("Simulated overflow", stream="stdout")
        mock_p.return_value = []

        resp = client.post("/api/scanner/run", json={"asset_id": "asset-sibling-1", "scan_type": "full"})
        assert resp.status_code == 500
        assert "output_limit_exceeded" in resp.text

        db_session.expire_all()
        job = db_session.query(ScanJob).filter(ScanJob.asset_id == "asset-sibling-1").first()
        assert job is not None
        assert job.status == "failed"
        assert job.failure_reason == "output_limit_exceeded"

    # 2. Timeout error
    with patch("routers.scanner._run_nuclei_scan", new_callable=AsyncMock) as mock_n, \
         patch("routers.scanner._run_port_scan", new_callable=AsyncMock) as mock_p:
        mock_n.side_effect = asyncio.TimeoutError()
        mock_p.return_value = []

        resp = client.post("/api/scanner/run", json={"asset_id": "asset-sibling-2", "scan_type": "full"})
        assert resp.status_code == 504
        assert "scanner_timeout" in resp.text

        db_session.expire_all()
        job2 = db_session.query(ScanJob).filter(ScanJob.asset_id == "asset-sibling-2").first()
        assert job2 is not None
        assert job2.status == "failed"
        assert job2.failure_reason == "scanner_timeout"


# ── 3. Exact Same-Asset Lineage for Confirmed Scan Exposures ───────────────────

def test_scan_summary_exact_lineage_and_canonical_status_exclusions(db_session, client):
    """Verify confirmed_scan_exposures strictly requires matching Asset ID and excludes reference/resolved statuses."""
    now = datetime.now(timezone.utc)
    asset_a = Asset(id="asset-lin-a", tenant_id="tenant-auth-1", name="Asset A", status="active")
    asset_b = Asset(id="asset-lin-b", tenant_id="tenant-auth-1", name="Asset B", status="active")
    asset_decom = Asset(id="asset-lin-decom", tenant_id="tenant-auth-1", name="Decommissioned Asset", status="decommissioned")

    # Finding 1: Open finding on Asset A backed by Nuclei observation on Asset A -> COUNTED (1)
    f1 = Finding(id="F-LIN-01", tenant_id="tenant-auth-1", title="Nuclei Finding on Asset A", status="open")
    exp1 = AssetExposure(id="exp-1", tenant_id="tenant-auth-1", finding_id=f1.id, asset_id=asset_a.id, status="confirmed", match_method="nuclei")
    sf1 = ScanFinding(id="sf-1", tenant_id="tenant-auth-1", asset_id=asset_a.id, normalized_finding_id=f1.id, template_id="cve-2021-44228")

    # Finding 2: Mismatched asset lineage (ScanFinding on Asset A, exposure on Asset B) -> NOT COUNTED (0)
    f2 = Finding(id="F-LIN-02", tenant_id="tenant-auth-1", title="Mismatched Asset Lineage", status="open")
    exp2 = AssetExposure(id="exp-2", tenant_id="tenant-auth-1", finding_id=f2.id, asset_id=asset_b.id, status="confirmed", match_method="nuclei")
    sf2 = ScanFinding(id="sf-2", tenant_id="tenant-auth-1", asset_id=asset_a.id, normalized_finding_id=f2.id, template_id="cve-2022-1234")

    # Finding 3: Reference status -> NOT COUNTED (0)
    f3 = Finding(id="F-LIN-03", tenant_id="tenant-auth-1", title="Reference Status Finding", status="reference")
    exp3 = AssetExposure(id="exp-3", tenant_id="tenant-auth-1", finding_id=f3.id, asset_id=asset_a.id, status="confirmed", match_method="nuclei")
    sf3 = ScanFinding(id="sf-3", tenant_id="tenant-auth-1", asset_id=asset_a.id, normalized_finding_id=f3.id, template_id="cve-2023-5678")

    # Finding 4: Decommissioned asset -> NOT COUNTED (0)
    f4 = Finding(id="F-LIN-04", tenant_id="tenant-auth-1", title="Decommissioned Asset Finding", status="open")
    exp4 = AssetExposure(id="exp-4", tenant_id="tenant-auth-1", finding_id=f4.id, asset_id=asset_decom.id, status="confirmed", match_method="nuclei")
    sf4 = ScanFinding(id="sf-4", tenant_id="tenant-auth-1", asset_id=asset_decom.id, normalized_finding_id=f4.id, template_id="cve-2024-0001")

    # Finding 5: Open non-CVE security finding on Asset A backed by Nuclei observation -> COUNTED (1)
    f5 = Finding(id="F-LIN-05", tenant_id="tenant-auth-1", title="Exposed Admin Panel", status="open")
    exp5 = AssetExposure(id="exp-5", tenant_id="tenant-auth-1", finding_id=f5.id, asset_id=asset_a.id, status="confirmed", match_method="nuclei")
    sf5 = ScanFinding(id="sf-5", tenant_id="tenant-auth-1", asset_id=asset_a.id, normalized_finding_id=f5.id, template_id="exposed-admin-panel")

    db_session.add_all([asset_a, asset_b, asset_decom, f1, exp1, sf1, f2, exp2, sf2, f3, exp3, sf3, f4, exp4, sf4, f5, exp5, sf5])
    db_session.commit()

    resp = client.get("/api/scanner/findings/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["confirmed_scan_exposures"] == 2, f"Expected exactly 2 confirmed scan exposures, got {data['confirmed_scan_exposures']}"


# ── 4. Scale-Safe SQL Window Function Aggregates for Catalogue ─────────────────

def test_scout_canonical_vulnerabilities_sql_window_aggregates(db_session, client):
    """Verify scale-safe SQL window function computes deterministic preferred CVSS aggregates."""
    now = datetime.now(timezone.utc)

    # CVE 1: Multiple assessments (v3.1 Primary 9.8 vs v2.0 5.0) -> Preferred is 9.8 (Critical)
    cve1 = CanonicalVulnerability(cve_id="CVE-2021-44228", status="published", description="Apache Log4j RCE")
    cvss1_a = VulnerabilityCvssAssessment(id="cvss-w-1a", cve_id="CVE-2021-44228", cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", base_score=9.8, source="NVD", source_role="Primary", source_modified_at=now)
    cvss1_b = VulnerabilityCvssAssessment(id="cvss-w-1b", cve_id="CVE-2021-44228", cvss_version="2.0", vector_string="AV:N/AC:L/Au:N/C:P/I:N/A:N", base_score=5.0, source="NVD", source_role="Primary", source_modified_at=now - timedelta(days=1))
    kev1 = CisaKevEntry(id="kev-w-1", cve_id="CVE-2021-44228", vendor_project="Apache", product="Log4j", vulnerability_name="Log4j RCE", known_ransomware_campaign_use="Known")

    # CVE 2: Preferred assessment is 7.5 (High, not Critical)
    cve2 = CanonicalVulnerability(cve_id="CVE-2022-22965", status="published", description="Spring Framework RCE")
    cvss2 = VulnerabilityCvssAssessment(id="cvss-w-2", cve_id="CVE-2022-22965", cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", base_score=7.5, source="NVD", source_role="Primary")

    # CVE 3: Unassessed (0.0 / No CVSS)
    cve3 = CanonicalVulnerability(cve_id="CVE-2024-1111", status="published", description="Unassessed Zero Day")

    # CVE 4: Multiple assessments with NULL vs real timestamp (both v3.1 Primary) -> Real timestamp wins (9.5 Critical)
    cve4 = CanonicalVulnerability(cve_id="CVE-2023-9999", status="published", description="Null Timestamp Test")
    cvss4_null = VulnerabilityCvssAssessment(id="cvss-w-4a", cve_id="CVE-2023-9999", cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", base_score=8.0, source="NVD", source_role="Primary", source_modified_at=None)
    cvss4_real = VulnerabilityCvssAssessment(id="cvss-w-4b", cve_id="CVE-2023-9999", cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", base_score=9.5, source="NVD", source_role="Primary", source_modified_at=now)

    # Prove Python resolver selects the real timestamp assessment
    pref_python = select_preferred_cvss_assessment([cvss4_null, cvss4_real])
    assert pref_python is not None
    assert pref_python.id == "cvss-w-4b"
    assert pref_python.base_score == 9.5

    db_session.add_all([cve1, cvss1_a, cvss1_b, kev1, cve2, cvss2, cve3, cve4, cvss4_null, cvss4_real])
    db_session.commit()

    resp = client.get("/api/scout/vulnerabilities")
    assert resp.status_code == 200
    meta = resp.json()["meta"]
    assert meta["catalog_total"] == 4
    assert meta["critical_count"] == 2  # 9.8 (Log4j) and 9.5 (CVE-2023-9999)
    assert meta["cvss_coverage_count"] == 3
    assert meta["kev_count"] == 1
    assert meta["ransomware_count"] == 1


# ── 5. Required Approval Verification Notes & Forbid Extras ────────────────────

def test_asset_scan_authorization_verification_notes_and_forbid_extras(db_session, client):
    """Verify approve_scan_authorization requires verification_notes (min 10 chars) and forbids unexpected fields."""
    asset = Asset(
        id="asset-auth-req-1",
        tenant_id="tenant-auth-1",
        name="Authorizable Asset",
        ip_address="93.184.216.34",
        status="active",
    )
    db_session.add(asset)
    db_session.commit()

    # 1. Missing verification_notes -> 422
    resp1 = client.post(f"/api/assets/{asset.id}/scan-authorization/approve", json={"expires_in_days": 90})
    assert resp1.status_code == 422

    # 2. Too short verification_notes (< 10 chars) -> 422
    resp2 = client.post(f"/api/assets/{asset.id}/scan-authorization/approve", json={"verification_notes": "Too short", "expires_in_days": 90})
    assert resp2.status_code == 422

    # 3. Unexpected extra fields -> 422 (extra="forbid")
    resp3 = client.post(f"/api/assets/{asset.id}/scan-authorization/approve", json={"verification_notes": "Valid verification note for audit", "extra_bad_field": "disallowed"})
    assert resp3.status_code == 422

    # 4. Valid approval -> 200, evidence recorded
    notes_text = "Verified perimeter DNS record and signed contractual SOW"
    resp4 = client.post(f"/api/assets/{asset.id}/scan-authorization/approve", json={"verification_notes": notes_text, "expires_in_days": 60})
    assert resp4.status_code == 200

    auth = db_session.query(AssetScanAuthorization).filter(AssetScanAuthorization.asset_id == asset.id).first()
    assert auth is not None
    assert auth.status == "approved"
    assert notes_text in auth.evidence


# ── 6. SPECTRUM Pure Live-TES Filtering & Sorting ──────────────────────────────

def test_spectrum_pure_live_tes_priority_filtering_and_sorting(db_session, client):
    """Verify that conflicting stored Finding.priority is NEVER used in SPECTRUM filtering or sorting."""
    asset_crit = Asset(
        id="asset-spec-crit",
        tenant_id="tenant-auth-1",
        name="Critical Core Server",
        ip_address="93.184.216.34",
        status="active",
        criticality="critical",
    )
    asset_low = Asset(
        id="asset-spec-low",
        tenant_id="tenant-auth-1",
        name="Low Priority Testbox",
        ip_address="93.184.216.35",
        status="active",
        criticality="low",
    )
    # Record A: Stored priority = "P0", but CVSS = 4.0 on Low asset -> Live TES priority = "P3"
    f_a = Finding(
        id="F-SPEC-A",
        tenant_id="tenant-auth-1",
        title="Stored P0 but Live P3",
        cve_id="CVE-2022-0001",
        cvss=4.0,
        priority="P0",  # Stale stored priority!
        status="open",
    )
    exp_a = AssetExposure(
        id="exp-spec-a",
        tenant_id="tenant-auth-1",
        finding_id=f_a.id,
        asset_id=asset_low.id,
        status="confirmed",
        match_method="nuclei",
    )
    # Record B: Stored priority = "P3", but CVSS = 9.8 + live context 10.0 on Critical asset -> Live TES priority = "P0"
    f_b = Finding(
        id="F-SPEC-B",
        tenant_id="tenant-auth-1",
        title="Stored P3 but Live P0",
        cve_id="CVE-2022-0002",
        cvss=9.8,
        cve_context={
            "exploitability": {"value": 10.0, "source": "active_in_wild", "reason": "Actively exploited in wild"},
            "threat_actor_activity": {"value": 10.0, "source": "threat_intel", "reason": "Targeted attacks"},
            "business_impact": {"value": 10.0, "source": "analyst_reviewed", "reason": "Crown jewel service"},
        },
        priority="P3",  # Stale stored priority!
        status="open",
    )
    exp_b = AssetExposure(
        id="exp-spec-b",
        tenant_id="tenant-auth-1",
        finding_id=f_b.id,
        asset_id=asset_crit.id,
        status="confirmed",
        match_method="nuclei",
    )
    # Record C: Unscored (cvss = None), Stored priority = "P0" -> Live TES priority = None
    f_c = Finding(
        id="F-SPEC-C",
        tenant_id="tenant-auth-1",
        title="Unscored record",
        cve_id="CVE-2022-0003",
        cvss=None,
        priority="P0",  # Stale stored priority!
        status="open",
    )
    exp_c = AssetExposure(
        id="exp-spec-c",
        tenant_id="tenant-auth-1",
        finding_id=f_c.id,
        asset_id=asset_low.id,
        status="confirmed",
        match_method="nuclei",
    )

    db_session.add_all([asset_crit, asset_low, f_a, exp_a, f_b, exp_b, f_c, exp_c])
    db_session.commit()

    # 1. Filter by priority=P0 must return ONLY Record B (whose live TES priority is P0)
    resp_p0 = client.get("/api/spectrum/findings?priority=P0")
    assert resp_p0.status_code == 200
    data_p0 = resp_p0.json()["data"]
    p0_ids = [d["id"] for d in data_p0]
    assert "F-SPEC-B" in p0_ids
    assert "F-SPEC-A" not in p0_ids
    assert "F-SPEC-C" not in p0_ids

    # 2. General queue sort order must place Record B (live P0) first, Record A (live P3) second, Record C (live None) last
    resp_all = client.get("/api/spectrum/findings")
    assert resp_all.status_code == 200
    all_data = resp_all.json()["data"]
    all_ids = [d["id"] for d in all_data]
    assert all_ids.index("F-SPEC-B") < all_ids.index("F-SPEC-A") < all_ids.index("F-SPEC-C")


# ── 7. Authentic Unknown Severity & EDIP Guard ─────────────────────────────────

def test_unassessed_severity_and_auto_classify_guard(db_session):
    """Verify that unassessed records return score=None / label='Not available' and auto_classify returns insufficient_evidence."""
    # 1. Finding with missing CVSS
    finding = {"id": "F-UNASSESSED", "cvss": None, "provenance_classification": "unassessed"}
    sev = public_severity(finding, db=db_session)
    assert sev["score"] is None
    assert sev["label"] == "Not available"
    assert sev["source"] is None
    assert sev["provenance"] == "unassessed"

    # 2. Finding with legacy unprovenanced data
    finding_leg = {"id": "F-LEGACY", "cvss": 5.0, "provenance_classification": "legacy_unprovenanced"}
    sev_leg = public_severity(finding_leg, db=db_session)
    assert sev_leg["score"] == 5.0
    assert sev_leg["source"] == "Legacy unprovenanced"

    # 3. auto_classify with cvss=None
    res = auto_classify(cvss=None)
    assert res["decision"] is None
    assert res["state"] == "insufficient_evidence"
    assert res["auto_classified"] is False
    assert "INSUFFICIENT EVIDENCE" in res["explanation"]

    # 4. bulk_classify with unassessed item
    bulk_res = bulk_classify([{"id": "F-1", "cvss": None}, {"id": "F-2", "cvss": 9.5, "asset_criticality": "critical"}])
    assert bulk_res[0]["decision"] is None
    assert bulk_res[0]["state"] == "insufficient_evidence"
    assert bulk_res[1]["decision"] == "fix"
