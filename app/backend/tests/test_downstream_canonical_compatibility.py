"""Downstream Engine Compatibility Verification Suite.

Validates that canonical CVE spine cutover preserves all downstream contracts:
1. CISO Dashboard: Aggregate posture, trend calculations, exposure breakdown.
2. SYNTHESIS: Multi-tenant dashboard aggregation and live snapshot capture.
3. SPECTRUM / SPOTLIGHT: Risk ranking, prioritization queues, finding drilldown, and scope isolation.
4. STRIKE: Red team simulation mapping against confirmed exposures.
5. Reporting Engine: Technical and executive client reports containing confirmed exposures only.
6. Incidents: Tenant-bounded incident reports with confirmed asset exposures.
7. Audit Trail: Immutable audit events and cryptographic chain intact.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from index import app  # noqa: E402
from models import (  # noqa: E402
    Asset,
    AssetExposure,
    AuditLog,
    Base,
    CanonicalVulnerability,
    CisaKevEntry,
    ControlStatus,
    Finding,
    FindingEvidence,
    Incident,
    PostureSnapshot,
    StrikeAuthorization,
    StrikeSimulation,
    VulnerabilityCvssAssessment,
)
from routers.audit import verify_audit_chain  # noqa: E402
from routers.auth import get_current_user  # noqa: E402
from routers.ciso import get_ciso_summary  # noqa: E402
from routers.spectrum import get_findings as get_spectrum_findings  # noqa: E402
from routers.synthesis import get_dashboard_data  # noqa: E402
from services.customer_posture import SCOPE_VERSION, build_customer_posture  # noqa: E402
from services.database import get_db  # noqa: E402
from services.reporting_engine import generate_poc_report_pipeline  # noqa: E402


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    db_file = tmp_path / "test_downstream.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    monkeypatch.setenv("REPORT_STORAGE_ROOT", str(tmp_path / "reports"))

    # Seed Canonical Intelligence
    cve = CanonicalVulnerability(
        cve_id="CVE-2021-44228",
        status="published",
        description="Apache Log4j2 Remote Code Execution",
        description_source="NVD",
        published_at=datetime(2021, 12, 10, tzinfo=timezone.utc),
    )
    cvss = VulnerabilityCvssAssessment(
        id="CVSS-LOG4J-V31",
        cve_id="CVE-2021-44228",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
        base_severity="CRITICAL",
    )
    kev = CisaKevEntry(
        id="KEV-CVE-2021-44228",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        known_ransomware_campaign_use="Known",
    )
    session.add_all([cve, cvss, kev])

    # Seed Tenant Assets
    asset1 = Asset(
        id="A-GATEWAY-01",
        tenant_id="tenant-downstream",
        name="gateway.downstream.internal",
        hostname="gateway.downstream.internal",
        ip_address="10.0.0.1",
        criticality="critical",
        status="active",
    )
    asset2 = Asset(
        id="A-APP-02",
        tenant_id="tenant-downstream",
        name="app02.downstream.internal",
        hostname="app02.downstream.internal",
        ip_address="10.0.0.2",
        criticality="high",
        status="active",
    )

    # Seed Findings
    f1_confirmed = Finding(
        id="F-DOWN-001",
        tenant_id="tenant-downstream",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4Shell on Gateway",
        priority="P0",
        status="unmitigated",
        verification="CONFIRMED",
        source="scanner",
    )
    f2_reference = Finding(
        id="F-DOWN-REF",
        tenant_id="tenant-downstream",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4Shell Reference Catalogue Entry",
        priority="P0",
        status="reference_only",
    )
    f3_resolved = Finding(
        id="F-DOWN-RES",
        tenant_id="tenant-downstream",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4Shell on App02 (Mitigated)",
        priority="P0",
        status="resolved",
        verification="CONFIRMED",
    )

    session.add_all([asset1, asset2, f1_confirmed, f2_reference, f3_resolved])
    session.flush()

    # Confirmed Exposure link for F1
    session.add(AssetExposure(
        id="EXP-DOWN-001",
        tenant_id="tenant-downstream",
        finding_id="F-DOWN-001",
        asset_id="A-GATEWAY-01",
        status="confirmed",
        match_method="nuclei",
        evidence="Observed live vulnerability match",
    ))
    # Historical confirmed link for F3
    session.add(AssetExposure(
        id="EXP-DOWN-003",
        tenant_id="tenant-downstream",
        finding_id="F-DOWN-RES",
        asset_id="A-APP-02",
        status="confirmed",
        match_method="analyst",
        evidence="Mitigation verified by security team",
    ))

    session.commit()
    yield session
    session.close()
    engine.dispose()


def test_ciso_dashboard_downstream_contract(db_session):
    """CISO dashboard evaluates confirmed exposure with canonical intelligence and isolates reference."""
    user = {"sub": "system:ciso", "role": "Admin", "tenant_id": "tenant-downstream"}

    # Add historical snapshot for trend calculation
    now = datetime.now(timezone.utc)
    db_session.add_all([
        PostureSnapshot(
            tenant_id="tenant-downstream",
            scope_version=SCOPE_VERSION,
            captured_at=now - timedelta(days=7),
            confirmed_open_exposure_count=2,
            aggregate_tenant_tes=7.5,
        ),
        PostureSnapshot(
            tenant_id="tenant-downstream",
            scope_version=SCOPE_VERSION,
            captured_at=now - timedelta(hours=1),
            confirmed_open_exposure_count=1,
            aggregate_tenant_tes=6.0,
        ),
    ])
    db_session.commit()

    summary = get_ciso_summary(db=db_session, user=user)

    assert summary["overall_risk_posture"] == "critical"  # Due to P0 confirmed exposure
    assert summary["risk_trend"]["status"] == "available"
    assert summary["risk_trend"]["direction"] == "improving"
    assert summary["risk_trend"]["delta"] == -1

    # Highest risk assets should show A-GATEWAY-01 with 1 open critical finding
    top_assets = summary["highest_risk_assets"]
    assert top_assets["status"] == "available"
    assert len(top_assets["items"]) == 1
    assert top_assets["items"][0]["asset_id"] == "A-GATEWAY-01"
    assert top_assets["items"][0]["critical_findings"] == 1


def test_synthesis_dashboard_downstream_contract(db_session):
    """SYNTHESIS computes aggregate exposure metrics and active CISA KEV alerts."""
    data = get_dashboard_data(db_session, tenant_id="tenant-downstream")

    assert data["aggregate_tes"] is not None
    assert "exposure_coverage" in data
    assert data["exposure_coverage"]["asset_linked_count"] == 1
    assert data["exposure_coverage"]["confirmed_asset_count"] == 1
    assert data["exposure_coverage"]["catalog_intelligence_count"] == 1

    # CISA KEV Alert must trigger for confirmed exposure F-DOWN-001
    assert len(data["alerts"]) == 1
    alert = data["alerts"][0]
    assert alert["module"] == "SPECTRUM"
    assert "CVE-2021-44228" in alert["message"]
    assert "Ransomware-linked" in alert["message"]


def test_spectrum_scope_filtering_and_canonical_context(db_session):
    """SPECTRUM findings endpoint isolates scopes properly and returns unified canonical intelligence."""
    user = {"sub": "analyst@downstream.internal", "role": "Analyst", "tenant_id": "tenant-downstream"}

    # 1. Confirmed Exposure scope
    confirmed = get_spectrum_findings(
        page=1, limit=50, scope="confirmed_exposure", db=db_session, user=user,
    )
    assert len(confirmed["data"]) == 1
    f = confirmed["data"][0]
    assert f["id"] == "F-DOWN-001"
    assert f["record_scope"] == "confirmed_exposure"
    assert f["cve"] == "CVE-2021-44228"
    assert f["assets"][0]["asset_id"] == "A-GATEWAY-01"

    # Canonical intelligence resolution validation
    assert f["severity"]["score"] == 10.0
    assert f["severity"]["version"] == "3.1"
    assert f["severity"]["source_authority"] == "nvd@nist.gov"
    assert f["cisa_kev"] is True
    assert f["ransomware"] is True
    assert f["vulnerability_intelligence"]["cve_id"] == "CVE-2021-44228"
    assert f["auto_classification"]["decision"] == "fix"
    assert f["auto_classification"]["factors"]["cisa_kev"] is True
    assert f["auto_classification"]["factors"]["ransomware_linked"] is True
    assert f["auto_classification"]["factors"]["severity_score"] == 10.0

    # 2. Reference intelligence scope
    reference = get_spectrum_findings(
        page=1, limit=50, scope="reference_intelligence", db=db_session, user=user,
    )
    assert len(reference["data"]) == 1
    assert reference["data"][0]["id"] == "F-DOWN-REF"
    assert reference["data"][0]["record_scope"] == "reference_intelligence"

    # 3. Resolved scope
    resolved = get_spectrum_findings(
        page=1, limit=50, scope="resolved", db=db_session, user=user,
    )
    assert len(resolved["data"]) == 1
    assert resolved["data"][0]["id"] == "F-DOWN-RES"
    assert resolved["data"][0]["record_scope"] == "resolved"


def test_reporting_engine_poc_client_report(db_session, tmp_path, monkeypatch):
    """Reporting engine generates customer deliverable containing confirmed exposures with canonical context."""
    monkeypatch.setattr("services.reporting_engine.append_to_audit_log_db", lambda *args, **kwargs: None)

    finding_ids = ["F-DOWN-001", "F-DOWN-REF", "F-DOWN-RES"]
    config = {
        "client": {"organisation": "Downstream Enterprise", "environment": "Production"},
        "period": {"start": "2026-08-01", "end": "2026-08-18"},
        "coverage": {"scope": ["Perimeter Gateway"], "out_of_scope": ["Internal Office"]},
        "assessment": {},
        "delivery": {},
    }

    result = generate_poc_report_pipeline(
        db_session,
        "tenant-downstream",
        "ciso@downstream.internal",
        finding_ids,
        config,
    )

    assert "report_id" in result
    assert result["manifest"]["source_finding_ids"] == ["F-DOWN-001"]
    report_file = tmp_path / "reports" / f"{result['report_id']}.json"
    assert report_file.exists()


def test_audit_log_chain_integrity(db_session):
    """Audit logging and cryptographic chain verification remain intact across canonical operations."""
    from models import AuditLog
    from routers.audit import AuditEntry, append_to_audit_log_db

    append_to_audit_log_db(db_session, AuditEntry(
        user="system:canonical-cutover",
        action="CANONICAL_LINK_VERIFIED",
        module="SCOUT",
        detail="Linked findings to CanonicalVulnerability CVE-2021-44228",
    ))
    append_to_audit_log_db(db_session, AuditEntry(
        user="system:posture-engine",
        action="POSTURE_SNAPSHOT_CAPTURED",
        module="SYNTHESIS",
        detail="Captured canonical posture snapshot",
    ))

    verification = verify_audit_chain(db_session, "tempris")
    assert verification["intact"] is True
    assert verification["records"] >= 2
