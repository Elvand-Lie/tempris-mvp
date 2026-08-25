"""Tests for Synthesis Semantics and Global Vulnerability Intelligence.

Validates core semantic invariants:
1. Global intelligence aggregates come strictly from canonical tables; tenant noise never affects them.
2. Global intelligence cvss_critical_canonical_cves strictly evaluates preferred CVSS assessment.
3. Reference-only, N/A, resolved, and unlinked findings are excluded from confirmed exposures.
4. TES coverage denominator = confirmed open customer exposures; scoring_coverage_pct = scored / denominator.
5. Tenant TES is the mean of scoreable confirmed open exposures, or None (N/A, not 0.0) when unavailable.
6. CISA KEV exposure scoping includes only confirmed open exposures resolving to KEV.
7. EDIP confirmed exposure treatment and owner coverage evaluate confirmed exposed assets only.
8. Synthesis dashboard alerts include only findings whose ID is in asset_linked_cisa_kev_ids.
9. API endpoints (/api/synthesis/dashboard, /api/scout/stats, workflow overview) expose global intelligence.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from index import app  # noqa: E402
from models import (  # noqa: E402
    Asset,
    AssetExposure,
    Base,
    CanonicalVulnerability,
    CisaKevEntry,
    EdipDecision,
    Finding,
    VulnerabilityCvssAssessment,
)
from routers.auth import get_current_user  # noqa: E402
from routers.synthesis import get_dashboard_data  # noqa: E402
from services.cve_intelligence import build_global_intelligence_summary  # noqa: E402
from services.customer_posture import build_customer_posture, canonical_exposure_rows  # noqa: E402
from services.database import get_db  # noqa: E402
from services.workflow_connections import (  # noqa: E402
    build_exposure_coverage,
    build_workflow_overview,
    build_workflow_readiness,
)


@pytest.fixture()
def db(tmp_path):
    """Isolated SQLite database session for unit testing semantics."""
    db_file = tmp_path / "test_synthesis_semantics.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def scenario_db(db):
    """Seeded database containing canonical spine, tenant posture, and edge cases."""
    now = datetime.now(timezone.utc)

    # 1. Canonical vulnerability catalogue (Global spine)
    db.add_all([
        CanonicalVulnerability(cve_id="CVE-2021-44228", status="published", description="Log4j", published_at=now),
        CanonicalVulnerability(cve_id="CVE-2023-38606", status="published", description="WebKit", published_at=now),
        CanonicalVulnerability(cve_id="CVE-2024-0001", status="published", description="Multi-CVSS", published_at=now),
        CanonicalVulnerability(cve_id="CVE-2024-0002", status="published", description="Version-CVSS", published_at=now),
        CanonicalVulnerability(cve_id="CVE-2024-0003", status="published", description="Unassessed", published_at=now),
        CanonicalVulnerability(cve_id="CVE-2020-9999", status="rejected", description="Rejected"),
        CisaKevEntry(
            id="KEV-CVE-2021-44228", cve_id="CVE-2021-44228", vendor_project="Apache", product="Log4j",
            vulnerability_name="Log4Shell", date_added="2021-12-10", due_date="2021-12-24",
            required_action="Patch", known_ransomware_campaign_use="Known",
        ),
        CisaKevEntry(
            id="KEV-CVE-2023-38606", cve_id="CVE-2023-38606", vendor_project="Apple", product="iOS",
            vulnerability_name="WebKit", date_added="2023-07-26", due_date="2023-08-10",
            required_action="Update", known_ransomware_campaign_use="Unknown",
        ),
        # CVE-2021-44228: Primary v3.1 10.0 (Critical)
        VulnerabilityCvssAssessment(id="CVSS-1", cve_id="CVE-2021-44228", source="nvd@nist.gov", source_role="Primary", cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", base_score=10.0, base_severity="CRITICAL"),
        # CVE-2023-38606: Primary v3.1 7.8 (High)
        VulnerabilityCvssAssessment(id="CVSS-2", cve_id="CVE-2023-38606", source="nvd@nist.gov", source_role="Primary", cvss_version="3.1", vector_string="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", base_score=7.8, base_severity="HIGH"),
        # CVE-2024-0001: Primary v3.1 7.2 vs Secondary v3.1 9.8 -> preferred Primary 7.2 (< 9.0)
        VulnerabilityCvssAssessment(id="CVSS-3-PRI", cve_id="CVE-2024-0001", source="nvd@nist.gov", source_role="Primary", cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", base_score=7.2, base_severity="HIGH"),
        VulnerabilityCvssAssessment(id="CVSS-3-SEC", cve_id="CVE-2024-0001", source="vendor@test", source_role="Secondary", cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", base_score=9.8, base_severity="CRITICAL"),
        # CVE-2024-0002: Primary v4.0 9.3 vs Primary v3.1 6.5 -> preferred v4.0 9.3 (>= 9.0)
        VulnerabilityCvssAssessment(id="CVSS-4-V31", cve_id="CVE-2024-0002", source="nvd@nist.gov", source_role="Primary", cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", base_score=6.5, base_severity="MEDIUM"),
        VulnerabilityCvssAssessment(id="CVSS-4-V40", cve_id="CVE-2024-0002", source="nvd@nist.gov", source_role="Primary", cvss_version="4.0", vector_string="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", base_score=9.3, base_severity="CRITICAL"),
    ])

    # 2. Tenant Alpha Assets & Findings
    tenant = "tenant-alpha"
    db.add_all([
        Asset(id="A-OWNED", tenant_id=tenant, name="Owned Web Server", owner="sec-ops@example.com", criticality="critical", status="active"),
        Asset(id="A-UNOWNED", tenant_id=tenant, name="Unowned API Gateway", owner=None, criticality="high", status="active"),
        Asset(id="A-IDLE", tenant_id=tenant, name="Idle DB", owner="dba@example.com", criticality="medium", status="active"),
        Asset(id="A-DECOMM", tenant_id=tenant, name="Decommissioned Host", owner="retired@example.com", status="decommissioned"),
        Asset(id="A-FOREIGN", tenant_id="tenant-foreign", name="Foreign Host", owner="beta@example.com", status="active"),
        # Findings
        Finding(id="F-CONF-1", tenant_id=tenant, cve="CVE-2021-44228", cve_id="CVE-2021-44228", title="Log4Shell Exploit", status="unmitigated", priority="P0", cvss=10.0, ransomware=True, cisa_kev=True),
        Finding(id="F-CONF-2", tenant_id=tenant, cve="CVE-2024-0002", cve_id="CVE-2024-0002", title="Critical Vuln", status="unmitigated", priority="P0", cvss=9.3),
        Finding(id="F-CONF-3", tenant_id=tenant, title="Scoreable SSS", status="unmitigated", source="sss", sss_data={"scoring": {"base_severity": 7.0}}),
        Finding(id="F-CONF-4", tenant_id=tenant, cve="CVE-2024-0003", cve_id="CVE-2024-0003", title="Unscoreable Vuln", status="unmitigated", cvss=None),
        Finding(id="F-REF", tenant_id=tenant, cve="CVE-2021-44228", cve_id="CVE-2021-44228", title="Log4Shell Ref", status="reference", priority="P0", cvss=10.0, ransomware=True),
        Finding(id="F-NA", tenant_id=tenant, cve="CVE-2023-38606", cve_id="CVE-2023-38606", title="NA Vuln", status="not_applicable", cvss=7.8),
        Finding(id="F-RESOLVED", tenant_id=tenant, cve="CVE-2023-38606", cve_id="CVE-2023-38606", title="Resolved Vuln", status="resolved", cvss=7.8),
        Finding(id="F-UNLINKED", tenant_id=tenant, cve="CVE-2021-44228", cve_id="CVE-2021-44228", title="Unlinked Vuln", status="unmitigated", priority="P0", cvss=10.0, ransomware=True),
        Finding(id="F-ON-DECOMM", tenant_id=tenant, cve="CVE-2023-38606", cve_id="CVE-2023-38606", title="On Decomm", status="unmitigated", cvss=7.8),
        Finding(id="F-ON-FOREIGN", tenant_id=tenant, cve="CVE-2023-38606", cve_id="CVE-2023-38606", title="On Foreign", status="unmitigated", cvss=7.8),
        # Tenant noise in foreign tenant
        Finding(id="F-NOISE", tenant_id="tenant-foreign", cve="CVE-9999-9999", title="Foreign Noise", status="unmitigated", priority="P0", cvss=10.0, ransomware=True, cisa_kev=True),
    ])
    db.flush()

    # Asset Exposure Links
    db.add_all([
        AssetExposure(id="EXP-1", tenant_id=tenant, finding_id="F-CONF-1", asset_id="A-OWNED", status="confirmed"),
        AssetExposure(id="EXP-2", tenant_id=tenant, finding_id="F-CONF-2", asset_id="A-UNOWNED", status="confirmed"),
        AssetExposure(id="EXP-3", tenant_id=tenant, finding_id="F-CONF-3", asset_id="A-OWNED", status="confirmed"),
        AssetExposure(id="EXP-4", tenant_id=tenant, finding_id="F-CONF-4", asset_id="A-UNOWNED", status="confirmed"),
        AssetExposure(id="EXP-7", tenant_id=tenant, finding_id="F-RESOLVED", asset_id="A-OWNED", status="confirmed"),
        AssetExposure(id="EXP-8", tenant_id=tenant, finding_id="F-ON-DECOMM", asset_id="A-DECOMM", status="confirmed"),
        AssetExposure(id="EXP-9", tenant_id=tenant, finding_id="F-ON-FOREIGN", asset_id="A-FOREIGN", status="confirmed"),
    ])

    # Edip Decisions (mix of confirmed, unlinked, ref, resolved, orphan)
    db.add_all([
        EdipDecision(tenant_id=tenant, finding_id="F-CONF-1", decision="PATCH", rationale="Immediate"),
        EdipDecision(tenant_id=tenant, finding_id="F-REF", decision="INVESTIGATE", rationale="Ref only"),
        EdipDecision(tenant_id=tenant, finding_id="F-UNLINKED", decision="DEFER", rationale="Unlinked"),
        EdipDecision(tenant_id=tenant, finding_id="F-RESOLVED", decision="PATCH", rationale="Resolved"),
        EdipDecision(tenant_id=tenant, finding_id="F-ORPHAN", decision="DEFER", rationale="Orphan"),
    ])

    # Unscoreable tenant for N/A checks
    asset_unsc = Asset(id="A-UNSC", tenant_id="tenant-unscoreable", name="Unsc Asset", status="active")
    f_unsc = Finding(id="F-UNSC", tenant_id="tenant-unscoreable", cve="CVE-2024-0003", cve_id="CVE-2024-0003", title="Unsc Vuln", status="unmitigated", cvss=None)
    db.add_all([asset_unsc, f_unsc])
    db.flush()
    db.add(AssetExposure(id="EXP-UNSC", tenant_id="tenant-unscoreable", finding_id="F-UNSC", asset_id="A-UNSC", status="confirmed"))

    db.commit()
    return db


def test_global_intelligence_and_cvss_resolution(scenario_db):
    """Global intelligence aggregates come strictly from canonical tables and apply preferred CVSS policy."""
    summary = build_global_intelligence_summary(scenario_db)

    assert summary["scope"] == "global_vulnerability_intelligence"
    assert summary["canonical_cves"] == 6
    assert summary["cisa_kev_entries"] == 2
    assert summary["ransomware_linked_kev_entries"] == 1
    # Assessed: CVE-2021-44228, CVE-2023-38606, CVE-2024-0001, CVE-2024-0002 -> 4/6 = 66.7%
    assert summary["cvss_coverage"] == {"assessed_canonical_cves": 4, "canonical_cves": 6, "pct": 66.7}
    # Critical: CVE-2021-44228 (10.0) and CVE-2024-0002 (9.3 preferred).
    # CVE-2024-0001 has Secondary 9.8 but preferred Primary is 7.2 (< 9.0).
    assert summary["cvss_critical_canonical_cves"] == 2


def test_customer_posture_governance_and_alerts(scenario_db):
    """Posture, governance scopes, and alerts filter to confirmed open exposures on active assets."""
    tenant = "tenant-alpha"

    # Confirmed exposure rows must contain ONLY confirmed open exposures on active assets (4 findings)
    open_rows = canonical_exposure_rows(scenario_db, tenant, open_only=True)
    assert {f.id for f, _, _ in open_rows} == {"F-CONF-1", "F-CONF-2", "F-CONF-3", "F-CONF-4"}

    # Posture aggregation: reference, N/A, resolved, and unlinked/decomm exclusions
    posture = build_customer_posture(scenario_db, tenant)
    assert posture["confirmed_open_exposure_count"] == 4
    assert posture["reference_intelligence_count"] == 1
    assert posture["not_applicable_count"] == 1
    assert posture["resolved_finding_count"] == 1
    assert posture["needs_classification_count"] == 3  # F-UNLINKED, F-ON-DECOMM, F-ON-FOREIGN
    assert posture["active_asset_count"] == 3  # A-OWNED, A-UNOWNED, A-IDLE
    assert posture["asset_linked_cisa_kev_ids"] == ["F-CONF-1"]
    assert posture["asset_linked_cisa_kev_count"] == 1
    assert posture["confirmed_ransomware_linked_count"] == 1

    # Governance: EDIP confirmed exposure treatment & Owner readiness coverage
    readiness = build_workflow_readiness(scenario_db, tenant)
    assert readiness["edip"]["decisions_recorded"] == 5
    assert readiness["edip"]["confirmed_exposure_treatment"]["applicable"] == 4
    assert readiness["edip"]["confirmed_exposure_treatment"]["recorded"] == 1  # Only F-CONF-1
    assert readiness["owners"]["applicable"] == 4
    assert readiness["owners"]["recorded"] == 2  # F-CONF-1 & F-CONF-3 on A-OWNED
    assert readiness["owners"]["source"] == "ASSETS.owner"

    # Alerts: Only confirmed open KEV findings alert; reference & unlinked KEV are excluded
    dashboard = get_dashboard_data(scenario_db, tenant_id=tenant)
    alerts = dashboard.get("alerts", [])
    assert len(alerts) == 1
    assert "CVE-2021-44228" in alerts[0]["message"]
    assert "Log4Shell Exploit" in alerts[0]["message"]


def test_tes_coverage_and_aggregate_mean_or_na(scenario_db):
    """TES coverage denominator is confirmed open exposures, and tenant TES returns mean or None (N/A)."""
    # Active tenant with 4 confirmed exposures (3 scoreable, 1 unscoreable)
    coverage = build_exposure_coverage(scenario_db, "tenant-alpha")
    assert coverage["asset_linked_count"] == 4
    assert coverage["scored_asset_linked_count"] == 3
    assert coverage["scoring_coverage_pct"] == 75.0
    assert coverage["unscored_finding_ids"] == ["F-CONF-4"]
    assert coverage["status"] == "available"
    assert isinstance(coverage["aggregate_tes"], float) and coverage["aggregate_tes"] > 0

    posture = build_customer_posture(scenario_db, "tenant-alpha")
    assert posture["aggregate_tenant_tes"] == coverage["aggregate_tes"]

    # Empty tenant -> None (N/A, not 0.0)
    empty_posture = build_customer_posture(scenario_db, "tenant-empty")
    empty_coverage = build_exposure_coverage(scenario_db, "tenant-empty")
    assert empty_posture["aggregate_tenant_tes"] is None
    assert empty_coverage["aggregate_tes"] is None
    assert empty_coverage["status"] == "unavailable"

    # Tenant with only unscoreable exposure -> None (N/A, not 0.0)
    unsc_posture = build_customer_posture(scenario_db, "tenant-unscoreable")
    unsc_coverage = build_exposure_coverage(scenario_db, "tenant-unscoreable")
    assert unsc_posture["aggregate_tenant_tes"] is None
    assert unsc_coverage["aggregate_tes"] is None
    assert unsc_coverage["status"] == "unavailable"


def test_api_endpoints_and_overview_contracts(scenario_db):
    """API endpoints and workflow overview expose global_intelligence and maintain contracts."""
    tenant = "tenant-alpha"

    overview = build_workflow_overview(scenario_db, tenant)
    assert "global_intelligence" in overview
    assert overview["global_intelligence"]["canonical_cves"] == 6
    assert overview["global_intelligence"]["cvss_critical_canonical_cves"] == 2

    app.dependency_overrides[get_db] = lambda: scenario_db
    app.dependency_overrides[get_current_user] = lambda: {
        "sub": "auditor@example.test",
        "role": "Auditor",
        "tenant_id": tenant,
        "tier": "enterprise",
        "is_superadmin": False,
    }

    try:
        with TestClient(app) as client:
            synth_resp = client.get("/api/synthesis/dashboard")
            assert synth_resp.status_code == 200
            synth_data = synth_resp.json()
            assert synth_data["global_intelligence"]["canonical_cves"] == 6
            assert synth_data["global_intelligence"]["cvss_critical_canonical_cves"] == 2
            assert synth_data["exposure_coverage"]["aggregate_scope"] == "confirmed_open_customer_exposure"

            scout_resp = client.get("/api/scout/stats")
            assert scout_resp.status_code == 200
            scout_data = scout_resp.json()
            assert scout_data["global_intelligence"]["canonical_cves"] == 6
            for legacy_key in ("total_findings", "critical_count", "reference_catalogue", "customer_scan_activity"):
                assert legacy_key in scout_data
    finally:
        app.dependency_overrides.clear()
