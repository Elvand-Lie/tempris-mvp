"""Tests for STANDARD Compliance Advisories & MAS Draft Invariants.

Validates:
- Global reference CVE / KEV entries are intelligence notices, NOT active customer compliance violations
- Compliance alerts trigger only when confirmed AssetExposure links an active customer Asset to a vulnerability
- Advisories distinguish 'confirmed_customer_exposure' vs 'advisory_notice'
- MAS TRM 1-Hour Incident Notice report strictly bounds to tenant incident & confirmed asset exposures
- Canonical CVE intelligence (canonical_cve_id, CVSS, CISA KEV, ransomware) is resolved on confirmed incident exposures
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import (  # noqa: E402
    Asset,
    AssetExposure,
    Base,
    CanonicalVulnerability,
    CisaKevEntry,
    ControlStatus,
    Finding,
    Incident,
    IncidentReport,
    VulnerabilityCvssAssessment,
)
from routers.standard import (  # noqa: E402
    IncidentReportRequest,
    _get_live_advisories,
    generate_incident_report,
    get_frameworks,
)


@pytest.fixture()
def db_session(tmp_path):
    db_file = tmp_path / "test_standard.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Pre-seed global canonical vulnerabilities in catalogue
    log4j = CanonicalVulnerability(
        cve_id="CVE-2021-44228",
        status="published",
        description="Apache Log4j2 RCE",
        description_source="NVD",
    )
    log4j_cvss = VulnerabilityCvssAssessment(
        id="CVSS-LOG4J-V31",
        cve_id="CVE-2021-44228",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
        base_severity="CRITICAL",
    )
    log4j_kev = CisaKevEntry(
        id="KEV-CVE-2021-44228",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        known_ransomware_campaign_use="Known",
    )
    session.add_all([log4j, log4j_cvss, log4j_kev])
    session.commit()

    yield session
    session.close()
    engine.dispose()


def test_unconfirmed_global_cve_does_not_trigger_compliance_violation(db_session):
    """An unconfirmed CVE in catalogue or unassigned finding is not a compliance violation."""
    # Tenant has an active asset, but NO confirmed exposures to Log4Shell
    asset = Asset(
        id="A-CORP-01",
        tenant_id="tenant-acme",
        name="corp-portal.acme.com",
        status="active",
    )
    # A reference catalog finding exists in the tenant space
    catalog_finding = Finding(
        id="F-CAT-LOG4J",
        tenant_id="tenant-acme",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Apache Log4Shell Reference",
        status="unmitigated",
        priority="P0",
    )
    db_session.add_all([asset, catalog_finding])
    db_session.commit()

    advisories = _get_live_advisories(db_session, "tenant-acme")

    # Patching control MAS-TRM-11.1.1 should be absent or NOT a critical violation when 0 confirmed exposures exist
    if "MAS-TRM-11.1.1" in advisories:
        mas_adv = advisories["MAS-TRM-11.1.1"]
        assert mas_adv["level"] != "critical"
        assert mas_adv["type"] != "confirmed_customer_exposure"
        assert "0 confirmed critical customer exposures" in mas_adv["message"]


def test_confirmed_customer_exposure_triggers_compliance_alert(db_session):
    """When a confirmed AssetExposure links an active asset to a P0 CVE, compliance alerts trigger."""
    asset = Asset(
        id="A-CORP-01",
        tenant_id="tenant-acme",
        name="corp-portal.acme.com",
        status="active",
    )
    finding = Finding(
        id="F-ACT-LOG4J",
        tenant_id="tenant-acme",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Apache Log4Shell Exposed",
        status="unmitigated",
        priority="P0",
    )
    db_session.add_all([asset, finding])
    db_session.flush()

    # Create confirmed asset exposure
    db_session.add(AssetExposure(
        id="EXP-LOG4J",
        tenant_id="tenant-acme",
        finding_id="F-ACT-LOG4J",
        asset_id="A-CORP-01",
        status="confirmed",
        match_method="nuclei",
        evidence="Observed via nuclei scan",
    ))
    db_session.commit()

    advisories = _get_live_advisories(db_session, "tenant-acme")

    # MAS-TRM-11.1.1 and IM8A-AM-3 must now trigger critical advisory alerts
    assert advisories["MAS-TRM-11.1.1"]["level"] == "critical"
    assert advisories["MAS-TRM-11.1.1"]["type"] == "confirmed_customer_exposure"
    assert advisories["MAS-TRM-11.1.1"]["confirmed_count"] == 1
    assert "1 confirmed critical customer exposures require remediation review" in advisories["MAS-TRM-11.1.1"]["message"]
    assert "1 confirmed exposures are ransomware-linked" in advisories["MAS-TRM-11.1.1"]["message"]

    assert advisories["IM8A-AM-3"]["level"] == "critical"
    assert advisories["PCI-6.3.3"]["level"] == "warning"


def test_mas_trm_incident_draft_canonical_intelligence_and_scope(db_session, monkeypatch):
    """MAS incident draft incorporates canonical intelligence for confirmed exposures only."""
    monkeypatch.setattr("routers.standard.append_to_audit_log_db", lambda *args, **kwargs: None)

    asset = Asset(
        id="A-PROD-DB",
        tenant_id="tenant-fin",
        name="prod-db.fin.internal",
        status="active",
    )
    finding = Finding(
        id="F-FIN-01",
        tenant_id="tenant-fin",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4Shell on Prod DB",
        priority="P0",
        status="unmitigated",
    )
    # Unlinked catalog finding
    unlinked_finding = Finding(
        id="F-UNLINKED",
        tenant_id="tenant-fin",
        cve="CVE-2023-38606",
        title="Unconfirmed iOS Bug",
        priority="P0",
    )

    incident = Incident(
        id="INC-FIN-001",
        tenant_id="tenant-fin",
        external_event_id="SIEM-9921",
        source="siem",
        discovered_at=datetime.now(timezone.utc),
        title="Ransomware Actor Ingress via Log4Shell",
        summary="Exploitation of Log4Shell observed on internal DB host",
        severity="critical",
        status="investigating",
        affected_asset_ids=["A-PROD-DB"],
        related_finding_ids=["F-FIN-01", "F-UNLINKED"],
        observed_impact="Unauthorized process execution",
    )
    db_session.add_all([asset, finding, unlinked_finding, incident])
    db_session.flush()

    db_session.add(AssetExposure(
        id="EXP-FIN-01",
        tenant_id="tenant-fin",
        finding_id="F-FIN-01",
        asset_id="A-PROD-DB",
        status="confirmed",
        match_method="analyst",
        evidence="SIEM correlation and memory dump",
    ))
    db_session.commit()

    report = generate_incident_report(
        IncidentReportRequest(incident_id="INC-FIN-001"),
        db=db_session,
        user={"sub": "ciso@fin.internal", "role": "Admin", "tenant_id": "tenant-fin"},
    )

    assert report["incident_id"] == "INC-FIN-001"
    assert report["status"] == "DRAFT — PENDING SUBMISSION TO MAS"
    assert len(report["confirmed_related_exposures"]) == 1

    exp = report["confirmed_related_exposures"][0]
    assert exp["finding_id"] == "F-FIN-01"
    assert exp["cve"] == "CVE-2021-44228"
    assert exp["canonical_cve_id"] == "CVE-2021-44228"
    assert exp["ransomware_linked"] is True  # Derived from canonical CISA KEV
    assert exp["cisa_kev"] is True
    assert report["confirmed_critical_count"] == 1
    assert report["confirmed_ransomware_linked_count"] == 1
    assert "global intelligence is excluded" in report["scope_note"]
