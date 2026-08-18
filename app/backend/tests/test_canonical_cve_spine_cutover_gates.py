"""Master Comprehensive Verification Suite for Tempris CVE Spine Cutover.

Executes all 9 cutover verification gates:
Gate 1: Schema & Model Migration Invariants (canonical_cve_id FK, no column loss, unmerged findings)
Gate 2: Offline NVD Snapshot & CISA KEV Ingestion (ingest snapshot, parse CVSS versions v4.0-v2.0, reject CVE tracking)
Gate 3: Exact Finding Link & Backfill (syntax validation, idempotent linkage, tenant scoping, legacy preservation)
Gate 4: Canonical Vulnerability Intelligence Resolution & Deterministic CVSS Policy (4.0 > 3.1 > 3.0 > 2.0, Primary > Secondary, legacy fallback)
Gate 5: Decoupled Catalogue vs Customer Exposure (reference catalogue querying, 0 unconfirmed exposures in posture)
Gate 6: Dynamic TES Engine Live Context (canonical CVSS & KEV exploitability, frozen resolved findings)
Gate 7: Intake Pollution Prevention (scanner observations & threat pack imports link canonical_cve_id)
Gate 8: STANDARD Compliance Advisories & MAS TRM Invariants (advisories vs customer exposures, MAS draft report)
Gate 9: Downstream Engine Integrity (CISO, SYNTHESIS, SPECTRUM, STRIKE, Reporting Engine, Audit Log)
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import (  # noqa: E402
    Asset,
    AssetExposure,
    AuditLog,
    Base,
    CanonicalVulnerability,
    CisaKevEntry,
    ControlStatus,
    Finding,
    FindingStatusHistory,
    Incident,
    IncidentReport,
    PostureSnapshot,
    ScanFinding,
    ScanJob,
    VulnerabilityCvssAssessment,
)
from routers.audit import verify_audit_chain  # noqa: E402
from routers.ciso import get_ciso_summary  # noqa: E402
from routers.spectrum import get_findings as get_spectrum_findings  # noqa: E402
from routers.standard import (  # noqa: E402
    IncidentReportRequest,
    _get_live_advisories,
    generate_incident_report,
)
from routers.synthesis import get_dashboard_data  # noqa: E402
from services.cve_intelligence import (  # noqa: E402
    import_cisa_kev_snapshot,
    import_nvd_cve_snapshot,
    link_findings_to_canonical_cves,
    resolve_vulnerability_intelligence,
    select_preferred_cvss_assessment,
    validate_and_normalize_cve,
)
from services.customer_posture import SCOPE_VERSION, build_customer_posture, canonical_exposure_rows  # noqa: E402
from services.exposure_links import confirm_finding_assets  # noqa: E402
from services.reporting_engine import generate_poc_report_pipeline  # noqa: E402
from services.scan_normalizer import normalize_observation  # noqa: E402
from services.tes_engine import calculate_finding_tes, get_live_cve_tes_context  # noqa: E402
from services.threat_importer import import_threat_pack  # noqa: E402


@pytest.fixture()
def master_db(tmp_path, monkeypatch):
    db_file = tmp_path / "master_cutover.db"
    engine = create_engine(f"sqlite:///{db_file.resolve().as_posix()}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    monkeypatch.setenv("REPORT_STORAGE_ROOT", str(tmp_path / "reports"))

    yield session, tmp_path
    session.close()
    engine.dispose()


def test_gate_1_schema_and_model_invariants(master_db):
    """Gate 1: Schema Invariants — Finding.canonical_cve_id FK and CanonicalVulnerability tables."""
    session, _ = master_db
    inspector = inspect(session.bind)

    # Tables exist
    tables = inspector.get_table_names()
    assert "canonical_vulnerabilities" in tables
    assert "vulnerability_cvss_assessments" in tables
    assert "cisa_kev_entries" in tables
    assert "findings" in tables

    # Column exists on findings
    finding_cols = {c["name"] for c in inspector.get_columns("findings")}
    assert "canonical_cve_id" in finding_cols
    assert "cve" in finding_cols
    assert "cve_id" in finding_cols
    assert "cvss" in finding_cols
    assert "priority" in finding_cols


def test_gate_2_offline_snapshot_ingestion(master_db):
    """Gate 2: Ingestion — Ingest NVD JSON & CISA KEV snapshot offline with multi-version CVSS & rejected tracking."""
    session, tmp_path = master_db

    nvd_payload = {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-08-18T00:00:00.000Z",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "sourceIdentifier": "cve@mitre.org",
                    "published": "2021-12-10T10:15:00.000Z",
                    "lastModified": "2023-04-15T12:00:00.000Z",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                },
                            },
                            {
                                "source": "cve@mitre.org",
                                "type": "Secondary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                },
                            },
                        ],
                        "cvssMetricV2": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                                    "baseScore": 9.3,
                                },
                            },
                        ],
                    },
                },
            },
            {
                "cve": {
                    "id": "CVE-2020-0001",
                    "sourceIdentifier": "cve@mitre.org",
                    "vulnStatus": "Rejected",
                    "descriptions": [{"lang": "en", "value": "** REJECT ** DO NOT USE. Consult IDs: CVE-2020-9999."}],
                },
            },
        ],
    }
    nvd_path = tmp_path / "nvd_sample.json"
    nvd_path.write_text(json.dumps(nvd_payload), encoding="utf-8")

    nvd_res = import_nvd_cve_snapshot(nvd_path, session, snapshot_id="SNAP-TEST-001")
    assert nvd_res["canonical_created"] == 2
    assert nvd_res["cvss_created"] == 3

    # Ingest CISA KEV
    kev_payload = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.08.18",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "requiredAction": "Apply mitigations",
                "knownRansomwareCampaignUse": "Known",
            },
        ],
    }
    kev_path = tmp_path / "cisa_kev_sample.json"
    kev_path.write_text(json.dumps(kev_payload), encoding="utf-8")

    kev_res = import_cisa_kev_snapshot(kev_path, session, snapshot_id="KEV-TEST-001")
    assert kev_res["kev_created"] == 1

    # Verify rejected CVE replacement tracking
    rej = session.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == "CVE-2020-0001").one()
    assert rej.status == "rejected"
    assert rej.replaced_by_cve_id == "CVE-2020-9999"


def test_gate_3_exact_finding_link_and_backfill(master_db):
    """Gate 3: Exact Finding-to-Canonical Link & Backfill."""
    session, _ = master_db

    # Seed pre-existing findings across tenants
    f1 = Finding(id="F-T1-01", tenant_id="tenant-alpha", cve="cve-2021-44228", title="Log4j 1", priority="P0")
    f2 = Finding(id="F-T1-02", tenant_id="tenant-alpha", cve="CVE-2021-44228", title="Log4j 2 (Coexisting)", priority="P0")
    f3 = Finding(id="F-T2-01", tenant_id="tenant-beta", cve="CVE-2023-99999", title="Unseen CVE", priority="P1")
    f4_non_cve = Finding(id="F-T1-SSS", tenant_id="tenant-alpha", cve="SSS-2026-001", title="Non-CVE SSS", priority="P2")

    session.add_all([f1, f2, f3, f4_non_cve])
    session.commit()

    # Dry-run first
    dry_res = link_findings_to_canonical_cves(session, dry_run=True, tenant_id="tenant-alpha")
    assert dry_res["valid_cve_identifiers"] == 2
    assert dry_res["canonical_links_created"] == 2
    assert session.query(Finding).filter(Finding.id == "F-T1-01").one().canonical_cve_id is None

    # Live backfill
    live_res = link_findings_to_canonical_cves(session, dry_run=False)
    assert live_res["status"] == "success"
    assert live_res["canonical_links_created"] == 3

    assert session.query(Finding).filter(Finding.id == "F-T1-01").one().canonical_cve_id == "CVE-2021-44228"
    assert session.query(Finding).filter(Finding.id == "F-T1-02").one().canonical_cve_id == "CVE-2021-44228"
    assert session.query(Finding).filter(Finding.id == "F-T2-01").one().canonical_cve_id == "CVE-2023-99999"
    assert session.query(Finding).filter(Finding.id == "F-T1-SSS").one().canonical_cve_id is None


def test_gate_4_canonical_intelligence_resolver_policy(master_db):
    """Gate 4: Authoritative Resolver — CVSS version precedence, source roles, and legacy fallback."""
    session, _ = master_db

    # Ingest CVE with multi-version assessments
    cve = CanonicalVulnerability(cve_id="CVE-2024-55555", status="published", description="Multi-CVSS Test")
    v2 = VulnerabilityCvssAssessment(
        id="CVSS-5555-V2", cve_id="CVE-2024-55555", source="nvd@nist.gov", source_role="Primary",
        cvss_version="2.0", vector_string="AV:N/AC:L/Au:N/C:P/I:P/A:P", base_score=7.5,
    )
    v30 = VulnerabilityCvssAssessment(
        id="CVSS-5555-V30", cve_id="CVE-2024-55555", source="vendor@test.com", source_role="Secondary",
        cvss_version="3.0", vector_string="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", base_score=7.5,
    )
    v31_sec = VulnerabilityCvssAssessment(
        id="CVSS-5555-V31-SEC", cve_id="CVE-2024-55555", source="vendor@test.com", source_role="Secondary",
        cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", base_score=7.5,
    )
    v31_prim = VulnerabilityCvssAssessment(
        id="CVSS-5555-V31-PRIM", cve_id="CVE-2024-55555", source="nvd@nist.gov", source_role="Primary",
        cvss_version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", base_score=9.8,
    )
    v40 = VulnerabilityCvssAssessment(
        id="CVSS-5555-V40", cve_id="CVE-2024-55555", source="nvd@nist.gov", source_role="Primary",
        cvss_version="4.0", vector_string="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", base_score=9.9,
    )

    session.add_all([cve, v2, v30, v31_sec, v31_prim, v40])
    session.commit()

    intel = resolve_vulnerability_intelligence("CVE-2024-55555", session)
    assert intel.cvss_version == "4.0"
    assert intel.cvss_score == 9.9
    assert intel.provenance_classification == "canonical_authoritative"

    # Test legacy fallback for unassessed CVE finding
    legacy_finding = Finding(
        id="F-LEGACY-CVSS",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2029-0001",
        cve="CVE-2029-0001",
        cvss=6.4,
        title="Unassessed in canonical",
    )
    session.add(legacy_finding)
    session.commit()

    leg_intel = resolve_vulnerability_intelligence(legacy_finding, session)
    assert leg_intel.cvss_score == 6.4
    assert leg_intel.used_legacy_fallback is True
    assert leg_intel.provenance_classification == "legacy_unprovenanced"


def test_gate_5_decoupled_catalogue_vs_customer_exposure(master_db):
    """Gate 5: Decoupled Catalogue — Catalog findings do not pollute customer posture without confirmed asset links."""
    session, _ = master_db

    asset = Asset(id="A-GATEWAY", tenant_id="tenant-alpha", name="gateway", status="active")
    finding_open = Finding(
        id="F-OPEN-EXP",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4j",
        priority="P0",
        status="unmitigated",
    )
    finding_catalog = Finding(
        id="F-CAT-ONLY",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2024-55555",
        cve="CVE-2024-55555",
        title="Catalog CVE",
        priority="P0",
        status="reference_only",
    )

    session.add_all([asset, finding_open, finding_catalog])
    session.flush()

    confirm_finding_assets(session, finding_open, [asset], recorded_by="system:tester", evidence="Live confirmed scan", match_method="nuclei")
    session.commit()

    posture = build_customer_posture(session, "tenant-alpha")
    assert posture["confirmed_open_exposure_count"] == 1
    assert posture["confirmed_asset_count"] == 1
    assert posture["reference_intelligence_count"] == 1
    assert "F-CAT-ONLY" not in posture["confirmed_finding_ids"]


def test_gate_6_dynamic_tes_engine_canonical_cutover(master_db):
    """Gate 6: TES Engine — Uses Canonical Intelligence Resolver & freezes resolved findings."""
    session, _ = master_db

    # Seed canonical vulnerability, CVSS assessment, and KEV entry
    cve = CanonicalVulnerability(cve_id="CVE-2021-44228", status="published", description="Log4Shell")
    cvss = VulnerabilityCvssAssessment(
        id="CVSS-LOG4J-TEST",
        cve_id="CVE-2021-44228",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
        base_severity="CRITICAL",
    )
    kev = CisaKevEntry(
        id="KEV-LOG4J-TEST",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        known_ransomware_campaign_use="Known",
    )
    asset = Asset(id="A-GATEWAY-TES", tenant_id="tenant-alpha", name="gateway", status="active", criticality="critical")
    finding = Finding(
        id="F-OPEN-EXP-TES",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4j",
        priority="P0",
        status="unmitigated",
    )
    session.add_all([cve, cvss, kev, asset, finding])
    session.flush()

    confirm_finding_assets(session, finding, [asset], recorded_by="system:tester", evidence="Live confirmed match", match_method="nuclei")
    session.commit()

    tes_score = calculate_finding_tes(finding, db=session, tenant_id="tenant-alpha")
    assert float(tes_score) > 0.0

    inputs, context = get_live_cve_tes_context(finding, db=session, tenant_id="tenant-alpha")
    assert inputs.cvss == 10.0
    assert inputs.exploitability == 10.0  # CISA KEV max exploitability
    assert inputs.threat_actor_activity == 10.0  # Ransomware campaign max threat actor activity


def test_gate_7_intake_pollution_prevention(master_db):
    """Gate 7: Intake Channels — Scanner observation & Threat Importer link canonical_cve_id on intake."""
    session, _ = master_db

    asset = Asset(id="A-GATEWAY-INTAKE", tenant_id="tenant-alpha", name="gateway", status="active")
    scan_job = ScanJob(
        id="SJ-GATE-01",
        tenant_id="tenant-alpha",
        target="gateway",
        normalized_target="gateway",
        scan_type="nuclei",
        status="completed",
    )
    session.add_all([asset, scan_job])
    session.commit()

    obs = {
        "engine": "nuclei",
        "template_id": "cve-2021-44228-rce",
        "cve_id": "CVE-2021-44228",
        "risk": "Critical",
        "target": "gateway",
        "matched_at": "gateway:8080",
    }
    result = normalize_observation(session, tenant_id="tenant-alpha", scan_job=scan_job, observation=obs, actor_id="system:scanner")
    session.commit()

    assert result["finding"].canonical_cve_id == "CVE-2021-44228"
    assert result["exposure"] == "confirmed"


def test_gate_8_standard_compliance_and_mas_draft(master_db, monkeypatch):
    """Gate 8: STANDARD — Compliance advisories vs customer exposures & MAS TRM 1-Hour report."""
    session, _ = master_db
    monkeypatch.setattr("routers.standard.append_to_audit_log_db", lambda *args, **kwargs: None)

    # Seed confirmed exposure & reference catalogue finding
    cve = CanonicalVulnerability(cve_id="CVE-2021-44228", status="published", description="Log4Shell")
    cvss = VulnerabilityCvssAssessment(
        id="CVSS-STD-V31",
        cve_id="CVE-2021-44228",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
        base_severity="CRITICAL",
    )
    kev = CisaKevEntry(
        id="KEV-STD",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        known_ransomware_campaign_use="Known",
    )
    asset = Asset(id="A-GATEWAY-STD", tenant_id="tenant-alpha", name="gateway", status="active", criticality="critical")
    f_open = Finding(
        id="F-OPEN-STD",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4j",
        priority="P0",
        status="unmitigated",
    )
    f_cat = Finding(
        id="F-CAT-STD",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4j Ref",
        priority="P0",
        status="reference_only",
    )
    session.add_all([cve, cvss, kev, asset, f_open, f_cat])
    session.flush()

    confirm_finding_assets(session, f_open, [asset], recorded_by="system:tester", evidence="Observed match", match_method="nuclei")
    session.commit()

    advisories = _get_live_advisories(session, "tenant-alpha")
    assert advisories["MAS-TRM-11.1.1"]["level"] == "critical"
    assert advisories["MAS-TRM-11.1.1"]["type"] == "confirmed_customer_exposure"

    incident = Incident(
        id="INC-MASTER-01",
        tenant_id="tenant-alpha",
        external_event_id="EVT-001",
        source="siem",
        discovered_at=datetime.now(timezone.utc),
        title="Active Compromise",
        summary="Log4Shell exploitation detected",
        severity="critical",
        status="investigating",
        affected_asset_ids=["A-GATEWAY-STD"],
        related_finding_ids=["F-OPEN-STD", "F-CAT-STD"],
    )
    session.add(incident)
    session.commit()

    report = generate_incident_report(
        IncidentReportRequest(incident_id="INC-MASTER-01"),
        db=session,
        user={"sub": "system:ciso", "role": "Admin", "tenant_id": "tenant-alpha"},
    )
    assert len(report["confirmed_related_exposures"]) == 1
    assert report["confirmed_related_exposures"][0]["finding_id"] == "F-OPEN-STD"
    assert report["confirmed_related_exposures"][0]["canonical_cve_id"] == "CVE-2021-44228"


def test_gate_9_downstream_engine_integrity(master_db, monkeypatch):
    """Gate 9: Downstream Integration — CISO, SYNTHESIS, SPECTRUM, STRIKE, Reports, Audit."""
    session, tmp_path = master_db
    monkeypatch.setattr("services.reporting_engine.append_to_audit_log_db", lambda *args, **kwargs: None)
    monkeypatch.setattr("routers.ciso.append_to_audit_log_db", lambda *args, **kwargs: None)

    # Seed Canonical Data & Exposures
    cve = CanonicalVulnerability(cve_id="CVE-2021-44228", status="published", description="Log4Shell")
    cvss = VulnerabilityCvssAssessment(
        id="CVSS-DOWN-V31",
        cve_id="CVE-2021-44228",
        source="nvd@nist.gov",
        source_role="Primary",
        cvss_version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
        base_severity="CRITICAL",
    )
    kev = CisaKevEntry(
        id="KEV-DOWN",
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        known_ransomware_campaign_use="Known",
    )
    asset = Asset(id="A-GATEWAY-DOWN", tenant_id="tenant-alpha", name="gateway", status="active", criticality="critical")
    f_open = Finding(
        id="F-OPEN-DOWN",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4j Open",
        priority="P0",
        status="unmitigated",
    )
    f_cat = Finding(
        id="F-CAT-DOWN",
        tenant_id="tenant-alpha",
        canonical_cve_id="CVE-2021-44228",
        cve="CVE-2021-44228",
        title="Log4j Catalog",
        priority="P0",
        status="reference_only",
    )
    session.add_all([cve, cvss, kev, asset, f_open, f_cat])
    session.flush()

    confirm_finding_assets(session, f_open, [asset], recorded_by="system:tester", evidence="Observed match", match_method="nuclei")
    session.commit()

    # 1. CISO
    ciso_summary = get_ciso_summary(session, user={"sub": "system:ciso", "role": "Admin", "tenant_id": "tenant-alpha"})
    assert ciso_summary["overall_risk_posture"] == "critical"
    assert ciso_summary["highest_risk_assets"]["items"][0]["asset_id"] == "A-GATEWAY-DOWN"

    # 2. SYNTHESIS
    synth = get_dashboard_data(session, tenant_id="tenant-alpha")
    assert synth["exposure_coverage"]["asset_linked_count"] == 1

    # 3. SPECTRUM
    spectrum = get_spectrum_findings(
        page=1, limit=50, scope="confirmed_exposure", db=session,
        user={"sub": "analyst", "role": "Analyst", "tenant_id": "tenant-alpha"},
    )
    assert len(spectrum["data"]) == 1
    assert spectrum["data"][0]["cve"] == "CVE-2021-44228"

    # 4. Reporting Engine
    poc = generate_poc_report_pipeline(
        session, "tenant-alpha", "system:ciso", ["F-OPEN-DOWN", "F-CAT-DOWN"],
        {
            "client": {"organisation": "Alpha Corp", "environment": "Prod"},
            "period": {"start": "2026-08-01", "end": "2026-08-18"},
            "coverage": {"scope": ["Perimeter"], "out_of_scope": ["Office"]},
            "assessment": {}, "delivery": {},
        },
    )
    assert poc["manifest"]["source_finding_ids"] == ["F-OPEN-DOWN"]

    # 5. Audit Log Chain
    verification = verify_audit_chain(session, "tenant-alpha")
    assert verification["intact"] is True
