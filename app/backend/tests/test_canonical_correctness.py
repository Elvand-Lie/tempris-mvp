import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import (  # noqa: E402
    Asset,
    AssetExposure,
    Base,
    Finding,
    FindingStatusHistory,
    GeneratedReport,
    GrcPolicyDocument,
    Incident,
    IncidentReport,
    OperationalEvent,
    PostureSnapshot,
    ScanFinding,
    ScanJob,
    StrikeAuthorization,
    StrikeSimulation,
)
from routers.scanner import get_scan_findings, get_scan_history, get_scan_summary  # noqa: E402
from routers.spectrum import get_findings as get_spectrum_findings  # noqa: E402
from routers.strike import (  # noqa: E402
    _normalise_results,
    get_authorizations,
    get_mitre_matrix,
    get_simulation_status,
    get_simulations,
)
from routers.standard import IncidentReportRequest, generate_incident_report, get_frameworks  # noqa: E402
from routers.synthesis import dashboard as synthesis_dashboard  # noqa: E402
from routers.workflow import FindingLifecycleRequest, reopen_finding, resolve_finding  # noqa: E402
from routers.grc import PolicyCreate, create_policy, delete_policy  # noqa: E402
from routers.incidents import IncidentInput, create_incident  # noqa: E402
from services.customer_posture import build_customer_posture, canonical_exposure_rows  # noqa: E402
from services.exposure_links import confirm_finding_assets, set_finding_assets  # noqa: E402
from services.reporting_engine import generate_poc_report_pipeline  # noqa: E402
from services.scan_normalizer import normalize_observation  # noqa: E402


@pytest.fixture()
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'canonical.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    monkeypatch.setenv("REPORT_STORAGE_ROOT", str(tmp_path / "reports"))
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _finding(identifier: str, tenant: str = "tenant-a", **values) -> Finding:
    defaults = {
        "id": identifier,
        "tenant_id": tenant,
        "title": identifier,
        "status": "unmitigated",
        "priority": "P0",
        "source": "sss",
        "raw_inputs": {
            "cvss": 8.0,
            "exploitability": 8.0,
            "business_impact": 8.0,
            "asset_criticality": 8.0,
            "threat_actor_activity": 8.0,
        },
    }
    defaults.update(values)
    return Finding(**defaults)


def test_scanner_and_strike_reads_are_tenant_isolated(db):
    now = datetime.now(timezone.utc)
    db.add_all([
        ScanJob(id="SCAN-A", tenant_id="tenant-a", target="a.example.test", normalized_target="a.example.test", scan_type="fixture", engines=["fixture"], status="completed", result_count=1, started_at=now),
        ScanJob(id="SCAN-B", tenant_id="tenant-b", target="b.example.test", normalized_target="b.example.test", scan_type="fixture", engines=["fixture"], status="completed", result_count=1, started_at=now),
        ScanFinding(id="SF-A", tenant_id="tenant-a", scan_id="SCAN-A", target="a.example.test", risk="High", service="fixture", last_seen_at=now),
        ScanFinding(id="SF-B", tenant_id="tenant-b", scan_id="SCAN-B", target="b.example.test", risk="Critical", service="fixture", last_seen_at=now),
        StrikeAuthorization(id="AUTH-A", tenant_id="tenant-a", target_name="a.example.test", status="signed", techniques=["T1595"]),
        StrikeAuthorization(id="AUTH-B", tenant_id="tenant-b", target_name="b.example.test", status="signed", techniques=["T1046"]),
        StrikeSimulation(id="SIM-A", tenant_id="tenant-a", authorization_id="AUTH-A", status="completed", techniques_tested=["T1595"], results=[{"technique_id": "T1595", "result": "NO_EXPOSURE_OBSERVED", "confidence": 0.8}], started_at=now, completed_at=now),
        StrikeSimulation(id="SIM-B", tenant_id="tenant-b", authorization_id="AUTH-B", status="completed", techniques_tested=["T1046"], results=[{"technique_id": "T1046", "result": "EXPLOITABLE_OBSERVED", "confidence": 0.9}], started_at=now, completed_at=now),
        StrikeSimulation(id="SIM-CROSS", tenant_id="tenant-a", authorization_id="AUTH-B", status="completed", techniques_tested=[], results=[], started_at=now, completed_at=now),
    ])
    db.commit()
    user = {"sub": "analyst@example.test", "role": "Analyst", "tenant_id": "tenant-a"}

    assert [row["id"] for row in get_scan_findings(db=db, user=user)] == ["SF-A"]
    assert [row["scan_id"] for row in get_scan_history(db=db, user=user)] == ["SCAN-A"]
    assert get_scan_summary(db=db, user=user)["total"] == 1
    assert [row["id"] for row in get_authorizations(db=db, user=user)] == ["AUTH-A"]
    assert {row["id"] for row in get_simulations(db=db, user=user)} == {"SIM-A", "SIM-CROSS"}
    assert get_simulation_status("SIM-CROSS", db=db, user=user)["target"] == "unknown"
    matrix = get_mitre_matrix(db=db, user=user)
    assert matrix["Reconnaissance"][0]["result"] == "NO_EXPOSURE_OBSERVED"
    assert matrix["Discovery"][0]["tested"] is False


def test_canonical_exposure_rejects_legacy_suggestions_reference_resolved_and_inactive(db):
    active = Asset(id="A-ACT", tenant_id="tenant-a", name="Active", hostname="active.test", status="active")
    retired = Asset(id="A-OLD", tenant_id="tenant-a", name="Retired", status="decommissioned")
    other = Asset(id="A-B", tenant_id="tenant-b", name="Other", status="active")
    confirmed = _finding("F-CONF")
    legacy = _finding("F-LEG", asset_id="A-ACT")
    suggested = _finding("F-SUG", vendor="Active", product="Active")
    reference = _finding("F-REF", status="reference_only")
    not_applicable = _finding("F-NA", status="not_applicable")
    resolved = _finding("F-RES", status="resolved")
    on_retired = _finding("F-OLD")
    db.add_all([active, retired, other, confirmed, legacy, suggested, reference, not_applicable, resolved, on_retired])
    db.flush()
    db.add_all([
        AssetExposure(id="EXP-1", tenant_id="tenant-a", finding_id="F-CONF", asset_id="A-ACT", status="confirmed", evidence="scanner", match_method="nuclei"),
        AssetExposure(id="EXP-ACCEPTED", tenant_id="tenant-a", finding_id="F-LEG", asset_id="A-ACT", status="accepted", evidence="legacy state", match_method="legacy"),
        AssetExposure(id="EXP-2", tenant_id="tenant-a", finding_id="F-REF", asset_id="A-ACT", status="confirmed", evidence="old", match_method="manual"),
        AssetExposure(id="EXP-3", tenant_id="tenant-a", finding_id="F-NA", asset_id="A-ACT", status="confirmed", evidence="old", match_method="manual"),
        AssetExposure(id="EXP-4", tenant_id="tenant-a", finding_id="F-RES", asset_id="A-ACT", status="confirmed", evidence="old", match_method="manual"),
        AssetExposure(id="EXP-5", tenant_id="tenant-a", finding_id="F-OLD", asset_id="A-OLD", status="confirmed", evidence="old", match_method="manual"),
    ])
    db.commit()

    rows = canonical_exposure_rows(db, "tenant-a")
    assert [(finding.id, asset.id) for finding, asset, _ in rows] == [("F-CONF", "A-ACT")]
    posture = build_customer_posture(db, "tenant-a")
    assert posture["confirmed_open_exposure_count"] == 1
    assert posture["confirmed_exposure_link_count"] == 1
    assert posture["legacy_unverified_finding_ids"] == ["F-LEG"]
    assert posture["reference_intelligence_count"] >= 1
    assert posture["not_applicable_count"] == 1
    assert posture["resolved_finding_count"] == 1
    assert posture["suggested_match_count"] == 1

    spectrum = get_spectrum_findings(
        page=1, limit=50, scope="confirmed_exposure", db=db,
        user={"sub": "analyst@example.test", "role": "Analyst", "tenant_id": "tenant-a"},
    )
    assert [row["id"] for row in spectrum["data"]] == ["F-CONF"]
    assert spectrum["data"][0]["asset"]["asset_id"] == "A-ACT"
    assert spectrum["data"][0]["asset"]["name"] == "Active"
    assert spectrum["data"][0]["assets"][0]["source"] == "nuclei"
    assert "raw_inputs" not in spectrum["data"][0]

    with pytest.raises(ValueError, match="active assets from the finding tenant"):
        confirm_finding_assets(db, confirmed, [other], "analyst", evidence="invalid")
    with pytest.raises(ValueError, match="active assets from the finding tenant"):
        confirm_finding_assets(db, confirmed, [retired], "analyst", evidence="invalid")


def test_clearing_asset_assignment_preserves_exposure_provenance(db):
    asset = Asset(id="A-HISTORY", tenant_id="tenant-a", name="History", status="active")
    finding = _finding("F-HISTORY")
    db.add_all([asset, finding])
    db.flush()
    confirm_finding_assets(db, finding, [asset], "analyst", evidence="Recorded evidence")
    db.commit()

    before, after, added, removed = set_finding_assets(db, finding, [], "analyst")
    db.commit()

    assert before == ["A-HISTORY"]
    assert after == []
    assert added == []
    assert removed == ["A-HISTORY"]
    retained = db.query(AssetExposure).filter(AssetExposure.finding_id == finding.id).one()
    assert retained.status == "removed"
    assert retained.evidence == "Recorded evidence"
    assert finding.asset_id is None


def test_scanner_normalization_is_deterministic_and_evidence_backed(db):
    asset = Asset(id="A-WEB", tenant_id="tenant-a", name="Web", hostname="web.example.test", status="active")
    existing = _finding("F-CVE", cve="CVE-2026-12345", cve_id="CVE-2026-12345", source="kev")
    job = ScanJob(
        id="SCAN-1", tenant_id="tenant-a", target="https://web.example.test/path",
        normalized_target="web.example.test", scan_type="full", engines=["nuclei"], status="completed",
        result_count=1,
    )
    db.add_all([asset, existing, job])
    db.commit()
    observation = {
        "engine": "nuclei",
        "target": "https://web.example.test/path",
        "matched_at": "https://web.example.test/login",
        "template_id": "CVE-2026-12345",
        "cve_id": "CVE-2026-12345",
        "service": "Known test CVE",
        "risk": "critical",
        "detail": "Fixture matcher evidence",
        "metadata": {"tags": ["cve"]},
    }
    first = normalize_observation(db, tenant_id="tenant-a", scan_job=job, observation=observation, actor_id="tester")
    second = normalize_observation(db, tenant_id="tenant-a", scan_job=job, observation=observation, actor_id="tester")
    db.commit()
    assert first["finding"].id == "F-CVE"
    assert second["scan_finding"].id == first["scan_finding"].id
    assert db.query(ScanFinding).count() == 1
    assert db.query(Finding).filter(Finding.cve == "CVE-2026-12345").count() == 1
    links = db.query(AssetExposure).all()
    assert len(links) == 1
    assert links[0].match_method == "nuclei"
    assert links[0].evidence_metadata["raw_result_hash"]

    nmap = normalize_observation(
        db, tenant_id="tenant-a", scan_job=job,
        observation={"engine": "nmap", "target": "web.example.test", "port": 443, "service": "https", "risk": "Info"},
        actor_id="tester",
    )
    fingerprint = normalize_observation(
        db, tenant_id="tenant-a", scan_job=job,
        observation={"engine": "nuclei", "target": "web.example.test", "template_id": "tech-detect", "service": "Apache", "risk": "info", "metadata": {"tags": ["tech"]}},
        actor_id="tester",
    )
    assert nmap["finding"] is None
    assert fingerprint["finding"] is None


def test_non_cve_security_template_and_unknown_target_enter_correct_states(db):
    job = ScanJob(
        id="SCAN-2", tenant_id="tenant-a", target="unknown.example.test",
        normalized_target="unknown.example.test", scan_type="full", engines=["nuclei"], status="completed", result_count=1,
    )
    db.add(job)
    db.commit()
    result = normalize_observation(
        db, tenant_id="tenant-a", scan_job=job,
        observation={
            "engine": "nuclei", "target": "unknown.example.test", "template_id": "exposed-admin-console",
            "service": "Exposed administrative console", "risk": "high", "detail": "Fixture matched",
            "metadata": {"tags": ["misconfig"]},
        }, actor_id="tester",
    )
    db.commit()
    assert result["finding"] is not None
    assert result["exposure"] == "needs_classification"
    assert db.query(AssetExposure).count() == 0
    assert build_customer_posture(db, "tenant-a")["needs_classification_count"] == 1


def test_strike_no_exposure_is_not_a_defensive_block():
    rows = _normalise_results([
        {"technique_id": "T1", "result": "blocked", "confidence": 0.85},
        {"technique_id": "T2", "result": "DEFENSIVE_BLOCK_VERIFIED", "evidence": "stopped"},
        {"technique_id": "T3", "result": "DEFENSIVE_BLOCK_VERIFIED", "evidence": "stopped", "defensive_control_id": "WAF-1"},
    ])
    assert rows[0]["result"] == "NO_EXPOSURE_OBSERVED"
    assert rows[0]["confidence_label"] == "Check confidence"
    assert rows[1]["result"] == "ERROR"
    assert rows[2]["result"] == "DEFENSIVE_BLOCK_VERIFIED"


def test_synthesis_trend_requires_two_comparable_canonical_snapshots(db, monkeypatch):
    monkeypatch.setattr(
        "routers.synthesis.get_dashboard_data",
        lambda db, tenant_id: {"aggregate_tes": 6.0, "_stats": {}},
    )
    user = {"sub": "viewer@example.test", "role": "Viewer", "tenant_id": "tenant-a"}
    now = datetime.now(timezone.utc)
    db.add(PostureSnapshot(
        tenant_id="tenant-a", scope_version="canonical-customer-exposure-v1",
        captured_at=now - timedelta(days=2), aggregate_tenant_tes=5.0,
    ))
    db.commit()
    assert synthesis_dashboard(db=db, user=user)["tes_trend"] is None

    db.add(PostureSnapshot(
        tenant_id="tenant-a", scope_version="canonical-customer-exposure-v1",
        captured_at=now - timedelta(days=1), aggregate_tenant_tes=5.5,
    ))
    db.commit()
    assert synthesis_dashboard(db=db, user=user)["tes_trend"] == "+1.0"


def test_client_report_includes_many_to_many_confirmed_only(db, tmp_path, monkeypatch):
    monkeypatch.setattr("services.reporting_engine.append_to_audit_log_db", lambda *args, **kwargs: None)
    assets = [
        Asset(id="A-1", tenant_id="tenant-a", name="One", status="active"),
        Asset(id="A-2", tenant_id="tenant-a", name="Two", status="active"),
    ]
    confirmed = _finding("F-RPT")
    legacy = _finding("F-LGY", asset_id="A-1")
    reference = _finding("F-RRF", status="reference_only")
    db.add_all([*assets, confirmed, legacy, reference])
    db.flush()
    db.add_all([
        AssetExposure(id="R-1", tenant_id="tenant-a", finding_id="F-RPT", asset_id="A-1", status="confirmed", match_method="analyst", evidence="one"),
        AssetExposure(id="R-2", tenant_id="tenant-a", finding_id="F-RPT", asset_id="A-2", status="confirmed", match_method="analyst", evidence="two"),
        AssetExposure(id="R-3", tenant_id="tenant-a", finding_id="F-RRF", asset_id="A-1", status="confirmed", match_method="analyst", evidence="excluded"),
    ])
    db.commit()
    result = generate_poc_report_pipeline(
        db, "tenant-a", "admin@example.test", ["F-RPT", "F-LGY", "F-RRF"],
        {
            "client": {"organisation": "Fixture customer", "environment": "Test"},
            "period": {"start": "2026-08-01", "end": "2026-08-15"},
            "coverage": {"scope": ["Fixture scope"], "out_of_scope": ["Everything else"]},
            "assessment": {}, "delivery": {},
        },
    )
    assert result["manifest"]["source_finding_ids"] == ["F-RPT"]
    assert len(list((tmp_path / "reports").glob(f"{result['report_id']}*"))) == 3
    assert db.query(OperationalEvent).filter(OperationalEvent.tenant_id == "tenant-a").count() >= 1


def test_standard_coverage_and_compliance_only_use_recorded_assessments(db):
    empty = {row["id"]: row for row in get_frameworks(db=db, user={"sub": "admin", "role": "Admin", "tenant_id": "tenant-a"})}
    assert empty["pdpa"]["assessment_coverage_label"] == "0 / 3"
    assert empty["pdpa"]["compliance_among_assessed_pct"] is None
    from models import ControlStatus

    db.add_all([
        ControlStatus(tenant_id="tenant-a", framework_id="pdpa", control_id="PDPA-26", status="compliant"),
        ControlStatus(tenant_id="tenant-a", framework_id="pdpa", control_id="PDPA-24", status="partial"),
    ])
    db.commit()
    assessed = {row["id"]: row for row in get_frameworks(db=db, user={"sub": "admin", "role": "Admin", "tenant_id": "tenant-a"})}
    assert assessed["pdpa"]["assessment_coverage_label"] == "2 / 3"
    assert assessed["pdpa"]["assessment_coverage_pct"] == 66.7
    assert assessed["pdpa"]["compliance_among_assessed_pct"] == 75.0


def test_incident_draft_uses_real_incident_and_confirmed_related_exposure_only(db, monkeypatch):
    monkeypatch.setattr("routers.standard.append_to_audit_log_db", lambda *args, **kwargs: None)
    asset = Asset(id="A-INC", tenant_id="tenant-a", name="Incident asset", status="active")
    confirmed = _finding("F-INC", ransomware=True)
    catalogue = _finding("F-CAT", source="kev", cisa_kev=True)
    incident = Incident(
        id="INC-REAL", tenant_id="tenant-a", external_event_id="SOC-1", source="soc",
        discovered_at=datetime.now(timezone.utc), title="Observed event", summary="Observed summary",
        severity="high", status="open", affected_asset_ids=["A-INC"],
        related_finding_ids=["F-INC", "F-CAT"], evidence_references=["https://evidence.example/1"],
        observed_impact="Service degradation", response_actions=["Contained account"],
    )
    db.add_all([asset, confirmed, catalogue, incident])
    db.flush()
    db.add(AssetExposure(
        id="EXP-INC", tenant_id="tenant-a", finding_id="F-INC", asset_id="A-INC",
        status="confirmed", match_method="analyst", evidence="SOC correlation",
    ))
    db.commit()
    report = generate_incident_report(
        IncidentReportRequest(incident_id="INC-REAL"), db=db,
        user={"sub": "admin", "role": "Admin", "tenant_id": "tenant-a"},
    )
    assert report["incident_id"] == "INC-REAL"
    assert [item["finding_id"] for item in report["confirmed_related_exposures"]] == ["F-INC"]
    assert report["confirmed_ransomware_linked_count"] == 1
    assert db.query(IncidentReport).count() == 1
    with pytest.raises(HTTPException) as missing:
        generate_incident_report(
            IncidentReportRequest(), db=db,
            user={"sub": "admin", "role": "Admin", "tenant_id": "tenant-a"},
        )
    assert missing.value.status_code == 422


def test_resolve_and_reopen_preserve_history_and_update_posture(db, monkeypatch):
    monkeypatch.setattr("routers.workflow._publish_finding_refresh", lambda *args: None)
    monkeypatch.setattr("routers.workflow.append_to_audit_log_db", lambda *args, **kwargs: None)
    asset = Asset(id="A-LIFE", tenant_id="tenant-a", name="Lifecycle", status="active")
    finding = _finding("F-LIFE")
    db.add_all([asset, finding])
    db.flush()
    db.add(AssetExposure(
        id="EXP-LIFE", tenant_id="tenant-a", finding_id="F-LIFE", asset_id="A-LIFE",
        status="confirmed", match_method="analyst", evidence="Validated",
    ))
    db.commit()
    user = {"sub": "super@example.test", "role": "Superadmin", "tenant_id": "tenant-a"}
    assert build_customer_posture(db, "tenant-a")["confirmed_open_exposure_count"] == 1
    resolve_finding("F-LIFE", FindingLifecycleRequest(rationale="Resolved in fixture test"), db=db, user=user)
    assert build_customer_posture(db, "tenant-a")["confirmed_open_exposure_count"] == 0
    reopen_finding("F-LIFE", FindingLifecycleRequest(rationale="Reopened in fixture test"), db=db, user=user)
    assert build_customer_posture(db, "tenant-a")["confirmed_open_exposure_count"] == 1
    history = db.query(FindingStatusHistory).filter(FindingStatusHistory.finding_id == "F-LIFE").all()
    assert [(row.old_status, row.new_status) for row in history] == [
        ("unmitigated", "resolved"), ("resolved", "unmitigated")
    ]


def test_grc_policy_delete_rules_and_audit_events(db, monkeypatch):
    monkeypatch.setattr("routers.grc.append_to_audit_log", lambda *args, **kwargs: None)
    user = {"sub": "super@example.test", "role": "Superadmin", "tenant_id": "tenant-a"}
    with pytest.raises(HTTPException) as bundled:
        delete_policy("iso42001", db=db, user=user)
    assert bundled.value.status_code == 409

    first = create_policy(PolicyCreate(title="Disposable custom", content="fixture"), db=db, user=user)
    assert delete_policy(first["id"], db=db, user=user)["status"] == "deleted"
    assert db.query(GrcPolicyDocument).filter(GrcPolicyDocument.id == first["id"]).first() is None

    second = create_policy(PolicyCreate(title="Referenced custom", content="fixture"), db=db, user=user)
    db.add(GeneratedReport(
        id="REP-POL", tenant_id="tenant-a", report_type="json", generator_version="test",
        requested_by="super@example.test", source_finding_ids=[], source_evidence_ids=[],
        framework_configuration={"policy_id": second["id"]}, content_hash="a" * 64,
        artifact_location="fixture.json",
    ))
    db.commit()
    result = delete_policy(second["id"], db=db, user=user)
    assert result["status"] == "archived"
    assert db.query(GrcPolicyDocument).filter(GrcPolicyDocument.id == second["id"]).one().status == "Archived"
    event_types = {row.event_type for row in db.query(OperationalEvent).all()}
    assert {"policy.created", "policy.deleted", "policy.archived"} <= event_types


def test_incident_intake_is_idempotent_and_rejects_cross_tenant_links(db, monkeypatch):
    monkeypatch.setattr("routers.incidents.append_to_audit_log_db", lambda *args, **kwargs: None)
    db.add_all([
        Asset(id="A-TA", tenant_id="tenant-a", name="Tenant A", status="active"),
        Asset(id="A-TB", tenant_id="tenant-b", name="Tenant B", status="active"),
        _finding("F-TA", tenant="tenant-a"),
        _finding("F-TB", tenant="tenant-b"),
    ])
    db.commit()
    user = {"sub": "analyst@example.test", "role": "Analyst", "tenant_id": "tenant-a"}
    payload = IncidentInput(
        external_event_id="EXT-1", source="soc", discovered_at=datetime.now(timezone.utc),
        title="Tenant incident", summary="Fixture summary", severity="high",
        affected_asset_ids=["A-TA"], related_finding_ids=["F-TA"],
    )
    created = create_incident(payload, db=db, user=user)
    repeated = create_incident(payload, db=db, user=user)
    assert created["created"] is True
    assert repeated["created"] is False
    assert db.query(Incident).filter(Incident.tenant_id == "tenant-a").count() == 1
    cross_tenant = payload.model_copy(update={"external_event_id": "EXT-2", "affected_asset_ids": ["A-TB"]})
    with pytest.raises(HTTPException) as blocked:
        create_incident(cross_tenant, db=db, user=user)
    assert blocked.value.status_code == 422
