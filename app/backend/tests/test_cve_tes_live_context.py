"""Regression coverage for current, evidence-backed CVE TES context."""

import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import Asset, AssetExposure, Base, Finding, ScanFinding
from routers.spectrum import BusinessImpactUpdate, update_business_impact
from services.customer_posture import build_customer_posture
from services.tes_engine import get_live_cve_tes_context, recalculate_open_cve_findings


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _confirmed_cve(db, *, finding_id="F-CVE", criticality="critical", tenant="tenant-a", **values):
    asset = Asset(id=f"A-{finding_id}", tenant_id=tenant, name="Customer asset", criticality=criticality, status="active")
    defaults = {
        "id": finding_id, "tenant_id": tenant, "cve": "CVE-2026-1000", "cve_id": "CVE-2026-1000",
        "title": "CVE finding", "cvss": 8.0, "status": "unmitigated", "source": "kev",
        # Deliberately wrong legacy values: current scoring must ignore them.
        "raw_inputs": {"cvss": 1.0, "exploitability": 10.0, "business_impact": 10.0, "asset_criticality": 1.0, "threat_actor_activity": 10.0},
    }
    defaults.update(values)
    finding = Finding(**defaults)
    db.add_all([asset, finding])
    db.flush()
    db.add(AssetExposure(
        id=f"EXP-{finding_id}", tenant_id=tenant, finding_id=finding.id, asset_id=asset.id,
        status="confirmed", evidence="Analyst confirmed affected asset", match_method="manual",
    ))
    db.commit()
    return finding, asset


def _as_dict(finding):
    return {
        "id": finding.id, "cve": finding.cve, "cve_id": finding.cve_id, "cvss": finding.cvss,
        "cisa": finding.cisa_kev, "ransomware": finding.ransomware,
        "cve_context": finding.cve_context or {}, "dateAdded": finding.date_added,
    }


def test_cve_context_uses_stored_cvss_confirmed_asset_and_neutral_unassessed_impact(db):
    finding, asset = _confirmed_cve(db)
    inputs, context = get_live_cve_tes_context(_as_dict(finding), db=db, tenant_id="tenant-a")

    assert inputs.cvss == 8.0
    assert inputs.asset_criticality == 10.0
    assert inputs.business_impact == 5.0
    assert inputs.exploitability == 0.0
    assert inputs.threat_actor_activity == 0.0
    assert context["business_impact"]["assessed"] is False

    asset.criticality = "medium"
    db.flush()
    inputs, _ = get_live_cve_tes_context(_as_dict(finding), db=db, tenant_id="tenant-a")
    assert inputs.asset_criticality == 5.0


def test_cve_context_uses_highest_confirmed_active_asset_and_deterministic_evidence(db):
    finding, _ = _confirmed_cve(db, criticality="low", cisa_kev=True)
    high_asset = Asset(id="A-HIGH", tenant_id="tenant-a", name="High asset", criticality="high", status="active")
    db.add(high_asset)
    db.flush()
    db.add(AssetExposure(
        id="EXP-HIGH", tenant_id="tenant-a", finding_id=finding.id, asset_id=high_asset.id,
        status="confirmed", evidence="Scanner evidence", match_method="nuclei",
    ))
    db.commit()

    inputs, context = get_live_cve_tes_context(_as_dict(finding), db=db, tenant_id="tenant-a")
    assert inputs.asset_criticality == 8.0
    assert inputs.exploitability == 8.0
    assert inputs.threat_actor_activity == 8.0
    assert context["exploitability"]["source"] == "cisa_kev"


def test_nuclei_match_is_exploit_evidence_but_port_observation_is_not(db):
    finding, _ = _confirmed_cve(db)
    db.add(ScanFinding(
        id="SF-PORT", tenant_id="tenant-a", normalized_finding_id="OTHER", target="asset.test",
        service="https", risk="Info", evidence_metadata={"engine": "nmap"},
    ))
    db.flush()
    inputs, _ = get_live_cve_tes_context(_as_dict(finding), db=db, tenant_id="tenant-a")
    assert inputs.exploitability == 0.0

    db.add(ScanFinding(
        id="SF-NUCLEI", tenant_id="tenant-a", normalized_finding_id=finding.id, target="asset.test",
        template_id="cve-template", risk="High", evidence_metadata={"engine": "nuclei"},
    ))
    db.flush()
    inputs, context = get_live_cve_tes_context(_as_dict(finding), db=db, tenant_id="tenant-a")
    assert inputs.exploitability == 7.0
    assert context["exploitability"]["source"] == "nuclei_match"


def test_analyst_business_impact_recalculates_open_cve_and_preserves_resolved_history(db, monkeypatch):
    finding, _ = _confirmed_cve(db)
    finding.score = 3.4
    resolved, _ = _confirmed_cve(db, finding_id="F-RES", criticality="critical", status="resolved", score=9.9)
    db.commit()
    monkeypatch.setattr("routers.audit.append_to_audit_log_db", lambda *args, **kwargs: {})

    result = update_business_impact(
        finding.id,
        BusinessImpactUpdate(value=9.0, justification="Confirmed impact to the customer payment service."),
        db=db,
        user={"sub": "analyst@example.test", "role": "Analyst", "tenant_id": "tenant-a"},
    )
    db.refresh(finding)
    db.refresh(resolved)
    assert result["business_impact"] == 9.0
    assert finding.cve_context["business_impact"]["source"] == "analyst_assessment"
    assert finding.score == 5.8
    assert finding.cve_context["scoring_history"][-1]["reason"] == "business_impact_updated"
    assert resolved.score == 9.9
    assert not resolved.cve_context


def test_tenant_tes_uses_one_live_score_per_confirmed_cve_not_asset_occurrence(db):
    finding, _ = _confirmed_cve(db, cisa_kev=True)
    extra = Asset(id="A-EXTRA", tenant_id="tenant-a", name="Extra", criticality="critical", status="active")
    db.add(extra)
    db.flush()
    db.add(AssetExposure(
        id="EXP-EXTRA", tenant_id="tenant-a", finding_id=finding.id, asset_id=extra.id,
        status="confirmed", evidence="Additional affected asset", match_method="manual",
    ))
    db.commit()
    expected = recalculate_open_cve_findings(db, "tenant-a", reason="test")
    assert expected == [finding.id]
    posture = build_customer_posture(db, "tenant-a")
    assert posture["confirmed_open_exposure_count"] == 1
    assert posture["confirmed_exposure_link_count"] == 2
    assert posture["aggregate_tenant_tes"] == finding.score
