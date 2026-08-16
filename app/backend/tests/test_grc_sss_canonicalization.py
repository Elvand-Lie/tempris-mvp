"""Regression coverage for canonical GRC assessments and non-CVE TES."""

import os
import sys

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import Base, Finding, GrcPolicyDocument, PolicyControlLink
from routers.edip import SssIntake
from routers.grc import PolicyCreate, _replace_policy_links
from services.tes_engine import calculate_sss_tes
from services.grc_framework import (
    ISO_42001_ID,
    assessment_rows,
    ensure_framework_catalog,
    ensure_tenant_assessments,
    get_live_grc_modifiers,
    recalculate_open_sss_findings,
)


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _complete_all(db, tenant_id="tenant-a"):
    for _, assessment, _, _ in assessment_rows(db, tenant_id):
        assessment.status = "completed"
        assessment.end_user_agreed = True
        assessment.pic_signed_off = True
    db.flush()


def test_server_managed_iso_controls_and_live_modifier_boundaries(db):
    ensure_framework_catalog(db)
    ensure_tenant_assessments(db, "tenant-a")
    rows = assessment_rows(db, "tenant-a")
    assert [control.control_id for control, *_ in rows] == [
        "A.2.2", "A.3.2", "A.5.2", "A.6.2.2", "A.7.4", "A.9.2", "A.10.3",
    ]
    assert get_live_grc_modifiers(db, "tenant-a") | {"as_of": None} == {
        "AGM": 1.5, "DRF": 1.3, "TEF": 1.2, "as_of": None,
    }

    _complete_all(db)
    assert get_live_grc_modifiers(db, "tenant-a") | {"as_of": None} == {
        "AGM": 1.0, "DRF": 1.0, "TEF": 1.0, "as_of": None,
    }

    data_quality = next(row for control, row, *_ in assessment_rows(db, "tenant-a") if control.control_id == "A.7.4")
    data_quality.status = "pending"
    data_quality.end_user_agreed = False
    data_quality.pic_signed_off = False
    db.flush()
    assert get_live_grc_modifiers(db, "tenant-a") | {"as_of": None} == {
        "AGM": 1.0, "DRF": 1.3, "TEF": 1.0, "as_of": None,
    }


def test_grc_recalculation_updates_open_sss_and_preserves_resolved_history(db):
    ensure_tenant_assessments(db, "tenant-a")
    finding = Finding(
        id="F-SSS-GRC", tenant_id="tenant-a", title="Manual identity finding",
        source="sss", status="unmitigated", cvss=4.0, cve="SSS-TEST",
        sss_data={"scoring": {"base_severity": 4.0, "AGM": 1.0, "DRF": 1.0, "TEF": 1.0}},
    )
    resolved = Finding(
        id="F-SSS-RES", tenant_id="tenant-a", title="Resolved identity finding",
        source="sss", status="resolved", cvss=5.0, cve="SSS-RES",
        score=5.0,
        sss_data={"scoring": {"base_severity": 5.0, "AGM": 1.0, "DRF": 1.0, "TEF": 1.0}},
    )
    db.add_all([finding, resolved])
    db.flush()

    changed = recalculate_open_sss_findings(db, "tenant-a", "tester")
    assert changed == ["F-SSS-GRC"]
    assert finding.score == 5.6
    assert finding.decision == "INVESTIGATE"
    assert finding.sss_data["scoring_history"][-1]["modifiers"] == {"AGM": 1.0, "DRF": 1.0, "TEF": 1.0}
    assert resolved.sss_data["scoring"]["AGM"] == 1.0
    assert resolved.score == 5.0

    _complete_all(db)
    changed = recalculate_open_sss_findings(db, "tenant-a", "tester")
    assert changed == ["F-SSS-GRC"]
    assert finding.score == 4.0
    assert finding.decision == "INVESTIGATE"
    assert resolved.sss_data["scoring"]["AGM"] == 1.0
    assert resolved.score == 5.0


def test_non_cve_combined_grc_adjustment_is_bounded_before_final_tes_cap():
    scoring = {"base_severity": 4.0}
    assert calculate_sss_tes(scoring, live_modifiers={"AGM": 1.1, "DRF": 1.0, "TEF": 1.0}) == 4.4
    assert calculate_sss_tes(scoring, live_modifiers={"AGM": 1.2, "DRF": 1.1, "TEF": 1.1}) == 5.6
    assert calculate_sss_tes({"base_severity": 8.0}, live_modifiers={"AGM": 1.5, "DRF": 1.3, "TEF": 1.2}) == 10.0


def test_policy_link_is_explicit_and_never_completes_a_control(db):
    ensure_tenant_assessments(db, "tenant-a")
    policy = GrcPolicyDocument(id="POL-1", tenant_id="tenant-a", title="Custom", content="evidence")
    db.add(policy)
    db.flush()
    with pytest.raises(HTTPException):
        _replace_policy_links(db, "tenant-a", policy.id, None, [], False, "tester")
    _replace_policy_links(db, "tenant-a", policy.id, ISO_42001_ID, ["A.2.2"], False, "tester")
    assert db.query(PolicyControlLink).count() == 1
    assert get_live_grc_modifiers(db, "tenant-a")["AGM"] == 1.5


def test_custom_policy_declares_unmapped_or_explicit_control_links():
    with pytest.raises(ValidationError):
        PolicyCreate.model_validate({"title": "Undeclared policy"})
    assert PolicyCreate.model_validate({"title": "Supporting document", "unmapped": True}).unmapped is True


def test_manual_identity_and_agentic_intake_require_explicit_sss():
    base = {"title": "Manual posture", "description": "Analyst-recorded posture evidence."}
    with pytest.raises(ValidationError, match="SSS base severity is required"):
        SssIntake.model_validate({**base, "class": "IDENTITY_POSTURE", "sub_class": "MFA_ENROLMENT"})
    with pytest.raises(ValidationError, match="SSS base severity is required"):
        SssIntake.model_validate({**base, "class": "AGENTIC_EXPOSURE", "sub_class": "ADVERSARY_AI"})
    result = SssIntake.model_validate({
        **base, "class": "IDENTITY_POSTURE", "sub_class": "MFA_ENROLMENT", "base_severity": 6.5,
    })
    assert result.base_severity == 6.5


def test_tenant_assessments_are_isolated(db):
    ensure_tenant_assessments(db, "tenant-a")
    ensure_tenant_assessments(db, "tenant-b")
    _complete_all(db, "tenant-a")
    assert get_live_grc_modifiers(db, "tenant-a")["AGM"] == 1.0
    assert get_live_grc_modifiers(db, "tenant-b")["AGM"] == 1.5
