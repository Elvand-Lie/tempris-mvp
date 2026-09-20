# backend/tests/test_p08_approval_backed_non_cve_tes.py
"""
P0-08 — APPROVAL-BACKED NON-CVE TES (PRD-000 v1.11 §3.6.3–§3.6.6 esp.
#3 overrides / #5 negative-ER attestation / #6 manual FINAL;
§3.3.2–§3.3.5; Chapter 5 primitive (Stage 1); Appendix C Q11/Q12/Q17;
Appendix D PATCH-13).

Covers: full propose→decide→apply flows for the three registered subject
types; the fail-closed battery (self-approval, wrong role, stale subject,
altered payload, cross-tenant, replay, superseded episode); approved SSS as
EFFECTIVE INPUT ONLY (TES may stay PROVISIONAL — approval never auto-FINALs);
override provenance "analyst override" with the pre-override value visible;
attestation ER 1.0 for the exact episode, expiry ⇒ unknown while visible;
identical decomposition semantics to a CVE intrinsic; no second approval
store (search-proof); recurrence requires new approvals.

Production gating (unchanged, P0-06): no approved VRT/rubric content exists,
so production derivation stays disabled — every approval-flow test here uses
the established fixture-operator pattern (operator-seeded approved
sss_derivation_versions rows, test_only schema).
"""
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import psycopg
import pytest

from app.approvals import (
    ApprovalAlreadyAppliedError,
    ApprovalAuthorityError,
    ApprovalDualControlError,
    ApprovalNotFoundError,
    ApprovalPayloadMismatchError,
    ApprovalStateError,
    ApprovalStaleSubjectError,
    ApprovalSubjectError,
    _REGISTRY,
    apply_approval,
    decide,
    propose,
)
from app.db import get_db_connection
from app.exposure import approval_consumers as consumers
from app.exposure.approval_consumers import (
    SUBJECT_ER_ATTESTATION,
    SUBJECT_MANUAL_SSS,
    SUBJECT_SSS_OVERRIDE,
    propose_override_binding,
)
from app.exposure.approval_consumers_noncve_read import (
    current_sss_intrinsic_with_provenance,
)
from app.exposure.models import ExposureConfirm, FindingCreate
from app.exposure.scoring_inputs import (
    ExploitationEvidenceIn,
    ReachabilityEvidenceIn,
    record_exploitation_evidence,
    record_non_exploitation_attestation,
    record_reachability_evidence,
)
from app.exposure.sss import create_sss_proposal, derive_sss_rubric
from app.exposure.service import confirm_exposure, create_finding
from app.exposure.tes_kernel import ProvenanceClass
from app.exposure.tes_read_model import get_exposure_tes
from tests.conftest import TENANT_A, TENANT_B

RUBRIC_CONTENT = {
    "facts": {
        "mfa_coverage": {"type": "enum", "values": ["none", "partial", "enforced"]},
    },
    "rules": [
        {"name": "mfa_none", "severity": "9.0", "match": {"mfa_coverage": ["none"]}},
    ],
}

ADMIN = "admin-a"
ADMIN2 = "superadmin-a"
ANALYST = "analyst-a"

AS_OF = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fixtures / seed helpers (fixture-operator pattern — P0-06)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env():
    """Isolation for the P0-08 scope."""
    def _clean():
        tenants = [str(TENANT_A), str(TENANT_B)]
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # one TRUNCATE over the whole FK-closed group: consumer rows
                # reference chapter5_approvals, so everything truncates together
                cur.execute(
                    "TRUNCATE chapter5_approval_audit, chapter5_approvals, "
                    "non_cve_sss_override_proposals, "
                    "non_cve_sss_proposals, non_cve_sss_derivations, "
                    "non_cve_classifications, "
                    "exposure_non_exploitation_attestations, "
                    "exposure_exploitation_evidence, exposure_business_impact, "
                    "exposure_reachability_evidence, asset_exposures, "
                    "asset_applicability_reviews CASCADE;")
                cur.execute("TRUNCATE identity_boundary_audit, tenant_identity_boundary;")
                cur.execute(
                    "DELETE FROM findings WHERE tenant_id = ANY(%s::uuid[]);",
                    (tenants,))
                cur.execute(
                    "DELETE FROM assets WHERE tenant_id = ANY(%s::uuid[]);",
                    (tenants,))
                cur.execute(
                    "DELETE FROM audit_events WHERE tenant_id = ANY(%s::uuid[]);",
                    (tenants,))
            conn.commit()
    _clean()
    yield
    _clean()


@pytest.fixture(autouse=True)
def _consumers_registered():
    """The consumer module registers at import; assert the three types."""
    for t in (SUBJECT_MANUAL_SSS, SUBJECT_SSS_OVERRIDE, SUBJECT_ER_ATTESTATION):
        assert t in _REGISTRY, f"{t} not registered"
    yield


def _make_asset(tenant=TENANT_A, target_type="domain"):
    target = (f"{uuid.uuid4().hex[:8]}.example.com" if target_type == "domain"
              else f"10.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}.1")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality, status
                ) VALUES (%s, %s, 'server', %s, %s, %s, 'internal', 'production',
                          'low', 'active')
                RETURNING id;
                """,
                (str(tenant), f"asset-{uuid.uuid4().hex[:6]}", target_type,
                 target, target.lower()),
            )
            asset_id = cur.fetchone()["id"]
        conn.commit()
    return asset_id


def _make_noncve_finding(tenant=TENANT_A, classification=None):
    with get_db_connection() as conn:
        finding = create_finding(conn, tenant, FindingCreate(
            title="posture finding", severity="high"))
        conn.commit()
    return finding.id


_TAX = {"taxonomy_class": "IDENTITY_POSTURE",
        "taxonomy_subclass": "MFA_ENROLMENT"}


def _seed_rubric_and_derive(tenant, finding_id):
    """Fixture-operator pattern: seed an operator-approved rubric version
    (no application code path creates approved content) and derive."""
    version_id = f"rubric-p08-{uuid.uuid4()}"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sss_derivation_versions
                    (version_id, kind, content, status, test_only,
                     approved_by, approved_at)
                VALUES (%s, 'rubric', %s, 'approved', FALSE,
                        'ops-approver', now())
                ON CONFLICT (version_id) DO NOTHING;
                """,
                (version_id, psycopg.types.json.Json(RUBRIC_CONTENT)),
            )
        derive_sss_rubric(
            conn, tenant, finding_id,
            rubric_version=version_id,
            taxonomy_class="IDENTITY_POSTURE",
            taxonomy_subclass="MFA_ENROLMENT",
            taxonomy_subtype=None,
            facts={"mfa_coverage": "none"},
            evidence={"source": "connector", "ref": "graph-auth"},
            actor_id="ops-approver", actor_role="admin",
        )
        conn.commit()
    return version_id


def _confirm(conn, tenant, finding_id, asset_id):
    return confirm_exposure(
        conn, tenant,
        ExposureConfirm(finding_id=finding_id, asset_id=asset_id,
                        evidence={"source": "analyst", "note": "confirmed"}),
        actor_id=ANALYST, actor_role="analyst",
    )


def _make_episode(tenant=TENANT_A, with_derivation=True, posture=True):
    """A confirmed non-CVE episode; optionally with a current derivation.
    posture=True designates the boundary (§3.6.6 #7 confirmation
    precondition); posture=False tests plain non-CVE exposures."""
    asset_id = _make_asset(tenant)
    fid = _make_noncve_finding(tenant)
    if with_derivation:
        _seed_rubric_and_derive(tenant, fid)
    if posture:
        from app.exposure.identity_boundary import create_identity_boundary
        with get_db_connection() as conn:
            create_identity_boundary(
                conn, tenant, asset_id=asset_id, criticality="medium",
                actor_id=ADMIN, actor_role="admin")
            conn.commit()
    with get_db_connection() as conn:
        result = _confirm(conn, tenant, fid, asset_id)
        conn.commit()
    return fid, asset_id, result.exposure.id


def _propose_and_approve(subject_type, subject_id, payload, *,
                         tenant=TENANT_A, proposer=ANALYST,
                         approver=ADMIN, extra=None):
    """Full propose → decide outside apply; returns the approval row."""
    with get_db_connection() as conn:
        row = propose(
            conn, tenant, subject_type=subject_type, subject_id=subject_id,
            payload=payload, actor_id=proposer, actor_role="analyst",
        )
        if extra:
            extra(conn)
        conn.commit()
    with get_db_connection() as conn:
        decide(conn, tenant, row["id"], decision="approved",
               approver_id=approver, approver_role="admin")
        conn.commit()
    return row


def _read_tes(exposure_id, tenant=TENANT_A, as_of=AS_OF):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
        cur.execute("SELECT 1;")
        cur.fetchone()
        cur.close()
        payload = get_exposure_tes(conn, tenant, exposure_id, as_of=as_of)
        conn.rollback()
    return payload


# ===========================================================================
# Subject 1 — manual SSS proposal: approval resolves the INPUT only
# ===========================================================================


class TestManualSssApproval:
    def test_full_flow_effective_input_only_never_auto_final(self):
        fid, asset_id, exposure_id = _make_episode(with_derivation=False,
                                                    posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="4.5",
                reason="manual triage", evidence={"ticket": "t-1"},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})
        with get_db_connection() as conn:
            out = apply_approval(conn, TENANT_A, approval["id"],
                                 actor_id=ADMIN, actor_role="admin")
            conn.commit()
        assert "derivation_id" in out["result"]

        # the approved value is now the EFFECTIVE SSS input
        with get_db_connection() as conn:
            intrinsic = current_sss_intrinsic_with_provenance(
                conn, TENANT_A, fid)
        assert intrinsic is not None and intrinsic.value == Decimal("4.5")

        # TES computes with the approved SSS but stays PROVISIONAL:
        # reachability/BI are unknown — approval NEVER auto-FINALs
        payload = _read_tes(exposure_id)
        assert payload["state"] in ("PROVISIONAL", "UNSCOREABLE")
        assert payload["state"] == "PROVISIONAL"
        intr_row = [r for r in payload["decomposition"]
                    if r["axis"] == "intrinsic"][0]
        assert intr_row["raw_value"] == {"__decimal__": "4.5000"}
        assert payload["source_view"]["sss"]["provenance"] == "approved manual"
        assert str(payload["source_view"]["sss"]["approval_id"]) == str(approval["id"])

    def test_proposal_pending_scores_nothing(self):
        fid, asset_id, exposure_id = _make_episode(with_derivation=False,
                                                    posture=False)
        with get_db_connection() as conn:
            create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="4.5",
                reason="manual triage", evidence={"ticket": "t-1"},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        payload = _read_tes(exposure_id)
        assert payload["state"] == "UNSCOREABLE"  # pending proposal never scores

    def test_self_approval_refused_end_to_end(self):
        fid, _a, _e = _make_episode(with_derivation=False, posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ADMIN, actor_role="admin")
            conn.commit()
        with get_db_connection() as conn:
            row = propose(conn, TENANT_A, subject_type=SUBJECT_MANUAL_SSS,
                          subject_id=str(proposal["id"]),
                          payload={"kind": "publish_manual_sss"},
                          actor_id=ADMIN, actor_role="admin")
            conn.commit()
            with pytest.raises(ApprovalDualControlError):
                decide(conn, TENANT_A, row["id"], decision="approved",
                       approver_id=ADMIN, approver_role="admin")

    def test_wrong_role_refused(self):
        fid, _a, _e = _make_episode(with_derivation=False, posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
            row = propose(conn, TENANT_A, subject_type=SUBJECT_MANUAL_SSS,
                          subject_id=str(proposal["id"]),
                          payload={"kind": "publish_manual_sss"},
                          actor_id=ANALYST, actor_role="analyst")
            conn.commit()
            with pytest.raises(ApprovalAuthorityError):
                decide(conn, TENANT_A, row["id"], decision="approved",
                       approver_id=ANALYST, approver_role="analyst")

    def test_replay_apply_visible_conflict(self):
        fid, _a, _e = _make_episode(with_derivation=False, posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})
        with get_db_connection() as conn:
            apply_approval(conn, TENANT_A, approval["id"],
                           actor_id=ADMIN, actor_role="admin")
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(ApprovalAlreadyAppliedError):
                apply_approval(conn, TENANT_A, approval["id"],
                               actor_id=ADMIN, actor_role="admin")
            conn.rollback()

    def test_cross_tenant_not_found(self):
        fid, _a, _e = _make_episode(TENANT_B, with_derivation=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_B, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        with get_db_connection() as conn:
            row = propose(conn, TENANT_B, subject_type=SUBJECT_MANUAL_SSS,
                          subject_id=str(proposal["id"]),
                          payload={"kind": "publish_manual_sss"},
                          actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(ApprovalNotFoundError):
                decide(conn, TENANT_A, row["id"], decision="approved",
                       approver_id=ADMIN, approver_role="admin")


# ===========================================================================
# Subject 2 — SSS override: provenance + visible pre-override value
# ===========================================================================


class TestSssOverride:
    def _override_flow(self, tenant=TENANT_A):
        fid, asset_id, exposure_id = _make_episode(tenant)
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id FROM non_cve_sss_derivations "
                "WHERE tenant_id=%s AND finding_id=%s AND is_current;",
                (str(tenant), str(fid)))
            derived_id = cur.fetchone()["id"]
            cur.execute("SELECT value FROM non_cve_sss_derivations WHERE id=%s;",
                        (derived_id,))
            derived_value = cur.fetchone()["value"]
            conn.rollback()
        payload = consumers.canonical_override_payload(
            "2.5", "analyst override", {"ref": "war-room"})
        with get_db_connection() as conn:
            row = propose(
                conn, tenant, subject_type=SUBJECT_SSS_OVERRIDE,
                subject_id=str(fid), payload=payload,
                actor_id=ANALYST, actor_role="analyst")
            propose_override_binding(
                conn, tenant, fid, row["id"], value=payload["value"],
                reason=payload["reason"], evidence=payload["evidence"])
            conn.commit()
        with get_db_connection() as conn:
            decide(conn, tenant, row["id"], decision="approved",
                   approver_id=ADMIN, approver_role="admin")
            conn.commit()
        return fid, asset_id, exposure_id, derived_id, derived_value, row

    def test_override_applies_with_provenance_and_visible_pre_override(self):
        fid, asset_id, exposure_id, derived_id, derived_value, approval = \
            self._override_flow()
        with get_db_connection() as conn:
            out = apply_approval(conn, TENANT_A, approval["id"],
                                 actor_id=ADMIN, actor_role="admin")
            conn.commit()
        assert str(out["result"]["pre_override_derivation_id"]) == str(derived_id)

        with get_db_connection() as conn:
            intrinsic = current_sss_intrinsic_with_provenance(
                conn, TENANT_A, fid)
        assert intrinsic.value == Decimal("2.5000")
        sv = intrinsic.source_view
        assert sv["path"] == "override"
        assert str(sv["approval_id"]) == str(approval["id"])
        assert str(sv["pre_override_derivation_id"]) == str(derived_id)
        assert Decimal(str(sv["pre_override_value"])) == derived_value  # visible

        payload = _read_tes(exposure_id)
        assert payload["source_view"]["sss"]["provenance"] == "analyst override"
        assert payload["source_view"]["sss"]["pre_override_value"] is not None
        intr_row = [r for r in payload["decomposition"]
                    if r["axis"] == "intrinsic"][0]
        assert intr_row["provenance_class"] == "analyst_entered"

    def test_stale_override_refused(self):
        fid, asset_id, exposure_id, derived_id, derived_value, approval = \
            self._override_flow()
        # a re-derivation changes the current derivation AFTER approval
        _seed_rubric_and_derive(TENANT_A, fid)  # publishes a NEW current
        with get_db_connection() as conn:
            with pytest.raises(ApprovalStaleSubjectError):
                apply_approval(conn, TENANT_A, approval["id"],
                               actor_id=ADMIN, actor_role="admin")
            conn.rollback()
        # nothing was published by the refused apply: the only current
        # derivation is the rubric re-derivation, and NO override row exists
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT count(*) AS c FROM non_cve_sss_derivations
                WHERE tenant_id=%s AND finding_id=%s AND path='override';
                """,
                (str(TENANT_A), str(fid)))
            assert cur.fetchone()["c"] == 0
            conn.rollback()

    def test_cve_finding_override_refused(self):
        from tests.test_p03_cve_intelligence_resolvers import _canon
        cve = f"CVE-2026-{8000 + uuid.uuid4().int % 900}"
        with get_db_connection() as conn:
            _canon(conn, cve)
            from app.exposure.service import allocate_finding_for_cve
            fid = allocate_finding_for_cve(
                conn, TENANT_A, cve, default_title="cve", default_severity="high",
                actor_id="system", actor_role="admin")
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(ApprovalSubjectError,
                               match="non-CVE findings only"):
                propose(conn, TENANT_A, subject_type=SUBJECT_SSS_OVERRIDE,
                        subject_id=str(fid),
                        payload={"value": "1", "reason": "r", "evidence": {"e": 1}},
                        actor_id=ANALYST, actor_role="analyst")
            conn.rollback()


# ===========================================================================
# Subject 3 — negative ER attestation: ER 1.0, exact episode, expiry visible
# ===========================================================================


class TestNegativeErAttestation:
    def _attested_episode(self, tenant=TENANT_A):
        fid, asset_id, exposure_id = _make_episode(tenant)
        with get_db_connection() as conn:
            result = record_non_exploitation_attestation(
                conn, tenant, exposure_id, evidence_ref="assertion-1",
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        return fid, asset_id, exposure_id, result.record.id

    def test_unapproved_assertion_never_er1(self):
        fid, asset_id, exposure_id, att_id = self._attested_episode()
        payload = _read_tes(exposure_id)
        er_row = [r for r in payload["decomposition"]
                  if r["axis"] == "exploit_reality"][0]
        assert er_row["selected_rung"] is None
        assert payload["source_view"]["attestation_state"] == "unapproved"
        # the record remains visible
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT count(*) AS c FROM "
                        "exposure_non_exploitation_attestations;")
            assert cur.fetchone()["c"] == 1
            conn.rollback()

    def test_approved_attestation_yields_er1_provisional(self):
        fid, asset_id, exposure_id, att_id = self._attested_episode()
        approval = _propose_and_approve(
            SUBJECT_ER_ATTESTATION, str(att_id),
            {"kind": "approve_attestation"})
        with get_db_connection() as conn:
            apply_approval(conn, TENANT_A, approval["id"],
                           actor_id=ADMIN, actor_role="admin")
            conn.commit()
        payload = _read_tes(exposure_id)
        er_row = [r for r in payload["decomposition"]
                  if r["axis"] == "exploit_reality"][0]
        assert er_row["selected_rung"] == "attested_no_exploitation"
        assert er_row["raw_value"] == {"__decimal__": "1"}
        assert er_row["provenance_class"] == "analyst_entered"
        assert payload["state"] == "PROVISIONAL"  # reachability/BI still unknown
        assert payload["source_view"]["attestation_state"] == "fresh_approved"

    def test_expired_attestation_unknown_while_visible(self):
        fid, asset_id, exposure_id, att_id = self._attested_episode()
        approval = _propose_and_approve(
            SUBJECT_ER_ATTESTATION, str(att_id),
            {"kind": "approve_attestation"})
        with get_db_connection() as conn:
            apply_approval(conn, TENANT_A, approval["id"],
                           actor_id=ADMIN, actor_role="admin")
            conn.commit()
        # read AFTER the 180-day window: attested_at is set at apply time,
        # so backdate by reading with a future as_of
        future = AS_OF + timedelta(days=200)
        payload = _read_tes(exposure_id, as_of=future)
        er_row = [r for r in payload["decomposition"]
                  if r["axis"] == "exploit_reality"][0]
        assert er_row["selected_rung"] is None
        assert payload["state"] == "PROVISIONAL"
        assert payload["source_view"]["attestation_state"] == "stale"
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT approval_id FROM "
                        "exposure_non_exploitation_attestations WHERE id=%s;",
                        (str(att_id),))
            assert cur.fetchone()["approval_id"] is not None  # visible, stamped
            conn.rollback()

    def test_superseded_episode_attestation_never_approved(self):
        fid, asset_id, exposure_id, att_id = self._attested_episode()
        # supersede the episode (decommission the asset)
        with get_db_connection() as conn:
            from app.exposure.service import supersede_exposures_for_asset
            supersede_exposures_for_asset(
                conn, TENANT_A, asset_id, actor_id=ADMIN, actor_role="admin",
                reason="asset decommission")
            conn.commit()
        # the attestation can no longer be approved (episode is superseded —
        # the validator refuses with the subject error, not a 404)
        with get_db_connection() as conn:
            with pytest.raises(ApprovalSubjectError,
                               match="CURRENT confirmed episodes"):
                propose(conn, TENANT_A, subject_type=SUBJECT_ER_ATTESTATION,
                        subject_id=str(att_id),
                        payload={"kind": "approve_attestation"},
                        actor_id=ANALYST, actor_role="analyst")
            conn.rollback()

    def test_recurring_episode_requires_new_approval(self):
        fid, asset_id, exposure_id, att_id = self._attested_episode()
        approval = _propose_and_approve(
            SUBJECT_ER_ATTESTATION, str(att_id),
            {"kind": "approve_attestation"})
        with get_db_connection() as conn:
            apply_approval(conn, TENANT_A, approval["id"],
                           actor_id=ADMIN, actor_role="admin")
            conn.commit()
        # recurrence: a NEW episode of the same finding (re-confirm after
        # supersession)
        with get_db_connection() as conn:
            from app.exposure.service import supersede_exposures_for_asset
            supersede_exposures_for_asset(
                conn, TENANT_A, asset_id, actor_id=ADMIN, actor_role="admin",
                reason="boundary moved")
            conn.commit()
            r2 = _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()
        new_exposure_id = r2.exposure.id
        assert new_exposure_id != exposure_id
        # the new episode's read sees NO attestation (approvals are never
        # copied to a successor episode)
        payload = _read_tes(new_exposure_id)
        er_row = [r for r in payload["decomposition"]
                  if r["axis"] == "exploit_reality"][0]
        assert er_row["selected_rung"] is None
        assert payload["source_view"]["attestation_state"] is None


# ===========================================================================
# Read model — design-A criticality + CVE-parity decomposition
# ===========================================================================


class TestReadModelDesignA:
    def test_identity_posture_reads_boundary_criticality_not_asset(self):
        # posture=False: no boundary yet — create one with criticality 'low'
        # while the asset itself is 'critical'; design A must read the BOUNDARY
        fid = _make_noncve_finding()
        _seed_rubric_and_derive(TENANT_A, fid)
        asset_id = _make_asset()
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE assets SET criticality='critical' WHERE id=%s;",
                (str(asset_id),))
            conn.commit()
            from app.exposure.identity_boundary import create_identity_boundary
            create_identity_boundary(
                conn, TENANT_A, asset_id=asset_id, criticality="low",
                actor_id=ADMIN, actor_role="admin")
            conn.commit()
            result = _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()
        exposure_id = result.exposure.id
        payload = _read_tes(exposure_id)
        crit_row = [r for r in payload["decomposition"]
                    if r["axis"] == "criticality"][0]
        assert crit_row["raw_value"] == {"__decimal__": "2"}  # boundary low, not asset critical
        assert crit_row["source"].startswith("identity_boundary:")

    def test_non_identity_taxonomy_reads_asset_criticality(self):
        """Design A: the boundary-criticality reading is keyed on the
        exposure's IDENTITY_POSTURE taxonomy; a non-IDENTITY exposure on the
        same asset keeps assets.criticality (an unclassified manual-SSS
        finding has taxonomy_class None)."""
        fid = _make_noncve_finding()
        # seed a NON-IDENTITY rubric derivation via the operator path
        version_id = f"rubric-p08c-{uuid.uuid4()}"
        content = {
            "facts": {"s3_public": {"type": "enum", "values": ["yes", "no"]}},
            "rules": [{"name": "s3", "severity": "5.0",
                       "match": {"s3_public": ["yes"]}}],
        }
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO sss_derivation_versions
                        (version_id, kind, content, status, test_only,
                         approved_by, approved_at)
                    VALUES (%s, 'rubric', %s, 'approved', FALSE,
                            'ops-approver', now())
                    ON CONFLICT (version_id) DO NOTHING;
                    """,
                    (version_id, psycopg.types.json.Json(content)),
                )
        asset_id = _make_asset()
        with get_db_connection() as conn:
            derive_sss_rubric(
                conn, TENANT_A, fid,
                rubric_version=version_id,
                taxonomy_class="VALIDATION_EVIDENCE",
                taxonomy_subclass=None,
                taxonomy_subtype=None,
                facts={"s3_public": "yes"},
                evidence={"source": "operator"},
                actor_id="ops-approver", actor_role="admin",
            )
            conn.commit()
            result = _confirm(conn, TENANT_A, fid, asset_id)
            conn.commit()
        payload = _read_tes(result.exposure.id)
        crit_row = [r for r in payload["decomposition"]
                    if r["axis"] == "criticality"][0]
        assert crit_row["raw_value"] == {"__decimal__": "2"}  # assets 'low'
        assert crit_row["source"] == "assets-service"

    def test_non_cve_decomposition_matches_cve_semantics(self):
        """Approved non-CVE input produces identical decomposition SEMANTICS
        to a CVE intrinsic: same five locked axes, same weight order, same
        state machine, formula_version 'tes-v1'."""
        fid, asset_id, exposure_id = _make_episode()
        payload = _read_tes(exposure_id)
        assert payload["formula_version"] == "tes-v1"
        axes = [r["axis"] for r in payload["decomposition"]]
        assert axes == ["intrinsic", "exploit_reality", "criticality",
                        "reachability", "business_impact"]
        weights = [r["base_weight"] for r in payload["decomposition"]]
        assert weights == [{"__decimal__": "0.40"}, {"__decimal__": "0.30"},
                           {"__decimal__": "0.15"}, {"__decimal__": "0.10"},
                           {"__decimal__": "0.05"}]
        # anchor reachability never leaks into the exposure's reachability
        with get_db_connection() as conn:
            record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external",
                                       evidence={"scan": "s"}),
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        payload = _read_tes(exposure_id)
        reach_row = [r for r in payload["decomposition"]
                     if r["axis"] == "reachability"][0]
        assert reach_row["state"] == "known"

    def test_no_derivation_unscoreable(self):
        fid, asset_id, exposure_id = _make_episode(with_derivation=False,
                                                    posture=False)
        payload = _read_tes(exposure_id)
        assert payload["state"] == "UNSCOREABLE"
        assert payload["source_view"]["cvss_unscoreable_reason_code"] == \
            "no_valid_sss"

    def test_exploitation_evidence_yields_er10_on_non_cve(self):
        fid, asset_id, exposure_id = _make_episode()
        with get_db_connection() as conn:
            record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="observed", result="succeeded",
                                       evidence={"actor": "red-team"}),
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        payload = _read_tes(exposure_id)
        er_row = [r for r in payload["decomposition"]
                  if r["axis"] == "exploit_reality"][0]
        assert er_row["selected_rung"] == "exact_exposure_evidence"
        assert er_row["raw_value"] == {"__decimal__": "10"}


# ===========================================================================
# Races + failure injection
# ===========================================================================


class TestRacesAndFailures:
    def test_two_applies_exactly_one_wins(self):
        fid, _a, _e = _make_episode(with_derivation=False, posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})
        outcomes = []

        def worker():
            try:
                with get_db_connection() as conn:
                    apply_approval(conn, TENANT_A, approval["id"],
                                   actor_id=ADMIN, actor_role="admin")
                    conn.commit()
                outcomes.append("ok")
            except Exception as exc:  # noqa: BLE001
                outcomes.append(type(exc).__name__)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start(); t2.start(); t1.join(); t2.join()
        assert outcomes.count("ok") == 1
        # exactly ONE derivation published (the loser wrote nothing)
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT count(*) AS c FROM non_cve_sss_derivations "
                "WHERE tenant_id=%s AND finding_id=%s;",
                (str(TENANT_A), str(fid)))
            assert cur.fetchone()["c"] == 1

    def test_subject_change_window_between_decide_and_apply(self):
        fid, _a, _e = _make_episode(with_derivation=False, posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})
        # the finding changes AFTER approval (a new derivation publishes)
        _seed_rubric_and_derive(TENANT_A, fid)
        with get_db_connection() as conn:
            with pytest.raises(ApprovalStaleSubjectError):
                apply_approval(conn, TENANT_A, approval["id"],
                               actor_id=ADMIN, actor_role="admin")
            conn.rollback()
        # nothing written: the manual derivation was never published
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT count(*) AS c FROM non_cve_sss_derivations "
                "WHERE tenant_id=%s AND finding_id=%s AND path='manual';",
                (str(TENANT_A), str(fid)))
            assert cur.fetchone()["c"] == 0
            conn.rollback()

    def test_authority_revocation_between_decision_and_apply(self):
        fid, _a, _e = _make_episode(with_derivation=False, posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_memberships SET status='disabled' "
                    "WHERE user_id=(SELECT id FROM users WHERE LOWER(email)"
                    "=LOWER(%s)) AND tenant_id=%s;",
                    (ADMIN, str(TENANT_A)))
            conn.commit()
        try:
            with get_db_connection() as conn:
                with pytest.raises(ApprovalAuthorityError):
                    apply_approval(conn, TENANT_A, approval["id"],
                                   actor_id=ADMIN, actor_role="admin")
                conn.rollback()
        finally:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE tenant_memberships SET status='active' "
                        "WHERE user_id=(SELECT id FROM users WHERE LOWER(email)"
                        "=LOWER(%s)) AND tenant_id=%s;",
                        (ADMIN, str(TENANT_A)))
                conn.commit()

    def test_apply_rollback_on_handler_failure(self, monkeypatch):
        fid, _a, _e = _make_episode(with_derivation=False, posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})

        import app.approvals as ap

        def boom(*a, **k):
            raise RuntimeError("audit sink down")

        monkeypatch.setattr(ap, "record_audit_event", boom)
        with get_db_connection() as conn:
            with pytest.raises(RuntimeError):
                apply_approval(conn, TENANT_A, approval["id"],
                               actor_id=ADMIN, actor_role="admin")
            conn.rollback()
        monkeypatch.setattr(ap, "record_audit_event", lambda *a, **k: None)
        # nothing written
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT count(*) AS c FROM non_cve_sss_derivations "
                "WHERE tenant_id=%s AND finding_id=%s AND path='manual';",
                (str(TENANT_A), str(fid)))
            assert cur.fetchone()["c"] == 0
            cur.execute("SELECT state FROM chapter5_approvals WHERE id=%s;",
                        (approval["id"],))
            assert cur.fetchone()["state"] == "approved"
            conn.rollback()

    def test_timeout_after_commit_retry_visible_conflict(self):
        """timeout-after-commit: the client retries an apply that already
        committed — the retry gets the VISIBLE conflict, and the mutation is
        present exactly once."""
        fid, _a, _e = _make_episode(with_derivation=False, posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="3",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})
        with get_db_connection() as conn:
            apply_approval(conn, TENANT_A, approval["id"],
                           actor_id=ADMIN, actor_role="admin")
            conn.commit()
        # (timeout — client retries)
        with get_db_connection() as conn:
            with pytest.raises(ApprovalAlreadyAppliedError):
                apply_approval(conn, TENANT_A, approval["id"],
                               actor_id=ADMIN, actor_role="admin")
            conn.rollback()
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT count(*) AS c FROM non_cve_sss_derivations "
                "WHERE tenant_id=%s AND finding_id=%s AND path='manual';",
                (str(TENANT_A), str(fid)))
            assert cur.fetchone()["c"] == 1


# ===========================================================================
# No second approval store (search-proof)
# ===========================================================================


class TestNoSecondApprovalStore:
    def test_registry_contains_the_three_chapter3_types(self):
        assert {
            SUBJECT_MANUAL_SSS, SUBJECT_SSS_OVERRIDE, SUBJECT_ER_ATTESTATION,
        } <= set(_REGISTRY)

    def test_chapter3_tables_reference_the_single_approval_store(self):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT conrelid::regclass AS tbl, conname
                    FROM pg_constraint
                    WHERE confrelid = 'chapter5_approvals'::regclass;
                """)
                referencing = sorted(str(r["tbl"]) for r in cur.fetchall())
        # All Chapter 3 consumers point at the one primitive table; later
        # chapters may register additional consumers of that same primitive.
        assert {
            "chapter5_approval_audit",
            "non_cve_sss_derivations",
            "exposure_non_exploitation_attestations",
            "non_cve_sss_override_proposals",
        } <= set(referencing)


# ===========================================================================
# §3.6.6 #2 escape hatch — manual/override version provenance (P0-09 fix):
# approval-applied derivations publish with a NULL version_id_ref and the
# approval id as provenance; the manual path requires NO approved version
# content (nothing borrowed, nothing invented).
# ===========================================================================


class TestManualOverrideVersionProvenance:
    def test_manual_sss_apply_succeeds_with_zero_approved_versions(self):
        """THE escape-hatch proof: with sss_derivation_versions completely
        empty (the current production state), an approved manual SSS still
        publishes — no approved RUBRIC version row is required or borrowed."""
        fid, asset_id, exposure_id = _make_episode(with_derivation=False,
                                                    posture=False)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM sss_derivation_versions;")
                cur.execute("SELECT count(*) AS c FROM sss_derivation_versions;")
                assert cur.fetchone()["c"] == 0
            conn.commit()
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="6.5",
                reason="manual triage without approved content",
                evidence={"ticket": "t-eh"},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})
        with get_db_connection() as conn:
            out = apply_approval(conn, TENANT_A, approval["id"],
                                 actor_id=ADMIN, actor_role="admin")
            conn.commit()
        assert "derivation_id" in out["result"]
        # nothing was created or borrowed in the versions table
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS c FROM sss_derivation_versions;")
                assert cur.fetchone()["c"] == 0
                cur.execute(
                    "SELECT version_id_ref, approval_id, path "
                    "FROM non_cve_sss_derivations WHERE id=%s;",
                    (out["result"]["derivation_id"],))
                drow = cur.fetchone()
            conn.rollback()
        assert drow["version_id_ref"] is None
        assert str(drow["approval_id"]) == str(approval["id"])
        assert drow["path"] == "manual"

    def test_manual_label_renders_from_approval_id_both_readers(self):
        fid, asset_id, exposure_id = _make_episode(with_derivation=False,
                                                    posture=False)
        with get_db_connection() as conn:
            proposal = create_sss_proposal(
                conn, TENANT_A, fid, proposed_value="4",
                reason="r", evidence={"x": 1},
                taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                          "taxonomy_subclass": "MFA_ENROLMENT"},
                actor_id=ANALYST, actor_role="analyst")
            conn.commit()
        approval = _propose_and_approve(
            SUBJECT_MANUAL_SSS, str(proposal["id"]),
            {"kind": "publish_manual_sss"})
        with get_db_connection() as conn:
            apply_approval(conn, TENANT_A, approval["id"],
                           actor_id=ADMIN, actor_role="admin")
            conn.commit()
        expected = f"sss_manual:approval:{approval['id']}"
        with get_db_connection() as conn:
            provenance = current_sss_intrinsic_with_provenance(
                conn, TENANT_A, fid)
        assert provenance.derivation == expected
        assert provenance.provenance_class == ProvenanceClass.ANALYST_ENTERED
        with get_db_connection() as conn:
            from app.exposure.sss import current_sss_intrinsic
            plain = current_sss_intrinsic(conn, TENANT_A, fid)
        assert plain.derivation == expected

    def test_vrt_path_still_requires_a_version_row(self):
        """The shape CHECK is path-conditioned BOTH ways: a content-path
        derivation without a version is impossible (INSERT rejected)."""
        fid, asset_id, exposure_id = _make_episode(with_derivation=False,
                                                    posture=False)
        with get_db_connection() as conn:
            cur = conn.cursor()
            # a real classification row first (the shape CHECK must be the
            # failure, not the classification FK)
            cur.execute(
                """
                INSERT INTO non_cve_classifications (
                    tenant_id, finding_id, finding_revision_xmin,
                    taxonomy_class, taxonomy_subclass, taxonomy_subtype,
                    path, version_id_ref, inputs, evidence,
                    validation_state, created_by, created_role
                ) VALUES (
                    %s, %s, '1', 'IDENTITY_POSTURE', 'MFA_ENROLMENT', NULL,
                    'vrt', NULL, '{}'::jsonb, '{"e": 1}'::jsonb,
                    'confirmed', 't', 'admin')
                RETURNING id;
                """,
                (str(TENANT_A), str(fid)))
            classification_id = cur.fetchone()["id"]
            with pytest.raises(psycopg.errors.CheckViolation,
                               match="version_shape"):
                cur.execute(
                    """
                    INSERT INTO non_cve_sss_derivations (
                        tenant_id, finding_id, finding_revision_xmin,
                        classification_id, taxonomy_class,
                        taxonomy_subclass, taxonomy_subtype,
                        path, version_id_ref, inputs, value, evidence,
                        created_by, created_role
                    ) VALUES (
                        %s, %s, '1', %s, 'IDENTITY_POSTURE',
                        'MFA_ENROLMENT', NULL,
                        'vrt', NULL, '{}'::jsonb, 5, '{"e": 1}'::jsonb,
                        't', 'admin')
                    """,
                    (str(TENANT_A), str(fid), str(classification_id)))
            conn.rollback()

    def test_override_row_carries_null_version_with_bindings(self):
        fid, asset_id, exposure_id, derived_id, derived_value, approval = \
            TestSssOverride()._override_flow()
        with get_db_connection() as conn:
            apply_approval(conn, TENANT_A, approval["id"],
                           actor_id=ADMIN, actor_role="admin")
            conn.commit()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT version_id_ref, approval_id,
                           pre_override_derivation_id
                    FROM non_cve_sss_derivations
                    WHERE tenant_id=%s AND finding_id=%s
                      AND path='override' AND is_current;
                    """,
                    (str(TENANT_A), str(fid)))
                drow = cur.fetchone()
            conn.rollback()
        assert drow["version_id_ref"] is None
        assert str(drow["approval_id"]) == str(approval["id"])
        assert str(drow["pre_override_derivation_id"]) == str(derived_id)
        # label renders path + approval id; pre-override value stays visible
        with get_db_connection() as conn:
            provenance = current_sss_intrinsic_with_provenance(
                conn, TENANT_A, fid)
        assert provenance.derivation == f"sss_override:approval:{approval['id']}"
        assert provenance.source_view["pre_override_value"] is not None
        assert Decimal(str(provenance.source_view["pre_override_value"])) \
            == Decimal(str(derived_value))


# ===========================================================================
# P0-08a — label pin: the §3.6.6 #2 approval-path derivation labels are part
# of the provenance contract; future consumers depend on this exact format.
# ===========================================================================


class TestApprovalPathLabelPin:
    @pytest.mark.parametrize("path_prefix", ["manual", "override"])
    def test_labels_render_path_plus_approval_id(self, path_prefix):
        """The read-model label is EXACTLY ``sss_<path>:approval:<id>`` —
        pinned so the P0-08 label change cannot silently regress."""
        if path_prefix == "manual":
            fid, asset_id, exposure_id = _make_episode(
                with_derivation=False, posture=False)
            with get_db_connection() as conn:
                proposal = create_sss_proposal(
                    conn, TENANT_A, fid, proposed_value="4",
                    reason="r", evidence={"x": 1},
                    taxonomy={"taxonomy_class": "IDENTITY_POSTURE",
                              "taxonomy_subclass": "MFA_ENROLMENT"},
                    actor_id=ANALYST, actor_role="analyst")
                conn.commit()
            approval = _propose_and_approve(
                SUBJECT_MANUAL_SSS, str(proposal["id"]),
                {"kind": "publish_manual_sss"})
            with get_db_connection() as conn:
                apply_approval(conn, TENANT_A, approval["id"],
                               actor_id=ADMIN, actor_role="admin")
                conn.commit()
        else:
            (fid, asset_id, exposure_id, _derived_id, _dv,
             approval) = TestSssOverride()._override_flow()
            with get_db_connection() as conn:
                apply_approval(conn, TENANT_A, approval["id"],
                               actor_id=ADMIN, actor_role="admin")
                conn.commit()
        with get_db_connection() as conn:
            provenance = current_sss_intrinsic_with_provenance(
                conn, TENANT_A, fid)
        assert provenance.derivation == f"sss_{path_prefix}:approval:{approval['id']}"
        with get_db_connection() as conn:
            payload = get_exposure_tes(conn, TENANT_A, exposure_id, as_of=AS_OF)
            conn.rollback()
        assert payload["source_view"]["sss"]["approval_id"] is not None
