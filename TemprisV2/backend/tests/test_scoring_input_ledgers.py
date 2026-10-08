# backend/tests/test_scoring_input_ledgers.py
"""
P0-02 — Scoring input ledgers (PRD-000 v1.11 §§3.3.2–3.3.4) focused suite.

Covers: exact-episode binding and recurrence isolation; BI boundaries
(0/10/invalid/missing-reason) and versioning; reachability selection and
unknown semantics; server-side evidence-kind classification, producer
allowlists, and success-only semantics; TTL boundaries with expired rows
persisting; approval-gated attestation reservation; tenant/IDOR and forged
field negatives; duplicate-callback idempotency; evidence-vs-supersession
race; timeout-retry idempotency; audit-failure rollback; evidence-download
audit.
"""
import json
import threading
import uuid
from datetime import timedelta
from decimal import Decimal

import psycopg
import pytest
from psycopg.rows import dict_row

from app.db import get_db_connection
from app.exposure.exceptions import (
    EvidencePolicyError,
    ExposureConflictError,
    TenantMismatchError,
)
from app.exposure.models import ExposureResolve
from app.exposure.scoring_inputs import (
    ATTESTATION_TTL,
    BusinessImpactIn,
    ExploitationEvidenceIn,
    ReachabilityEvidenceIn,
    RecordResult,
    _utcnow,
    current_business_impact,
    current_reachability,
    get_scoring_inputs,
    is_attestation_eligible,
    is_exploitation_evidence_eligible,
    list_exploitation_evidence,
    record_exploitation_evidence,
    record_non_exploitation_attestation,
    record_reachability_evidence,
    revoke_evidence,
    set_business_impact,
)
from app.exposure.service import resolve_exposure, supersede_exposures_for_asset
from tests.conftest import TENANT_A, TENANT_B
from tests.test_exposure_domain import create_test_asset
from tests.test_exposure_lifecycle_authority import (
    audit_events,
    confirm as confirm_cmd,
    make_finding_and_asset,
)


def make_current_episode(cve_id=None):
    """Confirmed episode on an active asset; returns (exposure_id, finding_id, asset_id)."""
    finding_id, asset_id = make_finding_and_asset(cve_id=cve_id)
    with get_db_connection() as conn:
        result = confirm_cmd(conn, TENANT_A, finding_id, asset_id, {"seed": True})
        conn.commit()
    return result.exposure.id, finding_id, asset_id


def db_rows(table, exposure_id):
    with get_db_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                f"SELECT * FROM {table} WHERE tenant_id = %s AND exposure_id = %s;",
                (str(TENANT_A), str(exposure_id)),
            )
            return cur.fetchall()


def current_business_impact_value(exposure_id):
    with get_db_connection() as conn:
        return current_business_impact(conn, TENANT_A, exposure_id).value


# ===========================================================================
# Business Impact
# ===========================================================================


class TestBusinessImpact:
    def test_boundaries_zero_and_ten_and_missing_reason_accepted(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            low = set_business_impact(
                conn, TENANT_A, exposure_id,
                BusinessImpactIn(value=0),
                actor_id="analyst-a", actor_role="analyst",
            ).record
            conn.commit()
        with get_db_connection() as conn:
            high = set_business_impact(
                conn, TENANT_A, exposure_id,
                BusinessImpactIn(value=10, reason="payroll system"),
                actor_id="analyst-a", actor_role="analyst",
            ).record
            conn.commit()
        assert float(low.value) == 0.0
        assert low.reason is None  # optional by contract (PRD §3.3.2)
        assert float(high.value) == 10.0
        # current = latest version; every version carries actor + timestamp
        with get_db_connection() as conn:
            current = current_business_impact(conn, TENANT_A, exposure_id)
        assert float(current.value) == 10.0
        assert current.assessed_by == "analyst-a"
        assert current.created_at is not None

    def test_invalid_values_rejected(self, client, auth_headers_tenant_a_admin):
        exposure_id, _, _ = make_current_episode()
        for bad in (-0.1, 10.5, 99):
            res = client.post(
                f"/api/exposure/{exposure_id}/business-impact",
                headers=auth_headers_tenant_a_admin,
                json={"value": bad},
            )
            assert res.status_code == 422, bad
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.CheckViolation):
                    cur.execute(
                        """
                        INSERT INTO exposure_business_impact (tenant_id, exposure_id, value, assessed_by)
                        VALUES (%s, %s, 10.5, 'x');
                        """,
                        (str(TENANT_A), str(exposure_id)),
                    )
            conn.rollback()

    def test_per_episode_isolation_and_update_locality(self):
        exposure_a, _, _ = make_current_episode()
        exposure_b, _, _ = make_current_episode()
        with get_db_connection() as conn:
            set_business_impact(
                conn, TENANT_A, exposure_a, BusinessImpactIn(value=3, reason="dev box"),
                actor_id="analyst-a", actor_role="analyst",
            )
            set_business_impact(
                conn, TENANT_A, exposure_b, BusinessImpactIn(value=9, reason="payroll"),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        # changing A again affects only A
        with get_db_connection() as conn:
            set_business_impact(
                conn, TENANT_A, exposure_a, BusinessImpactIn(value=4),
                actor_id="analyst-b", actor_role="analyst",
            )
            conn.commit()
        with get_db_connection() as conn:
            assert float(current_business_impact(conn, TENANT_A, exposure_a).value) == 4.0
            assert float(current_business_impact(conn, TENANT_A, exposure_b).value) == 9.0


# ===========================================================================
# Reachability
# ===========================================================================


class TestReachability:
    def test_vantage_values_and_latest_wins(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="internal", evidence={"path": "svc"}),
                actor_id="analyst-a", actor_role="analyst",
                source_object_type="probe", source_object_id="p1",
            )
            conn.commit()
        with get_db_connection() as conn:
            value, record = current_reachability(conn, TENANT_A, exposure_id)
        assert value == Decimal("8.0")
        assert record.vantage == "internal"

        # later external observation wins -> 10
        with get_db_connection() as conn:
            record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external", evidence={"route": "internet"}),
                actor_id="analyst-a", actor_role="analyst",
                source_object_type="probe", source_object_id="p2",
            )
            conn.commit()
        with get_db_connection() as conn:
            value, record = current_reachability(conn, TENANT_A, exposure_id)
        assert value == Decimal("10.0")

    def test_absent_is_unknown_never_host_level(self):
        # asset-level network_scope says internet, but no exact-exposure record
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE assets SET network_scope = 'internet' WHERE id = "
                    "(SELECT asset_id FROM asset_exposures WHERE id = %s);",
                    (str(exposure_id),),
                )
            conn.commit()
            value, record = current_reachability(conn, TENANT_A, exposure_id)
        assert value is None and record is None

    def test_revoked_record_yields_unknown(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            result = record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external", evidence={"p": 1}),
                actor_id="analyst-a", actor_role="analyst",
                source_object_type="probe", source_object_id="p1",
            )
            conn.commit()
        with get_db_connection() as conn:
            result = revoke_evidence(
                conn, TENANT_A, exposure_id, result.record.id, "reachability",
                "wrong vantage", actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            value, record = current_reachability(conn, TENANT_A, exposure_id)
        assert value is None and record is None
        # append-only: both rows persist
        assert len(db_rows("exposure_reachability_evidence", exposure_id)) == 2
        assert result.outcome == "created"


# ===========================================================================
# Exploitation evidence policy
# ===========================================================================


class TestExploitationEvidencePolicy:
    def test_server_assigned_kind_from_basis(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            observed = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="observed", result="succeeded",
                                       evidence={"incident": "IR-42"}),
                actor_id="analyst-a", actor_role="analyst",
            ).record
            validated = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded",
                                       evidence={"test": "poc ok"}),
                actor_id="analyst-a", actor_role="analyst",
            ).record
            conn.commit()
        assert observed.evidence_kind == "observed_exploitation"
        assert observed.producer == "analyst_review"
        assert validated.evidence_kind == "controlled_validation"

    def test_failed_prevented_cancelled_attempts_never_record(self):
        exposure_id, _, _ = make_current_episode()
        for result in ("failed", "prevented", "cancelled", "unconfirmed"):
            with pytest.raises(Exception):
                ExploitationEvidenceIn(basis="validated", result=result, evidence={"x": 1})
        # service-level guard: hand-built model bypassing pydantic (internal
        # caller with raw non-success semantics) is policy-rejected, no row
        hand_built = ExploitationEvidenceIn.model_construct(
            basis="validated", result="failed", evidence={"x": 1}
        )
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="not a success"):
                record_exploitation_evidence(
                    conn, TENANT_A, exposure_id, hand_built,
                    actor_id="analyst-a", actor_role="analyst",
                )
            conn.rollback()

    def test_producer_allowlist_closed(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            for reserved in ("siem", "edr", "strike_workspace_artifact", "connector"):
                with pytest.raises(EvidencePolicyError):
                    record_exploitation_evidence(
                        conn, TENANT_A, exposure_id,
                        ExploitationEvidenceIn(basis="observed", result="succeeded", evidence={"x": 1}),
                        actor_id="analyst-a", actor_role="analyst",
                        producer=reserved,
                    )
                conn.rollback()
            # allowlisted internal producers are accepted by the service
            strike = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded",
                                       evidence={"engagement": "E-1"}),
                actor_id="strike:E-1", actor_role="system",
                producer="strike",
                source_object_type="strike_event", source_object_id="ev-1",
            )
            conn.commit()
        assert strike.record.producer == "strike"

    def test_occurrence_time_enforced_server_side(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="future"):
                record_exploitation_evidence(
                    conn, TENANT_A, exposure_id,
                    ExploitationEvidenceIn(
                        basis="observed", result="succeeded", evidence={"x": 1},
                        observed_at=_utcnow() + timedelta(hours=1),
                    ),
                    actor_id="analyst-a", actor_role="analyst",
                )
            conn.rollback()
            # small skew tolerated; absent observed_at uses the server clock
            ok = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(
                    basis="observed", result="succeeded", evidence={"x": 1},
                    observed_at=_utcnow() + timedelta(minutes=1),
                ),
                actor_id="analyst-a", actor_role="analyst",
            ).record
            conn.commit()
        assert ok.observed_at is not None

    def test_forged_fields_rejected_at_api(self, client, auth_headers_tenant_a_admin):
        exposure_id, _, _ = make_current_episode()
        forged_payloads = [
            {"basis": "observed", "result": "succeeded", "evidence": {"x": 1},
             "evidence_kind": "observed_exploitation"},
            {"basis": "observed", "result": "succeeded", "evidence": {"x": 1}, "producer": "siem"},
            {"basis": "observed", "result": "succeeded", "evidence": {"x": 1},
             "tenant_id": str(TENANT_B)},
            {"basis": "observed", "result": "succeeded", "evidence": {"x": 1},
             "recorded_by": "spoof"},
            {"basis": "observed", "result": "failed", "evidence": {"x": 1}},
        ]
        for payload in forged_payloads:
            res = client.post(
                f"/api/exposure/{exposure_id}/exploitation-evidence",
                headers=auth_headers_tenant_a_admin,
                json=payload,
            )
            assert res.status_code == 422, payload
        with get_db_connection() as conn:
            assert list_exploitation_evidence(conn, TENANT_A, exposure_id) == []


# ===========================================================================
# TTL + eligibility (expiry never deletes)
# ===========================================================================


class TestTTLEligibility:
    def _record_with_observed_at(self, exposure_id, basis, observed_at):
        with get_db_connection() as conn:
            result = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis=basis, result="succeeded", evidence={"x": 1},
                                       observed_at=observed_at),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        return result.record

    def test_observed_365_day_boundary(self):
        exposure_id, _, _ = make_current_episode()
        fresh = self._record_with_observed_at(
            exposure_id, "observed", _utcnow() - timedelta(days=364, hours=23)
        )
        expired = self._record_with_observed_at(
            exposure_id, "observed", _utcnow() - timedelta(days=365, hours=1)
        )
        assert is_exploitation_evidence_eligible(fresh) is True
        assert is_exploitation_evidence_eligible(expired) is False

    def test_controlled_180_day_boundary(self):
        exposure_id, _, _ = make_current_episode()
        fresh = self._record_with_observed_at(
            exposure_id, "validated", _utcnow() - timedelta(days=179, hours=23)
        )
        expired = self._record_with_observed_at(
            exposure_id, "validated", _utcnow() - timedelta(days=180, hours=1)
        )
        assert is_exploitation_evidence_eligible(fresh) is True
        assert is_exploitation_evidence_eligible(expired) is False

    def test_expired_rows_persist_and_render_ineligible(self, client, auth_headers_tenant_a_admin):
        exposure_id, _, _ = make_current_episode()
        self._record_with_observed_at(
            exposure_id, "observed", _utcnow() - timedelta(days=400)
        )
        with get_db_connection() as conn:
            rows = list_exploitation_evidence(conn, TENANT_A, exposure_id)
        assert len(rows) == 1, "expired evidence persists as history"
        snapshot = client.get(
            f"/api/exposure/{exposure_id}/scoring-inputs",
            headers=auth_headers_tenant_a_admin,
        ).json()
        assert len(snapshot["exploitation_evidence"]) == 1
        assert snapshot["exploitation_evidence"][0]["eligible"] is False

    def test_stable_source_reuse_with_unstable_occurrence_time_rejected(self):
        """Round-2 rule: a producer retrying the same source event must supply
        the SAME stable occurrence timestamp. A retry with a different time
        (e.g. a freshly generated server timestamp) is a conflicting reuse:
        evidence_policy_rejected, the committed row is never disclosed, and
        nothing is written."""
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="observed", result="succeeded", evidence={"ir": "IR-8"}),
                actor_id="analyst-a", actor_role="analyst",
                source_object_type="incident", source_object_id="IR-8",
            )
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="not disclosed"):
                record_exploitation_evidence(
                    conn, TENANT_A, exposure_id,
                    ExploitationEvidenceIn(basis="observed", result="succeeded", evidence={"ir": "IR-8"}),
                    actor_id="analyst-a", actor_role="analyst",
                    source_object_type="incident", source_object_id="IR-8",
                )
            conn.rollback()
        with get_db_connection() as conn:
            assert len(db_rows("exposure_exploitation_evidence", exposure_id)) == 1

    def test_replay_rejects_differing_actor_and_reviewer(self):
        """Replay equality includes recorded_by (and reviewed_by for
        exploitation evidence): a different actor on the same source identity
        is a conflicting reuse."""
        exposure_id, _, _ = make_current_episode()
        stable_time = _utcnow() - timedelta(minutes=2)
        with get_db_connection() as conn:
            record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded", evidence={"poc": 1},
                                       observed_at=stable_time),
                actor_id="analyst-a", actor_role="analyst",
                source_object_type="test", source_object_id="T-1",
            )
            conn.commit()
        with get_db_connection() as conn:
            # Same time, payload, producer, episode — different recorded_by
            with pytest.raises(EvidencePolicyError, match="not disclosed"):
                record_exploitation_evidence(
                    conn, TENANT_A, exposure_id,
                    ExploitationEvidenceIn(basis="validated", result="succeeded", evidence={"poc": 1},
                                           observed_at=stable_time),
                    actor_id="analyst-b", actor_role="analyst",
                    source_object_type="test", source_object_id="T-1",
                )
            conn.rollback()
        with get_db_connection() as conn:
            assert len(db_rows("exposure_exploitation_evidence", exposure_id)) == 1

    def test_revoked_evidence_ineligible(self):
        exposure_id, _, _ = make_current_episode()
        record = self._record_with_observed_at(exposure_id, "observed", None)
        with get_db_connection() as conn:
            revocation = revoke_evidence(
                conn, TENANT_A, exposure_id, record.id, "exploitation",
                "withdrawn by review", actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        assert revocation.outcome == "created"
        with get_db_connection() as conn:
            listed = list_exploitation_evidence(conn, TENANT_A, exposure_id)
        assert listed[0].revoked is True
        assert is_exploitation_evidence_eligible(listed[0]) is False


# ===========================================================================
# Non-exploitation attestation (reserved, approval-gated)
# ===========================================================================


class TestAttestationReservation:
    def test_non_cve_only_and_never_eligible_without_approval(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            result = record_non_exploitation_attestation(
                conn, TENANT_A, exposure_id,
                evidence_ref="review://mfa-2026",
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        record = result.record
        assert record.approved_by is None and record.approved_at is None
        assert is_attestation_eligible(record) is False

        # P0-08 readiness: with a valid approval attached (simulated directly
        # in the primitive's own shape — an approved chapter5_approvals row,
        # then the single permitted stamp UPDATE referencing it via
        # approval_id, per the migration-022 trigger), eligibility follows
        # the 180-day window from attested_at
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chapter5_approvals (
                        tenant_id, subject_type, subject_id, subject_version,
                        payload_hash, proposer_id, proposer_role, state,
                        approver_id, approver_role, decided_at
                    ) VALUES (
                        %s, 'negative_er_attestation', %s, 'v1',
                        'simulated-payload-hash', 'analyst-a', 'analyst',
                        'approved', 'admin-b', 'superadmin', now()
                    ) RETURNING id;
                    """,
                    (str(TENANT_A), f"attestation:{record.id}"),
                )
                approval_row = cur.fetchone()
                approval_id = approval_row["id"] if isinstance(approval_row, dict) else approval_row[0]
                cur.execute(
                    """
                    UPDATE exposure_non_exploitation_attestations
                    SET approved_by = 'admin-b', approved_at = now(),
                        approval_id = %s
                    WHERE id = %s;
                    """,
                    (str(approval_id), str(record.id)),
                )
            conn.commit()
        from app.exposure.scoring_inputs import list_attestations

        with get_db_connection() as conn:
            approved = list_attestations(conn, TENANT_A, exposure_id)[0]
        assert is_attestation_eligible(approved) is True

    def test_cve_exposure_rejected(self):
        from tests.test_exposure_domain import seed_canonical_cve

        with get_db_connection() as conn:
            cve = seed_canonical_cve(conn, "CVE-2026-0100")
            conn.commit()
        exposure_id, _, _ = make_current_episode(cve_id=cve)
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="non-CVE"):
                record_non_exploitation_attestation(
                    conn, TENANT_A, exposure_id,
                    evidence_ref="review://x",
                    actor_id="analyst-a", actor_role="analyst",
                )
            conn.rollback()


# ===========================================================================
# Tenant isolation / IDOR negatives
# ===========================================================================


class TestTenantIsolation:
    def test_cross_tenant_exposure_ids_rejected(self, client, auth_headers_tenant_a_admin):
        # Build an episode in tenant B
        from app.exposure.models import ExposureConfirm, FindingCreate
        from app.exposure.service import confirm_exposure, create_finding

        with get_db_connection() as conn:
            finding_b = create_finding(conn, TENANT_B, FindingCreate(title="B", severity="high"))
            asset_b = create_test_asset(conn, TENANT_B, name="ledger-b", target_value="10.90.0.1")
            conn.commit()
            result_b = confirm_exposure(
                conn, TENANT_B,
                ExposureConfirm(finding_id=finding_b.id, asset_id=asset_b, evidence={"b": 1}),
                actor_id="analyst-b", actor_role="analyst",
            )
            conn.commit()
        exposure_b = result_b.exposure.id

        for method, path, body in (
            ("post", f"/api/exposure/{exposure_b}/reachability", {"vantage": "external", "evidence": {"x": 1}}),
            ("post", f"/api/exposure/{exposure_b}/business-impact", {"value": 5}),
            ("post", f"/api/exposure/{exposure_b}/exploitation-evidence",
             {"basis": "observed", "result": "succeeded", "evidence": {"x": 1}}),
        ):
            res = client.post(path, headers=auth_headers_tenant_a_admin, json=body)
            assert res.status_code == 404, path
        res = client.get(
            f"/api/exposure/{exposure_b}/scoring-inputs", headers=auth_headers_tenant_a_admin
        )
        assert res.status_code == 404

    def test_composite_fk_rejects_cross_tenant_direct_sql(self):
        exposure_id, _, _ = make_current_episode()
        # column-complete inserts so the ONLY violation is the composite
        # (tenant_id, exposure_id) FK
        inserts = {
            "exposure_reachability_evidence": """
                INSERT INTO exposure_reachability_evidence (
                    tenant_id, exposure_id, vantage, evidence, producer,
                    observed_at, recorded_by, source_object_type, source_object_id
                ) VALUES (%s, %s, 'external', '{"x": 1}'::jsonb, 'analyst', now(), 't', 't', 't');
            """,
            "exposure_business_impact": """
                INSERT INTO exposure_business_impact (tenant_id, exposure_id, value, assessed_by)
                VALUES (%s, %s, 5.0, 't');
            """,
            "exposure_exploitation_evidence": """
                INSERT INTO exposure_exploitation_evidence (
                    tenant_id, exposure_id, evidence_kind, producer, evidence,
                    observed_at, recorded_by, reviewed_by, source_object_type, source_object_id
                ) VALUES (%s, %s, 'observed_exploitation', 'analyst_review',
                          '{"x": 1}'::jsonb, now(), 't', 't', 't', 't');
            """,
            "exposure_non_exploitation_attestations": """
                INSERT INTO exposure_non_exploitation_attestations (
                    tenant_id, exposure_id, attested_by, evidence_ref
                ) VALUES (%s, %s, 't', 'ref');
            """,
        }
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                for table, statement in inserts.items():
                    with pytest.raises(psycopg.errors.ForeignKeyViolation):
                        cur.execute(statement, (str(TENANT_B), str(exposure_id)))
                    conn.rollback()

    def test_migration_017_applied(self):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT version FROM schema_migrations WHERE version = '017_scoring_input_ledgers.sql';"
                )
                assert cur.fetchone() is not None


# ===========================================================================
# Recurrence isolation
# ===========================================================================


class TestRecurrenceIsolation:
    def test_new_episode_starts_with_empty_ledgers(self, client, auth_headers_tenant_a_admin):
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            episode1 = confirm_cmd(conn, TENANT_A, finding_id, asset_id, {"gen": 1}).exposure
            conn.commit()
            record_reachability_evidence(
                conn, TENANT_A, episode1.id,
                ReachabilityEvidenceIn(vantage="external", evidence={"p": 1}),
                actor_id="analyst-a", actor_role="analyst",
                source_object_type="probe", source_object_id=f"probe-{episode1.id}",
            )
            set_business_impact(
                conn, TENANT_A, episode1.id, BusinessImpactIn(value=8),
                actor_id="analyst-a", actor_role="analyst",
            )
            record_exploitation_evidence(
                conn, TENANT_A, episode1.id,
                ExploitationEvidenceIn(basis="observed", result="succeeded", evidence={"ir": 1}),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
            resolve_exposure(
                conn, TENANT_A, episode1.id, ExposureResolve(status="resolved"),
                actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
            episode2 = confirm_cmd(conn, TENANT_A, finding_id, asset_id, {"gen": 2}).exposure
            conn.commit()

        # Ledger state NEVER crosses episodes
        with get_db_connection() as conn:
            value, record = current_reachability(conn, TENANT_A, episode2.id)
            assert value is None and record is None
            assert current_business_impact(conn, TENANT_A, episode2.id) is None
            assert list_exploitation_evidence(conn, TENANT_A, episode2.id) == []
        # Episode 1 keeps its history
        snapshot1 = client.get(
            f"/api/exposure/{episode1.id}/scoring-inputs", headers=auth_headers_tenant_a_admin
        ).json()
        assert snapshot1["reachability"]["value"] == 10.0
        assert snapshot1["business_impact"]["value"] == 8.0
        assert len(snapshot1["exploitation_evidence"]) == 1

        # terminal episodes reject new score-bearing writes
        with get_db_connection() as conn:
            with pytest.raises(ExposureConflictError):
                set_business_impact(
                    conn, TENANT_A, episode1.id, BusinessImpactIn(value=5),
                    actor_id="analyst-a", actor_role="analyst",
                )
            conn.rollback()


# ===========================================================================
# Race and failure semantics
# ===========================================================================


def run_isolated(fn):
    errors = []

    def wrapper():
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    return threading.Thread(target=wrapper), errors


class TestRaceAndFailure:
    def test_duplicate_producer_callback_creates_one_record(self):
        """Timeout after commit, then retry of the same source event: the
        stable producer supplies the SAME occurrence time on the retry, so the
        replay is exact (round-2 rule: the service never generates a fresh
        server timestamp for a retry of the same source event)."""
        exposure_id, _, _ = make_current_episode()
        stable_time = _utcnow() - timedelta(minutes=3)
        with get_db_connection() as conn:
            first = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded", evidence={"t": 1},
                                       observed_at=stable_time),
                actor_id="strike:E-9", actor_role="system", producer="strike",
                source_object_type="strike_event", source_object_id="evt-42",
            )
            conn.commit()
        with get_db_connection() as conn:
            retry = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded", evidence={"t": 1},
                                       observed_at=stable_time),
                actor_id="strike:E-9", actor_role="system", producer="strike",
                source_object_type="strike_event", source_object_id="evt-42",
            )
            conn.commit()
        assert first.outcome == "created"
        assert retry.outcome == "replay"
        assert retry.record.id == first.record.id
        assert len(db_rows("exposure_exploitation_evidence", exposure_id)) == 1

    def test_concurrent_duplicate_callbacks_one_record(self):
        exposure_id, _, _ = make_current_episode()
        barrier = threading.Barrier(2)
        stable_time = _utcnow() - timedelta(minutes=3)

        def callback():
            barrier.wait()
            with get_db_connection() as conn:
                record_exploitation_evidence(
                    conn, TENANT_A, exposure_id,
                    ExploitationEvidenceIn(basis="validated", result="succeeded", evidence={"t": 1},
                                           observed_at=stable_time),
                    actor_id="strike:E-9", actor_role="system", producer="strike",
                    source_object_type="strike_event", source_object_id="evt-race",
                )
                conn.commit()

        t1, e1 = run_isolated(callback)
        t2, e2 = run_isolated(callback)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert e1 == [] and e2 == []
        assert len(db_rows("exposure_exploitation_evidence", exposure_id)) == 1

    def test_evidence_race_supersession_serialized(self):
        exposure_id, _, asset_id = make_current_episode()
        outcome = {}
        barrier = threading.Barrier(2)

        def recorder():
            barrier.wait()
            with get_db_connection() as conn:
                try:
                    outcome["record"] = record_exploitation_evidence(
                        conn, TENANT_A, exposure_id,
                        ExploitationEvidenceIn(basis="observed", result="succeeded", evidence={"x": 1}),
                        actor_id="analyst-a", actor_role="analyst",
                    )
                    conn.commit()
                except ExposureConflictError as exc:
                    outcome["rejected"] = exc
                    conn.rollback()

        def decommissioner():
            barrier.wait()
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE assets SET status = 'decommissioned', decommissioned_at = now()
                        WHERE id = %s AND tenant_id = %s;
                        """,
                        (str(asset_id), str(TENANT_A)),
                    )
                supersede_exposures_for_asset(
                    conn, TENANT_A, asset_id,
                    actor_id="admin-a", actor_role="admin", reason="asset decommissioned",
                )
                conn.commit()

        t1, e1 = run_isolated(recorder)
        t2, e2 = run_isolated(decommissioner)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert e1 == [] and e2 == []

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status FROM asset_exposures WHERE id = %s;", (str(exposure_id),))
                assert cur.fetchone()["status"] == "superseded"
        if "record" in outcome:
            # recorder won the race: the row is history on a terminal episode —
            # persisted, never current-score eligible
            rows = db_rows("exposure_exploitation_evidence", exposure_id)
            assert len(rows) == 1
        else:
            assert isinstance(outcome.get("rejected"), ExposureConflictError)
            assert db_rows("exposure_exploitation_evidence", exposure_id) == []

    def test_audit_failure_rolls_back_score_bearing_mutation(self, monkeypatch):
        exposure_id, _, _ = make_current_episode()

        def broken_audit(*args, **kwargs):
            raise RuntimeError("audit sink down")

        monkeypatch.setattr("app.exposure.scoring_inputs.record_audit_event", broken_audit)
        with get_db_connection() as conn:
            with pytest.raises(RuntimeError, match="audit sink down"):
                set_business_impact(
                    conn, TENANT_A, exposure_id, BusinessImpactIn(value=5),
                    actor_id="analyst-a", actor_role="analyst",
                )
            conn.rollback()
        monkeypatch.undo()
        assert db_rows("exposure_business_impact", exposure_id) == []


# ===========================================================================
# Evidence download audit
# ===========================================================================


class TestDownloadAudit:
    def test_snapshot_read_is_audited(self, client, auth_headers_tenant_a_admin):
        exposure_id, _, _ = make_current_episode()
        res = client.get(
            f"/api/exposure/{exposure_id}/scoring-inputs",
            headers=auth_headers_tenant_a_admin,
        )
        assert res.status_code == 200
        body = res.json()
        assert body["reachability"] is None and body["business_impact"] is None
        events = audit_events("exposure.evidence_downloaded")
        assert any(e["details"]["exposure_id"] == str(exposure_id) for e in events)


# ===========================================================================
# Correction 1 — producer-agnostic reachability (§3.3.2)
# ===========================================================================


class TestProducerAgnosticReachability:
    def test_server_side_additional_producer_accepted(self):
        """A second server-side producer (SCOUT here; the public analyst route
        assigns 'analyst' server-side) records reachability — the ledger is
        producer-agnostic while identity stays server-owned and non-empty."""
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            result = record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external", evidence={"byproduct": True}),
                actor_id="scout:job-1", actor_role="system",
                producer="scout",
                source_object_type="scout_observation", source_object_id="obs-1",
            )
            conn.commit()
        assert result.record.producer == "scout"
        assert result.outcome == "created"

    def test_producer_must_be_non_empty(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="non-empty"):
                record_reachability_evidence(
                    conn, TENANT_A, exposure_id,
                    ReachabilityEvidenceIn(vantage="external", evidence={"x": 1}),
                    actor_id="analyst-a", actor_role="analyst",
                    producer="   ",
                )
            conn.rollback()

    def test_client_cannot_forge_producer_on_public_route(self, client, auth_headers_tenant_a_admin):
        exposure_id, _, _ = make_current_episode()
        res = client.post(
            f"/api/exposure/{exposure_id}/reachability",
            headers=auth_headers_tenant_a_admin,
            json={"vantage": "external", "evidence": {"x": 1}, "producer": "scout"},
        )
        assert res.status_code == 422
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM exposure_reachability_evidence "
                    "WHERE exposure_id = %s AND producer = 'scout';",
                    (str(exposure_id),),
                )
                assert cur.fetchone()["c"] == 0
        # The public analyst route assigns its producer SERVER-side
        res2 = client.post(
            f"/api/exposure/{exposure_id}/reachability",
            headers=auth_headers_tenant_a_admin,
            json={"vantage": "internal", "evidence": {"x": 1}},
        )
        assert res2.status_code == 201
        assert res2.json()["producer"] == "analyst"


# ===========================================================================
# Correction 4 — exact stable-source replay (reachability + exploitation)
# ===========================================================================


class TestStableSourceReplay:
    def test_sequential_cross_episode_reuse_rejected_without_disclosure(self):
        exposure_a, _, _ = make_current_episode()
        exposure_b, _, _ = make_current_episode()
        evidence_body = {"probe": "p-1"}
        with get_db_connection() as conn:
            first = record_reachability_evidence(
                conn, TENANT_A, exposure_a,
                ReachabilityEvidenceIn(vantage="external", evidence=evidence_body),
                actor_id="analyst-a", actor_role="analyst", producer="analyst",
                source_object_type="probe", source_object_id="shared-probe",
            )
            conn.commit()
        # Same stable source identity reused against ANOTHER episode, different
        # evidence: rejected — the old episode's row is never returned.
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="not disclosed"):
                record_reachability_evidence(
                    conn, TENANT_A, exposure_b,
                    ReachabilityEvidenceIn(vantage="internal", evidence={"different": 1}),
                    actor_id="analyst-a", actor_role="analyst", producer="analyst",
                    source_object_type="probe", source_object_id="shared-probe",
                )
            conn.rollback()
        with get_db_connection() as conn:
            rows = db_rows("exposure_reachability_evidence", exposure_b)
        assert rows == []

        # An exact replay of the same logical record (same stable occurrence
        # time, actor, payload, producer, episode) still replays
        with get_db_connection() as conn:
            replay = record_reachability_evidence(
                conn, TENANT_A, exposure_a,
                ReachabilityEvidenceIn(
                    vantage="external", evidence=evidence_body,
                    observed_at=first.record.observed_at,
                ),
                actor_id=first.record.recorded_by,
                actor_role="analyst", producer="analyst",
                source_object_type="probe", source_object_id="shared-probe",
            )
            conn.commit()
        assert replay.outcome == "replay"
        assert replay.record.id == first.record.id

    def test_exploitation_cross_episode_reuse_rejected(self):
        exposure_a, _, _ = make_current_episode()
        exposure_b, _, _ = make_current_episode()
        with get_db_connection() as conn:
            record_exploitation_evidence(
                conn, TENANT_A, exposure_a,
                ExploitationEvidenceIn(basis="observed", result="succeeded",
                                       evidence={"ir": "IR-7"}),
                actor_id="analyst-a", actor_role="analyst",
                source_object_type="incident", source_object_id="IR-7",
            )
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="not disclosed"):
                record_exploitation_evidence(
                    conn, TENANT_A, exposure_b,
                    ExploitationEvidenceIn(basis="observed", result="succeeded",
                                           evidence={"ir": "IR-7"}),
                    actor_id="analyst-a", actor_role="analyst",
                    source_object_type="incident", source_object_id="IR-7",
                )
            conn.rollback()
        assert db_rows("exposure_exploitation_evidence", exposure_b) == []

    def test_concurrent_cross_episode_reuse_converges_on_rejection(self):
        exposure_a, _, _ = make_current_episode()
        exposure_b, _, _ = make_current_episode()
        barrier = threading.Barrier(2)
        outcomes = {}

        def writer(name, target):
            barrier.wait()
            with get_db_connection() as conn:
                try:
                    outcomes[name] = record_reachability_evidence(
                        conn, TENANT_A, target,
                        ReachabilityEvidenceIn(vantage="external", evidence={"shared": True}),
                        actor_id="analyst-a", actor_role="analyst", producer="analyst",
                        source_object_type="probe", source_object_id="race-probe",
                    )
                    conn.commit()
                except EvidencePolicyError as exc:
                    conn.rollback()
                    outcomes[name] = exc

        t1, e1 = run_isolated(lambda: writer("a", exposure_a))
        t2, e2 = run_isolated(lambda: writer("b", exposure_b))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert e1 == [] and e2 == []
        created = [v for v in outcomes.values() if isinstance(v, RecordResult)]
        rejected = [v for v in outcomes.values() if isinstance(v, EvidencePolicyError)]
        assert len(created) == 1 and len(rejected) == 1
        assert db_rows("exposure_reachability_evidence", exposure_b if outcomes["a"] is created[0] else exposure_a) == []


# ===========================================================================
# Correction 5 — idempotent revocation
# ===========================================================================


class TestRevocationIdempotency:
    def test_repeated_revocation_of_one_original_converges(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            evidence = record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external", evidence={"p": 1}),
                actor_id="analyst-a", actor_role="analyst", producer="analyst",
            )
            conn.commit()
        with get_db_connection() as conn:
            first = revoke_evidence(
                conn, TENANT_A, exposure_id, evidence.record.id, "reachability",
                "wrong vantage", actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            retry = revoke_evidence(
                conn, TENANT_A, exposure_id, evidence.record.id, "reachability",
                "wrong vantage (retry)", actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        assert first.outcome == "created"
        assert retry.outcome == "replay"
        assert retry.record["id"] == first.record["id"]
        assert len(db_rows("exposure_reachability_evidence", exposure_id)) == 2
        audits = [
            e for e in audit_events("exposure.evidence_revoked")
            if e["details"]["record_id"] == str(evidence.record.id)
        ]
        assert len(audits) == 1, "one revocation, one audit event"

    def test_concurrent_revocation_converges_one_row_one_audit(self):
        """Loser of the unique-insert race converges via ON CONFLICT DO
        NOTHING + select of the existing revocation — no connection rollback,
        no UniqueViolation leak, one row, one audit event."""
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            evidence = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded", evidence={"t": 1}),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        barrier = threading.Barrier(2)
        outcomes = {}

        def revoker(name):
            barrier.wait()
            with get_db_connection() as conn:
                outcomes[name] = revoke_evidence(
                    conn, TENANT_A, exposure_id, evidence.record.id, "exploitation",
                    f"withdrawn by {name}", actor_id="admin-a", actor_role="admin",
                )
                conn.commit()

        t1, e1 = run_isolated(lambda: revoker("a"))
        t2, e2 = run_isolated(lambda: revoker("b"))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert e1 == [] and e2 == [], "UniqueViolation must never leak"
        assert {outcomes["a"].outcome, outcomes["b"].outcome} == {"created", "replay"}
        assert outcomes["a"].record["id"] == outcomes["b"].record["id"]
        assert len(db_rows("exposure_exploitation_evidence", exposure_id)) == 2
        audits = [
            e for e in audit_events("exposure.evidence_revoked")
            if e["details"]["record_id"] == str(evidence.record.id)
        ]
        assert len(audits) == 1

    def test_prior_uncommitted_work_survives_revocation_replay(self):
        """A revocation replay (retry after another writer won) must never roll
        back or commit the caller's prior uncommitted work."""
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            evidence = record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external", evidence={"p": 1}),
                actor_id="analyst-a", actor_role="analyst", producer="analyst",
            )
            conn.commit()
        # Another writer revokes first (committed)
        with get_db_connection() as conn:
            revoke_evidence(
                conn, TENANT_A, exposure_id, evidence.record.id, "reachability",
                "first withdrawal", actor_id="admin-b", actor_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            # Prior uncommitted work in the caller's transaction
            set_business_impact(
                conn, TENANT_A, exposure_id, BusinessImpactIn(value=4),
                actor_id="analyst-a", actor_role="analyst",
            )
            result = revoke_evidence(
                conn, TENANT_A, exposure_id, evidence.record.id, "reachability",
                "retry after winner", actor_id="admin-a", actor_role="admin",
            )
            assert result.outcome == "replay"
            # Prior work must still be pending: invisible to other connections
            with get_db_connection() as probe_conn:
                with probe_conn.cursor() as cur:
                    cur.execute(
                        "SELECT count(*) AS c FROM exposure_business_impact WHERE exposure_id = %s;",
                        (str(exposure_id),),
                    )
                    assert cur.fetchone()["c"] == 0, "service must not commit caller work"
            conn.commit()
        assert len(db_rows("exposure_business_impact", exposure_id)) == 1

    def test_revoking_a_revocation_is_rejected(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            evidence = record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="internal", evidence={"p": 1}),
                actor_id="analyst-a", actor_role="analyst", producer="analyst",
            )
            conn.commit()
        with get_db_connection() as conn:
            first = revoke_evidence(
                conn, TENANT_A, exposure_id, evidence.record.id, "reachability",
                "wrong vantage", actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="cannot itself be revoked"):
                revoke_evidence(
                    conn, TENANT_A, exposure_id,
                    uuid.UUID(str(first.record["id"])), "reachability",
                    "undo the revocation", actor_id="admin-a", actor_role="admin",
                )
            conn.rollback()
        assert len(db_rows("exposure_reachability_evidence", exposure_id)) == 2


# ===========================================================================
# Correction 6 — analyst-review provenance
# ===========================================================================


class TestAnalystReviewProvenance:
    def test_reviewed_by_forced_to_authenticated_actor(self, client, auth_headers_tenant_a_analyst):
        exposure_id, _, _ = make_current_episode()
        res = client.post(
            f"/api/exposure/{exposure_id}/exploitation-evidence",
            headers=auth_headers_tenant_a_analyst,
            json={"basis": "validated", "result": "succeeded", "evidence": {"poc": "ok"}},
        )
        assert res.status_code == 201
        body = res.json()
        assert body["producer"] == "analyst_review"
        assert body["reviewed_by"] == "analyst-a"
        assert body["evidence_kind"] == "controlled_validation"

    def test_conflicting_internal_reviewer_rejected(self):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            with pytest.raises(EvidencePolicyError, match="conflicting reviewer"):
                record_exploitation_evidence(
                    conn, TENANT_A, exposure_id,
                    ExploitationEvidenceIn(basis="observed", result="succeeded",
                                           evidence={"ir": 1}),
                    actor_id="analyst-a", actor_role="analyst",
                    producer="analyst_review",
                    reviewed_by="someone-else",
                )
            conn.rollback()

    def test_successful_test_and_artifact_alone_never_observed_exploitation(self):
        """The write-time classification stays keyed to the declared basis: a
        controlled test result (or an uploaded artifact reference with no
        observed-compromise basis) records controlled_validation — producer
        identity never promotes a kind."""
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            validated = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded",
                                       evidence={"artifact": "sha256:abc"}),
                actor_id="analyst-a", actor_role="analyst",
            ).record
            strike_test = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded",
                                       evidence={"engagement": "E-2"}),
                actor_id="strike:E-2", actor_role="system", producer="strike",
                source_object_type="strike_event", source_object_id="ev-2",
            ).record
            conn.commit()
        assert validated.evidence_kind == "controlled_validation"
        assert strike_test.evidence_kind == "controlled_validation"
        assert strike_test.reviewed_by is None  # strike path needs no reviewer


# ===========================================================================
# Correction 7 — coherent combined read (REPEATABLE READ snapshot)
# ===========================================================================


class TestSnapshotCoherence:
    def _snapshot_caller(self, exposure_id):
        """Mimics the public route boundary: establish REPEATABLE READ before
        the first query, let the service read + audit inside that transaction,
        then commit at the application boundary. A concurrent audit append
        restarts the whole snapshot once, matching the public route."""
        from app import config as app_config

        for attempt in range(2):
            conn = psycopg.connect(app_config.DATABASE_URL, row_factory=dict_row)
            try:
                with conn.cursor() as cur:
                    cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
                snapshot = get_scoring_inputs(
                    conn, TENANT_A, exposure_id,
                    actor_id="admin-a", actor_role="admin",
                )
                conn.commit()
                return snapshot
            except psycopg.errors.SerializationFailure:
                conn.rollback()
                if attempt:
                    raise
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def test_mid_read_write_cannot_create_mixed_time_response(self):
        """Deterministic interleaving through the caller boundary: the snapshot
        read pauses after its first query; a write that commits DURING the read
        is invisible to every later query in the same snapshot, so the response
        cannot mix times. The service never commits — the caller boundary does."""
        import app.exposure.scoring_inputs as si

        exposure_id, _, _ = make_current_episode()
        reached_first_query = threading.Event()
        release_read = threading.Event()
        result_holder = {}

        original_lookup = si._lookup_exposure

        def gated_lookup(cur, tenant, exposure):
            out = original_lookup(cur, tenant, exposure)
            reached_first_query.set()  # snapshot now exists (first query done)
            assert release_read.wait(timeout=15), "writer never unblocked the reader"
            return out

        def reader():
            monkey = __import__("unittest.mock", fromlist=["patch"])
            with monkey.patch.object(si, "_lookup_exposure", gated_lookup):
                result_holder["snapshot"] = self._snapshot_caller(exposure_id)

        def mid_read_writer():
            assert reached_first_query.wait(timeout=15)
            with get_db_connection() as conn:
                si.set_business_impact(
                    conn, TENANT_A, exposure_id, BusinessImpactIn(value=7),
                    actor_id="analyst-b", actor_role="analyst",
                )
                conn.commit()
            release_read.set()

        t1, e1 = run_isolated(reader)
        t2, e2 = run_isolated(mid_read_writer)
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)
        assert e1 == [] and e2 == []

        snapshot = result_holder["snapshot"]
        # The first snapshot is discarded after its audit-chain conflict; the
        # retry is coherent and sees the committed BI rather than mixing times.
        assert snapshot["business_impact"]["value"] == Decimal("7.0000")
        # A separate read sees the same committed value.
        with get_db_connection() as conn:
            assert si.current_business_impact(conn, TENANT_A, exposure_id) is not None
        # The audit event committed through the caller's boundary.
        events = [
            e for e in audit_events("exposure.evidence_downloaded")
            if e["details"]["exposure_id"] == str(exposure_id)
        ]
        assert len(events) == 1

    def test_prior_uncommitted_caller_work_survives_snapshot_read(self):
        """The service must neither commit nor discard prior uncommitted work
        on the caller's connection: a pending BI insert stays pending through
        the snapshot read, is committed by the SAME boundary commit that
        publishes the response, and is NOT visible to the snapshot itself."""
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")
            # Prior uncommitted caller work in this same transaction
            set_business_impact(
                conn, TENANT_A, exposure_id, BusinessImpactIn(value=6),
                actor_id="analyst-a", actor_role="analyst",
            )
            snapshot = get_scoring_inputs(
                conn, TENANT_A, exposure_id,
                actor_id="admin-a", actor_role="admin",
            )
            # The snapshot is ONE point in time that includes the caller's own
            # pending write (a transaction always sees its own changes).
            assert snapshot["business_impact"]["value"] == Decimal("6.0000")
            # Nothing may have been committed behind the caller's back
            with get_db_connection() as second_conn:
                with second_conn.cursor() as cur:
                    cur.execute(
                        "SELECT count(*) AS c FROM exposure_business_impact WHERE exposure_id = %s;",
                        (str(exposure_id),),
                    )
                    assert cur.fetchone()["c"] == 0, "service must not commit caller work"
            conn.commit()  # application boundary commits EVERYTHING together
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM exposure_business_impact WHERE exposure_id = %s;",
                    (str(exposure_id),),
                )
                assert cur.fetchone()["c"] == 1, "prior work survives and commits with the boundary"

    def test_audit_failure_rolls_back_through_caller_boundary(self, monkeypatch):
        """On audit failure the service raises without committing; the caller's
        rollback discards the whole snapshot attempt including prior uncommitted
        work and the audit event."""
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            set_business_impact(
                conn, TENANT_A, exposure_id, BusinessImpactIn(value=5),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()

        with get_db_connection() as conn:
            # Prior uncommitted caller work in the same transaction (audit
            # sink still healthy at this point). Isolation level is irrelevant
            # to this rollback proof — the snapshot-coherence test covers RR.
            set_business_impact(
                conn, TENANT_A, exposure_id, BusinessImpactIn(value=9),
                actor_id="analyst-a", actor_role="analyst",
            )

            def broken_audit(*args, **kwargs):
                raise RuntimeError("audit sink down")

            monkeypatch.setattr("app.exposure.scoring_inputs.record_audit_event", broken_audit)
            try:
                with pytest.raises(RuntimeError, match="audit sink down"):
                    get_scoring_inputs(
                        conn, TENANT_A, exposure_id,
                        actor_id="admin-a", actor_role="admin",
                    )
            finally:
                monkeypatch.undo()
            conn.rollback()  # application boundary rolls back on failure
        # The committed 5 survived; the pending 9, the snapshot, and the audit
        # attempt were all discarded by the caller's rollback.
        assert len(db_rows("exposure_business_impact", exposure_id)) == 1
        assert float(current_business_impact_value(exposure_id)) == 5.0
        assert audit_events("exposure.evidence_downloaded") == []


# ===========================================================================
# Correction 8 — Business Impact decimal precision
# ===========================================================================


class TestBusinessImpactPrecision:
    def test_multi_decimal_value_preserved_exactly(self, client, auth_headers_tenant_a_admin):
        exposure_id, _, _ = make_current_episode()
        res = client.post(
            f"/api/exposure/{exposure_id}/business-impact",
            headers=auth_headers_tenant_a_admin,
            json={"value": 7.1234},
        )
        assert res.status_code == 201
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT value FROM exposure_business_impact WHERE exposure_id = %s;",
                    (str(exposure_id),),
                )
                stored = cur.fetchone()["value"]
        assert stored == Decimal("7.1234"), "preserved exactly, never rounded"

        with get_db_connection() as conn:
            record = current_business_impact(conn, TENANT_A, exposure_id)
        assert record.value == Decimal("7.1234")
        assert isinstance(record.value, Decimal), "Decimal at the application boundary"

    def test_excess_precision_rejected_never_rounded(self, client, auth_headers_tenant_a_admin):
        exposure_id, _, _ = make_current_episode()
        res = client.post(
            f"/api/exposure/{exposure_id}/business-impact",
            headers=auth_headers_tenant_a_admin,
            json={"value": 7.12345},
        )
        assert res.status_code == 422
        assert "decimal" in res.json()["detail"][0]["msg"]
        assert db_rows("exposure_business_impact", exposure_id) == []


# ===========================================================================
# Correction 5 (round 2) — database row-shape constraints
# ===========================================================================


class TestRowShapeConstraints:
    def _reject(self, conn, table, statement, params):
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.CheckViolation):
                cur.execute(statement, params)
        conn.rollback()

    def test_valid_evidence_and_revocation_rows_accepted(self):
        """Both shapes survive the row-shape CHECKs on both tables (written
        through the service for evidence, direct SQL for the revocation)."""
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            reach = record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external", evidence={"p": 1}),
                actor_id="analyst-a", actor_role="analyst", producer="analyst",
            )
            expl = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="validated", result="succeeded", evidence={"t": 1}),
                actor_id="analyst-a", actor_role="analyst",
            )
            strike = record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="observed", result="succeeded", evidence={"s": 1}),
                actor_id="strike:E-3", actor_role="system", producer="strike",
                source_object_type="strike_event", source_object_id="ev-3",
            )
            conn.commit()
        with get_db_connection() as conn:
            revoke_evidence(
                conn, TENANT_A, exposure_id, reach.record.id, "reachability",
                "bad vantage", actor_id="admin-a", actor_role="admin",
            )
            revoke_evidence(
                conn, TENANT_A, exposure_id, expl.record.id, "exploitation",
                "withdrawn", actor_id="admin-a", actor_role="admin",
            )
            conn.commit()
        # Strike evidence (reviewed_by NULL) is a valid shape; analyst_review
        # evidence requires reviewed_by — both stored fine above.
        assert strike.record.reviewed_by is None

    def test_malformed_reachability_rows_rejected(self):
        exposure_id, _, _ = make_current_episode()
        base = (str(TENANT_A), str(exposure_id))
        with get_db_connection() as conn:
            # One valid evidence row so the revocation-shape subselects below
            # have an original to point at.
            record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external", evidence={"seed": 1}),
                actor_id="analyst-a", actor_role="analyst", producer="analyst",
            )
            conn.commit()
        with get_db_connection() as conn:
            # Evidence shape missing vantage
            self._reject(conn, "exposure_reachability_evidence", """
                INSERT INTO exposure_reachability_evidence (
                    tenant_id, exposure_id, vantage, evidence, producer,
                    observed_at, recorded_by, source_object_type, source_object_id
                ) VALUES (%s, %s, NULL, '{"x": 1}'::jsonb, 'analyst', now(), 't', 't', 'shape-1');
            """, base)
            # Evidence shape with a revocation_reason (mixed shape)
            self._reject(conn, "exposure_reachability_evidence", """
                INSERT INTO exposure_reachability_evidence (
                    tenant_id, exposure_id, vantage, evidence, producer,
                    observed_at, recorded_by, source_object_type, source_object_id, revocation_reason
                ) VALUES (%s, %s, 'external', '{"x": 1}'::jsonb, 'analyst', now(), 't', 't', 'shape-2', 'oops');
            """, base)
            # Evidence shape with empty producer
            self._reject(conn, "exposure_reachability_evidence", """
                INSERT INTO exposure_reachability_evidence (
                    tenant_id, exposure_id, vantage, evidence, producer,
                    observed_at, recorded_by, source_object_type, source_object_id
                ) VALUES (%s, %s, 'external', '{"x": 1}'::jsonb, '', now(), 't', 't', 'shape-3');
            """, base)
            # Evidence shape with NULL observed_at
            self._reject(conn, "exposure_reachability_evidence", """
                INSERT INTO exposure_reachability_evidence (
                    tenant_id, exposure_id, vantage, evidence, producer,
                    observed_at, recorded_by, source_object_type, source_object_id
                ) VALUES (%s, %s, 'external', '{"x": 1}'::jsonb, 'analyst', NULL, 't', 't', 'shape-4');
            """, base)
            # Revocation shape without a reason
            self._reject(conn, "exposure_reachability_evidence", """
                INSERT INTO exposure_reachability_evidence (
                    tenant_id, exposure_id, revocation_of_id, revocation_reason,
                    recorded_by, source_object_type, source_object_id
                ) SELECT tenant_id, exposure_id, id, NULL, 't', 'revocation', 'shape-5'
                  FROM exposure_reachability_evidence WHERE exposure_id = %s LIMIT 1;
            """, (str(exposure_id),))
            # Revocation shape carrying evidence (mixed shape)
            self._reject(conn, "exposure_reachability_evidence", """
                INSERT INTO exposure_reachability_evidence (
                    tenant_id, exposure_id, revocation_of_id, revocation_reason, evidence,
                    recorded_by, source_object_type, source_object_id
                ) SELECT tenant_id, exposure_id, id, 'why', '{"x": 1}'::jsonb, 't', 'revocation', 'shape-6'
                  FROM exposure_reachability_evidence WHERE exposure_id = %s LIMIT 1;
            """, (str(exposure_id),))
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM exposure_reachability_evidence WHERE source_object_id LIKE 'shape-%';",
                )
                assert cur.fetchone()["c"] == 0

    def test_malformed_exploitation_rows_rejected(self):
        exposure_id, _, _ = make_current_episode()
        base = (str(TENANT_A), str(exposure_id))
        with get_db_connection() as conn:
            # One valid evidence row so the revocation-shape subselects below
            # have an original to point at.
            record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="observed", result="succeeded", evidence={"seed": 1}),
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        with get_db_connection() as conn:
            # Analyst-review evidence WITHOUT reviewed_by
            self._reject(conn, "exposure_exploitation_evidence", """
                INSERT INTO exposure_exploitation_evidence (
                    tenant_id, exposure_id, evidence_kind, producer, evidence,
                    observed_at, recorded_by, reviewed_by, source_object_type, source_object_id
                ) VALUES (%s, %s, 'controlled_validation', 'analyst_review',
                          '{"x": 1}'::jsonb, now(), 't', NULL, 't', 'shape-1');
            """, base)
            # Revocation shape without a reason
            self._reject(conn, "exposure_exploitation_evidence", """
                INSERT INTO exposure_exploitation_evidence (
                    tenant_id, exposure_id, revocation_of_id, revocation_reason,
                    recorded_by, source_object_type, source_object_id
                ) SELECT tenant_id, exposure_id, id, NULL, 't', 'revocation', 'shape-2'
                  FROM exposure_exploitation_evidence WHERE exposure_id = %s LIMIT 1;
            """, (str(exposure_id),))
            # Revocation shape carrying a reviewer (mixed shape)
            self._reject(conn, "exposure_exploitation_evidence", """
                INSERT INTO exposure_exploitation_evidence (
                    tenant_id, exposure_id, revocation_of_id, revocation_reason, reviewed_by,
                    recorded_by, source_object_type, source_object_id
                ) SELECT tenant_id, exposure_id, id, 'why', 'ghost', 't', 'revocation', 'shape-3'
                  FROM exposure_exploitation_evidence WHERE exposure_id = %s LIMIT 1;
            """, (str(exposure_id),))
            # Revocation shape carrying a producer (mixed shape)
            self._reject(conn, "exposure_exploitation_evidence", """
                INSERT INTO exposure_exploitation_evidence (
                    tenant_id, exposure_id, revocation_of_id, revocation_reason, producer,
                    recorded_by, source_object_type, source_object_id
                ) SELECT tenant_id, exposure_id, id, 'why', 'strike', 't', 'revocation', 'shape-4'
                  FROM exposure_exploitation_evidence WHERE exposure_id = %s LIMIT 1;
            """, (str(exposure_id),))
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM exposure_exploitation_evidence WHERE source_object_id LIKE 'shape-%';",
                )
                assert cur.fetchone()["c"] == 0


# ===========================================================================
# Correction 3 — retained immutable history (ON DELETE RESTRICT)
# ===========================================================================


class TestHistoryRetention:
    def test_exposure_with_ledger_history_cannot_be_deleted(self):
        exposure_id, finding_id, asset_id = make_current_episode()
        with get_db_connection() as conn:
            record_reachability_evidence(
                conn, TENANT_A, exposure_id,
                ReachabilityEvidenceIn(vantage="external", evidence={"p": 1}),
                actor_id="analyst-a", actor_role="analyst", producer="analyst",
            )
            set_business_impact(
                conn, TENANT_A, exposure_id, BusinessImpactIn(value=5),
                actor_id="analyst-a", actor_role="analyst",
            )
            record_exploitation_evidence(
                conn, TENANT_A, exposure_id,
                ExploitationEvidenceIn(basis="observed", result="succeeded", evidence={"ir": 1}),
                actor_id="analyst-a", actor_role="analyst",
            )
            record_non_exploitation_attestation(
                conn, TENANT_A, exposure_id,
                evidence_ref="review://mfa", actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                for table in (
                    "exposure_reachability_evidence",
                    "exposure_business_impact",
                    "exposure_exploitation_evidence",
                    "exposure_non_exploitation_attestations",
                ):
                    cur.execute(
                        f"""
                        SELECT confdeltype FROM pg_constraint
                        WHERE conrelid = '{table}'::regclass
                          AND conname LIKE 'fk_%_exposure';
                        """
                    )
                    # r = RESTRICT (NO ACTION equivalent with immediate check)
                    assert cur.fetchone()["confdeltype"] == "r", table
                with pytest.raises(psycopg.errors.ForeignKeyViolation):
                    cur.execute(
                        "DELETE FROM asset_exposures WHERE tenant_id = %s AND id = %s;",
                        (str(TENANT_A), str(exposure_id)),
                    )
            conn.rollback()

        # Deletion failed and ALL historical rows remain
        assert len(db_rows("exposure_reachability_evidence", exposure_id)) == 1
        assert len(db_rows("exposure_business_impact", exposure_id)) == 1
        assert len(db_rows("exposure_exploitation_evidence", exposure_id)) == 1
        assert len(db_rows("exposure_non_exploitation_attestations", exposure_id)) == 1


# ===========================================================================
# Correction 2 — SCOUT reachability byproduct
# ===========================================================================


class TestScoutReachabilityByproduct:
    def test_qualifying_central_confirmation_records_external_reachability(
        self, client, auth_headers_tenant_a_admin, monkeypatch
    ):
        from tests.test_scout_sprint02 import launch_vulnerability_job, seed_canonical

        seed_canonical()
        job_id, _ = launch_vulnerability_job(client, auth_headers_tenant_a_admin, monkeypatch)
        observations = client.get(
            f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_a_admin
        ).json()
        vulnerability = next(row for row in observations if row["scanner"] == "nuclei")
        exposure_id = vulnerability["normalized_exposure"]["exposure_id"]

        with get_db_connection() as conn:
            value, record = current_reachability(conn, TENANT_A, uuid.UUID(exposure_id))
        assert value == Decimal("10.0"), "CENTRAL_PUBLIC ⇒ external ⇒ 10"
        assert record.producer == "scout"
        assert record.vantage == "external"
        assert record.evidence["scout_job_id"] == job_id
        assert record.evidence["scout_observation_id"] == vulnerability["id"]
        assert record.evidence["scanner"] == "nuclei"
        assert record.evidence["job_route"] == "CENTRAL_PUBLIC"
        assert record.evidence["vantage"] == "external"
        assert record.evidence["cve_id"] == "CVE-2999-9001"
        assert record.evidence["template_id"] == "CVE-2999-9001"
        assert record.evidence["matcher_name"] == "exact-product"
        assert record.evidence["matched_at"]
        assert record.evidence["event"]
        assert record.source_object_type == "scout_observation"
        assert record.source_object_id == vulnerability["id"]

    def test_collector_internal_route_records_internal_reachability(self):
        """Direct normalization on a COLLECTOR_INTERNAL job ⇒ internal (8)."""
        from tests.test_scout_sprint02 import nuclei_event, seed_canonical
        from tests.test_scout_sprint03 import create_collector_and_internal_asset

        seed_canonical()
        col_id, asset_id, auth_id = create_collector_and_internal_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scout_jobs (
                        tenant_id, asset_id, authorization_id, profile, route, target_type,
                        normalized_target, network_scope, authorization_approved_at,
                        authorization_expires_at, requested_by, collector_id
                    ) VALUES (%s, %s, %s, 'VULNERABILITY_ASSESSMENT', 'COLLECTOR_INTERNAL', 'ip',
                              (SELECT normalized_target FROM assets WHERE id = %s), 'internal',
                              now(), now() + interval '1 hour', 'fixture', %s)
                    RETURNING *
                    """,
                    (str(TENANT_A), str(asset_id), str(auth_id), str(asset_id), str(col_id)),
                )
                job = dict(cur.fetchone())
                cur.execute(
                    """
                    INSERT INTO scout_tool_runs (tenant_id, job_id, engine, ordinal, state)
                    VALUES (%s, %s, 'nuclei', 1, 'succeeded') RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"])),
                )
                tool_run_id = cur.fetchone()["id"]
                cur.execute(
                    """
                    INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                    VALUES (%s, %s, %s, 'template_match', %s::jsonb) RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"]), str(tool_run_id),
                     json.dumps({"scanner": "nuclei", "event": nuclei_event()})),
                )
                observation_id = cur.fetchone()["id"]
            conn.commit()

        from app.scout import _normalize_nuclei_observation

        with get_db_connection() as conn:
            _normalize_nuclei_observation(conn, job, observation_id)
            conn.commit()

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT id FROM asset_exposures WHERE tenant_id = %s AND asset_id = %s;",
                    (str(TENANT_A), str(asset_id)),
                )
                exposure_id = cur.fetchone()["id"]
            value, record = current_reachability(conn, TENANT_A, exposure_id)
        assert value == Decimal("8.0"), "COLLECTOR_INTERNAL ⇒ internal ⇒ 8"
        assert record.vantage == "internal"
        assert record.producer == "scout"
        assert record.source_object_id == str(observation_id)

    def test_repeated_observation_replays_without_overwriting_provenance(self):
        """The same observation replayed (job retry) is idempotent: same
        reachability row, original provenance intact, no second audit."""
        from tests.test_scout_sprint02 import nuclei_event, seed_canonical
        from tests.test_scout_sprint03 import create_collector_and_internal_asset

        seed_canonical()
        col_id, asset_id, auth_id = create_collector_and_internal_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scout_jobs (
                        tenant_id, asset_id, authorization_id, profile, route, target_type,
                        normalized_target, network_scope, authorization_approved_at,
                        authorization_expires_at, requested_by, collector_id
                    ) VALUES (%s, %s, %s, 'VULNERABILITY_ASSESSMENT', 'COLLECTOR_INTERNAL', 'ip',
                              (SELECT normalized_target FROM assets WHERE id = %s), 'internal',
                              now(), now() + interval '1 hour', 'fixture', %s)
                    RETURNING *
                    """,
                    (str(TENANT_A), str(asset_id), str(auth_id), str(asset_id), str(col_id)),
                )
                job = dict(cur.fetchone())
                cur.execute(
                    """
                    INSERT INTO scout_tool_runs (tenant_id, job_id, engine, ordinal, state)
                    VALUES (%s, %s, 'nuclei', 1, 'succeeded') RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"])),
                )
                tool_run_id = cur.fetchone()["id"]
                cur.execute(
                    """
                    INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                    VALUES (%s, %s, %s, 'template_match', %s::jsonb) RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"]), str(tool_run_id),
                     json.dumps({"scanner": "nuclei", "event": nuclei_event()})),
                )
                observation_id = cur.fetchone()["id"]
            conn.commit()

        from app.scout import _normalize_nuclei_observation

        with get_db_connection() as conn:
            _normalize_nuclei_observation(conn, job, observation_id)
            conn.commit()
        audits_after_first = len(audit_events("exposure.reachability_recorded"))

        with get_db_connection() as conn:
            _normalize_nuclei_observation(conn, job, observation_id)
            conn.commit()

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT id FROM asset_exposures WHERE tenant_id = %s AND asset_id = %s;",
                    (str(TENANT_A), str(asset_id)),
                )
                exposure_id = cur.fetchone()["id"]
            rows = db_rows("exposure_reachability_evidence", exposure_id)
            value, record = current_reachability(conn, TENANT_A, exposure_id)
        assert len(rows) == 1
        assert record.source_object_id == str(observation_id)
        assert record.evidence["scout_job_id"] == str(job["id"])
        assert value == Decimal("8.0")
        assert len(audit_events("exposure.reachability_recorded")) == audits_after_first

    def test_retry_matches_exactly_and_replays_with_full_provenance(self):
        """A repeated observation must match the original EXACTLY (same stable
        match occurrence time, same payload) and replay; confirmation and
        reachability remain one transaction."""
        from tests.test_scout_sprint02 import nuclei_event, seed_canonical
        from tests.test_scout_sprint03 import create_collector_and_internal_asset

        seed_canonical()
        col_id, asset_id, auth_id = create_collector_and_internal_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scout_jobs (
                        tenant_id, asset_id, authorization_id, profile, route, target_type,
                        normalized_target, network_scope, authorization_approved_at,
                        authorization_expires_at, requested_by, collector_id
                    ) VALUES (%s, %s, %s, 'VULNERABILITY_ASSESSMENT', 'COLLECTOR_INTERNAL', 'ip',
                              (SELECT normalized_target FROM assets WHERE id = %s), 'internal',
                              now(), now() + interval '1 hour', 'fixture', %s)
                    RETURNING *
                    """,
                    (str(TENANT_A), str(asset_id), str(auth_id), str(asset_id), str(col_id)),
                )
                job = dict(cur.fetchone())
                cur.execute(
                    """
                    INSERT INTO scout_tool_runs (tenant_id, job_id, engine, ordinal, state)
                    VALUES (%s, %s, 'nuclei', 1, 'succeeded') RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"])),
                )
                tool_run_id = cur.fetchone()["id"]
                cur.execute(
                    """
                    INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                    VALUES (%s, %s, %s, 'template_match', %s::jsonb) RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"]), str(tool_run_id),
                     json.dumps({"scanner": "nuclei", "event": nuclei_event()})),
                )
                observation_id = cur.fetchone()["id"]
            conn.commit()

        from app.scout import _normalize_nuclei_observation

        with get_db_connection() as conn:
            _normalize_nuclei_observation(conn, job, observation_id)
            conn.commit()
        with get_db_connection() as conn:
            _normalize_nuclei_observation(conn, job, observation_id)
            conn.commit()

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT id FROM asset_exposures WHERE tenant_id = %s AND asset_id = %s;",
                    (str(TENANT_A), str(asset_id)),
                )
                exposure_id = cur.fetchone()["id"]
            rows = db_rows("exposure_reachability_evidence", exposure_id)
            value, record = current_reachability(conn, TENANT_A, exposure_id)
        assert len(rows) == 1, "exact replay: still exactly one reachability row"
        assert record.evidence["scout_job_id"] == str(job["id"])
        assert record.evidence["job_route"] == "COLLECTOR_INTERNAL"
        assert record.evidence["cve_id"] == "CVE-2999-9001"
        assert record.evidence["matcher_name"] == "exact-product"
        assert value == Decimal("8.0")

    def test_rollback_of_reachability_rolls_back_confirmation_together(self, monkeypatch):
        """Confirmation and reachability are one transaction: a failure in the
        reachability append (simulated audit sink failure) rolls back BOTH."""
        import app.scout as scout_mod
        from tests.test_scout_sprint02 import nuclei_event, seed_canonical
        from tests.test_scout_sprint03 import create_collector_and_internal_asset

        seed_canonical()
        col_id, asset_id, auth_id = create_collector_and_internal_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scout_jobs (
                        tenant_id, asset_id, authorization_id, profile, route, target_type,
                        normalized_target, network_scope, authorization_approved_at,
                        authorization_expires_at, requested_by, collector_id
                    ) VALUES (%s, %s, %s, 'VULNERABILITY_ASSESSMENT', 'COLLECTOR_INTERNAL', 'ip',
                              (SELECT normalized_target FROM assets WHERE id = %s), 'internal',
                              now(), now() + interval '1 hour', 'fixture', %s)
                    RETURNING *
                    """,
                    (str(TENANT_A), str(asset_id), str(auth_id), str(asset_id), str(col_id)),
                )
                job = dict(cur.fetchone())
                cur.execute(
                    """
                    INSERT INTO scout_tool_runs (tenant_id, job_id, engine, ordinal, state)
                    VALUES (%s, %s, 'nuclei', 1, 'succeeded') RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"])),
                )
                tool_run_id = cur.fetchone()["id"]
                cur.execute(
                    """
                    INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                    VALUES (%s, %s, %s, 'template_match', %s::jsonb) RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"]), str(tool_run_id),
                     json.dumps({"scanner": "nuclei", "event": nuclei_event()})),
                )
                observation_id = cur.fetchone()["id"]
            conn.commit()

        def broken_audit(*args, **kwargs):
            raise RuntimeError("audit sink down")

        monkeypatch.setattr(
            "app.exposure.scoring_inputs.record_audit_event", broken_audit
        )
        from app.scout import _normalize_nuclei_observation

        with get_db_connection() as conn:
            with pytest.raises(RuntimeError, match="audit sink down"):
                _normalize_nuclei_observation(conn, job, observation_id)
            conn.rollback()
        monkeypatch.undo()

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM asset_exposures WHERE tenant_id = %s AND asset_id = %s;",
                    (str(TENANT_A), str(asset_id)),
                )
                assert cur.fetchone()["c"] == 0, "confirmation rolled back too"
                cur.execute(
                    "SELECT count(*) AS c FROM exposure_reachability_evidence WHERE tenant_id = %s;",
                    (str(TENANT_A),),
                )
                assert cur.fetchone()["c"] == 0


# ===========================================================================
# Final correction 1 — Nuclei occurrence time without unsupported flags
# ===========================================================================


class TestNucleiOccurrenceTime:
    def test_nuclei_argv_has_no_unsupported_timestamp_flag(self):
        from datetime import datetime, timezone

        from app.scout import nuclei_argv

        argv = nuclei_argv("nuclei", "127.0.0.1", "/pinned/templates")
        assert "-jsonl-include-timestamp" not in argv, (
            "unsupported flag would fail a real scan's argument parsing"
        )
        for flag in ("-jsonl", "-silent", "-no-color"):
            assert flag in argv, "supported JSONL output flags must remain"

    def test_event_timestamp_preferred_when_present(self):
        from datetime import datetime, timezone

        from app.scout import _match_occurrence_time

        occurrence, source = _match_occurrence_time(
            {"event": {"timestamp": "2026-09-01T12:00:00Z"}},
            observation_created_at=datetime(2026, 9, 2, 8, 30, tzinfo=timezone.utc),
        )
        assert occurrence == datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
        assert source == "nuclei_timestamp"

    def test_timestampless_observation_falls_back_to_persisted_created_at(self):
        """An observation whose Nuclei event carries no timestamp uses the
        persisted scout_observations.created_at — never a newly generated
        server time."""
        from datetime import datetime, timezone

        from app.scout import _match_occurrence_time

        occurrence, source = _match_occurrence_time(
            {"event": {}},
            observation_created_at=datetime(2026, 9, 2, 8, 30, tzinfo=timezone.utc),
        )
        assert occurrence == datetime(2026, 9, 2, 8, 30, tzinfo=timezone.utc)
        assert source == "observation_created_at"
        assert occurrence is not None

    def test_timestampless_observation_replays_exactly_one_reachability_row(self):
        """Retrying an observation without an event timestamp replays exactly:
        the persisted observation created_at is the stable occurrence time, so
        the second normalize writes the identical evidence payload and
        observed_at — one reachability row, no second audit."""
        from tests.test_scout_sprint02 import nuclei_event, seed_canonical
        from tests.test_scout_sprint03 import create_collector_and_internal_asset

        seed_canonical()
        col_id, asset_id, auth_id = create_collector_and_internal_asset()
        event = nuclei_event()
        event.pop("timestamp", None)  # timestamp-less observation
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scout_jobs (
                        tenant_id, asset_id, authorization_id, profile, route, target_type,
                        normalized_target, network_scope, authorization_approved_at,
                        authorization_expires_at, requested_by, collector_id
                    ) VALUES (%s, %s, %s, 'VULNERABILITY_ASSESSMENT', 'COLLECTOR_INTERNAL', 'ip',
                              (SELECT normalized_target FROM assets WHERE id = %s), 'internal',
                              now(), now() + interval '1 hour', 'fixture', %s)
                    RETURNING *
                    """,
                    (str(TENANT_A), str(asset_id), str(auth_id), str(asset_id), str(col_id)),
                )
                job = dict(cur.fetchone())
                cur.execute(
                    """
                    INSERT INTO scout_tool_runs (tenant_id, job_id, engine, ordinal, state)
                    VALUES (%s, %s, 'nuclei', 1, 'succeeded') RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"])),
                )
                tool_run_id = cur.fetchone()["id"]
                cur.execute(
                    """
                    INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                    VALUES (%s, %s, %s, 'template_match', %s::jsonb) RETURNING id
                    """,
                    (str(TENANT_A), str(job["id"]), str(tool_run_id),
                     json.dumps({"scanner": "nuclei", "event": event})),
                )
                observation_id = cur.fetchone()["id"]
            conn.commit()

        from app.scout import _normalize_nuclei_observation

        with get_db_connection() as conn:
            _normalize_nuclei_observation(conn, job, observation_id)
            conn.commit()
        audits_after_first = len(audit_events("exposure.reachability_recorded"))

        with get_db_connection() as conn:
            _normalize_nuclei_observation(conn, job, observation_id)
            conn.commit()

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT id FROM asset_exposures WHERE tenant_id = %s AND asset_id = %s;",
                    (str(TENANT_A), str(asset_id)),
                )
                exposure_id = cur.fetchone()["id"]
            rows = db_rows("exposure_reachability_evidence", exposure_id)
            value, record = current_reachability(conn, TENANT_A, exposure_id)
        assert len(rows) == 1, "timestamp-less retry replays: still one reachability row"
        assert record.evidence["occurrence_time_source"] == "observation_created_at"
        assert record.evidence["scout_observation_id"] == str(observation_id)
        assert record.source_object_id == str(observation_id)
        assert record.observed_at is not None
        assert value == Decimal("8.0")
        assert len(audit_events("exposure.reachability_recorded")) == audits_after_first


# ===========================================================================
# Final correction 2 — one revocation per original, database-enforced
# ===========================================================================


class TestOneRevocationPerOriginal:
    def _seed_original(self, kind):
        exposure_id, _, _ = make_current_episode()
        with get_db_connection() as conn:
            if kind == "reachability":
                evidence = record_reachability_evidence(
                    conn, TENANT_A, exposure_id,
                    ReachabilityEvidenceIn(vantage="external", evidence={"p": 1}),
                    actor_id="analyst-a", actor_role="analyst", producer="analyst",
                )
            else:
                evidence = record_exploitation_evidence(
                    conn, TENANT_A, exposure_id,
                    ExploitationEvidenceIn(basis="validated", result="succeeded", evidence={"t": 1}),
                    actor_id="analyst-a", actor_role="analyst",
                )
            conn.commit()
        return exposure_id, evidence.record.id

    def test_alternate_source_identity_cannot_create_second_revocation(self):
        """The database invariant (partial unique index on
        (tenant_id, revocation_of_id)) forbids a second revocation of the same
        original under ANY source identity — the service derives the identity
        from the original record, and direct SQL cannot evade it."""
        for kind in ("reachability", "exploitation"):
            exposure_id, record_id = self._seed_original(kind)
            table = (
                "exposure_reachability_evidence"
                if kind == "reachability"
                else "exposure_exploitation_evidence"
            )
            with get_db_connection() as conn:
                first = revoke_evidence(
                    conn, TENANT_A, exposure_id, record_id, kind,
                    "first withdrawal", actor_id="admin-a", actor_role="admin",
                )
                conn.commit()
            assert first.outcome == "created"
            # Direct SQL: same source id, different reason — hits the partial
            # unique index.
            with get_db_connection() as conn:
                with pytest.raises(psycopg.errors.UniqueViolation):
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            INSERT INTO {table} (
                                tenant_id, exposure_id, revocation_of_id, revocation_reason,
                                recorded_by, source_object_type, source_object_id
                            ) VALUES (%s, %s, %s, 'alt reason', 'ghost', 'revocation', %s);
                            """,
                            (str(TENANT_A), str(exposure_id), str(record_id),
                             f"revocation:{record_id}"),
                        )
                conn.rollback()
            # Direct SQL: ALTERNATE source id — still hits the partial unique
            # index (the exact row the pre-fix schema permitted).
            with get_db_connection() as conn:
                with pytest.raises(psycopg.errors.UniqueViolation):
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            INSERT INTO {table} (
                                tenant_id, exposure_id, revocation_of_id, revocation_reason,
                                recorded_by, source_object_type, source_object_id
                            ) VALUES (%s, %s, %s, 'alt source', 'ghost', 'revocation', 'alt-source-identity');
                            """,
                            (str(TENANT_A), str(exposure_id), str(record_id)),
                        )
                conn.rollback()
            # Service path: derive-only identity means a retry replays.
            with get_db_connection() as conn:
                retry = revoke_evidence(
                    conn, TENANT_A, exposure_id, record_id, kind,
                    "retry reason", actor_id="admin-a", actor_role="admin",
                )
                conn.commit()
            assert retry.outcome == "replay"
            assert retry.record["id"] == first.record["id"]
            audits = [
                e for e in audit_events("exposure.evidence_revoked")
                if e["details"]["record_id"] == str(record_id)
            ]
            assert len(audits) == 1, "exactly one revocation and one audit event"
            with get_db_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(
                        f"SELECT count(*) AS c FROM {table} "
                        "WHERE tenant_id = %s AND revocation_of_id = %s;",
                        (str(TENANT_A), str(record_id)),
                    )
                    assert cur.fetchone()["c"] == 1

    def test_indexes_exist_in_migration(self):
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT indexname, indexdef FROM pg_indexes
                    WHERE indexname IN (
                        'uq_reachability_one_revocation',
                        'uq_exploitation_one_revocation'
                    ) ORDER BY indexname;
                    """
                )
                rows = {r["indexname"]: r["indexdef"] for r in cur.fetchall()}
        assert set(rows) == {
            "uq_reachability_one_revocation",
            "uq_exploitation_one_revocation",
        }
        for definition in rows.values():
            assert "revocation_of_id" in definition
            assert "WHERE" in definition, "must be a partial index"
