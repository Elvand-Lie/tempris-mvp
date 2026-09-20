# backend/tests/test_exposure_lifecycle_authority.py
"""
P0-01 — Exposure lifecycle authority (PRD-000 v1.11 §3.3.1) focused suite.

Covers: the four-value status set; legacy remediated data migration with an
auditable marker; duplicate-current validation before the unique constraint;
idempotent confirmation without provenance overwrite; finding reuse across
recurrence; CAS terminal transitions with stable conflict codes; server-owned
actor/tenant; decommission supersession + reactivation non-revival; atomic
rollback of confirmation on relationship/audit failure; and the concurrency
invariants (two-reviewer race, producer convergence, recurrence race,
decommission-vs-confirmation serialization, timeout-retry idempotency).
"""
import pathlib
import threading
import uuid

import psycopg
import pytest
from psycopg.rows import dict_row
from pydantic import ValidationError

from app.db import get_db_connection
from app.exposure.exceptions import (
    ExposureConflictError,
    InvalidAssetStatusError,
    ReviewBindingError,
    TenantMismatchError,
)
from app.exposure.models import (
    ExposureConfirm,
    ExposureResolve,
    FindingCreate,
    ReviewCreate,
)
from app.exposure.service import (
    allocate_finding_for_cve,
    close_finding,
    confirm_exposure,
    create_finding,
    get_canonical_current_exposures,
    resolve_exposure,
    supersede_exposures_for_asset,
)
from tests.conftest import TENANT_A, TENANT_B
from tests.test_exposure_domain import create_test_asset, seed_canonical_cve

MIGRATION_016 = (
    pathlib.Path(__file__).resolve().parents[1]
    / "migrations"
    / "016_exposure_lifecycle_authority.sql"
)


def confirm(conn, tenant_id, finding_id, asset_id, evidence, actor="analyst-a", role="analyst"):
    return confirm_exposure(
        conn,
        tenant_id,
        ExposureConfirm(finding_id=finding_id, asset_id=asset_id, evidence=evidence),
        actor_id=actor,
        actor_role=role,
    )


def audit_events(event_name, tenant_id=TENANT_A):
    with get_db_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT * FROM audit_events WHERE tenant_id = %s AND event_name = %s ORDER BY created_at;",
                (str(tenant_id), event_name),
            )
            return cur.fetchall()


def exposure_rows(tenant_id, finding_id=None, asset_id=None):
    with get_db_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT id, status, evidence, confirmed_by, confirmed_at
                FROM asset_exposures
                WHERE tenant_id = %s
                  AND (%s::uuid IS NULL OR finding_id = %s::uuid)
                  AND (%s::uuid IS NULL OR asset_id = %s::uuid)
                ORDER BY confirmed_at, id;
                """,
                (
                    str(tenant_id),
                    str(finding_id) if finding_id else None,
                    str(finding_id) if finding_id else None,
                    str(asset_id) if asset_id else None,
                    str(asset_id) if asset_id else None,
                ),
            )
            return cur.fetchall()


def make_finding_and_asset(title="P0-01 Finding", cve_id=None):
    token = uuid.uuid4().int
    with get_db_connection() as conn:
        finding = create_finding(
            conn,
            TENANT_A,
            FindingCreate(title=title, severity="high", canonical_cve_id=cve_id),
        )
        asset_id = create_test_asset(
            conn,
            TENANT_A,
            name=f"asset-{uuid.uuid4().hex[:8]}",
            target_value=f"10.77.{token % 250}.{(token >> 8) % 250}",
        )
        conn.commit()
    return finding.id, asset_id


# ===========================================================================
# Status set + migration / data treatment
# ===========================================================================


class TestStatusSetAndMigration:
    def test_storage_keeps_legacy_remediated_and_rejects_unknown_statuses(self):
        """Storage truth: the five-value CHECK keeps legacy 'remediated'
        compatible (PRD §3.3.1/D-16) while rejecting arbitrary values."""
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # legacy remediated remains storable (pre-existing rows are legal)
                cur.execute(
                    """
                    INSERT INTO asset_exposures (
                        id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by
                    ) VALUES (
                        gen_random_uuid(), %s, %s, %s, 'remediated', '{"legacy": 1}'::jsonb, 'old-system'
                    );
                    """,
                    (str(TENANT_A), str(finding_id), str(asset_id)),
                )
            conn.commit()
            for bad_status in ("active", "garbage", "CONFIRMED", ""):
                with conn.cursor() as cur:
                    with pytest.raises(psycopg.errors.CheckViolation):
                        cur.execute(
                            """
                            INSERT INTO asset_exposures (
                                id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by
                            ) VALUES (
                                gen_random_uuid(), %s, %s, %s, %s, '{"k": 1}'::jsonb, 'tester'
                            );
                            """,
                            (str(TENANT_A), str(finding_id), str(asset_id), bad_status),
                        )
                conn.rollback()

    def test_v3_write_paths_reject_remediated(self):
        """V3 never creates 'remediated': the application transition model
        rejects it even though storage keeps it compatible."""
        with pytest.raises(ValidationError):
            ExposureResolve(status="remediated")

    def test_public_resolve_route_removed_fails_closed(self, client, auth_headers_tenant_a_admin):
        """Phase 0 (audit round 2): no public route may transition an exposure
        — 'resolved' awaits the Ch.8 verified-closure intent and 'false_positive'
        a Ch.6/7 applicability decision. Every request fails closed."""
        for body in ({"status": "resolved"}, {"status": "false_positive"}, {}):
            res = client.post(
                f"/api/exposure/resolve/{uuid.uuid4()}",
                headers=auth_headers_tenant_a_admin,
                json=body,
            )
            assert res.status_code == 404, body
        # Internal service transitions remain available for owner modules
        assert ExposureResolve(status="resolved").status == "resolved"
        assert ExposureResolve(status="false_positive").status == "false_positive"

    def test_migration_016_applied_with_five_value_check_and_finding_identity(self):
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT version FROM schema_migrations WHERE version = '016_exposure_lifecycle_authority.sql';"
                )
                assert cur.fetchone() is not None, "migration 016 must be applied"
                cur.execute(
                    """
                    SELECT pg_get_constraintdef(c.oid) AS def
                    FROM pg_constraint c
                    WHERE c.conrelid = 'asset_exposures'::regclass
                      AND c.conname = 'ck_asset_exposures_status_v3';
                    """
                )
                definition = cur.fetchone()["def"]
                for value in (
                    "'confirmed'",
                    "'resolved'",
                    "'remediated'",
                    "'false_positive'",
                    "'superseded'",
                ):
                    assert value in definition, f"{value} missing from status CHECK"
                cur.execute(
                    """
                    SELECT indexname FROM pg_indexes
                    WHERE tablename = 'asset_exposures'
                      AND indexname = 'idx_asset_exposures_unique_current';
                    """
                )
                assert cur.fetchone() is not None
                cur.execute(
                    """
                    SELECT indexname FROM pg_indexes
                    WHERE tablename = 'findings'
                      AND indexname = 'idx_findings_tenant_cve_unique';
                    """
                )
                assert cur.fetchone() is not None

    def test_migration_preserves_legacy_remediated_rows_byte_for_value(self):
        """Executes the real migration artifact against a seeded legacy row
        inside a rolled-back transaction: the row is NOT rewritten, no
        synthetic marker/audit is produced, and an unverified legacy
        remediation claim is never promoted to 'resolved' (verified closed)."""
        finding_id, asset_id = make_finding_and_asset()
        sql = MIGRATION_016.read_text(encoding="utf-8")
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO asset_exposures (
                        id, tenant_id, finding_id, asset_id, status, evidence,
                        confirmed_by, resolved_at, resolved_by, resolution_reason
                    ) VALUES (
                        gen_random_uuid(), %s, %s, %s, 'remediated', '{"legacy": 1}'::jsonb,
                        'old-system', now(), 'old-admin', 'legacy remediation claim'
                    )
                    RETURNING id;
                    """,
                    (str(TENANT_A), str(finding_id), str(asset_id)),
                )
                legacy_id = cur.fetchone()["id"]
                cur.execute(sql)
                cur.execute(
                    """
                    SELECT status, resolved_by, resolution_reason FROM asset_exposures
                    WHERE id = %s;
                    """,
                    (str(legacy_id),),
                )
                row = cur.fetchone()
                cur.execute(
                    """
                    SELECT count(*) AS c FROM audit_events
                    WHERE tenant_id = %s
                      AND event_name = 'exposure.legacy_remediated_migrated';
                    """,
                    (str(TENANT_A),),
                )
                synthetic_audit = cur.fetchone()["c"]
            conn.rollback()  # never persist the simulated legacy state

        assert row["status"] == "remediated"
        assert row["resolved_by"] == "old-admin"
        assert row["resolution_reason"] == "legacy remediation claim"
        assert synthetic_audit == 0

    def test_migration_reports_duplicate_current_triples_instead_of_discarding(self):
        """With the unique index removed and duplicates seeded, the migration's
        validation block aborts loudly (no silent discard)."""
        finding_id, asset_id = make_finding_and_asset()
        sql = MIGRATION_016.read_text(encoding="utf-8")
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DROP INDEX idx_asset_exposures_unique_current;")
                for _ in range(2):
                    cur.execute(
                        """
                        INSERT INTO asset_exposures (
                            id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by
                        ) VALUES (
                            gen_random_uuid(), %s, %s, %s, 'confirmed', '{"dup": 1}'::jsonb, 'racer'
                        );
                        """,
                        (str(TENANT_A), str(finding_id), str(asset_id)),
                    )
                with pytest.raises(psycopg.errors.RaiseException, match="duplicate current"):
                    cur.execute(sql)
            conn.rollback()

    def test_migration_reports_duplicate_cve_findings_instead_of_discarding(self):
        """Finding identity: with the unique index removed and two findings for
        one (tenant, CVE) seeded, the migration aborts loudly."""
        cve = "CVE-2026-0099"
        with get_db_connection() as conn:
            seed_canonical_cve(conn, cve)
            conn.commit()
        sql = MIGRATION_016.read_text(encoding="utf-8")
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DROP INDEX idx_findings_tenant_cve_unique;")
                for title in ("First", "Second"):
                    cur.execute(
                        """
                        INSERT INTO findings (id, tenant_id, canonical_cve_id, title, severity, status)
                        VALUES (gen_random_uuid(), %s, %s, %s, 'high', 'open');
                        """,
                        (str(TENANT_A), cve, title),
                    )
                with pytest.raises(psycopg.errors.RaiseException, match="finding group"):
                    cur.execute(sql)
            conn.rollback()


# ===========================================================================
# Idempotency, provenance, producer convergence
# ===========================================================================


class TestIdempotencyAndProvenance:
    def test_replay_returns_committed_episode_without_mutation(self):
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            first = confirm(conn, TENANT_A, finding_id, asset_id, {"v": 1}, actor="analyst-1")
            conn.commit()
        with get_db_connection() as conn:
            second = confirm(conn, TENANT_A, finding_id, asset_id, {"v": 2}, actor="analyst-2")
            conn.commit()

        assert first.outcome == "created"
        assert second.outcome == "replay"
        assert second.exposure.id == first.exposure.id
        assert second.exposure.evidence == {"v": 1}
        assert second.exposure.confirmed_by == "analyst-1"
        assert second.exposure.confirmed_at == first.exposure.confirmed_at
        assert len(exposure_rows(TENANT_A, finding_id, asset_id)) == 1

    def test_timeout_after_commit_retry_is_idempotent_success(self):
        """Client timeout after commit, then retry: same episode, no duplicate
        row, and no additional confirmation audit (replays mutate nothing)."""
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            confirm(conn, TENANT_A, finding_id, asset_id, {"attempt": 1}, actor="analyst-1")
            conn.commit()
        base_audit = len(audit_events("exposure.confirmed"))

        with get_db_connection() as conn:
            retried = confirm(conn, TENANT_A, finding_id, asset_id, {"attempt": 2}, actor="analyst-1")
            conn.commit()

        assert retried.outcome == "replay"
        assert len(exposure_rows(TENANT_A, finding_id, asset_id)) == 1
        assert len(audit_events("exposure.confirmed")) == base_audit

    def test_scout_and_manual_producers_converge_on_one_episode(self):
        """SCOUT-confirmed and manually-confirmed tuples produce the same
        artifact through the same command: the second producer replays the
        first episode and provenance is preserved."""
        with get_db_connection() as conn:
            cve = seed_canonical_cve(conn, "CVE-2026-0001")
        finding_id, asset_id = make_finding_and_asset(cve_id=cve)
        with get_db_connection() as conn:
            scout_result = confirm(
                conn,
                TENANT_A,
                finding_id,
                asset_id,
                {"source": "scout", "scout_job_id": "job-1"},
                actor="scout:job-1",
                role="system",
            )
            conn.commit()
        with get_db_connection() as conn:
            manual_result = confirm(
                conn,
                TENANT_A,
                finding_id,
                asset_id,
                {"source": "manual", "analyst": "round 2"},
                actor="analyst-a",
            )
            conn.commit()

        assert scout_result.outcome == "created"
        assert manual_result.outcome == "replay"
        assert manual_result.exposure.id == scout_result.exposure.id
        assert manual_result.exposure.confirmed_by == "scout:job-1"
        assert manual_result.exposure.evidence["source"] == "scout"


# ===========================================================================
# Recurrence, finding reuse, roll-up derivation
# ===========================================================================


class TestRecurrenceAndReuse:
    def test_recurrence_creates_new_episode_and_reuses_finding(self):
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            episode1 = confirm(conn, TENANT_A, finding_id, asset_id, {"round": 1}).exposure
            conn.commit()
            resolve_exposure(
                conn,
                TENANT_A,
                episode1.id,
                ExposureResolve(status="resolved", resolution_reason="patched"),
                actor_id="admin-a",
                actor_role="admin",
            )
            conn.commit()
            episode2 = confirm(conn, TENANT_A, finding_id, asset_id, {"round": 2}).exposure
            conn.commit()

        assert episode2.id != episode1.id
        rows = exposure_rows(TENANT_A, finding_id, asset_id)
        assert len(rows) == 2
        assert [r["status"] for r in rows] == ["resolved", "confirmed"]
        # The same finding is reused — never a second finding for the same concept
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT count(*) AS c, max(status) AS rollup FROM findings
                    WHERE tenant_id = %s AND id = %s;
                    """,
                    (str(TENANT_A), str(finding_id)),
                )
                row = cur.fetchone()
        assert row["c"] == 1
        assert row["rollup"] == "open"

    def test_recurrence_reuses_terminal_episode_findings_via_cve_allocation(self):
        """The §3.4 SCOUT reuse gap: finding allocation by CVE reuses findings
        regardless of status — closed/resolved findings are not invisible."""
        with get_db_connection() as conn:
            cve = seed_canonical_cve(conn, "CVE-2026-0002")
        with get_db_connection() as conn:
            first_id = allocate_finding_for_cve(
                conn, TENANT_A, cve, default_title="T1", default_severity="high",
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
            # Simulate a terminal roll-up: close the finding
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE findings SET status = 'closed', closed_at = now() WHERE id = %s;",
                    (str(first_id),),
                )
            conn.commit()
            second_id = allocate_finding_for_cve(
                conn, TENANT_A, cve, default_title="T2", default_severity="high",
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        assert second_id == first_id

    def test_finding_rollup_derived_but_never_authority(self):
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            episode = confirm(conn, TENANT_A, finding_id, asset_id, {"x": 1}).exposure
            conn.commit()
            # Manual close (roll-up display only) cannot hide current truth
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE findings SET status = 'closed' WHERE tenant_id = %s AND id = %s;",
                    (str(TENANT_A), str(finding_id)),
                )
            conn.commit()
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1
            # A lifecycle transition re-derives the roll-up from exposure truth
            resolve_exposure(
                conn,
                TENANT_A,
                episode.id,
                ExposureResolve(status="resolved"),
                actor_id="admin-a",
                actor_role="admin",
            )
            conn.commit()
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT status, closed_at FROM findings WHERE id = %s;", (str(finding_id),)
                )
                row = cur.fetchone()
        assert row["status"] == "closed"
        assert row["closed_at"] is not None

    def test_close_rejected_while_current_exposure_exists(self):
        """Roll-up consistency (fix 4): a finding holding a current confirmed
        exposure cannot be closed — its derived state must stay open. After the
        exposure resolves, close succeeds. Current queries never filter on
        finding status either way."""
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            episode = confirm(conn, TENANT_A, finding_id, asset_id, {"x": 1}).exposure
            conn.commit()

            with pytest.raises(ExposureConflictError):
                close_finding(conn, TENANT_A, finding_id, closed_by="admin-a")
            conn.rollback()

            # Roll-up remains open and current truth is unchanged
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status FROM findings WHERE id = %s;", (str(finding_id),))
                assert cur.fetchone()["status"] == "open"
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1

            resolve_exposure(
                conn,
                TENANT_A,
                episode.id,
                ExposureResolve(status="resolved"),
                actor_id="admin-a",
                actor_role="admin",
            )
            conn.commit()
            closed = close_finding(conn, TENANT_A, finding_id, closed_by="admin-a")
            conn.commit()
        assert closed.status == "closed"


# ===========================================================================
# Manual disposition atomicity (review-backed confirmation)
# ===========================================================================


class TestManualDisposition:
    def test_manual_confirm_binds_applicable_review_atomically(
        self, client, auth_headers_tenant_a_admin
    ):
        """Fix 7: public manual confirmation creates the analyst's APPLICABLE
        review in the same transaction with the authenticated actor; a replay
        confirms without duplicating the exposure."""
        finding_id, asset_id = make_finding_and_asset()
        res = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={
                "finding_id": str(finding_id),
                "asset_id": str(asset_id),
                "evidence": {"p": 1},
            },
        )
        assert res.status_code == 200
        assert res.headers["x-exposure-outcome"] == "created"

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT applicability, reviewed_by FROM asset_applicability_reviews
                    WHERE tenant_id = %s AND finding_id = %s AND asset_id = %s;
                    """,
                    (str(TENANT_A), str(finding_id), str(asset_id)),
                )
                reviews = cur.fetchall()
        assert len(reviews) == 1
        assert reviews[0]["applicability"] == "APPLICABLE"
        assert reviews[0]["reviewed_by"] == "admin-a"

        # Replay does not duplicate the exposure (review trail stays append-only)
        res2 = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={
                "finding_id": str(finding_id),
                "asset_id": str(asset_id),
                "evidence": {"p": 2},
            },
        )
        assert res2.status_code == 200
        assert res2.headers["x-exposure-outcome"] == "replay"
        assert res2.json()["id"] == res.json()["id"]

    def test_scout_confirmation_remains_reviewless(self):
        """SCOUT qualifying observations carry their own disposition (the
        observation IS the evidence) and never write applicability reviews."""
        cve = "CVE-2026-0004"
        with get_db_connection() as conn:
            seed_canonical_cve(conn, cve)
            conn.commit()
        finding_id, asset_id = make_finding_and_asset(cve_id=cve)
        with get_db_connection() as conn:
            confirm(
                conn,
                TENANT_A,
                finding_id,
                asset_id,
                {"source": "scout", "scout_job_id": "job-x"},
                actor="scout:job-x",
                role="system",
            )
            conn.commit()
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT count(*) AS c FROM asset_applicability_reviews
                    WHERE tenant_id = %s AND finding_id = %s AND asset_id = %s;
                    """,
                    (str(TENANT_A), str(finding_id), str(asset_id)),
                )
                assert cur.fetchone()["c"] == 0

    def test_manual_cve_finding_creation_reuses_the_concept(
        self, client, auth_headers_tenant_a_admin
    ):
        """Fix 3: POST /findings with a canonical CVE routes through the shared
        serialized allocator — a second manual creation reuses the same
        finding instead of duplicating the concept."""
        cve = "CVE-2026-0005"
        with get_db_connection() as conn:
            seed_canonical_cve(conn, cve)
            conn.commit()

        res1 = client.post(
            "/api/exposure/findings",
            headers=auth_headers_tenant_a_admin,
            json={"title": "First title", "severity": "high", "canonical_cve_id": cve},
        )
        assert res1.status_code == 201
        res2 = client.post(
            "/api/exposure/findings",
            headers=auth_headers_tenant_a_admin,
            json={"title": "Second title", "severity": "critical", "canonical_cve_id": cve},
        )
        assert res2.status_code == 201
        assert res2.json()["id"] == res1.json()["id"]

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM findings WHERE tenant_id = %s AND canonical_cve_id = %s;",
                    (str(TENANT_A), cve),
                )
                assert cur.fetchone()["c"] == 1

    def test_allocator_audits_creation_only_on_actual_insert(self):
        """Fix 4: finding.created is emitted by the serialized CVE allocator on
        actual insert only, with the caller's server actor — SCOUT creation is
        audited with the service actor; reuse emits nothing."""
        cve = "CVE-2026-0008"
        with get_db_connection() as conn:
            seed_canonical_cve(conn, cve)
            conn.commit()

        with get_db_connection() as conn:
            first_id = allocate_finding_for_cve(
                conn, TENANT_A, cve,
                default_title="SCOUT match", default_severity="high",
                actor_id="scout:job-42", actor_role="system",
            )
            conn.commit()
        created = [
            e for e in audit_events("finding.created")
            if e["details"]["finding_id"] == str(first_id)
        ]
        assert len(created) == 1
        assert created[0]["actor_id"] == "scout:job-42"
        assert created[0]["actor_role"] == "system"

        with get_db_connection() as conn:
            second_id = allocate_finding_for_cve(
                conn, TENANT_A, cve,
                default_title="Manual", default_severity="high",
                actor_id="analyst-a", actor_role="analyst",
            )
            conn.commit()
        assert second_id == first_id
        reused = [
            e for e in audit_events("finding.created")
            if e["details"]["finding_id"] == str(first_id)
        ]
        assert len(reused) == 1, "reuse must not be falsely audited as creation"


# ===========================================================================
# CAS terminal transitions + stable conflict codes
# ===========================================================================


class TestResolveCompareAndSet:
    def _confirmed_episode(self):
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            episode = confirm(conn, TENANT_A, finding_id, asset_id, {"x": 1}).exposure
            conn.commit()
        return episode, finding_id, asset_id

    def test_same_transition_is_idempotent_replay(self):
        episode, _, _ = self._confirmed_episode()
        with get_db_connection() as conn:
            first = resolve_exposure(
                conn,
                TENANT_A,
                episode.id,
                ExposureResolve(status="resolved", resolution_reason="patched v1"),
                actor_id="admin-a",
                actor_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            second = resolve_exposure(
                conn,
                TENANT_A,
                episode.id,
                ExposureResolve(status="resolved", resolution_reason="patched v2"),
                actor_id="admin-b",
                actor_role="admin",
            )
            conn.commit()
        assert first.outcome == "transitioned"
        assert second.outcome == "replay"
        # Original transition provenance is never overwritten
        assert second.exposure.resolved_by == "admin-a"
        assert second.exposure.resolution_reason == "patched v1"

    def test_terminal_audit_event_names_the_actual_state(self):
        """Fix 4: the audit event carries the actual terminal state —
        exposure.false_positive vs exposure.resolved."""
        fp_episode, _, _ = self._confirmed_episode()
        resolved_episode, _, _ = self._confirmed_episode()
        with get_db_connection() as conn:
            resolve_exposure(
                conn,
                TENANT_A,
                fp_episode.id,
                ExposureResolve(status="false_positive", resolution_reason="withdrawn"),
                actor_id="admin-a",
                actor_role="admin",
            )
            resolve_exposure(
                conn,
                TENANT_A,
                resolved_episode.id,
                ExposureResolve(status="resolved", resolution_reason="verified closed"),
                actor_id="admin-a",
                actor_role="admin",
            )
            conn.commit()

        fp_events = audit_events("exposure.false_positive")
        resolved_events = audit_events("exposure.resolved")
        assert any(e["details"]["exposure_id"] == str(fp_episode.id) for e in fp_events)
        assert all(e["details"]["new_state"] == "false_positive" for e in fp_events)
        assert any(e["details"]["exposure_id"] == str(resolved_episode.id) for e in resolved_events)
        assert all(e["details"]["new_state"] == "resolved" for e in resolved_events)

    def test_conflicting_terminal_transition_rejected(self):
        episode, _, _ = self._confirmed_episode()
        with get_db_connection() as conn:
            resolve_exposure(
                conn,
                TENANT_A,
                episode.id,
                ExposureResolve(status="resolved"),
                actor_id="admin-a",
                actor_role="admin",
            )
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(ExposureConflictError) as exc_info:
                resolve_exposure(
                    conn,
                    TENANT_A,
                    episode.id,
                    ExposureResolve(status="false_positive"),
                    actor_id="admin-b",
                    actor_role="admin",
                )
            conn.rollback()
        assert exc_info.value.code == "exposure_conflict"

    def test_superseded_episode_rejects_transition_with_stable_code(self):
        episode, _, asset_id = self._confirmed_episode()
        with get_db_connection() as conn:
            supersede_exposures_for_asset(
                conn,
                TENANT_A,
                asset_id,
                actor_id="admin-a",
                actor_role="admin",
                reason="asset decommissioned",
            )
            conn.commit()
        with get_db_connection() as conn:
            with pytest.raises(ExposureConflictError) as exc_info:
                resolve_exposure(
                    conn,
                    TENANT_A,
                    episode.id,
                    ExposureResolve(status="false_positive"),
                    actor_id="admin-a",
                    actor_role="admin",
                )
            conn.rollback()
        assert exc_info.value.code == "exposure_conflict"

    def test_api_rejects_client_actor_fields(self, client, auth_headers_tenant_a_admin):
        finding_id, asset_id = make_finding_and_asset()
        res = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={
                "finding_id": str(finding_id),
                "asset_id": str(asset_id),
                "evidence": {"p": 1},
                "confirmed_by": "spoofed-actor",
            },
        )
        assert res.status_code == 422

        res2 = client.post(
            "/api/exposure/confirm",
            headers=auth_headers_tenant_a_admin,
            json={
                "finding_id": str(finding_id),
                "asset_id": str(asset_id),
                "evidence": {"p": 1},
            },
        )
        assert res2.status_code == 200
        assert res2.json()["confirmed_by"] == "admin-a"  # server-owned actor

        # The review route rejects client actor identity the same way
        res3 = client.post(
            "/api/exposure/reviews",
            headers=auth_headers_tenant_a_admin,
            json={
                "finding_id": str(finding_id),
                "asset_id": str(asset_id),
                "applicability": "APPLICABLE",
                "reviewed_by": "spoofed-actor",
            },
        )
        assert res3.status_code == 422

    def test_superseded_not_requestable_at_any_layer(self):
        """'superseded' is produced only by anchor lifecycle events (asset
        decommission, later boundary replace-or-clear) — never requestable."""
        with pytest.raises(ValidationError):
            ExposureResolve(status="superseded")

    def test_tenant_is_server_owned_cross_tenant_confirm_fails(self):
        with get_db_connection() as conn:
            finding_a = create_finding(
                conn, TENANT_A, FindingCreate(title="A", severity="high")
            )
            asset_b = create_test_asset(conn, TENANT_B, name="B asset", target_value="10.78.0.1")
            conn.commit()
            with pytest.raises(TenantMismatchError):
                confirm_exposure(
                    conn,
                    TENANT_A,
                    ExposureConfirm(finding_id=finding_a.id, asset_id=asset_b, evidence={"x": 1}),
                    actor_id="analyst-a",
                    actor_role="analyst",
                )
            conn.rollback()


# ===========================================================================
# Decommission supersession
# ===========================================================================


class TestDecommissionSupersession:
    def test_decommission_supersedes_all_current_exposures_atomically(
        self, client, auth_headers_tenant_a_admin
    ):
        with get_db_connection() as conn:
            finding1 = create_finding(conn, TENANT_A, FindingCreate(title="F1", severity="high"))
            finding2 = create_finding(conn, TENANT_A, FindingCreate(title="F2", severity="low"))
            asset_id = create_test_asset(conn, TENANT_A, name="fleet-node", target_value="10.79.0.1")
            e1 = confirm(conn, TENANT_A, finding1.id, asset_id, {"a": 1}).exposure
            e2 = confirm(conn, TENANT_A, finding2.id, asset_id, {"b": 2}).exposure
            conn.commit()

        res = client.post(f"/api/assets/{asset_id}/decommission", headers=auth_headers_tenant_a_admin)
        assert res.status_code == 200

        rows = {r["id"]: r["status"] for r in exposure_rows(TENANT_A, asset_id=asset_id)}
        assert rows == {e1.id: "superseded", e2.id: "superseded"}

        events = audit_events("exposure.superseded")
        superseded_ids = {e["details"]["exposure_id"] for e in events}
        assert {str(e1.id), str(e2.id)} <= superseded_ids
        assert all(e["details"]["prior_state"] == "confirmed" for e in events)
        assert all(e["details"]["new_state"] == "superseded" for e in events)

        with get_db_connection() as conn:
            # Current truth excludes the decommissioned asset
            assert len(get_canonical_current_exposures(conn, TENANT_A, asset_id=asset_id)) == 0
            # Roll-ups re-derived: no current exposures -> closed findings
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT f.id, f.status FROM findings f
                    WHERE f.tenant_id = %s AND f.id IN (%s, %s);
                    """,
                    (str(TENANT_A), str(finding1.id), str(finding2.id)),
                )
                rollups = {row["id"]: row["status"] for row in cur.fetchall()}
        assert rollups == {finding1.id: "closed", finding2.id: "closed"}

        # Idempotent re-decommission: nothing to supersede, no error
        res2 = client.post(f"/api/assets/{asset_id}/decommission", headers=auth_headers_tenant_a_admin)
        assert res2.status_code == 200
        assert len(exposure_rows(TENANT_A, asset_id=asset_id)) == 2

    def test_reactivation_does_not_revive_and_recurrence_reuses_finding(
        self, client, auth_headers_tenant_a_admin
    ):
        with get_db_connection() as conn:
            finding = create_finding(conn, TENANT_A, FindingCreate(title="F", severity="high"))
            asset_id = create_test_asset(conn, TENANT_A, name="phoenix", target_value="10.79.0.2")
            episode = confirm(conn, TENANT_A, finding.id, asset_id, {"gen": 1}).exposure
            conn.commit()

        client.post(f"/api/assets/{asset_id}/decommission", headers=auth_headers_tenant_a_admin)

        # Reactivate directly (operator SQL): the superseded episode never returns
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE assets SET status = 'active' WHERE id = %s;", (str(asset_id),))
            conn.commit()
            assert len(get_canonical_current_exposures(conn, TENANT_A, asset_id=asset_id)) == 0

            # New confirmation on the reactivated asset creates a NEW episode on
            # the same finding — the old episode stays superseded
            episode2 = confirm(conn, TENANT_A, finding.id, asset_id, {"gen": 2}).exposure
            conn.commit()

        assert episode2.id != episode.id
        rows = exposure_rows(TENANT_A, finding.id, asset_id)
        assert [r["status"] for r in rows] == ["superseded", "confirmed"]


# ===========================================================================
# Atomicity: relationship / audit failures roll back the whole confirmation
# ===========================================================================


class TestAtomicRollback:
    def test_audit_failure_rolls_back_confirmation(self, monkeypatch):
        finding_id, asset_id = make_finding_and_asset()

        def broken_audit(*args, **kwargs):
            raise RuntimeError("audit sink down")

        monkeypatch.setattr("app.exposure.service.record_audit_event", broken_audit)
        with get_db_connection() as conn:
            with pytest.raises(RuntimeError, match="audit sink down"):
                confirm(conn, TENANT_A, finding_id, asset_id, {"x": 1})
            conn.rollback()
        monkeypatch.undo()

        assert exposure_rows(TENANT_A, finding_id, asset_id) == []
        assert audit_events("exposure.confirmed") == []

    def test_mismatched_review_binding_rolls_back_confirmation(self):
        """The review bound to a confirmation command must reference the exact
        confirmed tuple; a mismatch aborts the whole confirmation —
        disposition, relationship, and audit commit together or not at all."""
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            other_finding = create_finding(
                conn, TENANT_A, FindingCreate(title="Other", severity="low")
            )
            conn.commit()
            with pytest.raises(ReviewBindingError):
                confirm_exposure(
                    conn,
                    TENANT_A,
                    ExposureConfirm(finding_id=finding_id, asset_id=asset_id, evidence={"x": 1}),
                    actor_id="analyst-a",
                    actor_role="analyst",
                    review=ReviewCreate(
                        finding_id=other_finding.id,  # tuple mismatch
                        asset_id=asset_id,
                        applicability="APPLICABLE",
                    ),
                )
            conn.rollback()

        assert exposure_rows(TENANT_A, finding_id, asset_id) == []
        assert audit_events("exposure.confirmed") == []


# ===========================================================================
# Concurrency invariants
# ===========================================================================


def run_isolated(fn):
    """Run fn in a thread with its own pooled connection; collect exceptions."""
    errors = []

    def wrapper():
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — collected and asserted below
            errors.append(exc)

    thread = threading.Thread(target=wrapper)
    return thread, errors


class TestConcurrencyInvariants:
    def test_two_reviewers_confirming_simultaneously_yield_one_episode(self):
        finding_id, asset_id = make_finding_and_asset()
        results = {}
        barrier = threading.Barrier(2)

        def reviewer(actor, evidence):
            barrier.wait()
            with get_db_connection() as conn:
                results[actor] = confirm(conn, TENANT_A, finding_id, asset_id, evidence, actor=actor)
                conn.commit()

        t1, e1 = run_isolated(lambda: reviewer("analyst-1", {"who": "one"}))
        t2, e2 = run_isolated(lambda: reviewer("analyst-2", {"who": "two"}))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert not t1.is_alive() and not t2.is_alive()
        assert e1 == [] and e2 == []

        outcomes = {r.outcome for r in results.values()}
        ids = {r.exposure.id for r in results.values()}
        assert outcomes == {"created", "replay"}
        assert len(ids) == 1
        rows = exposure_rows(TENANT_A, finding_id, asset_id)
        assert len(rows) == 1
        # The winner's evidence and provenance survive — nothing lost
        assert rows[0]["evidence"] in ({"who": "one"}, {"who": "two"})
        assert len(audit_events("exposure.confirmed")) == 1

    def test_scout_and_intake_equivalent_producers_race_to_one_episode(self):
        with get_db_connection() as conn:
            cve = seed_canonical_cve(conn, "CVE-2026-0003")
        finding_id, asset_id = make_finding_and_asset(cve_id=cve)
        results = {}
        barrier = threading.Barrier(2)

        def producer(name, actor, role, evidence):
            barrier.wait()
            with get_db_connection() as conn:
                results[name] = confirm(
                    conn, TENANT_A, finding_id, asset_id, evidence, actor=actor, role=role
                )
                conn.commit()

        t1, e1 = run_isolated(
            lambda: producer("scout", "scout:job-9", "system", {"source": "scout"})
        )
        t2, e2 = run_isolated(
            lambda: producer("manual", "analyst-a", "analyst", {"source": "manual"})
        )
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert e1 == [] and e2 == []
        assert {r.outcome for r in results.values()} == {"created", "replay"}
        assert len({r.exposure.id for r in results.values()}) == 1
        assert len(exposure_rows(TENANT_A, finding_id, asset_id)) == 1

    def test_recurrence_confirmation_races_another_confirmation(self):
        finding_id, asset_id = make_finding_and_asset()
        with get_db_connection() as conn:
            episode1 = confirm(conn, TENANT_A, finding_id, asset_id, {"gen": 1}).exposure
            resolve_exposure(
                conn,
                TENANT_A,
                episode1.id,
                ExposureResolve(status="resolved"),
                actor_id="admin-a",
                actor_role="admin",
            )
            conn.commit()

        barrier = threading.Barrier(2)

        def contender(actor):
            barrier.wait()
            with get_db_connection() as conn:
                confirm(conn, TENANT_A, finding_id, asset_id, {"gen": 2}, actor=actor)
                conn.commit()

        t1, e1 = run_isolated(lambda: contender("analyst-1"))
        t2, e2 = run_isolated(lambda: contender("analyst-2"))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert e1 == [] and e2 == []

        rows = exposure_rows(TENANT_A, finding_id, asset_id)
        assert len(rows) == 2
        assert [r["status"] for r in rows] == ["resolved", "confirmed"]
        with get_db_connection() as conn:
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1

    def test_decommission_races_confirmation_serialized_outcome(self):
        finding_id, asset_id = make_finding_and_asset()
        outcome = {}
        barrier = threading.Barrier(2)

        def confirme():
            barrier.wait()
            with get_db_connection() as conn:
                outcome["confirm"] = confirm(
                    conn, TENANT_A, finding_id, asset_id, {"race": True}, actor="analyst-a"
                )
                conn.commit()

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
                    conn,
                    TENANT_A,
                    asset_id,
                    actor_id="admin-a",
                    actor_role="admin",
                    reason="asset decommissioned",
                )
                conn.commit()
                outcome["decommission"] = True

        t1, e1 = run_isolated(confirme)
        t2, e2 = run_isolated(decommissioner)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert not t1.is_alive() and not t2.is_alive()
        assert e2 == []
        # Confirm either failed cleanly (asset already decommissioned) or
        # succeeded and was superseded; never a deadlock, never an error storm
        if e1:
            assert len(e1) == 1
            assert isinstance(e1[0], InvalidAssetStatusError)
        else:
            assert outcome["confirm"].outcome == "created"

        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status FROM assets WHERE id = %s;", (str(asset_id),))
                assert cur.fetchone()["status"] == "decommissioned"
                cur.execute(
                    """
                    SELECT count(*) AS c FROM asset_exposures
                    WHERE tenant_id = %s AND asset_id = %s AND status = 'confirmed';
                    """,
                    (str(TENANT_A), str(asset_id)),
                )
                assert cur.fetchone()["c"] == 0, "no confirmed episode remains current"
            assert len(get_canonical_current_exposures(conn, TENANT_A, asset_id=asset_id)) == 0

    def test_manual_manual_allocation_race_yields_one_finding(self):
        """Fix 3: two concurrent manual allocations for the same (tenant, CVE)
        converge on one finding — serialized allocation + storage uniqueness."""
        cve = "CVE-2026-0006"
        with get_db_connection() as conn:
            seed_canonical_cve(conn, cve)
            conn.commit()

        allocated = []
        barrier = threading.Barrier(2)

        def allocator(name):
            barrier.wait()
            with get_db_connection() as conn:
                allocated.append(
                    allocate_finding_for_cve(
                        conn, TENANT_A, cve, default_title=name, default_severity="high",
                        actor_id="analyst-a", actor_role="analyst",
                    )
                )
                conn.commit()

        t1, e1 = run_isolated(lambda: allocator("First"))
        t2, e2 = run_isolated(lambda: allocator("Second"))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert e1 == [] and e2 == []

        assert len(set(str(i) for i in allocated)) == 1
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM findings WHERE tenant_id = %s AND canonical_cve_id = %s;",
                    (str(TENANT_A), cve),
                )
                assert cur.fetchone()["c"] == 1

    def test_manual_scout_allocation_race_yields_one_finding_one_episode(self):
        """Fix 3: a manual CVE creation racing a SCOUT-equivalent
        (allocate+confirm) producer for the same concept converges on one
        finding and one current episode."""
        cve = "CVE-2026-0007"
        with get_db_connection() as conn:
            seed_canonical_cve(conn, cve)
            asset_id = create_test_asset(
                conn, TENANT_A, name="race-asset", target_value="10.81.0.9"
            )
            conn.commit()
        outcomes = {}
        barrier = threading.Barrier(2)

        def manual_producer():
            barrier.wait()
            with get_db_connection() as conn:
                fid = allocate_finding_for_cve(
                    conn, TENANT_A, cve, default_title="Manual", default_severity="high",
                    actor_id="analyst-a", actor_role="analyst",
                )
                conn.commit()
                outcomes["manual_fid"] = fid

        def scout_producer():
            barrier.wait()
            with get_db_connection() as conn:
                fid = allocate_finding_for_cve(
                    conn, TENANT_A, cve, default_title="SCOUT", default_severity="high",
                    actor_id="scout:race-job", actor_role="system",
                )
                result = confirm(
                    conn,
                    TENANT_A,
                    fid,
                    asset_id,
                    {"source": "scout", "scout_job_id": "race-job"},
                    actor="scout:race-job",
                    role="system",
                )
                conn.commit()
                outcomes["scout"] = result

        t1, e1 = run_isolated(manual_producer)
        t2, e2 = run_isolated(scout_producer)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert e1 == [] and e2 == []

        assert str(outcomes["manual_fid"]) == str(outcomes["scout"].exposure.finding_id)
        assert outcomes["scout"].outcome == "created"
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT count(*) AS c FROM findings WHERE tenant_id = %s AND canonical_cve_id = %s;",
                    (str(TENANT_A), cve),
                )
                assert cur.fetchone()["c"] == 1
            assert len(exposure_rows(TENANT_A, outcomes["manual_fid"], asset_id)) == 1

    def test_storage_backstop_collision_converges_without_aborting(self, monkeypatch):
        """Fix 6: a racing writer holds an UNCOMMITTED confirmed episode for the
        tuple (invisible to the command's current-episode check). The command's
        INSERT blocks on the unique index, the writer commits, and
        ON CONFLICT DO NOTHING keeps the transaction alive — the command
        converges on the committed episode as a replay instead of raising
        UniqueViolation inside an aborted transaction."""
        finding_id, asset_id = make_finding_and_asset()
        monkeypatch.setattr(
            "app.exposure.service._advisory_xact_lock", lambda cur, key: None
        )
        results = []
        writer_inserted = threading.Event()
        release_writer = threading.Event()

        def blocking_writer():
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO asset_exposures (
                            id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by
                        ) VALUES (
                            gen_random_uuid(), %s, %s, %s, 'confirmed', '{"who": "direct-writer"}'::jsonb,
                            'direct-writer'
                        )
                        RETURNING id;
                        """,
                        (str(TENANT_A), str(finding_id), str(asset_id)),
                    )
                    writer_id = cur.fetchone()["id"]
                writer_inserted.set()
                release_writer.wait(timeout=15)
                conn.commit()
                results.append(writer_id)

        def racer():
            writer_inserted.wait(timeout=15)
            with get_db_connection() as conn:
                # INSERT blocks on the writer's uncommitted unique-index entry;
                # on the writer's commit it conflicts and DO-NOTHINGs.
                results.append(
                    confirm(
                        conn,
                        TENANT_A,
                        finding_id,
                        asset_id,
                        {"who": "racer"},
                        actor="analyst-racer",
                    )
                )
                conn.commit()
            release_writer.set()

        t1, e1 = run_isolated(blocking_writer)
        t2, e2 = run_isolated(racer)
        t1.start()
        t2.start()
        t1.join(timeout=20)
        t2.join(timeout=20)
        monkeypatch.undo()
        assert not t1.is_alive() and not t2.is_alive()
        assert e1 == [] and e2 == [], "no InFailedSqlTransaction / UniqueViolation may escape"

        command_result = next(r for r in results if hasattr(r, "outcome"))
        writer_id = next(r for r in results if not hasattr(r, "outcome"))
        assert command_result.outcome == "replay"
        assert str(command_result.exposure.id) == str(writer_id)
        assert command_result.exposure.confirmed_by == "direct-writer"
        assert len(exposure_rows(TENANT_A, finding_id, asset_id)) == 1

    def test_allocator_and_confirm_race_decommission_without_deadlock(self):
        """Fix 1: allocation takes NO finding-row lock — a SCOUT-style
        (allocate + confirm) transaction racing asset decommission on a shared
        finding completes without deadlock; both serial orders leave a
        consistent state."""
        cve = "CVE-2026-0009"
        with get_db_connection() as conn:
            seed_canonical_cve(conn, cve)
            finding_id = allocate_finding_for_cve(
                conn, TENANT_A, cve,
                default_title="Race finding", default_severity="high",
                actor_id="analyst-a", actor_role="analyst",
            )
            asset_a = create_test_asset(conn, TENANT_A, name="decom-race", target_value="10.82.0.1")
            asset_b = create_test_asset(conn, TENANT_A, name="confirm-race", target_value="10.82.0.2")
            confirm(conn, TENANT_A, finding_id, asset_a, {"site": "a"})
            conn.commit()

        barrier = threading.Barrier(2)
        outcomes = {}

        def scout_style():
            barrier.wait()
            with get_db_connection() as conn:
                fid = allocate_finding_for_cve(
                    conn, TENANT_A, cve,
                    default_title="Race finding", default_severity="high",
                    actor_id="scout:race", actor_role="system",
                )
                outcomes["confirm"] = confirm(
                    conn, TENANT_A, fid, asset_b, {"site": "b"},
                    actor="scout:race", role="system",
                )
                conn.commit()

        def decommissioner():
            barrier.wait()
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE assets SET status = 'decommissioned', decommissioned_at = now()
                        WHERE id = %s AND tenant_id = %s;
                        """,
                        (str(asset_a), str(TENANT_A)),
                    )
                supersede_exposures_for_asset(
                    conn, TENANT_A, asset_a,
                    actor_id="admin-a", actor_role="admin",
                    reason="asset decommissioned",
                )
                conn.commit()
                outcomes["decommission"] = True

        t1, e1 = run_isolated(scout_style)
        t2, e2 = run_isolated(decommissioner)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert not t1.is_alive() and not t2.is_alive(), "deadlock detected"
        assert e1 == [] and e2 == []

        assert outcomes["confirm"].outcome == "created"
        with get_db_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status FROM assets WHERE id = %s;", (str(asset_a),))
                assert cur.fetchone()["status"] == "decommissioned"
                cur.execute(
                    "SELECT status FROM asset_exposures WHERE tenant_id = %s AND asset_id = %s ORDER BY confirmed_at;",
                    (str(TENANT_A), str(asset_a)),
                )
                assert cur.fetchone()["status"] == "superseded"
                cur.execute(
                    "SELECT status FROM asset_exposures WHERE tenant_id = %s AND asset_id = %s;",
                    (str(TENANT_A), str(asset_b)),
                )
                assert cur.fetchone()["status"] == "confirmed"
                cur.execute("SELECT status FROM findings WHERE id = %s;", (str(finding_id),))
                assert cur.fetchone()["status"] == "open"
            assert len(get_canonical_current_exposures(conn, TENANT_A, asset_id=asset_b)) == 1

    def test_close_races_confirm_both_orders_end_with_truthful_rollup(self):
        """Fix 3: close_finding locks and tenant-checks the finding row before
        the exposure check. Racing close vs confirm on one finding serializes;
        whichever order runs, the derived roll-up ends consistent with exposure
        truth (current confirmed episode => finding open)."""
        finding_id, asset_id = make_finding_and_asset()
        barrier = threading.Barrier(2)
        outcomes = {"close_error": None}

        def closer():
            barrier.wait()
            with get_db_connection() as conn:
                try:
                    close_finding(conn, TENANT_A, finding_id, closed_by="admin-a")
                    outcomes["closed"] = True
                except ExposureConflictError as exc:
                    outcomes["close_error"] = exc
                conn.commit()

        def confirme():
            barrier.wait()
            with get_db_connection() as conn:
                confirm(conn, TENANT_A, finding_id, asset_id, {"race": True}, actor="analyst-a")
                conn.commit()

        t1, e1 = run_isolated(closer)
        t2, e2 = run_isolated(confirme)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert not t1.is_alive() and not t2.is_alive()
        assert e1 == [] and e2 == []

        # Exactly one current episode exists in either serial order
        with get_db_connection() as conn:
            assert len(get_canonical_current_exposures(conn, TENANT_A, finding_id=finding_id)) == 1
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status FROM findings WHERE id = %s;", (str(finding_id),))
                # close-wins: confirm's derivation re-opens it;
                # confirm-wins: close was rejected. Either way: open.
                assert cur.fetchone()["status"] == "open"
