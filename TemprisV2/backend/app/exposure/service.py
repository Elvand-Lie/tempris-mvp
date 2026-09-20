# backend/app/exposure/service.py
"""
Service layer and repository functions for the Exposure Domain.

Exposure lifecycle authority (P0-01, PRD-000 v1.11 §3.3.1): the exposure
service is the ONLY writer of asset_exposures.status. Every producer (manual
analyst confirmation, SCOUT auto-normalization, future Intake) routes through
one shared confirmation command with a single concurrency-safe transaction
boundary. Exposure states are exactly confirmed / resolved / false_positive /
superseded; 'remediated' is legacy and never created.

Episode model: at most one CURRENT confirmed episode per
(tenant_id, finding_id, asset_id) — enforced in storage by the partial unique
index; historical episodes coexist. Confirmation of a tuple with an existing
current episode is an idempotent replay that returns the committed episode and
never overwrites its provenance. Recurrence after a terminal episode creates a
NEW episode on the SAME finding (finding status is a derived roll-up and never
an input to currentness or reuse).
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Optional
import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.exceptions import (
    AssetNotFoundError,
    ExposureConflictError,
    ExposureNotFoundError,
    FindingNotFoundError,
    InvalidAssetStatusError,
    InvalidEvidenceError,
    ReviewBindingError,
    TenantMismatchError,
)
from app.exposure.models import (
    ApplicabilityReview,
    AssetExposure,
    CanonicalExposureItem,
    ExposureConfirm,
    ExposureResolve,
    Finding,
    FindingCreate,
    ReviewCreate,
)

# Outcome markers for stable conflict/error semantics: retries can distinguish
# a committed mutation, an idempotent replay, and a rejected stale transition.
OUTCOME_CREATED = "created"
OUTCOME_REPLAY = "replay"
OUTCOME_TRANSITIONED = "transitioned"

_EXPOSURE_COLUMNS = (
    "id, tenant_id, finding_id, asset_id, status, evidence, "
    "confirmed_by, confirmed_at, resolved_at, resolved_by, resolution_reason"
)


@dataclass(frozen=True)
class ConfirmationResult:
    """Result of a lifecycle command: the episode plus a stable outcome marker."""

    exposure: AssetExposure
    outcome: str  # OUTCOME_CREATED | OUTCOME_REPLAY | OUTCOME_TRANSITIONED


def _serialize_evidence(evidence: Any) -> str:
    if not isinstance(evidence, dict) or len(evidence) == 0:
        raise InvalidEvidenceError("Evidence must be a non-empty dictionary/object")
    return json.dumps(evidence)


def _advisory_xact_lock(cur, key: str) -> None:
    """Serialize lifecycle commands on an advisory transaction lock."""
    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (key,))


def create_finding(conn: psycopg.Connection, tenant_id: uuid.UUID, data: FindingCreate) -> Finding:
    """Create a new tenant finding."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO findings (
                id, tenant_id, canonical_cve_id, title, description, severity, status, created_at, updated_at
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s, %s, 'open', now(), now()
            )
            RETURNING id, tenant_id, canonical_cve_id, title, description, severity, status, created_at, updated_at, closed_at;
            """,
            (
                str(tenant_id),
                data.canonical_cve_id,
                data.title,
                data.description,
                data.severity,
            ),
        )
        row = cur.fetchone()
        return Finding.model_validate(row)


def get_finding(conn: psycopg.Connection, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> Optional[Finding]:
    """Retrieve a finding by ID scoped to tenant."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, tenant_id, canonical_cve_id, title, description, severity, status, created_at, updated_at, closed_at
            FROM findings
            WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), str(finding_id)),
        )
        row = cur.fetchone()
        if not row:
            return None
        return Finding.model_validate(row)


def close_finding(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    closed_by: str,
    reason: Optional[str] = None,
) -> Finding:
    """
    Close a finding. Roll-up consistency rule (PRD §3.3.1/D-16): a finding
    with at least one current confirmed exposure must be open — its state
    derives from its exposures. Closing while a current exposure exists is
    rejected (ExposureConflictError); the finding cannot contradict exposure
    truth. Current-exposure queries never filter on finding status either way.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        # Lock and tenant-check the finding row FIRST — the exposure check and
        # the update then run against a stable row under the same lock order
        # (finding row) the confirmation command uses.
        cur.execute(
            "SELECT tenant_id FROM findings WHERE id = %s FOR UPDATE;",
            (str(finding_id),),
        )
        f_row = cur.fetchone()
        if not f_row:
            raise FindingNotFoundError(f"Finding {finding_id} not found")
        if str(f_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Finding {finding_id} belongs to tenant {f_row['tenant_id']}, not {tenant_id}"
            )

        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM asset_exposures e
                JOIN assets a
                  ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.status = 'active'
                WHERE e.tenant_id = %s
                  AND e.finding_id = %s
                  AND e.status = 'confirmed'
            ) AS has_current;
            """,
            (str(tenant_id), str(finding_id)),
        )
        if cur.fetchone()["has_current"]:
            raise ExposureConflictError(
                f"Finding {finding_id} has current confirmed exposures; the derived "
                "roll-up must stay open. Resolve or supersede the exposures first."
            )

        cur.execute(
            """
            UPDATE findings
            SET status = 'closed',
                closed_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING id, tenant_id, canonical_cve_id, title, description, severity, status, created_at, updated_at, closed_at;
            """,
            (str(tenant_id), str(finding_id)),
        )
        # The row was locked, tenant-checked, and exists — the return is guaranteed
        return Finding.model_validate(cur.fetchone())


def allocate_finding_for_cve(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    cve_id: str,
    *,
    default_title: str,
    default_severity: str,
    default_description: Optional[str] = None,
    actor_id: str,
    actor_role: str,
) -> uuid.UUID:
    """
    Serialized finding allocation for a canonical CVE (PRD §3.3.1 finding
    reuse): the same vulnerability concept is ALWAYS the same finding — any
    existing finding for (tenant, canonical_cve_id) is reused regardless of its
    status (reuse extends across resolved/closed episodes); a new finding is
    created only when none exists.

    Concurrency: the per-(tenant, CVE) advisory lock plus the partial unique
    index serialize allocation. The lookup deliberately takes NO row lock — a
    finding-row lock here would invert the asset→exposure→finding lock order
    used by confirmation and decommission and could deadlock.

    The finding.created audit is emitted here, on actual insert only, with the
    caller's server actor (manual analyst or SCOUT service actor); reuse emits
    nothing.
    """
    with conn.cursor() as cur:
        _advisory_xact_lock(cur, f"exposure-finding:{tenant_id}:{cve_id}")
        cur.execute(
            """
            SELECT id FROM findings
            WHERE tenant_id = %s AND canonical_cve_id = %s
            ORDER BY created_at, id
            LIMIT 1;
            """,
            (str(tenant_id), cve_id),
        )
        row = cur.fetchone()
        if row:
            return row["id"]

        finding = create_finding(
            conn,
            tenant_id,
            FindingCreate(
                canonical_cve_id=cve_id,
                title=default_title,
                description=default_description,
                severity=default_severity,
            ),
        )
        record_audit_event(
            conn=conn,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            event_name="finding.created",
            asset_id=None,
            details={
                "finding_id": str(finding.id),
                "title": finding.title,
                "canonical_cve_id": finding.canonical_cve_id,
                "severity": finding.severity,
            },
        )
        return finding.id


def record_applicability_review(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    data: ReviewCreate,
    *,
    actor_id: str,
) -> ApplicabilityReview:
    """Record an append-only applicability review decision (actor is server-owned)."""
    with conn.cursor(row_factory=dict_row) as cur:
        # Verify finding exists and belongs to tenant
        cur.execute("SELECT tenant_id FROM findings WHERE id = %s;", (str(data.finding_id),))
        f_row = cur.fetchone()
        if not f_row:
            raise FindingNotFoundError(f"Finding {data.finding_id} not found")
        if str(f_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Finding {data.finding_id} belongs to tenant {f_row['tenant_id']}, not {tenant_id}"
            )

        # Verify asset exists and belongs to tenant
        cur.execute("SELECT tenant_id FROM assets WHERE id = %s;", (str(data.asset_id),))
        a_row = cur.fetchone()
        if not a_row:
            raise AssetNotFoundError(f"Asset {data.asset_id} not found")
        if str(a_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Asset {data.asset_id} belongs to tenant {a_row['tenant_id']}, not {tenant_id}"
            )

        cur.execute(
            """
            INSERT INTO asset_applicability_reviews (
                id, tenant_id, finding_id, asset_id, applicability, reviewed_by, reason, created_at
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s, %s, %s, clock_timestamp()
            )
            RETURNING id, tenant_id, finding_id, asset_id, applicability, reviewed_by, reason, created_at;
            """,
            (
                str(tenant_id),
                str(data.finding_id),
                str(data.asset_id),
                data.applicability,
                actor_id,
                data.reason,
            ),
        )
        row = cur.fetchone()
        return ApplicabilityReview.model_validate(row)


def list_applicability_reviews(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: Optional[uuid.UUID] = None,
    asset_id: Optional[uuid.UUID] = None,
) -> list[ApplicabilityReview]:
    """List applicability review records for a tenant with optional finding/asset filters."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, tenant_id, finding_id, asset_id, applicability, reviewed_by, reason, created_at
            FROM asset_applicability_reviews
            WHERE tenant_id = %s
              AND (%s::uuid IS NULL OR finding_id = %s::uuid)
              AND (%s::uuid IS NULL OR asset_id = %s::uuid)
            ORDER BY created_at DESC, id ASC;
            """,
            (
                str(tenant_id),
                str(finding_id) if finding_id else None,
                str(finding_id) if finding_id else None,
                str(asset_id) if asset_id else None,
                str(asset_id) if asset_id else None,
            ),
        )
        rows = cur.fetchall()
        return [ApplicabilityReview.model_validate(r) for r in rows]


def _derive_finding_rollup_status(cur, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> None:
    """
    Derive the finding's roll-up status from its exposures. The roll-up is
    display truth only — it is never an input to currentness, reuse, or any
    lifecycle decision. 'open' iff at least one current confirmed exposure on
    an active asset exists.

    The finding row is locked BEFORE the exposure truth is read: concurrent
    derivations (confirmation vs decommission) then serialize on the row, and
    whoever derives last reads every exposure change committed before its turn
    — a stale last-writer-wins roll-up cannot survive.
    """
    cur.execute(
        "SELECT id FROM findings WHERE tenant_id = %s AND id = %s FOR UPDATE;",
        (str(tenant_id), str(finding_id)),
    )
    if cur.fetchone() is None:
        return
    cur.execute(
        """
        UPDATE findings f
        SET status = CASE WHEN EXISTS (
                SELECT 1
                FROM asset_exposures e
                JOIN assets a
                  ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.status = 'active'
                WHERE e.tenant_id = f.tenant_id
                  AND e.finding_id = f.id
                  AND e.status = 'confirmed'
            ) THEN 'open' ELSE 'closed' END,
            closed_at = CASE WHEN EXISTS (
                SELECT 1
                FROM asset_exposures e
                JOIN assets a
                  ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.status = 'active'
                WHERE e.tenant_id = f.tenant_id
                  AND e.finding_id = f.id
                  AND e.status = 'confirmed'
            ) THEN NULL ELSE COALESCE(f.closed_at, now()) END,
            updated_at = now()
        WHERE f.tenant_id = %s AND f.id = %s;
        """,
        (str(tenant_id), str(finding_id)),
    )


def confirm_exposure(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    data: ExposureConfirm,
    *,
    actor_id: str,
    actor_role: str,
    review: Optional[ReviewCreate] = None,
) -> ConfirmationResult:
    """
    The one shared confirmation command (manual / SCOUT / future Intake).

    Single concurrency-safe boundary per producer:
      * advisory transaction lock on (tenant, finding, asset) serializes the
        tuple across every producer;
      * the finding row is locked FOR UPDATE (serialized allocation/roll-up);
      * the asset row is locked FOR SHARE and its active status is rechecked
        inside the boundary (decommission cannot interleave);
      * disposition, review reference, and audit commit atomically with the
        exposure row.

    Idempotent: if a current confirmed episode already exists for the tuple it
    is returned UNCHANGED (outcome 'replay') — provenance and evidence are
    never overwritten. Otherwise a new episode is inserted (outcome 'created').

    Finding status is never an input: recurrence reuses findings across
    terminal episodes.
    """
    raw_evidence = _serialize_evidence(data.evidence)

    # A bound review is validated BEFORE any branch is taken (replay or
    # insert): it must reference the exact confirmed tuple and carry the
    # confirmation's APPLICABLE disposition.
    if review is not None:
        if review.finding_id != data.finding_id or review.asset_id != data.asset_id:
            raise ReviewBindingError(
                "Review bound to a confirmation must reference the exact "
                f"confirmed tuple: expected (finding={data.finding_id}, "
                f"asset={data.asset_id}), got (finding={review.finding_id}, "
                f"asset={review.asset_id})"
            )
        if review.applicability != "APPLICABLE":
            raise ReviewBindingError(
                "A confirmation-bound review must carry applicability "
                f"'APPLICABLE'; got '{review.applicability}'."
            )

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(
            cur, f"exposure:{tenant_id}:{data.finding_id}:{data.asset_id}"
        )

        # Lock order is asset -> finding everywhere (matching asset decommission's
        # asset -> exposure -> finding order) so concurrent lifecycle commands
        # cannot deadlock against the decommission transaction.
        #
        # Check + lock the asset; active state is rechecked inside the boundary
        cur.execute(
            "SELECT tenant_id, status FROM assets WHERE id = %s FOR SHARE;",
            (str(data.asset_id),),
        )
        a_row = cur.fetchone()
        if not a_row:
            raise AssetNotFoundError(f"Asset {data.asset_id} not found")
        if str(a_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Asset {data.asset_id} belongs to tenant {a_row['tenant_id']}, not {tenant_id}"
            )
        if a_row["status"] != "active":
            raise InvalidAssetStatusError(
                f"Asset {data.asset_id} is not active (status={a_row['status']})"
            )

        # Check + lock the finding (any status — finding status is not an input)
        cur.execute(
            "SELECT tenant_id FROM findings WHERE id = %s FOR UPDATE;",
            (str(data.finding_id),),
        )
        f_row = cur.fetchone()
        if not f_row:
            raise FindingNotFoundError(f"Finding {data.finding_id} not found")
        if str(f_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Finding {data.finding_id} belongs to tenant {f_row['tenant_id']}, not {tenant_id}"
            )

        # Idempotent replay: an existing current episode is returned unchanged
        cur.execute(
            f"""
            SELECT {_EXPOSURE_COLUMNS}
            FROM asset_exposures
            WHERE tenant_id = %s AND finding_id = %s AND asset_id = %s
              AND status = 'confirmed'
            ORDER BY confirmed_at DESC, id;
            """,
            (str(tenant_id), str(data.finding_id), str(data.asset_id)),
        )
        current_rows = cur.fetchall()
        if len(current_rows) > 1:
            raise RuntimeError("Ambiguous current exposure state")
        if current_rows:
            return ConfirmationResult(
                AssetExposure.model_validate(current_rows[0]), OUTCOME_REPLAY
            )

        # P0-07 precondition (§3.6.6 #7): an IDENTITY_POSTURE finding anchors
        # to the designated identity boundary — an ACTIVE current binding for
        # THIS asset is required, validated inside the common P0-01 boundary
        # (the asset is already locked FOR SHARE, so a concurrent boundary
        # clear serializes against this check). Lazy import: the boundary
        # module calls back into this service for supersession.
        if taxonomy_class_of_finding(cur, tenant_id, data.finding_id) == "IDENTITY_POSTURE":
            from app.exposure.identity_boundary import (
                assert_boundary_exists_for_confirmation,
            )
            assert_boundary_exists_for_confirmation(conn, tenant_id, data.asset_id)

        # Storage-backstop-safe insert: ON CONFLICT DO NOTHING cannot abort the
        # transaction; a NULL return means a racing writer committed the tuple's
        # current episode first and we converge on it (idempotent replay).
        cur.execute(
            """
            INSERT INTO asset_exposures (
                id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by, confirmed_at
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, 'confirmed', %s::jsonb, %s, now()
            )
            ON CONFLICT (tenant_id, finding_id, asset_id) WHERE status = 'confirmed'
            DO NOTHING
            RETURNING id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by, confirmed_at, resolved_at, resolved_by, resolution_reason;
            """,
            (
                str(tenant_id),
                str(data.finding_id),
                str(data.asset_id),
                raw_evidence,
                actor_id,
            ),
        )
        row = cur.fetchone()
        if row is None:
            cur.execute(
                f"""
                SELECT {_EXPOSURE_COLUMNS}
                FROM asset_exposures
                WHERE tenant_id = %s AND finding_id = %s AND asset_id = %s
                  AND status = 'confirmed'
                ORDER BY confirmed_at DESC, id;
                """,
                (str(tenant_id), str(data.finding_id), str(data.asset_id)),
            )
            raced = cur.fetchall()
            if len(raced) != 1:
                raise RuntimeError("Ambiguous current exposure state")
            return ConfirmationResult(
                AssetExposure.model_validate(raced[0]), OUTCOME_REPLAY
            )
        exposure = AssetExposure.model_validate(row)

        # Review reference (manual analyst disposition / Intake equivalent)
        # commits atomically with the exposure; tuple/applicability were
        # validated before any branch was taken.
        if review is not None:
            cur.execute(
                """
                INSERT INTO asset_applicability_reviews (
                    id, tenant_id, finding_id, asset_id, applicability, reviewed_by, reason, created_at
                ) VALUES (
                    gen_random_uuid(), %s, %s, %s, %s, %s, %s, clock_timestamp()
                )
                RETURNING id, tenant_id, finding_id, asset_id, applicability, reviewed_by, reason, created_at;
                """,
                (
                    str(tenant_id),
                    str(review.finding_id),
                    str(review.asset_id),
                    review.applicability,
                    actor_id,
                    review.reason,
                ),
            )

        # Audit commits atomically with the confirmation
        record_audit_event(
            conn=conn,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            event_name="exposure.confirmed",
            asset_id=exposure.asset_id,
            details={
                "finding_id": str(exposure.finding_id),
                "exposure_id": str(exposure.id),
                "outcome": OUTCOME_CREATED,
            },
        )

        _derive_finding_rollup_status(cur, tenant_id, data.finding_id)
        return ConfirmationResult(exposure, OUTCOME_CREATED)


def resolve_exposure(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    data: ExposureResolve,
    *,
    actor_id: str,
    actor_role: str,
) -> ConfirmationResult:
    """
    Terminal transition (resolved / false_positive) via compare-and-set.

    Idempotent: requesting the transition an episode already holds returns the
    committed row UNCHANGED (outcome 'replay'). A different transition on a
    terminal episode is stale/conflicting and rejected with
    ExposureConflictError (stable code 'exposure_conflict') — episodes are
    never reopened; recurrence confirms a NEW episode.
    """
    if data.status not in ("resolved", "false_positive"):
        raise ValueError(
            f"Invalid resolution status: {data.status}. Must be resolved or false_positive"
        )

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            SELECT {_EXPOSURE_COLUMNS}
            FROM asset_exposures
            WHERE id = %s
            FOR UPDATE;
            """,
            (str(exposure_id),),
        )
        row = cur.fetchone()
        if not row:
            raise ExposureNotFoundError(f"Exposure {exposure_id} not found")
        if str(row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Exposure {exposure_id} belongs to tenant {row['tenant_id']}, not {tenant_id}"
            )

        prior_status = row["status"]
        if prior_status == data.status:
            # Idempotent same-transition replay: return committed state unchanged
            return ConfirmationResult(AssetExposure.model_validate(row), OUTCOME_REPLAY)
        if prior_status != "confirmed":
            raise ExposureConflictError(
                f"Exposure {exposure_id} is already terminal (status={prior_status}); "
                f"transition to '{data.status}' rejected. Episodes are never reopened — "
                "recurrence confirms a new episode."
            )

        cur.execute(
            """
            UPDATE asset_exposures
            SET status = %s,
                resolved_at = now(),
                resolved_by = %s,
                resolution_reason = %s
            WHERE tenant_id = %s AND id = %s AND status = 'confirmed'
            RETURNING id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by, confirmed_at, resolved_at, resolved_by, resolution_reason;
            """,
            (
                data.status,
                actor_id,
                data.resolution_reason,
                str(tenant_id),
                str(exposure_id),
            ),
        )
        updated = cur.fetchone()
        if not updated:
            # Concurrent writer changed the episode between lock and CAS
            raise ExposureConflictError(
                f"Exposure {exposure_id} was concurrently transitioned; retry."
            )
        exposure = AssetExposure.model_validate(updated)

        record_audit_event(
            conn=conn,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_role=actor_role,
            # The audit event names the actual terminal state
            event_name=(
                "exposure.false_positive"
                if exposure.status == "false_positive"
                else "exposure.resolved"
            ),
            asset_id=exposure.asset_id,
            details={
                "finding_id": str(exposure.finding_id),
                "exposure_id": str(exposure.id),
                "prior_state": prior_status,
                "new_state": exposure.status,
                "reason": exposure.resolution_reason,
                "outcome": OUTCOME_TRANSITIONED,
            },
        )

        _derive_finding_rollup_status(cur, tenant_id, exposure.finding_id)
        return ConfirmationResult(exposure, OUTCOME_TRANSITIONED)


def taxonomy_class_of_finding(
    cur, tenant_id: uuid.UUID, finding_id: uuid.UUID
) -> Optional[str]:
    """The finding's non-CVE taxonomy class (P0-06 classification spine), or
    None for a plain (CVE) finding. Read-only helper; no locks."""
    cur.execute(
        """
        SELECT c.taxonomy_class
        FROM findings f
        JOIN non_cve_classifications c
          ON c.tenant_id = f.tenant_id AND c.finding_id = f.id
        WHERE f.tenant_id = %s AND f.id = %s AND f.canonical_cve_id IS NULL
        ORDER BY c.created_at DESC
        LIMIT 1;
        """,
        (str(tenant_id), str(finding_id)),
    )
    row = cur.fetchone()
    return row["taxonomy_class"] if row is not None else None


def supersede_exposures_for_asset(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
    reason: str,
    taxonomy_class: Optional[str] = None,
) -> list[AssetExposure]:
    """
    Supersede every current confirmed exposure on an asset. Called inside the
    asset lifecycle transaction (decommission, and the P0-07 boundary
    replace-or-clear) so the asset transition, the supersession rows, and the
    audit events commit atomically. Historical rows are never deleted; asset
    reactivation never revives a superseded episode.

    ``taxonomy_class`` narrows the supersession to exposures of one
    non-CVE taxonomy class (P0-07 design A: replacing/clearing the identity
    boundary supersedes ONLY IDENTITY_POSTURE exposures on the boundary
    asset — web/CVE exposures on the same domain keep ``assets.criticality``
    and stay current). The exposure's finding carries the taxonomy via the
    non-CVE classification spine; plain (CVE) findings never match a
    taxonomy class. Default None keeps the unfiltered decommission behavior
    (§3.3.1: decommissioning supersedes everything on the asset).

    DECISION RECORD (P0-08, resolving the carried P0-07 review note):
    this filter matches ANY HISTORICAL classification of the finding, while
    the P0-07 confirmation precondition reads the LATEST classification.
    The any-history reading is RATIFIED as the governing rule, for two
    reasons: (1) it is the conservative direction — an exposure confirmed
    while a finding was IDENTITY_POSTURE is superseded when the boundary
    moves, even if the finding was later re-classified; supersession is
    reversible-in-effect (re-confirmation recreates the episode) while a
    missed supersession would leave a current exposure anchored to a
    boundary that no longer exists; (2) classifications are immutable
    history (migration 019) — "latest" is a rendering choice, and a
    re-classification does not un-write the fact that the episode was
    anchored under the boundary contract. Consumers wanting the strict
    latest-class view must filter at the read layer, not here.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        if taxonomy_class is None:
            cur.execute(
                """
                UPDATE asset_exposures
                SET status = 'superseded',
                    resolved_at = now(),
                    resolved_by = %s,
                    resolution_reason = %s
                WHERE tenant_id = %s AND asset_id = %s AND status = 'confirmed'
                RETURNING """ + _EXPOSURE_COLUMNS + ";",
                (actor_id, reason, str(tenant_id), str(asset_id)),
            )
        else:
            cur.execute(
                """
                UPDATE asset_exposures e
                SET status = 'superseded',
                    resolved_at = now(),
                    resolved_by = %s,
                    resolution_reason = %s
                WHERE e.tenant_id = %s AND e.asset_id = %s AND e.status = 'confirmed'
                  AND EXISTS (
                      SELECT 1 FROM findings f
                      WHERE f.tenant_id = e.tenant_id AND f.id = e.finding_id
                        AND f.canonical_cve_id IS NULL
                        AND EXISTS (
                            SELECT 1 FROM non_cve_classifications c
                            WHERE c.tenant_id = f.tenant_id
                              AND c.finding_id = f.id
                              AND c.taxonomy_class = %s
                        )
                  )
                RETURNING """ + _EXPOSURE_COLUMNS + ";",
                (actor_id, reason, str(tenant_id), str(asset_id), taxonomy_class),
            )
        superseded = [AssetExposure.model_validate(r) for r in cur.fetchall()]

        affected_findings: set[uuid.UUID] = set()
        for exposure in superseded:
            record_audit_event(
                conn=conn,
                tenant_id=tenant_id,
                actor_id=actor_id,
                actor_role=actor_role,
                event_name="exposure.superseded",
                asset_id=exposure.asset_id,
                details={
                    "finding_id": str(exposure.finding_id),
                    "exposure_id": str(exposure.id),
                    "prior_state": "confirmed",
                    "new_state": "superseded",
                    "reason": reason,
                    "taxonomy_class": taxonomy_class,
                },
            )
            affected_findings.add(exposure.finding_id)

        for finding_id in affected_findings:
            _derive_finding_rollup_status(cur, tenant_id, finding_id)

        return superseded


def get_canonical_current_exposures(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: Optional[uuid.UUID] = None,
    asset_id: Optional[uuid.UUID] = None,
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
) -> list[CanonicalExposureItem]:
    """
    Execute the single canonical current-exposure query.

    Current means: exposure status 'confirmed' (which by definition excludes
    superseded/terminal episodes) on an active asset. Finding status is NEVER
    an input — the finding is the grouping/roll-up object (PRD §3.3.1).
    Deterministic ordering: confirmed_at DESC, id ASC.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT
                e.id AS exposure_id,
                e.tenant_id,
                e.finding_id,
                e.asset_id,
                e.status AS exposure_status,
                e.evidence,
                e.confirmed_by,
                e.confirmed_at,
                f.canonical_cve_id,
                f.title AS finding_title,
                f.severity AS finding_severity,
                f.status AS finding_status,
                a.name AS asset_name,
                a.target_type AS asset_target_type,
                a.normalized_target AS asset_normalized_target,
                a.network_scope AS asset_network_scope,
                a.status AS asset_status
            FROM asset_exposures e
            JOIN findings f
              ON e.tenant_id = f.tenant_id AND e.finding_id = f.id
            JOIN assets a
              ON e.tenant_id = a.tenant_id AND e.asset_id = a.id
            WHERE e.tenant_id = %s
              AND e.status = 'confirmed'
              AND a.status = 'active'
              AND (%s::uuid IS NULL OR e.finding_id = %s::uuid)
              AND (%s::uuid IS NULL OR e.asset_id = %s::uuid)
              AND (%s::text IS NULL OR f.canonical_cve_id = %s::text)
              AND (%s::text IS NULL OR f.severity = %s::text)
            ORDER BY e.confirmed_at DESC, e.id ASC;
            """,
            (
                str(tenant_id),
                str(finding_id) if finding_id else None,
                str(finding_id) if finding_id else None,
                str(asset_id) if asset_id else None,
                str(asset_id) if asset_id else None,
                cve_id,
                cve_id,
                severity,
                severity,
            ),
        )
        rows = cur.fetchall()
        return [CanonicalExposureItem.model_validate(r) for r in rows]
