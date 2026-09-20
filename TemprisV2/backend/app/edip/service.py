# backend/app/edip/service.py
"""
Service layer for EDIP — Remediation & Risk Decisions (PRD-000 v1.11 Ch.8).

Transaction ownership: no command here commits or rolls back — the caller
(route) owns the boundary, matching the exposure/spectrum/approvals pattern.
Routes that seal a snapshot establish ONE REPEATABLE READ boundary as the
FIRST statement of the transaction, so every sealed payload is one coherent
``as_of`` source view (PATCH-13).

The lifecycle (rule 2) — CAS-guarded edges, materialized effective state:

    needs_decision ─▶ planned ─▶ in_progress ─▶ mitigated ─▶ verification ─▶ closed
        ▲  │  ▲                                                        (terminal)
        │  │  └──────── reopen (dispute) ◀─────────┐
        │  └─▶ accepted_risk ──(review expiry)─────┘        (ACTIVE dispositions;
        └────▶ deferred ───────(review expiry)─────┘   mandatory review_due_at;
                                                       exposure stays confirmed)
    any non-terminal ─▶ superseded  (system: confirmation_withdrawn /
                                    exposure_superseded — PATCH-10)

Score-consuming branch actions (accept-risk apply, defer) insert a NEW
revision row sealing a FRESH snapshot and replace the prior revision —
history is a sequence of decision records (rule 3, PATCH-13, Q7).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.edip.errors import (
    EdipConflictError,
    EdipDecisionNotFoundError,
    EdipExposureNotFoundError,
    EdipWorkflowError,
)
from app.exposure.models import ExposureResolve
from app.exposure.service import (
    OUTCOME_TRANSITIONED,
    _advisory_xact_lock,
    resolve_exposure,
)
from app.exposure.tes_read_model import _jsonify, get_exposure_tes

# The unified decision vocabulary (rule 5). Band labels (ESCALATE/PATCH/…)
# are display-only consumer policy and deliberately absent.
DECISION_TYPES = ("remediate", "mitigate", "accept-risk", "defer")

DECISION_STATES = (
    "needs_decision", "planned", "in_progress", "mitigated", "verification",
    "accepted_risk", "deferred", "closed", "superseded",
)
TERMINAL_STATES = ("closed", "superseded")
ACTIVE_BRANCH_STATES = ("accepted_risk", "deferred")

# CAS-guarded lifecycle edges (rule 2). 'mitigated' is reachable from
# in_progress (plan executed) and from verification (a failed verification
# sends the decision back to mitigation).
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "planned": ("needs_decision",),
    "in_progress": ("planned",),
    "mitigated": ("in_progress", "verification"),
    "verification": ("mitigated",),
}

# Decision-level reopen (rule 9): the exposure is still confirmed; the same
# decision reopens with a recorded reason. Closed decisions NEVER reopen —
# recurrence is a NEW episode + NEW decision (D-16).
REOPEN_FROM = ("planned", "in_progress", "mitigated", "verification",
               "accepted_risk", "deferred")

# States a branch disposition may be taken from (accept/defer).
BRANCH_FROM = ("needs_decision", "planned", "in_progress", "mitigated")
# Alias used by the accepted-risk consumer wiring (same edge set).
ACCEPT_FROM = BRANCH_FROM

VERIFICATION_EVIDENCE_KINDS = ("analyst_attestation", "scout_job", "strike_artifact")
VERIFICATION_VERDICTS = ("pass", "fail")

SUPERSESSION_REASONS = {
    "false_positive": "confirmation_withdrawn",  # PATCH-10 vocabulary
    "superseded": "exposure_superseded",
}

_DECISION_COLUMNS = (
    "id, tenant_id, exposure_id, decision_group_id, revision, supersedes_id, "
    "previous_decision_id, handoff_id, decision_type, state, superseded_reason, "
    "owner, rationale, plan, due_at, review_due_at, mitigation_type, "
    "consumed_snapshot, snapshot_as_of, created_by, created_role, created_at, "
    "updated_at, closed_at, replaced_at, replaced_by_id"
)


def _canonical_due_at(value: datetime) -> str:
    """Deterministic textual form of a review/expiry instant (UTC ISO-8601).
    Both the accept-risk propose hash and the apply-time re-derivation render
    through this function, so the canonical payload is instant-stable."""
    return value.astimezone(timezone.utc).isoformat()


def _advisory_lock_by_decision(cur, tenant_id: uuid.UUID, decision_id: uuid.UUID) -> dict:
    """Serialize all decision commands per EXPOSURE (the lifecycle's unit)."""
    cur.execute(
        "SELECT exposure_id FROM edip_decisions "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), str(decision_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise EdipDecisionNotFoundError(f"Decision {decision_id} not found")
    _advisory_xact_lock(cur, f"edip:{tenant_id}:{row['exposure_id']}")
    return row


def _load_current_decision(
    cur, tenant_id: uuid.UUID, decision_id: uuid.UUID, *, for_update: bool = False
) -> dict:
    """Load a decision by ANY revision id, following the replacement chain to
    the CURRENT revision (a replaced id stays a valid address for the same
    decision). Every hop locks, so commands act on the live revision under
    the advisory lock."""
    row_id = decision_id
    for _hop in range(1000):  # chain depth is bounded by revision count
        cur.execute(
            f"SELECT {_DECISION_COLUMNS} FROM edip_decisions "
            "WHERE tenant_id = %s AND id = %s" + (" FOR UPDATE;" if for_update else ";"),
            (str(tenant_id), str(row_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise EdipDecisionNotFoundError(f"Decision {decision_id} not found")
        if row["replaced_at"] is None or not row["replaced_by_id"]:
            return row
        row_id = row["replaced_by_id"]
    raise EdipConflictError("Decision replacement chain is cyclic")


def _load_exposure(cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> dict:
    """Any tenant-scoped exposure row (any status) with its native row-version
    token — the PATCH-09 observation version used by verification binding."""
    cur.execute(
        """
        SELECT e.id, e.finding_id, e.asset_id, e.status,
               e.xmin::text AS exposure_version
        FROM asset_exposures e
        WHERE e.tenant_id = %s AND e.id = %s;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise EdipExposureNotFoundError(f"Exposure {exposure_id} not found")
    return row


def _load_current_exposure(cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> dict:
    """The 404 gate for decision creation/actions: unknown, cross-tenant,
    non-current, and inactive-asset exposures are the SAME not-found."""
    exposure = _load_exposure(cur, tenant_id, exposure_id)
    if exposure["status"] != "confirmed":
        raise EdipExposureNotFoundError(f"Exposure {exposure_id} not found")
    cur.execute(
        "SELECT 1 FROM assets WHERE tenant_id = %s AND id = %s AND status = 'active';",
        (str(tenant_id), str(exposure["asset_id"])),
    )
    if cur.fetchone() is None:
        raise EdipExposureNotFoundError(f"Exposure {exposure_id} not found")
    return exposure


# ---------------------------------------------------------------------------
# Effective-state materialization (rule 2 / rule 10 — no scheduler required)
# ---------------------------------------------------------------------------


def _materialize_effective_state(
    conn: psycopg.Connection,
    cur,
    tenant_id: uuid.UUID,
    row: dict,
    *,
    actor_id: str,
) -> dict:
    """Once ``now >= review_due_at`` an accepted/deferred decision IS a
    Needs-Decision decision on every read and action — the first observation
    materializes and audits the persisted transition. Confirmation withdrawal
    and exposure supersession auto-supersede the open decision (PATCH-10),
    effective immediately on reads with the same-transaction durable write
    (v2 is one service — there is no availability boundary to defer across).

    Every update is CAS-guarded, so concurrent observers converge without
    double-auditing; a row changed by someone else is simply re-read."""
    now = datetime.now(timezone.utc)

    # (a) review expiry — effective-state rule (rule 2)
    if (
        row["state"] in ACTIVE_BRANCH_STATES
        and row["review_due_at"] is not None
        and row["review_due_at"] <= now
    ):
        expired_review_at = row["review_due_at"]
        cur.execute(
            f"""
            UPDATE edip_decisions
            SET state = 'needs_decision', review_due_at = NULL, updated_at = now()
            WHERE tenant_id = %s AND id = %s
              AND state IN ('accepted_risk', 'deferred')
              AND review_due_at IS NOT NULL AND review_due_at <= %s
            RETURNING {_DECISION_COLUMNS};
            """,
            (str(tenant_id), str(row["id"]), now),
        )
        updated = cur.fetchone()
        if updated is not None:
            row = updated
            record_audit_event(
                conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                actor_role="system:effective_state",
                event_name="edip.review_expired", asset_id=None,
                details={
                    "decision_id": str(row["id"]),
                    "exposure_id": str(row["exposure_id"]),
                    "prior_state": "review_expired",
                    "new_state": "needs_decision",
                    "review_due_at": expired_review_at.isoformat(),
                },
            )

    # (b) exposure-level supersession of open decisions (rule 10, PATCH-10)
    if row["state"] not in TERMINAL_STATES:
        exposure = _load_exposure(cur, tenant_id, row["exposure_id"])
        reason = SUPERSESSION_REASONS.get(exposure["status"])
        if reason is not None:
            cur.execute(
                f"""
                UPDATE edip_decisions
                SET state = 'superseded', superseded_reason = %s, updated_at = now()
                WHERE tenant_id = %s AND id = %s
                  AND state NOT IN ('closed', 'superseded')
                RETURNING {_DECISION_COLUMNS};
                """,
                (reason, str(tenant_id), str(row["id"])),
            )
            updated = cur.fetchone()
            if updated is not None:
                row = updated
                record_audit_event(
                    conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                    actor_role="system:effective_state",
                    event_name="edip.decision_superseded", asset_id=None,
                    details={
                        "decision_id": str(row["id"]),
                        "exposure_id": str(row["exposure_id"]),
                        "reason": reason,
                        "exposure_status": exposure["status"],
                    },
                )
    return row


# ---------------------------------------------------------------------------
# Snapshot sealing (§3.3.6 history-only writer; PATCH-13)
# ---------------------------------------------------------------------------


def seal_score_snapshot(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    as_of: datetime,
) -> dict:
    """Capture the atomic §3.3.5 payload at ``as_of`` — value, state,
    formula_version, decomposition, provenance, freshness, source_view — as
    ONE coherent source view. The caller's transaction must have established
    the REPEATABLE READ boundary BEFORE its first query. Never re-derived in
    place: later recomputes never rewrite a sealed snapshot."""
    tes = get_exposure_tes(conn, tenant_id, exposure_id, as_of=as_of)
    return json.loads(json.dumps(_jsonify(tes)))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def create_decision(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    exposure_id: uuid.UUID,
    decision_type: str,
    owner: str,
    rationale: Optional[str],
    plan: Optional[str],
    due_at: Optional[datetime],
    handoff_id: Optional[uuid.UUID],
    previous_decision_id: Optional[uuid.UUID],
    actor_id: str,
    actor_role: str,
) -> dict:
    """Create the root decision revision in Needs-Decision state, sealing the
    score snapshot it consumes (rule 3). A handoff, when named, is correlated
    and consumed in the same transaction (PATCH-09)."""
    if decision_type not in DECISION_TYPES:
        raise EdipWorkflowError(
            f"unknown decision_type {decision_type!r} — the unified vocabulary "
            f"is {list(DECISION_TYPES)}"
        )

    with conn.cursor(row_factory=dict_row) as cur:
        _load_current_exposure(cur, tenant_id, exposure_id)
        _advisory_xact_lock(cur, f"edip:{tenant_id}:{exposure_id}")

        # ONE current decision per exposure (Q7): any standing row — including
        # a terminal one — blocks a second (reopen/transition the existing one;
        # a NEW decision belongs to a NEW episode, D-16).
        cur.execute(
            "SELECT id FROM edip_decisions "
            "WHERE tenant_id = %s AND exposure_id = %s AND replaced_at IS NULL;",
            (str(tenant_id), str(exposure_id)),
        )
        standing = cur.fetchone()
        if standing is not None:
            raise EdipConflictError(
                f"Exposure {exposure_id} already has a decision "
                f"({standing['id']}) — transition or reopen it; a new decision "
                "requires a new exposure episode"
            )

        # Handoff correlation (PATCH-09): the decision binds the exact open
        # handoff and consumes it atomically; retries correlate, never fork.
        if handoff_id is not None:
            cur.execute(
                """
                SELECT id, tenant_id, exposure_id, state FROM spectrum_edip_handoffs
                WHERE tenant_id = %s AND id = %s FOR UPDATE;
                """,
                (str(tenant_id), str(handoff_id)),
            )
            handoff = cur.fetchone()
            if handoff is None:
                raise EdipDecisionNotFoundError(f"Handoff {handoff_id} not found")
            if str(handoff["exposure_id"]) != str(exposure_id):
                raise EdipWorkflowError(
                    f"Handoff {handoff_id} belongs to exposure "
                    f"{handoff['exposure_id']}, not {exposure_id}"
                )
            if handoff["state"] != "NEEDS_DECISION":
                raise EdipConflictError(
                    f"Handoff {handoff_id} is not open (state={handoff['state']})"
                )

        # Recurrence linkage (rule 9/D-16): the previous decision must belong
        # to this tenant, sit on a RESOLVED episode of the SAME (finding,
        # asset) tuple, and is never reopened against the new episode.
        if previous_decision_id is not None:
            cur.execute(
                """
                SELECT d.id, d.tenant_id, d.exposure_id, e.status AS exposure_status,
                       e.finding_id, e.asset_id
                FROM edip_decisions d
                JOIN asset_exposures e
                  ON e.tenant_id = d.tenant_id AND e.id = d.exposure_id
                WHERE d.tenant_id = %s AND d.id = %s;
                """,
                (str(tenant_id), str(previous_decision_id)),
            )
            prior = cur.fetchone()
            if prior is None:
                raise EdipDecisionNotFoundError(
                    f"Previous decision {previous_decision_id} not found"
                )
            current = _load_exposure(cur, tenant_id, exposure_id)
            if prior["exposure_status"] != "resolved":
                raise EdipWorkflowError(
                    "A recurrence link requires the previous decision's "
                    "exposure to be resolved (decision-level reuse is a "
                    "reopen, not a new decision)"
                )
            if (str(prior["finding_id"]) != str(current["finding_id"])
                    or str(prior["asset_id"]) != str(current["asset_id"])):
                raise EdipWorkflowError(
                    "A recurrence link requires the same (finding, asset) "
                    "tuple as the previous decision's exposure"
                )

        as_of = datetime.now(timezone.utc)
        snapshot = seal_score_snapshot(conn, tenant_id, exposure_id, as_of=as_of)

        decision_id = uuid.uuid4()
        cur.execute(
            f"""
            INSERT INTO edip_decisions (
                id, tenant_id, exposure_id, decision_group_id, revision,
                previous_decision_id, handoff_id, decision_type, state, owner,
                rationale, plan, due_at, consumed_snapshot, snapshot_as_of,
                created_by, created_role
            ) VALUES (
                %s, %s, %s, %s, 1, %s, %s, %s, 'needs_decision', %s,
                %s, %s, %s, %s::jsonb, %s, %s, %s
            )
            RETURNING {_DECISION_COLUMNS};
            """,
            (
                str(decision_id), str(tenant_id), str(exposure_id),
                str(decision_id),
                str(previous_decision_id) if previous_decision_id else None,
                str(handoff_id) if handoff_id else None,
                decision_type, owner or actor_id, rationale, plan, due_at,
                json.dumps(snapshot), as_of, actor_id, actor_role,
            ),
        )
        row = cur.fetchone()

        if handoff_id is not None:
            cur.execute(
                """
                UPDATE spectrum_edip_handoffs
                SET state = 'CONSUMED', consumed_at = now(),
                    consumed_by = %s, edip_decision_id = %s
                WHERE tenant_id = %s AND id = %s AND state = 'NEEDS_DECISION';
                """,
                (actor_id, str(decision_id), str(tenant_id), str(handoff_id)),
            )
            if cur.rowcount != 1:
                raise EdipConflictError(
                    f"Handoff {handoff_id} was concurrently consumed; retry"
                )

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="edip.decision_created",
            asset_id=None,
            details={
                "decision_id": str(decision_id),
                "exposure_id": str(exposure_id),
                "decision_type": decision_type,
                "handoff_id": str(handoff_id) if handoff_id else None,
                "snapshot_as_of": as_of.isoformat(),
            },
        )
        return dict(row)


def _replace_revision(cur, tenant_id: uuid.UUID, prior: dict, new_id: uuid.UUID) -> None:
    """Stamp the prior revision replaced BEFORE the new revision inserts —
    the order matters: the one-current-per-exposure partial unique index
    cannot hold both rows at once."""
    cur.execute(
        """
        UPDATE edip_decisions
        SET replaced_at = now(), replaced_by_id = %s, updated_at = now()
        WHERE tenant_id = %s AND id = %s AND replaced_at IS NULL;
        """,
        (str(new_id), str(tenant_id), str(prior["id"])),
    )
    if cur.rowcount != 1:
        raise EdipConflictError(
            f"Decision {prior['id']} was concurrently replaced; retry"
        )


def transition_decision(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    to_state: str,
    *,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
) -> dict:
    """CAS-guarded lifecycle edge (rule 2). Plan/start/mitigate/verify — no
    score consumption, so the sealed snapshot is untouched."""
    if to_state not in TRANSITIONS:
        raise EdipWorkflowError(
            f"unknown transition target {to_state!r} — transitionable targets "
            f"are {sorted(TRANSITIONS)}"
        )

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id, for_update=True)
        row = _materialize_effective_state(conn, cur, tenant_id, row, actor_id=actor_id)

        from_states = TRANSITIONS[to_state]
        if row["state"] in TERMINAL_STATES:
            raise EdipConflictError(
                f"Decision {decision_id} is terminal (state={row['state']})"
            )
        if row["state"] not in from_states:
            raise EdipConflictError(
                f"Transition {row['state']} → {to_state} is not a lifecycle "
                f"edge (allowed from {list(from_states)})"
            )

        cur.execute(
            f"""
            UPDATE edip_decisions
            SET state = %s, updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state = %s AND replaced_at IS NULL
            RETURNING {_DECISION_COLUMNS};
            """,
            (to_state, str(tenant_id), str(row["id"]), row["state"]),
        )
        updated = cur.fetchone()
        if updated is None:
            raise EdipConflictError(
                f"Decision {decision_id} moved concurrently; retry"
            )

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="edip.decision_transition",
            asset_id=None,
            details={
                "decision_id": str(row["id"]),
                "exposure_id": str(row["exposure_id"]),
                "from": row["state"],
                "to": to_state,
                "note": note,
            },
        )
        return dict(updated)


def defer_decision(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    *,
    rationale: str,
    review_due_at: datetime,
    mitigation_type: Optional[str],
    actor_id: str,
    actor_role: str,
) -> dict:
    """Branch disposition Deferred (rule 2/8): ACTIVE, mandatory review date,
    and a FRESH sealed snapshot (PATCH-13 — never reuses the handoff score).
    Analyst action; not dual-controlled at v1 (only Accepted Risk is)."""
    if review_due_at <= datetime.now(timezone.utc):
        raise EdipWorkflowError("review_due_at must be in the future")

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id, for_update=True)
        row = _materialize_effective_state(conn, cur, tenant_id, row, actor_id=actor_id)
        if row["state"] in TERMINAL_STATES:
            raise EdipConflictError(
                f"Decision {decision_id} is terminal (state={row['state']})"
            )
        if row["state"] not in BRANCH_FROM:
            raise EdipConflictError(
                f"Defer is not available from state {row['state']}"
            )

        as_of = datetime.now(timezone.utc)
        snapshot = seal_score_snapshot(
            conn, tenant_id, row["exposure_id"], as_of=as_of
        )

        new_id = uuid.uuid4()
        # stamp the prior revision first (see _replace_revision — index order)
        _replace_revision(cur, tenant_id, row, new_id)
        cur.execute(
            f"""
            INSERT INTO edip_decisions (
                id, tenant_id, exposure_id, decision_group_id, revision,
                supersedes_id, previous_decision_id, handoff_id, decision_type,
                state, owner, rationale, plan, due_at, review_due_at,
                mitigation_type, consumed_snapshot, snapshot_as_of,
                created_by, created_role
            ) VALUES (
                %s, %s, %s, %s, %s + 1, %s, %s, %s, 'defer', 'deferred',
                %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s
            )
            RETURNING {_DECISION_COLUMNS};
            """,
            (
                str(new_id), str(tenant_id), str(row["exposure_id"]),
                str(row["decision_group_id"]), row["revision"],
                str(row["id"]),
                str(row["previous_decision_id"]) if row["previous_decision_id"] else None,
                str(row["handoff_id"]) if row["handoff_id"] else None,
                row["owner"], rationale, row["plan"], row["due_at"],
                review_due_at, mitigation_type,
                json.dumps(snapshot), as_of, actor_id, actor_role,
            ),
        )
        new_row = cur.fetchone()

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="edip.decision_deferred",
            asset_id=None,
            details={
                "decision_id": str(new_id),
                "exposure_id": str(row["exposure_id"]),
                "prior_revision": str(row["id"]),
                "review_due_at": _canonical_due_at(review_due_at),
                "snapshot_as_of": as_of.isoformat(),
            },
        )
        return dict(new_row)


def record_verification(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    *,
    evidence_kind: str,
    evidence_ref: dict,
    verdict: str,
    note: Optional[str],
    actor_id: str,
    actor_role: str,
) -> dict:
    """Ch.8's OWN verification-evidence class (rule 7, Flow D): references a
    SCOUT job, a STRIKE artifact, or an analyst attestation. A clean re-scan
    alone does not prove remediation — the verdict is a recorded judgment.
    PATCH-09: the verification binds the decision revision and the CURRENT
    exposure row version; a later move of that row invalidates it."""
    if evidence_kind not in VERIFICATION_EVIDENCE_KINDS:
        raise EdipWorkflowError(
            f"unknown evidence_kind {evidence_kind!r} — expected one of "
            f"{list(VERIFICATION_EVIDENCE_KINDS)}"
        )
    if verdict not in VERIFICATION_VERDICTS:
        raise EdipWorkflowError(
            f"unknown verdict {verdict!r} — expected one of "
            f"{list(VERIFICATION_VERDICTS)}"
        )
    if not isinstance(evidence_ref, dict) or not evidence_ref:
        raise EdipWorkflowError("evidence_ref must be a non-empty object")

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id, for_update=True)
        row = _materialize_effective_state(conn, cur, tenant_id, row, actor_id=actor_id)
        if row["state"] in TERMINAL_STATES:
            raise EdipConflictError(
                f"Decision {decision_id} is terminal (state={row['state']})"
            )
        if row["state"] not in ("mitigated", "verification"):
            raise EdipConflictError(
                f"Verification evidence attaches to a mitigated decision "
                f"(state={row['state']}); VERIFIED precedes Closed"
            )
        exposure = _load_exposure(cur, tenant_id, row["exposure_id"])
        if exposure["status"] != "confirmed":
            # materialization only fires on reads/actions through the current
            # row — this guard keeps the invariant explicit under races
            raise EdipConflictError(
                "The exposure is no longer current; the decision cannot take "
                "verification evidence"
            )

        cur.execute(
            """
            INSERT INTO edip_verifications (
                tenant_id, decision_id, evidence_kind, evidence_ref, verdict,
                note, verified_by, verified_role, decision_revision_id,
                exposure_version
            ) VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s)
            RETURNING id, tenant_id, decision_id, evidence_kind, evidence_ref,
                      verdict, note, verified_by, verified_role, verified_at,
                      decision_revision_id, exposure_version;
            """,
            (
                str(tenant_id), str(row["id"]), evidence_kind,
                json.dumps(evidence_ref), verdict, note, actor_id, actor_role,
                str(row["id"]), exposure["exposure_version"],
            ),
        )
        verification = dict(cur.fetchone())

        # First evidence moves mitigated → verification (the requested state).
        updated = row
        if row["state"] == "mitigated":
            cur.execute(
                f"""
                UPDATE edip_decisions
                SET state = 'verification', updated_at = now()
                WHERE tenant_id = %s AND id = %s AND state = 'mitigated'
                  AND replaced_at IS NULL
                RETURNING {_DECISION_COLUMNS};
                """,
                (str(tenant_id), str(row["id"])),
            )
            moved = cur.fetchone()
            if moved is not None:
                updated = moved

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="edip.verification_recorded",
            asset_id=None,
            details={
                "decision_id": str(row["id"]),
                "verification_id": str(verification["id"]),
                "evidence_kind": evidence_kind,
                "verdict": verdict,
                "exposure_version": exposure["exposure_version"],
            },
        )
        return {"verification": verification, "decision": dict(updated)}


def close_decision(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Verified closure (rule 4, PATCH-09) — ONE version-checked transaction:
    the decision closes AND its exact verified episode resolves through the
    Ch.3 exposure service (the only writer of exposure status). Compare-and-
    set on both states; any refusal rolls the whole boundary back, so a
    refused closure never leaves a closed decision against an open exposure.

    Fail-closed preconditions: state = verification (VERIFIED precedes
    Closed — the blflaw lesson); a PASS verification bound to THIS decision
    revision AND to the exposure row's CURRENT version (newer contradictory
    evidence invalidates it)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id, for_update=True)
        row = _materialize_effective_state(conn, cur, tenant_id, row, actor_id=actor_id)
        if row["state"] != "verification":
            raise EdipConflictError(
                f"Closure requires state 'verification' (state={row['state']}); "
                "VERIFIED precedes Closed"
            )

        exposure = _load_exposure(cur, tenant_id, row["exposure_id"])
        cur.execute(
            """
            SELECT id FROM edip_verifications
            WHERE tenant_id = %s AND decision_id = %s
              AND decision_revision_id = %s
              AND verdict = 'pass'
              AND exposure_version = %s
            LIMIT 1;
            """,
            (
                str(tenant_id), str(row["id"]), str(row["id"]),
                exposure["exposure_version"],
            ),
        )
        if cur.fetchone() is None:
            raise EdipConflictError(
                "Closure requires verification evidence bound to this decision "
                "revision and the exposure's current state — none is valid "
                "(missing, failed, or invalidated by newer evidence)"
            )

        # The transition INTENT: the Ch.3 exposure service owns and performs
        # confirmed → resolved inside THIS transaction (D-5/D-16).
        result = resolve_exposure(
            conn, tenant_id, row["exposure_id"],
            ExposureResolve(
                status="resolved",
                resolution_reason=f"EDIP verified closure (decision {row['id']})",
            ),
            actor_id=actor_id, actor_role=actor_role,
        )
        if result.outcome != OUTCOME_TRANSITIONED:
            raise EdipConflictError(
                "The exposure did not transition (already terminal or raced); "
                "the decision does not close"
            )

        cur.execute(
            f"""
            UPDATE edip_decisions
            SET state = 'closed', closed_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state = 'verification'
              AND replaced_at IS NULL
            RETURNING {_DECISION_COLUMNS};
            """,
            (str(tenant_id), str(row["id"])),
        )
        closed = cur.fetchone()
        if closed is None:
            raise EdipConflictError(
                f"Decision {decision_id} moved concurrently; nothing closed"
            )

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="edip.decision_closed",
            asset_id=None,
            details={
                "decision_id": str(row["id"]),
                "exposure_id": str(row["exposure_id"]),
                "exposure_outcome": result.outcome,
            },
        )
        return dict(closed)


def reopen_decision(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    *,
    reason: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Decision-level reopen (rule 9): the exposure is still confirmed and
    the same decision reopens with a recorded reason (dispute). Closed and
    superseded decisions never reopen — recurrence is a NEW episode and a
    NEW decision linked back (D-16)."""
    if not reason or not reason.strip():
        raise EdipWorkflowError("a reopen reason is mandatory")

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id, for_update=True)
        row = _materialize_effective_state(conn, cur, tenant_id, row, actor_id=actor_id)
        if row["state"] == "closed":
            raise EdipConflictError(
                "A closed decision never reopens — the episode resolved with "
                "it; recurrence confirms a NEW episode and creates a NEW "
                "decision linked back"
            )
        if row["state"] == "superseded":
            raise EdipConflictError(
                "A superseded decision never reopens — the exposure was "
                "withdrawn or superseded"
            )
        if row["state"] not in REOPEN_FROM:
            raise EdipConflictError(
                f"Decision {decision_id} is already in state {row['state']}"
            )
        exposure = _load_exposure(cur, tenant_id, row["exposure_id"])
        if exposure["status"] != "confirmed":
            raise EdipConflictError(
                "Decision-level reopen requires the exposure to still be "
                "confirmed; recurrence creates a new episode + new decision"
            )

        cur.execute(
            f"""
            UPDATE edip_decisions
            SET state = 'needs_decision', review_due_at = NULL, updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state = %s AND replaced_at IS NULL
            RETURNING {_DECISION_COLUMNS};
            """,
            (str(tenant_id), str(row["id"]), row["state"]),
        )
        updated = cur.fetchone()
        if updated is None:
            raise EdipConflictError(f"Decision {decision_id} moved concurrently; retry")

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="edip.decision_reopened",
            asset_id=None,
            details={
                "decision_id": str(row["id"]),
                "exposure_id": str(row["exposure_id"]),
                "from": row["state"],
                "reason": reason.strip(),
            },
        )
        return dict(updated)


# ---------------------------------------------------------------------------
# Accepted risk — the dual-controlled branch disposition (rule 8 — decided)
# ---------------------------------------------------------------------------
#
# The mechanism is the Ch.5 approval primitive (approver ≠ proposer,
# payload-bound, single-use); the consumer wiring lives in
# app.edip.approval_consumers. The propose transaction writes the consumer
# binding row (edip_accepted_risk_bindings) whose columns re-derive the
# canonical payload at apply time.


def propose_accepted_risk(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    *,
    rationale: str,
    review_due_at: datetime,
    mitigation_type: Optional[str],
    actor_id: str,
    actor_role: str,
) -> dict:
    from app.approvals import propose as approvals_propose
    from app.edip.approval_consumers import (
        SUBJECT_EDIP_ACCEPTED_RISK,
        canonical_accept_payload,
    )

    if not rationale or not rationale.strip():
        raise EdipWorkflowError("an accepted-risk rationale is mandatory")
    if review_due_at <= datetime.now(timezone.utc):
        raise EdipWorkflowError("review_due_at must be in the future")

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id, for_update=True)
        row = _materialize_effective_state(conn, cur, tenant_id, row, actor_id=actor_id)
        if row["state"] in TERMINAL_STATES:
            raise EdipConflictError(
                f"Decision {decision_id} is terminal (state={row['state']})"
            )
        if row["state"] not in ACCEPT_FROM:
            raise EdipConflictError(
                f"Accepted risk is not available from state {row['state']}"
            )

    payload = canonical_accept_payload(
        rationale.strip(), review_due_at, mitigation_type
    )
    proposal = approvals_propose(
        conn, tenant_id,
        subject_type=SUBJECT_EDIP_ACCEPTED_RISK,
        subject_id=str(row["id"]),  # the CURRENT revision is the subject
        payload=payload,
        actor_id=actor_id, actor_role=actor_role,
    )

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO edip_accepted_risk_bindings (
                tenant_id, decision_id, approval_id, rationale, review_due_at,
                mitigation_type, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                str(tenant_id), str(row["id"]), proposal["id"],
                rationale.strip(), review_due_at, mitigation_type, actor_id,
            ),
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="edip.accepted_risk_proposed",
            asset_id=None,
            details={
                "decision_id": str(row["id"]),
                "approval_id": str(proposal["id"]),
                "review_due_at": _canonical_due_at(review_due_at),
            },
        )
        return {
            "decision_id": str(row["id"]),
            "approval_id": proposal["id"],
            "state": proposal["state"],
        }


def _open_approval_for_decision(
    cur, tenant_id: uuid.UUID, decision_id: uuid.UUID, *, wanted: str
) -> Optional[dict]:
    """The decision's acceptance proposal in the wanted primitive state
    (pending / approved / applied); None when none stands. Proposals bind
    whichever revision was current at propose time, so the lookup spans the
    WHOLE revision group — a revision id stays a valid address for the same
    decision after a replacement."""
    from app.approvals import list_approvals_for_subject
    from app.edip.approval_consumers import SUBJECT_EDIP_ACCEPTED_RISK

    cur.execute(
        """
        SELECT decision_group_id FROM edip_decisions
        WHERE tenant_id = %s AND id = %s;
        """,
        (str(tenant_id), str(decision_id)),
    )
    group_row = cur.fetchone()
    if group_row is None:
        raise EdipDecisionNotFoundError(f"Decision {decision_id} not found")
    cur.execute(
        "SELECT id FROM edip_decisions "
        "WHERE tenant_id = %s AND decision_group_id = %s;",
        (str(tenant_id), str(group_row["decision_group_id"])),
    )
    group_ids = [r["id"] for r in cur.fetchall()]
    for subject_id in group_ids:
        for approval in list_approvals_for_subject(
            conn=cur.connection, tenant_id=tenant_id,
            subject_type=SUBJECT_EDIP_ACCEPTED_RISK, subject_id=str(subject_id),
        ):
            if approval["state"] == wanted:
                return approval
    return None


def decide_accepted_risk(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    *,
    decision: str,
    approver_id: str,
    approver_role: str,
) -> dict:
    """Admin decision on the standing proposal. EVERY decision requires
    CURRENT admin/superadmin authority and approver ≠ proposer — enforced by
    the primitive, not here."""
    from app.approvals import decide as approvals_decide

    if decision not in ("approved", "rejected"):
        raise EdipWorkflowError(
            "decision must be 'approved' or 'rejected' (cancellation uses "
            "the primitive's cancel path)"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id)
        approval = _open_approval_for_decision(
            cur, tenant_id, row["id"], wanted="pending"
        )
    if approval is None:
        raise EdipConflictError(
            f"Decision {decision_id} has no pending accepted-risk proposal"
        )
    return approvals_decide(
        conn, tenant_id, approval["id"],
        decision=decision, approver_id=approver_id, approver_role=approver_role,
    )


def apply_accepted_risk(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Apply the approved proposal: version-verified, atomic, single-use, by
    the APPROVER themself (the primitive enforces all of it). The route
    establishes the REPEATABLE READ boundary first so the fresh snapshot the
    apply seals is one coherent source view (PATCH-13)."""
    from app.approvals import apply_approval as approvals_apply

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id)
        # an approval in EITHER approved or applied state is addressed: the
        # primitive itself refuses an applied approval as the VISIBLE
        # single-use conflict (never silently absorbed here)
        approval = _open_approval_for_decision(
            cur, tenant_id, row["id"], wanted="approved"
        ) or _open_approval_for_decision(
            cur, tenant_id, row["id"], wanted="applied"
        )
    if approval is None:
        raise EdipConflictError(
            f"Decision {decision_id} has no approved accepted-risk proposal "
            "to apply"
        )
    return approvals_apply(
        conn, tenant_id, approval["id"], actor_id=actor_id, actor_role=actor_role,
    )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def get_decision(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    decision_id: uuid.UUID,
    *,
    actor_id: str,
) -> dict:
    """Decision detail addressed by ANY revision id — the response resolves
    to the CURRENT revision (a replaced id is a valid address for the same
    decision; its revision appears in the returned chain)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, decision_id)
        row = _load_current_decision(cur, tenant_id, decision_id)
        # follow the replacement chain to the current revision
        while row["replaced_at"] is not None and row["replaced_by_id"]:
            row = _load_current_decision(cur, tenant_id, row["replaced_by_id"])
        row = _materialize_effective_state(conn, cur, tenant_id, row, actor_id=actor_id)
        verifications = _verifications_for(cur, tenant_id, row["decision_group_id"])
        revisions = _revision_chain(cur, tenant_id, row["decision_group_id"])
        return {
            "decision": _decision_view(row),
            "verifications": verifications,
            "revisions": revisions,
        }


def list_exposure_decisions(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    actor_id: str,
) -> list[dict]:
    """The full decision history for an exposure (any status) — revisions and
    their verifications; readable even after the episode turns terminal."""
    with conn.cursor(row_factory=dict_row) as cur:
        _load_exposure(cur, tenant_id, exposure_id)
        cur.execute(
            f"""
            SELECT {_DECISION_COLUMNS} FROM edip_decisions
            WHERE tenant_id = %s AND exposure_id = %s
            ORDER BY created_at DESC, revision DESC;
            """,
            (str(tenant_id), str(exposure_id)),
        )
        rows = cur.fetchall()
        out = []
        for row in rows:
            if row["state"] not in TERMINAL_STATES:
                row = _materialize_effective_state(
                    conn, cur, tenant_id, row, actor_id=actor_id
                )
            out.append(_decision_view(row))
        return out


def list_open_decisions(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    actor_id: str,
    owner: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """The EDIP queue: CURRENT non-terminal decisions (accepted/deferred stay
    visible and current — rule 2), each materialized to its effective state
    first, with derived due-state (overdue is read-time, rule 6)."""
    if state is not None and state not in DECISION_STATES:
        raise EdipWorkflowError(f"unknown state {state!r}")

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            SELECT {_DECISION_COLUMNS} FROM edip_decisions
            WHERE tenant_id = %s AND replaced_at IS NULL
              AND state NOT IN ('closed', 'superseded')
              AND (%s::text IS NULL OR owner = %s::text)
              AND (%s::text IS NULL OR state = %s::text)
            ORDER BY created_at ASC, id
            LIMIT %s OFFSET %s;
            """,
            (
                str(tenant_id),
                owner, owner, state, state,
                max(1, min(limit, 500)), max(0, offset),
            ),
        )
        rows = cur.fetchall()
        now = datetime.now(timezone.utc)
        items = []
        for row in rows:
            row = _materialize_effective_state(
                conn, cur, tenant_id, row, actor_id=actor_id
            )
            if row["state"] in TERMINAL_STATES:
                continue  # materialized away mid-queue (withdrawal/supersession)
            items.append(_queue_view(row, now))
        return {"total": len(items), "items": items}


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------


def decision_owner(
    conn: psycopg.Connection, tenant_id: uuid.UUID, decision_id: uuid.UUID
) -> str:
    """The decision's owner (route-level authority gate: transitions by owner
    or admin). Unknown and cross-tenant ids are the identical not-found."""
    with conn.cursor(row_factory=dict_row) as cur:
        row = _load_current_decision(cur, tenant_id, decision_id)
        return row["owner"]



def _verifications_for(cur, tenant_id: uuid.UUID, group_id: uuid.UUID) -> list[dict]:
    cur.execute(
        """
        SELECT v.id, v.decision_id, v.evidence_kind, v.evidence_ref, v.verdict,
               v.note, v.verified_by, v.verified_role, v.verified_at,
               v.decision_revision_id, v.exposure_version
        FROM edip_verifications v
        JOIN edip_decisions d
          ON d.tenant_id = v.tenant_id AND d.id = v.decision_id
        WHERE v.tenant_id = %s AND d.decision_group_id = %s
        ORDER BY v.verified_at ASC, v.id;
        """,
        (str(tenant_id), str(group_id)),
    )
    return [dict(r) for r in cur.fetchall()]


def _revision_chain(cur, tenant_id: uuid.UUID, group_id: uuid.UUID) -> list[dict]:
    cur.execute(
        f"""
        SELECT {_DECISION_COLUMNS} FROM edip_decisions
        WHERE tenant_id = %s AND decision_group_id = %s
        ORDER BY revision ASC, created_at ASC;
        """,
        (str(tenant_id), str(group_id)),
    )
    return [_decision_view(r) for r in cur.fetchall()]


def _decision_view(row: dict) -> dict:
    view = dict(row)
    now = datetime.now(timezone.utc)
    view["overdue"] = bool(view.get("due_at") and view["due_at"] < now
                           and view["state"] not in TERMINAL_STATES)
    if view["state"] in ACTIVE_BRANCH_STATES and view.get("review_due_at"):
        view["review_expired"] = view["review_due_at"] <= now
    else:
        view["review_expired"] = False
    return view


def _queue_view(row: dict, now: datetime) -> dict:
    return {
        "decision_id": row["id"],
        "exposure_id": row["exposure_id"],
        "decision_type": row["decision_type"],
        "state": row["state"],
        "owner": row["owner"],
        "rationale": row["rationale"],
        "plan": row["plan"],
        "due_at": row["due_at"],
        "overdue": bool(row["due_at"] and row["due_at"] < now),
        "review_due_at": row["review_due_at"],
        "created_at": row["created_at"],
        "revision": row["revision"],
        "snapshot": {
            "as_of": row["snapshot_as_of"],
            "value": (row["consumed_snapshot"] or {}).get("value"),
            "state": (row["consumed_snapshot"] or {}).get("state"),
            "formula_version": (row["consumed_snapshot"] or {}).get("formula_version"),
        },
    }
