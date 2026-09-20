# backend/app/spectrum/service.py
"""
Service layer for the SPECTRUM workbench (PRD-000 v1.11 Ch.7).

Read paths are read-through: the queue and the detail view recompute the
current TES inside the caller's REPEATABLE READ boundary (as_of captured at
that boundary) — no stored score exists anywhere in this module, so a fresh
read always renders fresh state with no refresh machinery.

Write paths own ONLY workflow state at the exposure grain: assignment,
``analysis_state`` (new → assigned → in_analysis → action_required), notes/
history, STRIKE engagement drafts, and EDIP handoffs. The Ch.3 exposure
lifecycle is never written here; the two state fields never gate each other.

Mutations require the exposure to be a CURRENT confirmed episode on an ACTIVE
asset (the same fail-closed 404 shape as the Ch.3 TES reads); history stays
readable for any tenant-scoped exposure.
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.service import _advisory_xact_lock
from app.exposure.tes_read_model import get_exposure_tes
from app.spectrum.errors import SpectrumExposureNotFoundError, SpectrumWorkflowError

ANALYSIS_STATES = ("new", "assigned", "in_analysis", "action_required")

_WORKFLOW_COLUMNS = (
    "id, tenant_id, exposure_id, assigned_to, assigned_by, assigned_at, "
    "analysis_state, state_changed_by, state_changed_at, edip_handoff_at, "
    "created_at, updated_at"
)


def _load_current_exposure(cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> dict:
    """The 404 gate for workbench mutations: unknown, cross-tenant, resolved/
    superseded, and inactive-asset exposures are the SAME not-found — nothing
    is disclosed (the Ch.3 TES-read contract)."""
    cur.execute(
        """
        SELECT e.id, e.tenant_id, e.finding_id, e.asset_id
        FROM asset_exposures e
        JOIN assets a
          ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.status = 'active'
        WHERE e.tenant_id = %s AND e.id = %s AND e.status = 'confirmed';
        """,
        (str(tenant_id), str(exposure_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise SpectrumExposureNotFoundError(f"Exposure {exposure_id} not found")
    return row


def _ensure_workflow(cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> dict:
    cur.execute(
        f"""
        INSERT INTO spectrum_exposure_workflow (tenant_id, exposure_id)
        VALUES (%s, %s)
        ON CONFLICT (tenant_id, exposure_id) DO NOTHING;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    cur.execute(
        f"""
        SELECT {_WORKFLOW_COLUMNS}
        FROM spectrum_exposure_workflow
        WHERE tenant_id = %s AND exposure_id = %s;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    return cur.fetchone()


def _history(cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> list[dict]:
    cur.execute(
        """
        SELECT id, tenant_id, exposure_id, event, actor, actor_role, note, detail, created_at
        FROM spectrum_workflow_history
        WHERE tenant_id = %s AND exposure_id = %s
        ORDER BY created_at ASC, id ASC;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    return [dict(r) for r in cur.fetchall()]


def _record_history(
    cur,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    event: str,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
    detail: Optional[dict] = None,
) -> None:
    cur.execute(
        """
        INSERT INTO spectrum_workflow_history (
            tenant_id, exposure_id, event, actor, actor_role, note, detail
        ) VALUES (%s, %s, %s, %s, %s, %s, %s);
        """,
        (
            str(tenant_id), str(exposure_id), event, actor_id, actor_role,
            note, json.dumps(detail) if detail is not None else None,
        ),
    )


def _current_business_impact(cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> Optional[dict]:
    """The current BI assessment (§3.3.2 exposure grain) — READ-ONLY here:
    the analyst edit surface writes the Ch.3 ledger via the existing Ch.3
    route; SPECTRUM owns the workbench rendering, not the storage."""
    cur.execute(
        """
        SELECT value, reason, assessed_by, created_at
        FROM exposure_business_impact
        WHERE tenant_id = %s AND exposure_id = %s
        ORDER BY created_at DESC, id DESC
        LIMIT 1;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    row = cur.fetchone()
    if row is None:
        return None
    return {
        "value": row["value"],
        "reason": row["reason"],
        "assessed_by": row["assessed_by"],
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# Reads (read-through)
# ---------------------------------------------------------------------------


def get_spectrum_queue(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    as_of,
    finding_id: Optional[uuid.UUID] = None,
    asset_id: Optional[uuid.UUID] = None,
    analysis_state: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """The operational queue: CURRENT confirmed exposures on ACTIVE assets —
    nothing else. Each row carries its own recomputed TES (state, value,
    display_value, formula_version) plus the workflow fields and the current
    Business Impact. Historical views (resolved / false_positive / superseded)
    are NOT the operational queue (Ch.7 item 1)."""
    if analysis_state is not None and analysis_state not in ANALYSIS_STATES:
        raise SpectrumWorkflowError(f"unknown analysis_state {analysis_state!r}")

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT COUNT(*) AS total
            FROM asset_exposures e
            JOIN assets a
              ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.status = 'active'
            LEFT JOIN spectrum_exposure_workflow w
              ON w.tenant_id = e.tenant_id AND w.exposure_id = e.id
            WHERE e.tenant_id = %s AND e.status = 'confirmed'
              AND (%s::uuid IS NULL OR e.finding_id = %s::uuid)
              AND (%s::uuid IS NULL OR e.asset_id = %s::uuid)
              AND (%s::text IS NULL OR w.analysis_state = %s::text)
              AND (%s::text IS NULL OR w.assigned_to = %s::text);
            """,
            (
                str(tenant_id),
                str(finding_id) if finding_id else None,
                str(finding_id) if finding_id else None,
                str(asset_id) if asset_id else None,
                str(asset_id) if asset_id else None,
                analysis_state, analysis_state,
                assigned_to, assigned_to,
            ),
        )
        total = cur.fetchone()["total"]

        cur.execute(
            """
            SELECT
                e.id AS exposure_id,
                e.finding_id,
                e.asset_id,
                e.confirmed_at AS exposure_confirmed_at,
                f.canonical_cve_id,
                f.title AS finding_title,
                f.severity AS finding_severity,
                a.name AS asset_name,
                a.target_type AS asset_target_type,
                a.normalized_target AS asset_normalized_target,
                w.assigned_to, w.assigned_at,
                w.analysis_state, w.state_changed_at AS analysis_state_changed_at,
                w.edip_handoff_at
            FROM asset_exposures e
            JOIN findings f
              ON e.tenant_id = f.tenant_id AND e.finding_id = f.id
            JOIN assets a
              ON e.tenant_id = a.tenant_id AND e.asset_id = a.id AND a.status = 'active'
            LEFT JOIN spectrum_exposure_workflow w
              ON w.tenant_id = e.tenant_id AND w.exposure_id = e.id
            WHERE e.tenant_id = %s AND e.status = 'confirmed'
              AND (%s::uuid IS NULL OR e.finding_id = %s::uuid)
              AND (%s::uuid IS NULL OR e.asset_id = %s::uuid)
              AND (%s::text IS NULL OR w.analysis_state = %s::text)
              AND (%s::text IS NULL OR w.assigned_to = %s::text)
            ORDER BY e.confirmed_at DESC, e.id ASC
            LIMIT %s OFFSET %s;
            """,
            (
                str(tenant_id),
                str(finding_id) if finding_id else None,
                str(finding_id) if finding_id else None,
                str(asset_id) if asset_id else None,
                str(asset_id) if asset_id else None,
                analysis_state, analysis_state,
                assigned_to, assigned_to,
                max(1, min(limit, 500)), max(0, offset),
            ),
        )
        rows = cur.fetchall()

    items = []
    for row in rows:
        # Read-through recompute inside the caller's snapshot — the queue
        # never reads a stored score (there is none).
        tes = get_exposure_tes(conn, tenant_id, row["exposure_id"], as_of=as_of)
        with conn.cursor(row_factory=dict_row) as cur:
            bi = _current_business_impact(cur, tenant_id, row["exposure_id"])
        items.append({
            "exposure_id": row["exposure_id"],
            "finding_id": row["finding_id"],
            "asset_id": row["asset_id"],
            "canonical_cve_id": row["canonical_cve_id"],
            "finding_title": row["finding_title"],
            "finding_severity": row["finding_severity"],
            "asset_name": row["asset_name"],
            "asset_target_type": row["asset_target_type"],
            "asset_normalized_target": row["asset_normalized_target"],
            "exposure_confirmed_at": row["exposure_confirmed_at"],
            "tes": {
                "state": tes["state"],
                "value": tes["value"],
                "display_value": tes["display_value"],
                "formula_version": tes["formula_version"],
            },
            "analysis_state": row["analysis_state"] or "new",
            "assigned_to": row["assigned_to"],
            "assigned_at": row["assigned_at"],
            "analysis_state_changed_at": row["analysis_state_changed_at"],
            "edip_handoff_at": row["edip_handoff_at"],
            "business_impact": bi,
        })

    return {"total": total, "items": items}


def _get_workflow_readonly(cur, tenant_id: uuid.UUID, exposure_id: uuid.UUID) -> dict:
    """The workflow view WITHOUT writing: when no workbench action has ever
    touched the exposure the default shape is synthesized ('new') — reads
    never create rows."""
    cur.execute(
        f"""
        SELECT {_WORKFLOW_COLUMNS}
        FROM spectrum_exposure_workflow
        WHERE tenant_id = %s AND exposure_id = %s;
        """,
        (str(tenant_id), str(exposure_id)),
    )
    row = cur.fetchone()
    if row is not None:
        return dict(row)
    return {
        "id": None,
        "tenant_id": tenant_id,
        "exposure_id": exposure_id,
        "assigned_to": None,
        "assigned_by": None,
        "assigned_at": None,
        "analysis_state": "new",
        "state_changed_by": None,
        "state_changed_at": None,
        "edip_handoff_at": None,
        "created_at": None,
        "updated_at": None,
    }


def get_spectrum_exposure(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    as_of,
) -> dict:
    """The workbench detail: the full §3.3.5 decomposition payload
    (read-through), the workflow view (synthesized default 'new' when no
    action has ever touched the exposure), the workflow journal, and the
    current Business Impact."""
    tes = get_exposure_tes(conn, tenant_id, exposure_id, as_of=as_of)
    with conn.cursor(row_factory=dict_row) as cur:
        workflow = _get_workflow_readonly(cur, tenant_id, exposure_id)
        history = _history(cur, tenant_id, exposure_id)
        bi = _current_business_impact(cur, tenant_id, exposure_id)
    return {
        "exposure_id": exposure_id,
        "tes": tes,
        "workflow": workflow,
        "history": history,
        "business_impact": bi,
    }


def get_spectrum_history(
    conn: psycopg.Connection, tenant_id: uuid.UUID, exposure_id: uuid.UUID
) -> list[dict]:
    """The journal is readable for ANY tenant-scoped exposure — the workflow
    narrative outlives the episode's currentness (audit value)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT e.id FROM asset_exposures e
            WHERE e.tenant_id = %s AND e.id = %s;
            """,
            (str(tenant_id), str(exposure_id)),
        )
        if cur.fetchone() is None:
            raise SpectrumExposureNotFoundError(f"Exposure {exposure_id} not found")
        return _history(cur, tenant_id, exposure_id)


# ---------------------------------------------------------------------------
# Workflow mutations (exposure grain; Ch.3 lifecycle untouched)
# ---------------------------------------------------------------------------


def assign_exposure(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    assignee: str,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    if not assignee or not assignee.strip():
        raise SpectrumWorkflowError("assignee is required")
    with conn.cursor(row_factory=dict_row) as cur:
        _load_current_exposure(cur, tenant_id, exposure_id)
        _advisory_xact_lock(cur, f"spectrum:{tenant_id}:{exposure_id}")
        workflow = _ensure_workflow(cur, tenant_id, exposure_id)
        # analysis_state never gates assignment, and assignment never gates
        # it — except the natural bootstrap edge new → assigned.
        new_state = workflow["analysis_state"]
        if new_state == "new":
            new_state = "assigned"
        cur.execute(
            """
            UPDATE spectrum_exposure_workflow
            SET assigned_to = %s, assigned_by = %s, assigned_at = now(),
                analysis_state = %s,
                state_changed_by = CASE WHEN %s <> analysis_state THEN %s ELSE state_changed_by END,
                state_changed_at = CASE WHEN %s <> analysis_state THEN now() ELSE state_changed_at END,
                updated_at = now()
            WHERE tenant_id = %s AND exposure_id = %s
            RETURNING """ + _WORKFLOW_COLUMNS + ";",
            (
                assignee.strip(), actor_id, new_state,
                new_state, actor_id, new_state,
                str(tenant_id), str(exposure_id),
            ),
        )
        updated = cur.fetchone()
        _record_history(
            cur, tenant_id, exposure_id, event="assigned",
            actor_id=actor_id, actor_role=actor_role,
            detail={"assigned_to": assignee.strip(),
                    "analysis_state": updated["analysis_state"]},
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="spectrum.exposure_assigned",
            asset_id=None,
            details={
                "exposure_id": str(exposure_id),
                "assigned_to": assignee.strip(),
            },
        )
        return dict(updated)


def unassign_exposure(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        _load_current_exposure(cur, tenant_id, exposure_id)
        _advisory_xact_lock(cur, f"spectrum:{tenant_id}:{exposure_id}")
        _ensure_workflow(cur, tenant_id, exposure_id)
        cur.execute(
            """
            UPDATE spectrum_exposure_workflow
            SET assigned_to = NULL, assigned_by = NULL, assigned_at = NULL,
                updated_at = now()
            WHERE tenant_id = %s AND exposure_id = %s
            RETURNING """ + _WORKFLOW_COLUMNS + ";",
            (str(tenant_id), str(exposure_id)),
        )
        updated = cur.fetchone()
        _record_history(
            cur, tenant_id, exposure_id, event="unassigned",
            actor_id=actor_id, actor_role=actor_role,
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="spectrum.exposure_unassigned",
            asset_id=None,
            details={"exposure_id": str(exposure_id)},
        )
        return dict(updated)


def set_analysis_state(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    analysis_state: str,
    *,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
) -> dict:
    if analysis_state not in ANALYSIS_STATES:
        raise SpectrumWorkflowError(
            f"unknown analysis_state {analysis_state!r} — the closed v1 "
            f"lifecycle is {list(ANALYSIS_STATES)}"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        _load_current_exposure(cur, tenant_id, exposure_id)
        _advisory_xact_lock(cur, f"spectrum:{tenant_id}:{exposure_id}")
        workflow = _ensure_workflow(cur, tenant_id, exposure_id)
        prior = workflow["analysis_state"]
        cur.execute(
            """
            UPDATE spectrum_exposure_workflow
            SET analysis_state = %s, state_changed_by = %s,
                state_changed_at = now(), updated_at = now()
            WHERE tenant_id = %s AND exposure_id = %s
            RETURNING """ + _WORKFLOW_COLUMNS + ";",
            (analysis_state, actor_id, str(tenant_id), str(exposure_id)),
        )
        updated = cur.fetchone()
        _record_history(
            cur, tenant_id, exposure_id, event="analysis_state_changed",
            actor_id=actor_id, actor_role=actor_role, note=note,
            detail={"from": prior, "to": analysis_state},
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="spectrum.analysis_state_changed",
            asset_id=None,
            details={
                "exposure_id": str(exposure_id),
                "from": prior,
                "to": analysis_state,
                "note": note,
            },
        )
        return dict(updated)


def add_workflow_note(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    note: str,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    if not note or not note.strip():
        raise SpectrumWorkflowError("note is required")
    with conn.cursor(row_factory=dict_row) as cur:
        _load_current_exposure(cur, tenant_id, exposure_id)
        _advisory_xact_lock(cur, f"spectrum:{tenant_id}:{exposure_id}")
        _ensure_workflow(cur, tenant_id, exposure_id)
        _record_history(
            cur, tenant_id, exposure_id, event="note_added",
            actor_id=actor_id, actor_role=actor_role, note=note.strip(),
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="spectrum.note_added",
            asset_id=None,
            details={"exposure_id": str(exposure_id)},
        )
        cur.execute(
            "UPDATE spectrum_exposure_workflow SET updated_at = now() "
            "WHERE tenant_id = %s AND exposure_id = %s;",
            (str(tenant_id), str(exposure_id)),
        )
        return {"ok": True}


def request_strike(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
) -> dict:
    """STRIKE request = an engagement DRAFT pre-bound to the exposure
    (Ch.4 owns everything after). STRIKE unavailability can never be silent:
    v1 the request is durably queued as a draft."""
    with conn.cursor(row_factory=dict_row) as cur:
        _load_current_exposure(cur, tenant_id, exposure_id)
        _advisory_xact_lock(cur, f"spectrum:{tenant_id}:{exposure_id}")
        _ensure_workflow(cur, tenant_id, exposure_id)
        cur.execute(
            """
            INSERT INTO spectrum_strike_requests (tenant_id, exposure_id, requested_by, note)
            VALUES (%s, %s, %s, %s)
            RETURNING id, tenant_id, exposure_id, state, requested_by, note, created_at;
            """,
            (str(tenant_id), str(exposure_id), actor_id, note),
        )
        draft = dict(cur.fetchone())
        _record_history(
            cur, tenant_id, exposure_id, event="strike_requested",
            actor_id=actor_id, actor_role=actor_role, note=note,
            detail={"strike_request_id": str(draft["id"])},
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="spectrum.strike_requested",
            asset_id=None,
            details={
                "exposure_id": str(exposure_id),
                "strike_request_id": str(draft["id"]),
            },
        )
        return draft


def request_edip_handoff(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
    note: Optional[str] = None,
) -> dict:
    """The explicit action-required transition: the exposure's analysis_state
    becomes 'action_required' and the EDIP decision is created in
    Needs-Decision state — recorded and retryable (upstream truth intact,
    Q16). Manual at v1: no auto-handoff policy exists (§3.6.6 #9 reserved)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _load_current_exposure(cur, tenant_id, exposure_id)
        _advisory_xact_lock(cur, f"spectrum:{tenant_id}:{exposure_id}")
        _ensure_workflow(cur, tenant_id, exposure_id)
        cur.execute(
            """
            SELECT id FROM spectrum_edip_handoffs
            WHERE tenant_id = %s AND exposure_id = %s AND state = 'NEEDS_DECISION';
            """,
            (str(tenant_id), str(exposure_id)),
        )
        if cur.fetchone() is not None:
            raise SpectrumWorkflowError(
                "an open EDIP handoff already exists for this exposure — "
                "resolve it before requesting another"
            )
        cur.execute(
            """
            INSERT INTO spectrum_edip_handoffs (tenant_id, exposure_id, requested_by, note)
            VALUES (%s, %s, %s, %s)
            RETURNING id, tenant_id, exposure_id, state, requested_by, note, created_at;
            """,
            (str(tenant_id), str(exposure_id), actor_id, note),
        )
        handoff = dict(cur.fetchone())
        cur.execute(
            """
            UPDATE spectrum_exposure_workflow
            SET analysis_state = 'action_required',
                state_changed_by = %s, state_changed_at = now(),
                edip_handoff_at = now(), updated_at = now()
            WHERE tenant_id = %s AND exposure_id = %s
            RETURNING """ + _WORKFLOW_COLUMNS + ";",
            (actor_id, str(tenant_id), str(exposure_id)),
        )
        updated = cur.fetchone()
        _record_history(
            cur, tenant_id, exposure_id, event="edip_handoff",
            actor_id=actor_id, actor_role=actor_role, note=note,
            detail={
                "edip_handoff_id": str(handoff["id"]),
                "analysis_state": updated["analysis_state"],
            },
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="spectrum.edip_handoff",
            asset_id=None,
            details={
                "exposure_id": str(exposure_id),
                "edip_handoff_id": str(handoff["id"]),
            },
        )
        return {"handoff": handoff, "workflow": dict(updated)}
