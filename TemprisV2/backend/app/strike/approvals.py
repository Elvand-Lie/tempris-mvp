# backend/app/strike/approvals.py
"""STRIKE's consumption of the Chapter 5 dual-control primitive
(PRD-000 v1.11 Ch.4 security boundaries + Appendix C Q11).

Exactly the two decided subject types are registered here — no second
approval store, table, or workflow exists (the primitive in app/approvals.py
owns the mechanism; this module owns only the consumer policy):

  1. ``strike_engagement`` — authorization of a pending_approval engagement.
     Apply transitions pending_approval → authorized and stamps the approval
     binding (written exactly once, migration-027 trigger).
  2. ``strike_target`` — approval of a pending target. Apply transitions
     pending → approved, stamps the approval binding, and bumps the
     authorization version (enforcement binds to it, PATCH-03).

Subject-version tokens (opaque to the primitive): the engagement/target row's
``xmin`` plus, for engagements, the linked workspace generation count — any
mutation of the subject (including an abort or a target revocation after
proposal) moves the token so the apply's version recheck fails closed.

Apply handlers re-check, inside the caller's transaction (after the
primitive's payload-hash and subject-version rechecks): tenant, row state,
ROE window still open, and approver authority (re-verified by the primitive
itself). V1's auto-signing quick-scan is retired by construction: there is
no code path here that approves without going through the primitive.
"""
from __future__ import annotations

import uuid

import psycopg
from psycopg.rows import dict_row

from app.approvals import (
    ApprovalNotFoundError,
    ApprovalPayloadMismatchError,
    ApprovalSubjectError,
    SubjectHandler,
    _canonical_hash,
    register_subject_type,
)
from app.audit import record_audit_event
from app.exposure.service import _advisory_xact_lock

SUBJECT_ENGAGEMENT = "strike_engagement"
SUBJECT_TARGET = "strike_target"

_AUTHORIZE_ENGAGEMENT_PAYLOAD = {"kind": "authorize_strike_engagement"}
_APPROVE_TARGET_PAYLOAD = {"kind": "approve_strike_target"}


# ---------------------------------------------------------------------------
# Subject-version readers (unknown and cross-tenant ids: identical not-found)
# ---------------------------------------------------------------------------


def _engagement_version(cur, tenant_id: uuid.UUID, subject_id: str) -> str:
    cur.execute(
        """
        SELECT e.xmin::text AS v, e.state,
               (SELECT COUNT(*) FROM strike_workspaces w
                WHERE w.tenant_id = e.tenant_id AND w.engagement_id = e.id) AS workspace_rows
        FROM strike_engagements e
        WHERE e.tenant_id = %s AND e.id = %s;
        """,
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"engagement {subject_id} not found")
    return f"{row['v']}:{row['workspace_rows']}"


def _target_version(cur, tenant_id: uuid.UUID, subject_id: str) -> str:
    cur.execute(
        "SELECT xmin::text AS v FROM strike_targets "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"target {subject_id} not found")
    return row["v"]


# ---------------------------------------------------------------------------
# Payload validators (propose time)
# ---------------------------------------------------------------------------


def _validate_engagement(cur, tenant_id, subject_id, payload) -> None:
    if payload != _AUTHORIZE_ENGAGEMENT_PAYLOAD:
        raise ApprovalSubjectError(
            "engagement approval payload must be exactly "
            '{"kind": "authorize_strike_engagement"} — the ROE lives '
            "immutably on the engagement row"
        )
    cur.execute(
        "SELECT state FROM strike_engagements WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"engagement {subject_id} not found")
    if row["state"] != "pending_approval":
        raise ApprovalSubjectError(
            f"engagement {subject_id} is not pending_approval "
            f"(state={row['state']})"
        )


def _validate_target(cur, tenant_id, subject_id, payload) -> None:
    if payload != _APPROVE_TARGET_PAYLOAD:
        raise ApprovalSubjectError(
            "target approval payload must be exactly "
            '{"kind": "approve_strike_target"} — the tuple lives '
            "immutably on the target row"
        )
    cur.execute(
        "SELECT state FROM strike_targets WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"target {subject_id} not found")
    if row["state"] != "pending":
        raise ApprovalSubjectError(
            f"target {subject_id} is not pending (state={row['state']})"
        )


# ---------------------------------------------------------------------------
# Payload re-derivation (apply time — detects post-approval alteration)
# ---------------------------------------------------------------------------


def _rederive_engagement(cur, tenant_id, subject_id, payload_hash) -> dict:
    cur.execute(
        "SELECT xmin::text AS v FROM strike_engagements "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    if cur.fetchone() is None:
        raise ApprovalNotFoundError(f"engagement {subject_id} not found")
    if _canonical_hash(_AUTHORIZE_ENGAGEMENT_PAYLOAD) != payload_hash:
        raise ApprovalPayloadMismatchError(
            f"engagement {subject_id}: no payload re-derives to the approved hash"
        )
    return dict(_AUTHORIZE_ENGAGEMENT_PAYLOAD)


def _rederive_target(cur, tenant_id, subject_id, payload_hash) -> dict:
    cur.execute(
        "SELECT xmin::text AS v FROM strike_targets "
        "WHERE tenant_id = %s AND id = %s;",
        (str(tenant_id), subject_id),
    )
    if cur.fetchone() is None:
        raise ApprovalNotFoundError(f"target {subject_id} not found")
    if _canonical_hash(_APPROVE_TARGET_PAYLOAD) != payload_hash:
        raise ApprovalPayloadMismatchError(
            f"target {subject_id}: no payload re-derives to the approved hash"
        )
    return dict(_APPROVE_TARGET_PAYLOAD)


# ---------------------------------------------------------------------------
# Apply handlers (inside the caller's transaction, after the primitive's
# rechecks; commit atomically with the applied marking)
# ---------------------------------------------------------------------------


def _apply_engagement_authorize(
    conn, tenant_id, *, subject_id, approval, payload, actor_id, actor_role
):
    """pending_approval → authorized. Re-checks the engagement is still in
    the submitted state (an abort after proposal moved the version token and
    the primitive already refused), stamps the approval binding, and
    audits."""
    from app.strike.service import load_engagement

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{subject_id}")
        row = load_engagement(cur, tenant_id, uuid.UUID(subject_id), for_update=True)
        if row["state"] != "pending_approval":
            raise ApprovalSubjectError(
                f"engagement {subject_id} is {row['state']!r}, not "
                "pending_approval — apply fails closed"
            )
        cur.execute(
            """
            UPDATE strike_engagements
            SET state = 'authorized', authorized_at = now(),
                approval_id = %s, updated_at = now()
            WHERE tenant_id = %s AND id = %s AND approval_id IS NULL
            RETURNING id;
            """,
            (approval["id"], str(tenant_id), subject_id),
        )
        if cur.rowcount != 1:
            raise ApprovalSubjectError(
                f"engagement {subject_id} already carries an approval binding "
                "— apply fails closed"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.engagement_authorized",
            details={
                "engagement_id": subject_id,
                "approval_id": str(approval["id"]),
                "approver_id": approval["approver_id"],
            },
        )
        return {"engagement_id": subject_id, "state": "authorized"}


def _apply_target_approve(
    conn, tenant_id, *, subject_id, approval, payload, actor_id, actor_role
):
    """pending → approved. Bumps the authorization version (enforcement
    binds to it, PATCH-03), stamps the approval binding, bumps the live
    workspaces' egress generation, and audits."""
    from app.strike import workspaces as strike_workspaces
    from app.strike.service import load_target

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-target:{tenant_id}:{subject_id}")
        row = load_target(cur, tenant_id, uuid.UUID(subject_id), for_update=True)
        if row["state"] != "pending":
            raise ApprovalSubjectError(
                f"target {subject_id} is {row['state']!r}, not pending — "
                "apply fails closed"
            )
        cur.execute(
            """
            UPDATE strike_targets
            SET state = 'approved', approved_at = now(), approval_id = %s,
                authorization_version = authorization_version + 1,
                updated_at = now()
            WHERE tenant_id = %s AND id = %s AND approval_id IS NULL
            RETURNING engagement_id;
            """,
            (approval["id"], str(tenant_id), subject_id),
        )
        if cur.rowcount != 1:
            raise ApprovalSubjectError(
                f"target {subject_id} already carries an approval binding — "
                "apply fails closed"
            )
        engagement_id = cur.fetchone()["engagement_id"]
        strike_workspaces.bump_egress_generation(cur, tenant_id, engagement_id)
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.target_approved",
            details={
                "target_id": subject_id,
                "engagement_id": str(engagement_id),
                "approval_id": str(approval["id"]),
                "approver_id": approval["approver_id"],
            },
        )
        return {"target_id": subject_id, "state": "approved"}


# ---------------------------------------------------------------------------
# Control-plane propose helpers (called by the service commands in the same
# transaction as the state transition to pending)
# ---------------------------------------------------------------------------


def propose_engagement_approval(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    from app.approvals import propose

    return propose(
        conn, tenant_id,
        subject_type=SUBJECT_ENGAGEMENT,
        subject_id=str(engagement_id),
        payload=dict(_AUTHORIZE_ENGAGEMENT_PAYLOAD),
        actor_id=actor_id, actor_role=actor_role,
    )


def propose_target_approval(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    target_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    from app.approvals import propose

    return propose(
        conn, tenant_id,
        subject_type=SUBJECT_TARGET,
        subject_id=str(target_id),
        payload=dict(_APPROVE_TARGET_PAYLOAD),
        actor_id=actor_id, actor_role=actor_role,
    )


def register() -> None:
    register_subject_type(SUBJECT_ENGAGEMENT, SubjectHandler(
        validate_payload=_validate_engagement,
        current_version=_engagement_version,
        rederive_payload=_rederive_engagement,
        apply=_apply_engagement_authorize,
    ))
    register_subject_type(SUBJECT_TARGET, SubjectHandler(
        validate_payload=_validate_target,
        current_version=_target_version,
        rederive_payload=_rederive_target,
        apply=_apply_target_approve,
    ))
