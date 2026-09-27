# backend/app/strike/service.py
"""STRIKE engagement and target authorization commands (PRD-000 v1.11 Ch.4,
principles 1/3; the owned-state lifecycle table).

Transaction ownership: no command here commits or rolls back — the caller
owns the boundary (the established codebase pattern). Every lifecycle
transition is audited in the same transaction.

Dual control (decided — Appendix C Q11): engagement authorization and target
approval run EXCLUSIVELY through the Chapter 5 approval primitive
(``approvals.propose`` / ``approvals.decide_and_apply``) — approver ≠
proposer, payload-bound, single-use, version-verified apply. The apply
handlers live in ``app.strike.approvals`` and are registered at import of
that module (imported by the router). V1's auto-signing quick-scan is
retired: nothing here ever approves its own request.

Expiry is DERIVED AT READ (Appendix G): ``valid_until``/``expires_at`` passing
never rewrites stored state; enforcement commands simply refuse. Target
revocation is enforcement-immediate: the row flips, the authorization
version bumps, live workspaces re-derive their egress policy generation, and
new operations against the target are refused — all before the command
reports success.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.service import _advisory_xact_lock
from app.strike.errors import (
    EngagementExpiredError,
    EngagementNotFoundError,
    EngagementStateError,
    StrikeNotFoundError,
    TargetNotFoundError,
    TargetStateError,
)

ENGAGEMENT_DRAFT = "draft"
ENGAGEMENT_PENDING = "pending_approval"
ENGAGEMENT_AUTHORIZED = "authorized"
ENGAGEMENT_ACTIVE = "active"
ENGAGEMENT_COMPLETED = "completed"
ENGAGEMENT_ABORTED = "aborted"

TARGET_PENDING = "pending"
TARGET_APPROVED = "approved"
TARGET_REVOKED = "revoked"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Row access (tenant-scoped; unknown and cross-tenant ids: identical 404)
# ---------------------------------------------------------------------------


def load_engagement(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, engagement_id: uuid.UUID,
    *, for_update: bool = False,
) -> dict:
    cur.execute(
        "SELECT * FROM strike_engagements WHERE tenant_id = %s AND id = %s"
        + (" FOR UPDATE;" if for_update else ";"),
        (str(tenant_id), str(engagement_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise EngagementNotFoundError(f"Engagement {engagement_id} not found")
    return row


def load_target(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, target_id: uuid.UUID,
    *, for_update: bool = False,
) -> dict:
    cur.execute(
        "SELECT * FROM strike_targets WHERE tenant_id = %s AND id = %s"
        + (" FOR UPDATE;" if for_update else ";"),
        (str(tenant_id), str(target_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise TargetNotFoundError(f"Target {target_id} not found")
    return row


def _aware(value: datetime) -> datetime:
    """Naive datetimes are read as UTC (the codebase convention)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _with_derived_expiry(row: dict) -> dict:
    """Every engagement row the API ever renders carries the derived-expiry
    flag (Appendix G: derived states render, they are never stored)."""
    out = dict(row)
    out["derived_expired"] = engagement_is_expired(out)
    return out


def engagement_is_expired(engagement: dict, now: Optional[datetime] = None) -> bool:
    """Derived-at-read expiry: 'expired' is never a stored state (Appendix G
    — the derived states are derived at read, matching Ch.2)."""
    return (now or utcnow()) >= _aware(engagement["valid_until"])


def target_is_expired(target: dict, now: Optional[datetime] = None) -> bool:
    return (now or utcnow()) >= _aware(target["expires_at"])


def assert_engagement_operable(
    engagement: dict, *, allow_states=("authorized", "active"),
    now: Optional[datetime] = None,
) -> None:
    """Shared enforcement guard: the engagement must be inside its
    authorization window AND in an operable state. Expired ⇒ refused with
    the named derived-expiry error (fail-closed)."""
    if engagement["state"] not in allow_states:
        raise EngagementStateError(
            f"engagement {engagement['id']} is {engagement['state']!r}; this "
            f"command requires one of {sorted(allow_states)}"
        )
    if engagement_is_expired(engagement, now=now):
        raise EngagementExpiredError(
            f"engagement {engagement['id']} authorization window closed at "
            f"{engagement['valid_until'].isoformat()} — expired is enforced "
            "at read, never back-written"
        )


# ---------------------------------------------------------------------------
# Engagement commands
# ---------------------------------------------------------------------------


def create_engagement(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    data,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Create an engagement DRAFT (analyst+). Validation-linkage ids are
    stored by reference; their existence is re-validated server-side at
    activation and evidence time — the draft itself never trusts them."""
    now = utcnow()
    valid_from = _aware(data.valid_from)
    valid_until = _aware(data.valid_until)
    if valid_until <= valid_from:
        raise EngagementStateError(
            "valid_until must be after valid_from — the authorization window "
            "is the engagement lease"
        )
    if valid_until <= now:
        raise EngagementStateError(
            "valid_until must be in the future — an already-expired window "
            "never creates an engagement"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO strike_engagements (
                tenant_id, title, purpose, roe, roe_version,
                valid_from, valid_until, state,
                requested_by, requested_role, finding_id, asset_id
            ) VALUES (
                %s, %s, %s, %s::jsonb, %s, %s, %s, 'draft', %s, %s, %s, %s
            )
            RETURNING *;
            """,
            (
                str(tenant_id), data.title, data.purpose,
                json.dumps(data.roe.model_dump(mode="json")), "1",
                data.valid_from, data.valid_until,
                actor_id, actor_role,
                str(data.finding_id) if data.finding_id else None,
                str(data.asset_id) if data.asset_id else None,
            ),
        )
        row = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.engagement_created",
            details={
                "engagement_id": str(row["id"]),
                "title": row["title"],
                "roe_version": row["roe_version"],
                "valid_from": row["valid_from"].isoformat(),
                "valid_until": row["valid_until"].isoformat(),
            },
        )
        return _with_derived_expiry(row)


def submit_engagement(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Draft → pending_approval, proposing the dual-control approval in the
    SAME transaction. Only the requester submits their own draft; the
    approval itself is a different identity's act."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{engagement_id}")
        row = load_engagement(cur, tenant_id, engagement_id, for_update=True)
        if row["state"] != ENGAGEMENT_DRAFT:
            raise EngagementStateError(
                f"engagement {engagement_id} is {row['state']!r}; only a draft "
                "can be submitted"
            )
        if row["requested_by"] != actor_id:
            raise EngagementStateError(
                "only the requesting analyst submits an engagement draft"
            )
        if engagement_is_expired(row):
            raise EngagementExpiredError(
                f"engagement {engagement_id} authorization window already closed"
            )
        cur.execute(
            """
            UPDATE strike_engagements
            SET state = 'pending_approval', submitted_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        submitted = cur.fetchone()

    # lazy import: approvals.py's subject handlers call back into this module
    from app.strike import approvals as strike_approvals

    approval = strike_approvals.propose_engagement_approval(
        conn, tenant_id, engagement_id,
        actor_id=actor_id, actor_role=actor_role,
    )
    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
        actor_role=actor_role, event_name="strike.engagement_submitted",
        details={
            "engagement_id": str(engagement_id),
            "approval_id": str(approval["id"]),
        },
    )
    return {"engagement": _with_derived_expiry(submitted), "approval_id": approval["id"]}


def abort_engagement(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    reason: str,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Abort from any non-terminal state (admin+). Abortion is a safety
    action — enforcement-immediate, not proposal-gated; downstream guards
    refuse everything on a terminal engagement."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{engagement_id}")
        row = load_engagement(cur, tenant_id, engagement_id, for_update=True)
        if row["state"] in (ENGAGEMENT_COMPLETED, ENGAGEMENT_ABORTED):
            raise EngagementStateError(
                f"engagement {engagement_id} is already terminal "
                f"({row['state']!r})"
            )
        cur.execute(
            """
            UPDATE strike_engagements
            SET state = 'aborted', aborted_at = now(), aborted_by = %s,
                abort_reason = %s, updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (actor_id, reason, str(tenant_id), str(engagement_id)),
        )
        aborted = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.engagement_aborted",
            details={
                "engagement_id": str(engagement_id),
                "reason": reason,
                "prior_state": row["state"],
            },
        )
        return _with_derived_expiry(aborted)


def activate_engagement(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Authorized → active. Requires the ROE window to be open and at least
    one APPROVED, fresh target (fail-closed: an engagement with nothing
    authorized to touch never goes active)."""
    now = utcnow()
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{engagement_id}")
        row = load_engagement(cur, tenant_id, engagement_id, for_update=True)
        assert_engagement_operable(row, allow_states=(ENGAGEMENT_AUTHORIZED,), now=now)
        if row["valid_from"].tzinfo is None:
            valid_from = row["valid_from"].replace(tzinfo=timezone.utc)
        else:
            valid_from = row["valid_from"]
        if now < valid_from:
            raise EngagementStateError(
                f"engagement {engagement_id} ROE window opens at "
                f"{row['valid_from'].isoformat()}"
            )
        cur.execute(
            """
            SELECT 1 FROM strike_targets
            WHERE tenant_id = %s AND engagement_id = %s AND state = 'approved'
              AND expires_at > %s
            LIMIT 1;
            """,
            (str(tenant_id), str(engagement_id), now),
        )
        if cur.fetchone() is None:
            raise EngagementStateError(
                f"engagement {engagement_id} has no approved, fresh target — "
                "activation is refused (fail-closed)"
            )
        cur.execute(
            """
            UPDATE strike_engagements
            SET state = 'active', activated_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        activated = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.engagement_activated",
            details={"engagement_id": str(engagement_id)},
        )
        return _with_derived_expiry(activated)


def complete_engagement(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Active → completed (analyst+). The engagement record stays as
    permanent audit history; completing never deletes anything."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{engagement_id}")
        row = load_engagement(cur, tenant_id, engagement_id, for_update=True)
        if row["state"] != ENGAGEMENT_ACTIVE:
            raise EngagementStateError(
                f"engagement {engagement_id} is {row['state']!r}; only an "
                "active engagement completes"
            )
        cur.execute(
            """
            UPDATE strike_engagements
            SET state = 'completed', completed_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        completed = cur.fetchone()
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.engagement_completed",
            details={"engagement_id": str(engagement_id)},
        )
        return _with_derived_expiry(completed)


def get_engagement(conn: psycopg.Connection, tenant_id: uuid.UUID, engagement_id: uuid.UUID) -> dict:
    """One engagement with derived-expiry rendering and its target summary."""
    with conn.cursor(row_factory=dict_row) as cur:
        row = load_engagement(cur, tenant_id, engagement_id)
        cur.execute(
            """
            SELECT id, target_type, target_value, normalized_target, state,
                   expires_at, authorization_version
            FROM strike_targets
            WHERE tenant_id = %s AND engagement_id = %s
            ORDER BY requested_at ASC, id;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        targets = cur.fetchall()
        return _render_engagement(row, targets)


def list_engagements(conn: psycopg.Connection, tenant_id: uuid.UUID) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT * FROM strike_engagements
            WHERE tenant_id = %s
            ORDER BY created_at DESC, id;
            """,
            (str(tenant_id),),
        )
        return [_render_engagement(r, []) for r in cur.fetchall()]


def _render_engagement(row: dict, targets: list[dict]) -> dict:
    out = dict(row)
    out["derived_expired"] = engagement_is_expired(row)
    out["targets"] = [
        {**dict(t), "derived_expired": target_is_expired(t)} for t in targets
    ]
    return out


# ---------------------------------------------------------------------------
# Target commands
# ---------------------------------------------------------------------------


def request_target(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    engagement_id: uuid.UUID,
    data,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Request a target authorization (analyst+): snapshot the exact tuple,
    propose the dual-control approval in the same transaction. Requests are
    refused once the engagement is terminal or expired."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-engagement:{tenant_id}:{engagement_id}")
        row = load_engagement(cur, tenant_id, engagement_id, for_update=True)
        assert_engagement_operable(row, allow_states=(ENGAGEMENT_AUTHORIZED, ENGAGEMENT_ACTIVE))
        if data.expires_at <= utcnow():
            raise TargetStateError("expires_at must be in the future")
        if data.expires_at > row["valid_until"]:
            raise TargetStateError(
                "target expiry cannot outlive the engagement's authorization "
                "window (the engagement lease bounds everything under it)"
            )
        cur.execute(
            """
            INSERT INTO strike_targets (
                tenant_id, engagement_id, target_type, target_value,
                normalized_target, purpose, state, expires_at, requested_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, 'pending', %s, %s
            )
            RETURNING *;
            """,
            (
                str(tenant_id), str(engagement_id), data.target_type,
                data.target_value, data.normalized_target, data.purpose,
                data.expires_at, actor_id,
            ),
        )
        target = cur.fetchone()

    # lazy import: approvals.py's subject handlers call back into this module
    from app.strike import approvals as strike_approvals

    approval = strike_approvals.propose_target_approval(
        conn, tenant_id, target["id"],
        actor_id=actor_id, actor_role=actor_role,
    )
    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
        actor_role=actor_role, event_name="strike.target_requested",
        details={
            "target_id": str(target["id"]),
            "engagement_id": str(engagement_id),
            "target_type": target["target_type"],
            "target_value": target["target_value"],
            "approval_id": str(approval["id"]),
        },
    )
    return {"target": dict(target), "approval_id": approval["id"]}


def revoke_target(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    target_id: uuid.UUID,
    reason: str,
    *,
    actor_id: str,
    actor_role: str,
    now: Optional[datetime] = None,
) -> dict:
    """Revoke a target (admin+) — ENFORCEMENT-IMMEDIATE (failure modes): the
    authorization version bumps and every live workspace of the engagement
    has its egress generation bumped in the same transaction, so stale
    policy generations can never restore revoked access (PATCH-02/03). The
    open Ch.5 approval for a pending target is expired alongside."""
    now = now or utcnow()
    from app.strike import workspaces as strike_workspaces

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"strike-target:{tenant_id}:{target_id}")
        row = load_target(cur, tenant_id, target_id, for_update=True)
        if row["state"] == TARGET_REVOKED:
            raise TargetStateError(f"target {target_id} is already revoked")

        cur.execute(
            """
            UPDATE strike_targets
            SET state = 'revoked', revoked_at = now(), revoked_by = %s,
                revoke_reason = %s,
                authorization_version = authorization_version + 1,
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING *;
            """,
            (actor_id, reason, str(tenant_id), str(target_id)),
        )
        revoked = cur.fetchone()
        engagement_id = revoked["engagement_id"]

        # enforcement-immediate: live workspaces re-derive their egress
        # generation (the compiled policy can never silently keep the target)
        strike_workspaces.bump_egress_generation(cur, tenant_id, engagement_id)

        # a pending target's standing approval cannot outlive the withdrawal
        cur.execute(
            """
            SELECT id FROM chapter5_approvals
            WHERE tenant_id = %s AND subject_type = 'strike_target'
              AND subject_id = %s AND state = 'pending';
            """,
            (str(tenant_id), str(target_id)),
        )
        for approval_row in cur.fetchall():
            from app.approvals import expire

            expire(conn, tenant_id, approval_row["id"], actor_id=actor_id, actor_role=actor_role)

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="strike.target_revoked",
            details={
                "target_id": str(target_id),
                "engagement_id": str(engagement_id),
                "reason": reason,
                "authorization_version": revoked["authorization_version"],
            },
        )
        out = dict(revoked)
        out["derived_expired"] = target_is_expired(out, now=now)
        return out  # target revoke renders its own derived flag


def get_target(conn: psycopg.Connection, tenant_id: uuid.UUID, target_id: uuid.UUID) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        row = load_target(cur, tenant_id, target_id)
        out = dict(row)
        out["derived_expired"] = target_is_expired(out)
        return out


def list_targets(conn: psycopg.Connection, tenant_id: uuid.UUID, engagement_id: uuid.UUID) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        load_engagement(cur, tenant_id, engagement_id)
        cur.execute(
            """
            SELECT * FROM strike_targets
            WHERE tenant_id = %s AND engagement_id = %s
            ORDER BY requested_at ASC, id;
            """,
            (str(tenant_id), str(engagement_id)),
        )
        return [
            {**dict(r), "derived_expired": target_is_expired(r)}
            for r in cur.fetchall()
        ]


__all__ = [
    "EngagementNotFoundError",
    "StrikeNotFoundError",
    "abort_engagement",
    "activate_engagement",
    "assert_engagement_operable",
    "complete_engagement",
    "create_engagement",
    "engagement_is_expired",
    "get_engagement",
    "get_target",
    "list_engagements",
    "list_targets",
    "load_engagement",
    "load_target",
    "request_target",
    "revoke_target",
    "submit_engagement",
    "target_is_expired",
    "utcnow",
]
