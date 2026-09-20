# backend/app/approvals.py
"""
CHAPTER 5 DUAL-CONTROL APPROVAL PRIMITIVE (PRD-000 v1.11, Chapter 5 Target
architecture item 1) — the mechanism only, no consumer policy.

ONE generic approval object (migration 021 ``chapter5_approvals``). Chapter 3
(P0-08) consumes it by registering subject types; it never creates a second
approval store, table, or workflow.

Lifecycle (DB-pinned to exactly these edges, migration 021):

    pending ──approve──▶ approved ──apply──▶ applied (TERMINAL)
       ├──reject───▶ rejected
       ├──cancel───▶ cancelled
       └──expire───▶ expired

Invariants enforced BY THE PRIMITIVE (not by consumer discipline):

  * HARD dual control — the approver can never equal the proposer. Enforced
    twice: in the decide service and in the migration-021 trigger (DB layer);
  * decide-time authority — the approver must hold an admin/superadmin
    membership that is CURRENT (active user, active tenant, active membership,
    matching role) at the decision instant, re-verified in the deciding
    transaction;
  * immutable proposal binding — payload hash + subject-version snapshot are
    fixed at proposal (DB-enforced);
  * single-use by rule — one approval authorizes one mutation exactly once.
    A second apply is a VISIBLE conflict refusal (ApprovalAlreadyAppliedError,
    stable code ``approval_already_applied``), never silent idempotent
    absorption;
  * apply is version-verified and atomic — the handler runs inside the
    caller's transaction under an advisory lock keyed to the subject, and the
    primitive re-verifies, IN ORDER: (1) the payload hash equals the approved
    binding, (2) the subject's current version equals the approved snapshot.
    A payload altered after approval, or an approval rebased onto different
    subject state, fails closed with NOTHING written. approve+apply may be
    performed in one transaction for immediate actions (decide_and_apply);
  * tenant comes from the caller's AuthContext; unknown and cross-tenant
    subjects are the identical not-found; every transition is audited in the
    same transaction (append-only chapter5_approval_audit; audit failure rolls
    back the whole transition);
  * transaction ownership: no command here commits or rolls back — the
    caller owns the boundary (established pattern).

EXTENSION POINT: consumers register one :class:`SubjectHandler` per subject
type (payload validator + apply handler + subject-version reader). This
module registers NO consumers; P0-08 registers the three Chapter 3 subject
types at import time of ``app.exposure.approval_consumers``.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event
from app.exposure.exceptions import ExposureDomainError
from app.exposure.service import _advisory_xact_lock

STATE_PENDING = "pending"
STATE_APPROVED = "approved"
STATE_REJECTED = "rejected"
STATE_CANCELLED = "cancelled"
STATE_EXPIRED = "expired"
STATE_APPLIED = "applied"

DECIDER_ROLES = ("admin", "superadmin")


def _canonical_hash(payload: dict) -> str:
    """SHA-256 over canonical JSON (sorted keys, separators, no whitespace).
    The payload hash is the mutation's identity — re-deriving it at apply
    time detects any alteration of the proposed payload."""
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Errors (named, fail-closed; consumers surface these, never improvise)
# ---------------------------------------------------------------------------


class ApprovalDomainError(ExposureDomainError):
    """Base class for approval-primitive errors."""


class ApprovalNotFoundError(ApprovalDomainError):
    """The approval does not exist in the requesting tenant (unknown and
    cross-tenant ids are the identical not-found — no disclosure)."""


class ApprovalStateError(ApprovalDomainError):
    """The approval is not in the state the command requires (pending for
    decide/expire, approved for apply)."""


class ApprovalDualControlError(ApprovalDomainError):
    """The approver equals the proposer (HARD dual control) — refused at the
    service layer and again by the migration-021 trigger."""


class ApprovalAuthorityError(ApprovalDomainError):
    """The actor does not hold CURRENT admin/superadmin authority at the
    decision instant (wrong role, inactive membership/user/tenant, or
    authority revoked between decision and apply)."""


class ApprovalAlreadyAppliedError(ApprovalDomainError):
    """A second apply of the same approval — a VISIBLE conflict refusal,
    never silent idempotent absorption."""

    code = "approval_already_applied"


class ApprovalPayloadMismatchError(ApprovalDomainError):
    """The payload re-derived at apply time does not hash to the approved
    payload hash (the proposal was altered after approval)."""


class ApprovalStaleSubjectError(ApprovalDomainError):
    """The subject's current version does not equal the approved snapshot —
    the subject changed after proposal (propose→decide) or after approval
    (decide→apply). The apply fails closed with nothing written."""


class ApprovalSubjectError(ApprovalDomainError, ValueError):
    """The proposal payload failed the consumer's validator at propose time
    (or the subject does not admit the proposal, e.g. a resolved proposal)."""


# ---------------------------------------------------------------------------
# Extension point — consumer registry (NO consumers registered here)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubjectHandler:
    """One registered subject type.

    validate_payload   — callable(cur, tenant_id, subject_id, payload) -> None;
                         raises ApprovalSubjectError (or a subclass of it) on
                         any invalid proposal. Runs inside the propose
                         transaction after the subject version is read, so the
                         validator sees the exact subject state.
    current_version    — callable(cur, tenant_id, subject_id) -> str; returns
                         the subject's opaque version token, or raises
                         ApprovalNotFoundError for unknown/cross-tenant
                         subjects (the primitive never interprets ids).
    rederive_payload   — callable(cur, tenant_id, subject_id, payload_hash) ->
                         dict; re-derives the canonical payload the consumer
                         would propose for the mutation bound to this hash.
                         Must raise ApprovalNotFoundError when the subject is
                         gone and ApprovalPayloadMismatchError when it cannot
                         re-derive a payload for the given hash. The primitive
                         re-hashes what the handler returns and rejects any
                         mismatch — a payload altered after approval can
                         never slip through.
    apply              — callable(conn, tenant_id, *, subject_id, approval,
                                  payload, actor_id, actor_role) -> Any; the
                         consumer's mutation. Runs inside the caller's
                         transaction AFTER the primitive's rechecks and
                         BEFORE the approval is marked applied — the handler
                         and the applied marking commit atomically.
    """

    validate_payload: Callable[..., None]
    current_version: Callable[..., str]
    rederive_payload: Callable[..., dict]
    apply: Callable[..., Any]
    payload_hash: Callable[[dict], str] = _canonical_hash


_REGISTRY: Dict[str, SubjectHandler] = {}


def register_subject_type(subject_type: str, handler: SubjectHandler) -> None:
    """Register a consumer subject type (called by consumers, never here)."""
    if not isinstance(subject_type, str) or not subject_type.strip():
        raise ApprovalSubjectError("subject_type must be a non-empty string")
    if subject_type in _REGISTRY:
        raise ApprovalSubjectError(
            f"subject type {subject_type!r} is already registered"
        )
    _REGISTRY[subject_type] = handler


def get_subject_handler(subject_type: str) -> SubjectHandler:
    handler = _REGISTRY.get(subject_type)
    if handler is None:
        raise ApprovalSubjectError(
            f"subject type {subject_type!r} is not registered with the "
            "approval primitive"
        )
    return handler


def _hash_of(handler: SubjectHandler, payload: dict) -> str:
    return handler.payload_hash(payload)


# ---------------------------------------------------------------------------
# Authority check (Chapter 5 item 1: approver holds CURRENT authority)
# ---------------------------------------------------------------------------


def _require_current_decider_authority(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, actor_id: str, role: str
) -> None:
    """The actor must hold an admin/superadmin membership that is CURRENT at
    the decision instant: active user, active tenant, active membership, and
    the membership role matching the claimed role. Called inside the deciding
    transaction, so a revocation committing before the decision is seen; one
    committing concurrently serializes at the row level (decide re-reads the
    approval FOR UPDATE under the advisory lock)."""
    cur.execute(
        """
        SELECT 1
        FROM users u
        JOIN tenant_memberships m ON m.user_id = u.id AND m.tenant_id = %s
        JOIN tenants t ON t.id = m.tenant_id
        WHERE LOWER(u.email) = LOWER(%s)
          AND u.status = 'active'
          AND t.status = 'active'
          AND m.status = 'active'
          AND m.role = %s
          AND m.role IN ('admin', 'superadmin');
        """,
        (str(tenant_id), actor_id, role),
    )
    if cur.fetchone() is None:
        raise ApprovalAuthorityError(
            f"actor {actor_id!r} does not hold current admin/superadmin "
            f"authority in tenant {tenant_id} (claimed role {role!r})"
        )


# ---------------------------------------------------------------------------
# Audit (same transaction; append-only by migration-021 trigger)
# ---------------------------------------------------------------------------


def _audit(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    approval_id: uuid.UUID,
    action: str,
    actor_id: str,
    actor_role: str,
    details: dict,
) -> None:
    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id, actor_role=actor_role,
        event_name=f"approval.{action}", asset_id=None, details=details,
    )
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO chapter5_approval_audit (
                tenant_id, approval_id, action, actor_id, actor_role, details
            ) VALUES (%s, %s, %s, %s, %s, %s);
            """,
            (str(tenant_id), approval_id, action, actor_id, actor_role,
             json.dumps(details)),
        )


# ---------------------------------------------------------------------------
# Row access
# ---------------------------------------------------------------------------


def _load_approval(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, approval_id: uuid.UUID,
    *, for_update: bool = False,
) -> dict:
    cur.execute(
        "SELECT id, tenant_id, subject_type, subject_id, subject_version, "
        "payload_hash, proposer_id, proposer_role, proposed_at, state, "
        "approver_id, approver_role, decided_at, applied_by, applied_at "
        "FROM chapter5_approvals WHERE tenant_id = %s AND id = %s"
        + (" FOR UPDATE;" if for_update else ";"),
        (str(tenant_id), approval_id),
    )
    row = cur.fetchone()
    if row is None:
        # identical not-found for unknown and cross-tenant ids — the tenant
        # predicate above excluded the foreign row before any disclosure
        raise ApprovalNotFoundError(f"Approval {approval_id} not found")
    return row


def _active_for_subject(
    cur: psycopg.Cursor, tenant_id: uuid.UUID, subject_type: str, subject_id: str
) -> Optional[dict]:
    cur.execute(
        """
        SELECT id, state, payload_hash, subject_version
        FROM chapter5_approvals
        WHERE tenant_id = %s AND subject_type = %s AND subject_id = %s
          AND state IN ('pending', 'approved')
        ORDER BY proposed_at DESC, id
        LIMIT 1;
        """,
        (str(tenant_id), subject_type, subject_id),
    )
    return cur.fetchone()


# ---------------------------------------------------------------------------
# Commands (transaction ownership: caller's; nothing commits here)
# ---------------------------------------------------------------------------


def propose(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    subject_type: str,
    subject_id: str,
    payload: dict,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Propose a mutation of a subject. Captures the subject's CURRENT
    version as the snapshot, hashes the canonical payload, validates the
    payload through the registered handler, and audits — atomically.

    The primitive requires an exact-JSON payload (dict) — the canonical hash
    needs a closed shape; consumers put richer structures inside it."""
    handler = get_subject_handler(subject_type)
    if not isinstance(payload, dict) or not payload:
        raise ApprovalSubjectError(
            "payload must be a non-empty JSON object (closed canonical shape)"
        )
    if not isinstance(subject_id, str) or not subject_id.strip():
        raise ApprovalSubjectError("subject_id must be a non-empty string")
    payload_hash = _hash_of(handler, payload)

    with conn.cursor(row_factory=dict_row) as cur:
        # serialize proposals per subject: one open approval per subject
        _advisory_xact_lock(cur, f"chapter5-approval:{tenant_id}:{subject_type}:{subject_id}")
        standing = _active_for_subject(cur, tenant_id, subject_type, subject_id)
        if standing is not None:
            raise ApprovalStateError(
                f"subject {subject_type}/{subject_id} already has an open "
                f"approval {standing['id']} (state={standing['state']}) — "
                "resolve it before proposing again"
            )
        # the subject's CURRENT version at proposal time (the handler raises
        # ApprovalNotFoundError for unknown/cross-tenant subjects — identical
        # not-found, no disclosure)
        version = handler.current_version(cur, tenant_id, subject_id)
        # consumer payload validation against the exact subject state
        handler.validate_payload(cur, tenant_id, subject_id, payload)

        cur.execute(
            """
            INSERT INTO chapter5_approvals (
                tenant_id, subject_type, subject_id, subject_version,
                payload_hash, proposer_id, proposer_role, state
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')
            RETURNING id, state, subject_version, payload_hash, proposed_at;
            """,
            (str(tenant_id), subject_type, subject_id, version, payload_hash,
             actor_id, actor_role),
        )
        row = cur.fetchone()

    _audit(
        conn, tenant_id, row["id"], "proposed", actor_id, actor_role,
        {
            "subject_type": subject_type,
            "subject_id": subject_id,
            "subject_version": version,
            "payload_hash": payload_hash,
        },
    )
    return dict(row)


def decide(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    approval_id: uuid.UUID,
    *,
    decision: str,
    approver_id: str,
    approver_role: str,
) -> dict:
    """Approve, reject, or cancel a pending approval. EVERY decision requires
    CURRENT admin/superadmin authority at the decision instant and an approver
    who is not the proposer (HARD dual control — cancel included; the
    migration-021 trigger enforces the same invariant at the DB layer). The
    decision, its audit row, and the tenant audit_events mirror commit
    atomically."""
    if decision not in ("approved", "rejected", "cancelled"):
        raise ApprovalStateError(
            f"decision must be 'approved' | 'rejected' | 'cancelled', got {decision!r}"
        )

    handler = None  # loaded lazily; decide does not need the handler
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"chapter5-approval-decide:{tenant_id}:{approval_id}")
        row = _load_approval(cur, tenant_id, approval_id, for_update=True)
        if row["state"] != STATE_PENDING:
            raise ApprovalStateError(
                f"approval {approval_id} is not pending (state={row['state']}) — "
                "only a pending approval can be decided"
            )
        # EVERY decision out of pending — approve, reject, or cancel — is a
        # judgment act recorded with an approver identity: it requires CURRENT
        # decider authority and HARD dual control (approver ≠ proposer; the
        # migration-021 trigger enforces the same at the DB layer). A proposer
        # who wants their proposal gone asks a decider, or lets it expire.
        _require_current_decider_authority(cur, tenant_id, approver_id, approver_role)
        if approver_id == row["proposer_id"]:
            raise ApprovalDualControlError(
                f"self-approval refused: approver {approver_id!r} is the "
                f"proposer of approval {approval_id}"
            )
        cur.execute(
            """
            UPDATE chapter5_approvals
            SET state = %s, approver_id = %s, approver_role = %s, decided_at = now()
            WHERE id = %s AND tenant_id = %s
            RETURNING id, state, decided_at;
            """,
            (decision, approver_id, approver_role, approval_id, str(tenant_id)),
        )
        updated = cur.fetchone()

    _audit(
        conn, tenant_id, approval_id, decision, approver_id, approver_role,
        {
            "subject_type": row["subject_type"],
            "subject_id": row["subject_id"],
            "payload_hash": row["payload_hash"],
            "proposer_id": row["proposer_id"],
        },
    )
    return dict(updated)


def expire(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    approval_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Expire a pending approval (system/operator sweep — e.g. a retention
    policy). Only a pending approval can expire; decided approvals are
    already resolved."""
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"chapter5-approval-decide:{tenant_id}:{approval_id}")
        row = _load_approval(cur, tenant_id, approval_id, for_update=True)
        if row["state"] != STATE_PENDING:
            raise ApprovalStateError(
                f"approval {approval_id} is not pending (state={row['state']}) — "
                "only a pending approval can expire"
            )
        cur.execute(
            """
            UPDATE chapter5_approvals
            SET state = 'expired', approver_id = %s, approver_role = %s,
                decided_at = now()
            WHERE id = %s AND tenant_id = %s
            RETURNING id, state, decided_at;
            """,
            (actor_id, actor_role, approval_id, str(tenant_id)),
        )
        updated = cur.fetchone()

    _audit(
        conn, tenant_id, approval_id, "expired", actor_id, actor_role,
        {
            "subject_type": row["subject_type"],
            "subject_id": row["subject_id"],
            "payload_hash": row["payload_hash"],
        },
    )
    return dict(updated)


def apply_approval(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    approval_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Apply an approved approval: version-verified, atomic, single-use.

    Order inside the caller's transaction:
      1. advisory lock keyed to the subject (serializes apply vs decide vs
         propose vs any concurrent mutation of the same subject);
      2. load the approval FOR UPDATE; not-approved ⇒ ApprovalStateError;
         already-applied ⇒ ApprovalAlreadyAppliedError (visible conflict);
      3. re-derive the payload hash from the handler — a mismatch means the
         proposed payload was altered after approval ⇒ fail closed;
      4. re-read the subject's CURRENT version — a mismatch with the
         approved snapshot means the subject moved after approval ⇒ fail
         closed (nothing written);
      5. run the registered apply handler (the consumer's mutation);
      6. mark applied (applied_by/applied_at written once; the migration-021
         trigger refuses a second apply);
      7. audit in-transaction — audit failure rolls everything back.

    Approver authority at APPLY time: apply executes a mutation the approver
    authorized. If the APPROVER's authority was revoked between decision and
    apply, the primitive refuses: the approver's admin/superadmin membership
    is re-verified here (CURRENT at the apply instant) inside the same
    transaction as the mutation — an approval whose authority lapsed after
    the decision fails closed with nothing written. The EXECUTOR must be the
    approver themself (dual control is preserved end-to-end); an executor who
    is neither approver nor proposer-with-authority cannot apply.
    """
    handler = get_subject_handler(_subject_type_of(conn, tenant_id, approval_id))
    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_xact_lock(cur, f"chapter5-approval-decide:{tenant_id}:{approval_id}")
        approval = _load_approval(cur, tenant_id, approval_id, for_update=True)
        if approval["state"] == STATE_APPLIED:
            raise ApprovalAlreadyAppliedError(
                f"approval {approval_id} was already applied at "
                f"{approval['applied_at'].isoformat()} — single-use by rule"
            )
        if approval["state"] != STATE_APPROVED:
            raise ApprovalStateError(
                f"approval {approval_id} is not approved (state={approval['state']}) — "
                "it cannot be applied"
            )

        # authority revocation between decision and apply: the APPROVER must
        # still hold current decider authority at the apply instant, and the
        # executor must be the approver (who else may execute an authorized
        # mutation is not the proposer's call)
        if actor_id != approval["approver_id"]:
            raise ApprovalAuthorityError(
                f"apply executor {actor_id!r} is not the approver "
                f"{approval['approver_id']!r} of approval {approval_id}"
            )
        _require_current_decider_authority(
            cur, tenant_id, approval["approver_id"], approval["approver_role"]
        )

        # (3) payload re-derivation: the handler re-derives the canonical
        # payload it would apply for this hash from its own subject rows; the
        # primitive re-hashes it — any alteration after approval mismatches.
        rederived = handler.rederive_payload(
            cur, tenant_id, approval["subject_id"], approval["payload_hash"]
        )
        if _hash_of(handler, rederived) != approval["payload_hash"]:
            raise ApprovalPayloadMismatchError(
                f"approval {approval_id} payload no longer hashes to the "
                "approved binding — the proposed payload was altered after "
                "approval; apply fails closed"
            )

        # (4) subject moved since approval ⇒ stale ⇒ nothing written
        current_version = handler.current_version(
            cur, tenant_id, approval["subject_id"]
        )
        if current_version != approval["subject_version"]:
            raise ApprovalStaleSubjectError(
                f"approval {approval_id} is rebased onto different subject "
                f"state (approved snapshot {approval['subject_version']!r}, "
                f"current {current_version!r}) — apply fails closed"
            )

        # run the consumer's mutation (commits atomically with the marking)
        result = handler.apply(
            conn, tenant_id,
            subject_id=approval["subject_id"],
            approval=dict(approval),
            payload=rederived,
            actor_id=actor_id,
            actor_role=actor_role,
        )

        # (6) mark applied — single-use enforced again by the DB trigger
        cur.execute(
            """
            UPDATE chapter5_approvals
            SET state = 'applied', applied_by = %s, applied_at = now()
            WHERE id = %s AND tenant_id = %s
            RETURNING id, state, applied_at;
            """,
            (actor_id, approval_id, str(tenant_id)),
        )
        updated = cur.fetchone()

    _audit(
        conn, tenant_id, approval_id, "applied", actor_id, actor_role,
        {
            "subject_type": approval["subject_type"],
            "subject_id": approval["subject_id"],
            "payload_hash": approval["payload_hash"],
            "approver_id": approval["approver_id"],
        },
    )
    return {"approval": dict(updated), "result": result}


def _subject_type_of(
    conn: psycopg.Connection, tenant_id: uuid.UUID, approval_id: uuid.UUID
) -> str:
    with conn.cursor(row_factory=dict_row) as cur:
        row = _load_approval(cur, tenant_id, approval_id)
    return row["subject_type"]


def decide_and_apply(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    approval_id: uuid.UUID,
    *,
    approver_id: str,
    approver_role: str,
) -> dict:
    """Immediate actions: approve + apply in ONE transaction (Chapter 5 item 1
    allows the atomic pair). The decision commits together with the applied
    mutation or not at all."""
    decision = decide(
        conn, tenant_id, approval_id,
        decision="approved", approver_id=approver_id, approver_role=approver_role,
    )
    applied = apply_approval(
        conn, tenant_id, approval_id,
        actor_id=approver_id, actor_role=approver_role,
    )
    return {"decision": decision, "apply": applied}


# ---------------------------------------------------------------------------
# Read helpers (tenant-scoped; no locks)
# ---------------------------------------------------------------------------


def get_approval(
    conn: psycopg.Connection, tenant_id: uuid.UUID, approval_id: uuid.UUID
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        return dict(_load_approval(cur, tenant_id, approval_id))


def list_approvals_for_subject(
    conn: psycopg.Connection, tenant_id: uuid.UUID,
    subject_type: str, subject_id: str,
) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, subject_type, subject_id, subject_version, payload_hash,
                   proposer_id, proposer_role, proposed_at, state,
                   approver_id, approver_role, decided_at, applied_by, applied_at
            FROM chapter5_approvals
            WHERE tenant_id = %s AND subject_type = %s AND subject_id = %s
            ORDER BY proposed_at DESC, id;
            """,
            (str(tenant_id), subject_type, subject_id),
        )
        return cur.fetchall()


def list_open_approvals(
    conn: psycopg.Connection, tenant_id: uuid.UUID
) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, subject_type, subject_id, subject_version, payload_hash,
                   proposer_id, proposer_role, proposed_at, state
            FROM chapter5_approvals
            WHERE tenant_id = %s AND state IN ('pending', 'approved')
            ORDER BY proposed_at ASC, id;
            """,
            (str(tenant_id),),
        )
        return cur.fetchall()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
