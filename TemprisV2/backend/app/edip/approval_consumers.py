# backend/app/edip/approval_consumers.py
"""
EDIP's consumer wiring for the Chapter 5 dual-control primitive (PRD-000
v1.11 Ch.8 rule 8 — "Accepted Risk is dual-control — decided"; Appendix C
Q11's locked use list). Exactly ONE subject type is registered here; this
module adds NO second approval store, table, or workflow.

  ``edip_accepted_risk`` — accepting risk on a standing EDIP decision. The
  apply inserts a NEW decision revision in ``accepted_risk`` state carrying
  the approved rationale/mitigation type, the MANDATORY review date, and a
  FRESH sealed score snapshot (PATCH-13: each score-consuming decision
  revision gets its own immutable payload — never the original handoff
  score), then replaces the prior revision.

Subject-version token (opaque to the primitive):
    f"{decision.xmin}:{exposure.xmin}" — any mutation of the decision row
    (a review-expiry materialization included) or of the exposure row moves
    the token, so the apply's version recheck fails closed.

The canonical payload is re-derived at apply time from the consumer-side
binding row (``edip_accepted_risk_bindings``, migration 030 — the P0-08
override-binding pattern): the primitive stores only the payload HASH, so
the binding row written in the propose transaction is what makes the
approved payload reproducible. The review date renders through the
instant-stable canonical form shared with the service.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from psycopg.rows import dict_row

from app.approvals import (
    ApprovalNotFoundError,
    ApprovalPayloadMismatchError,
    ApprovalStaleSubjectError,
    ApprovalSubjectError,
    SubjectHandler,
    _canonical_hash,
    register_subject_type,
)
from app.audit import record_audit_event
from app.edip.service import _canonical_due_at

SUBJECT_EDIP_ACCEPTED_RISK = "edip_accepted_risk"

# The branch-from edge set is owned by the service (single source of truth).
from app.edip.service import ACCEPT_FROM  # noqa: E402


def canonical_accept_payload(
    rationale: str, review_due_at: datetime, mitigation_type: Optional[str]
) -> dict:
    """The canonical accepted-risk payload. Callers MUST propose with exactly
    this payload so the approved hash matches the apply-time re-derivation."""
    payload = {
        "rationale": rationale,
        "review_due_at": _canonical_due_at(review_due_at),
    }
    if mitigation_type is not None:
        payload["mitigation_type"] = mitigation_type
    return payload


# ---------------------------------------------------------------------------
# Subject version + payload validation (propose time)
# ---------------------------------------------------------------------------


def _accepted_risk_version(cur, tenant_id: uuid.UUID, subject_id: str) -> str:
    cur.execute(
        """
        SELECT d.xmin::text AS decision_rev, d.exposure_id, e.xmin::text AS exposure_rev
        FROM edip_decisions d
        JOIN asset_exposures e
          ON e.tenant_id = d.tenant_id AND e.id = d.exposure_id
        WHERE d.tenant_id = %s AND d.id = %s;
        """,
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"decision {subject_id} not found")
    return f"{row['decision_rev']}:{row['exposure_rev']}"


def _validate_accepted_risk(cur, tenant_id, subject_id, payload) -> None:
    if set(payload) - {"rationale", "review_due_at", "mitigation_type"} or \
            "rationale" not in payload or "review_due_at" not in payload:
        raise ApprovalSubjectError(
            "accepted-risk payload must be exactly "
            "{rationale, review_due_at[, mitigation_type]} — propose through "
            "the EDIP accept-risk flow"
        )
    if not isinstance(payload.get("rationale"), str) or not payload["rationale"].strip():
        raise ApprovalSubjectError("accepted-risk rationale is mandatory")
    if not isinstance(payload.get("review_due_at"), str):
        raise ApprovalSubjectError("review_due_at must be an ISO-8601 instant")
    try:
        due = datetime.fromisoformat(payload["review_due_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalSubjectError("review_due_at is not a valid ISO-8601 instant") from exc
    if due <= datetime.now(timezone.utc):
        raise ApprovalSubjectError("review_due_at must be in the future")

    cur.execute(
        """
        SELECT d.state, d.replaced_at, e.status AS exposure_status
        FROM edip_decisions d
        JOIN asset_exposures e
          ON e.tenant_id = d.tenant_id AND e.id = d.exposure_id
        WHERE d.tenant_id = %s AND d.id = %s;
        """,
        (str(tenant_id), subject_id),
    )
    row = cur.fetchone()
    if row is None:
        raise ApprovalNotFoundError(f"decision {subject_id} not found")
    if row["replaced_at"] is not None:
        raise ApprovalSubjectError(
            f"decision {subject_id} has been replaced by a newer revision"
        )
    if row["state"] not in ACCEPT_FROM:
        raise ApprovalSubjectError(
            f"accepted risk is not available from state {row['state']}"
        )
    if row["exposure_status"] != "confirmed":
        raise ApprovalSubjectError(
            "accepted risk requires a CURRENT confirmed exposure"
        )


# ---------------------------------------------------------------------------
# Payload re-derivation (apply time — detects post-approval alteration)
# ---------------------------------------------------------------------------


def _rederive_accepted_risk(cur, tenant_id, subject_id, payload_hash) -> dict:
    """Rebuild the canonical payload from the LATEST binding row for this
    decision; the primitive re-hashes it — any post-approval alteration of
    the binding mismatches and fails closed."""
    cur.execute(
        """
        SELECT rationale, review_due_at, mitigation_type
        FROM edip_accepted_risk_bindings
        WHERE tenant_id = %s AND decision_id = %s
        ORDER BY created_at DESC, id DESC
        LIMIT 1;
        """,
        (str(tenant_id), subject_id),
    )
    binding = cur.fetchone()
    if binding is None:
        raise ApprovalPayloadMismatchError(
            f"decision {subject_id}: no accepted-risk binding row re-derives "
            "the approved payload"
        )
    rederived = canonical_accept_payload(
        binding["rationale"], binding["review_due_at"], binding["mitigation_type"]
    )
    if _canonical_hash(rederived) != payload_hash:
        raise ApprovalPayloadMismatchError(
            f"decision {subject_id}: the accepted-risk binding no longer "
            "hashes to the approved payload"
        )
    return rederived


# ---------------------------------------------------------------------------
# Apply handler (runs INSIDE the caller's transaction, after the primitive's
# payload-hash + subject-version rechecks)
# ---------------------------------------------------------------------------


def _apply_accepted_risk(
    conn, tenant_id, *, subject_id, approval, payload, actor_id, actor_role
):
    from app.edip.service import (  # local import: service imports this module's canonical payload
        _DECISION_COLUMNS,
        _advisory_lock_by_decision,
        _replace_revision,
        seal_score_snapshot,
    )

    with conn.cursor(row_factory=dict_row) as cur:
        _advisory_lock_by_decision(cur, tenant_id, uuid.UUID(subject_id))
        cur.execute(
            f"""
            SELECT {_DECISION_COLUMNS} FROM edip_decisions
            WHERE tenant_id = %s AND id = %s FOR UPDATE;
            """,
            (str(tenant_id), subject_id),
        )
        decision = cur.fetchone()
        if decision is None:
            raise ApprovalNotFoundError(f"decision {subject_id} not found")
        if decision["replaced_at"] is not None:
            raise ApprovalStaleSubjectError(
                f"decision {subject_id} was replaced by a newer revision — "
                "apply fails closed"
            )
        if decision["state"] not in ACCEPT_FROM:
            raise ApprovalStaleSubjectError(
                f"decision {subject_id} moved to state {decision['state']} "
                "after approval — apply fails closed"
            )

        # subject-version recheck (defense in depth — the primitive rechecked
        # already; the advisory lock order here re-reads under our lock)
        current_version = _accepted_risk_version(cur, tenant_id, subject_id)
        if current_version != approval["subject_version"]:
            raise ApprovalStaleSubjectError(
                f"accepted-risk snapshot moved (approved "
                f"{approval['subject_version']!r}, now {current_version!r}) — "
                "apply fails closed"
            )

        due = datetime.fromisoformat(payload["review_due_at"].replace("Z", "+00:00"))
        as_of = datetime.now(timezone.utc)
        snapshot = seal_score_snapshot(
            conn, tenant_id, decision["exposure_id"], as_of=as_of
        )

        new_id = uuid.uuid4()
        # stamp the prior revision first (the one-current-per-exposure
        # partial unique index cannot hold both rows at once)
        _replace_revision(cur, tenant_id, decision, new_id)
        cur.execute(
            f"""
            INSERT INTO edip_decisions (
                id, tenant_id, exposure_id, decision_group_id, revision,
                supersedes_id, previous_decision_id, handoff_id, decision_type,
                state, owner, rationale, plan, due_at, review_due_at,
                mitigation_type, consumed_snapshot, snapshot_as_of,
                created_by, created_role
            ) VALUES (
                %s, %s, %s, %s, %s + 1, %s, %s, %s, 'accept-risk',
                'accepted_risk', %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s
            )
            RETURNING {_DECISION_COLUMNS};
            """,
            (
                str(new_id), str(tenant_id), str(decision["exposure_id"]),
                str(decision["decision_group_id"]), decision["revision"],
                str(decision["id"]),
                str(decision["previous_decision_id"]) if decision["previous_decision_id"] else None,
                str(decision["handoff_id"]) if decision["handoff_id"] else None,
                decision["owner"], payload["rationale"], decision["plan"],
                decision["due_at"], due, payload.get("mitigation_type"),
                json.dumps(snapshot), as_of, actor_id, actor_role,
            ),
        )
        cur.fetchone()

        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="edip.accepted_risk_applied",
            asset_id=None,
            details={
                "decision_id": str(new_id),
                "exposure_id": str(decision["exposure_id"]),
                "prior_revision": str(decision["id"]),
                "approval_id": str(approval["id"]),
                "approver_id": approval["approver_id"],
                "review_due_at": payload["review_due_at"],
                "snapshot_as_of": as_of.isoformat(),
            },
        )
        return {
            "decision_id": str(new_id),
            "exposure_id": str(decision["exposure_id"]),
            "state": "accepted_risk",
        }


def register() -> None:
    register_subject_type(SUBJECT_EDIP_ACCEPTED_RISK, SubjectHandler(
        validate_payload=_validate_accepted_risk,
        current_version=_accepted_risk_version,
        rederive_payload=_rederive_accepted_risk,
        apply=_apply_accepted_risk,
    ))


register()
