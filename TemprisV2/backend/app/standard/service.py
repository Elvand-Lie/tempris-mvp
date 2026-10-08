# backend/app/standard/service.py
"""
Service layer for STANDARD / GRC (PRD-000 v1.11 Ch.9).

Transaction ownership: no command commits or rolls back — the caller (route)
owns the boundary. Incident commands serialize on an advisory lock keyed to
the incident (the same concurrency boundary as edits, evaluations, and
resolution — PATCH-11's commit-time revision check is that lock plus a
current-revision re-read inside it).

This module NEVER writes findings, asset_exposures, or any score-bearing
state (frozen decision 1) — the boundary is structural, and the test suite
asserts it end-to-end.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import psycopg
from psycopg.rows import dict_row

from app.audit import record_audit_event, verify_tenant_audit_chain
from app.edip.service import _advisory_xact_lock
from app.standard.errors import (
    StandardConflictError,
    StandardNotFoundError,
    StandardWorkflowError,
)

ASSESSMENT_STATUSES = ("compliant", "partial", "non_compliant")
EVIDENCE_MEDIA_TYPES = (
    "application/pdf", "text/plain", "text/csv", "application/json", "image/png",
)
EVIDENCE_MAX_BYTES = 8 * 1024 * 1024
SIGNOFF_CAPACITIES = ("end_user", "pic")
UNFINISHED_EVALUATION_STATES = ("pending", "evaluation_error", "manual_review_required")
OPEN_OBLIGATION_STATES = ("open", "in_progress")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Governance substrate: frameworks / controls / assessments
# ---------------------------------------------------------------------------


def list_frameworks(conn: psycopg.Connection, tenant_id: uuid.UUID) -> list[dict]:
    """The reference catalogs with the tenant's per-control assessed status
    and the ONLY framework metric: compliance_among_assessed, always rendered
    WITH its assessment coverage (frozen decision 5 — a bare percentage is
    forbidden; one assessed control must never read as total compliance)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT f.framework_code, f.name, f.description,
                   c.id AS control_id, c.control_code, c.title AS control_title,
                   c.description AS control_description,
                   a.id AS assessment_id, a.state AS assessment_state,
                   a.status AS assessment_status, a.notes AS assessment_notes,
                   a.end_user_signoff_by, a.end_user_signoff_at,
                   a.pic_signoff_by, a.pic_signoff_at,
                   a.signed_at AS assessment_signed_at,
                   a.updated_at AS assessment_updated_at
            FROM standard_frameworks f
            JOIN standard_controls c
              ON c.framework_code = f.framework_code
            LEFT JOIN standard_control_assessments a
              ON a.control_id = c.id AND a.tenant_id = %s AND a.state <> 'archived'
            ORDER BY f.framework_code, c.control_code;
            """,
            (str(tenant_id),),
        )
        rows = cur.fetchall()

    frameworks: dict[str, dict] = {}
    for row in rows:
        fw = frameworks.setdefault(row["framework_code"], {
            "framework_code": row["framework_code"],
            "name": row["name"],
            "description": row["description"],
            "controls": [],
        })
        assessed = row["assessment_state"] == "signed" and row["assessment_status"] is not None
        has_live = row["assessment_id"] is not None
        fw["controls"].append({
            "control_id": row["control_id"],
            "control_code": row["control_code"],
            "title": row["control_title"],
            "description": row["control_description"],
            "assessment_id": row["assessment_id"],
            "assessment_state": row["assessment_state"],
            "status": row["assessment_status"] if assessed else "not_assessed",
            # The saved draft truth: a pending draft is NOT signed compliance.
            "saved_status": row["assessment_status"] if has_live else None,
            "saved_notes": row["assessment_notes"] if has_live else None,
            "assessment_updated_at": row["assessment_updated_at"] if has_live else None,
            "assessment_signed_at": row["assessment_signed_at"] if has_live else None,
            "signoffs": {
                "end_user": {
                    "by": row["end_user_signoff_by"],
                    "at": row["end_user_signoff_at"],
                },
                "pic": {
                    "by": row["pic_signoff_by"],
                    "at": row["pic_signoff_at"],
                },
            } if has_live else None,
        })

    for fw in frameworks.values():
        total = len(fw["controls"])
        counts = {"compliant": 0, "partial": 0, "non_compliant": 0, "not_assessed": 0}
        for control in fw["controls"]:
            counts[control["status"]] += 1
        assessed = total - counts["not_assessed"]
        if assessed > 0:
            metric = (counts["compliant"] + 0.5 * counts["partial"]) / assessed * 100
            coverage = f"{round(metric, 2)}% among assessed · {assessed}/{total} assessed"
        else:
            metric = None
            coverage = f"not assessed · 0/{total} assessed"
        fw["compliance"] = {
            # compliance_among_assessed is the ONLY framework metric — never
            # full-framework compliance (frozen decision 5)
            "compliance_among_assessed": metric,
            "assessed": assessed,
            "total": total,
            "compliant": counts["compliant"],
            "partial": counts["partial"],
            "non_compliant": counts["non_compliant"],
            "not_assessed": counts["not_assessed"],
            # every percentage renders with its coverage — never bare
            "rendering": coverage,
        }
    return list(frameworks.values())


def create_assessment(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    control_id: uuid.UUID,
    status: str,
    notes: Optional[str],
    actor_id: str,
    actor_role: str,
) -> dict:
    if status not in ASSESSMENT_STATUSES:
        raise StandardWorkflowError(
            f"unknown assessment status {status!r} — expected one of "
            f"{list(ASSESSMENT_STATUSES)}"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, framework_code FROM standard_controls WHERE id = %s;",
            (str(control_id),),
        )
        if cur.fetchone() is None:
            raise StandardNotFoundError(f"Control {control_id} not found")
        cur.execute(
            """
            SELECT id FROM standard_control_assessments
            WHERE tenant_id = %s AND control_id = %s AND state <> 'archived';
            """,
            (str(tenant_id), str(control_id)),
        )
        standing = cur.fetchone()
        if standing is not None:
            raise StandardConflictError(
                f"Control {control_id} already has a live assessment "
                f"({standing['id']}) — archive it first"
            )
        cur.execute(
            """
            INSERT INTO standard_control_assessments (
                tenant_id, control_id, status, notes, created_by
            ) VALUES (%s, %s, %s, %s, %s)
            RETURNING id, tenant_id, control_id, state, status, notes,
                      end_user_signoff_by, end_user_signoff_at,
                      pic_signoff_by, pic_signoff_at, signed_at, archived_at,
                      created_by, created_at;
            """,
            (str(tenant_id), str(control_id), status, notes, actor_id),
        )
        row = dict(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.assessment_created",
            asset_id=None,
            details={"assessment_id": str(row["id"]), "control_id": str(control_id),
                     "status": status},
        )
        return row


def signoff_assessment(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
    *,
    capacity: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    """One sign-off capacity per actor: the end_user/PIC dual sign-off with
    two DIFFERENT actors (DB CHECK + service guard). The second sign-off
    completes the assessment (draft → signed)."""
    if capacity not in SIGNOFF_CAPACITIES:
        raise StandardWorkflowError(
            f"unknown sign-off capacity {capacity!r} — expected one of "
            f"{list(SIGNOFF_CAPACITIES)}"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, state, status, end_user_signoff_by, pic_signoff_by
            FROM standard_control_assessments
            WHERE tenant_id = %s AND id = %s FOR UPDATE;
            """,
            (str(tenant_id), str(assessment_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardNotFoundError(f"Assessment {assessment_id} not found")
        if row["state"] != "draft":
            raise StandardConflictError(
                f"Assessment {assessment_id} is not draft (state={row['state']})"
            )
        other = (
            row["pic_signoff_by"] if capacity == "end_user" else row["end_user_signoff_by"]
        )
        if other is not None and other == actor_id:
            raise StandardConflictError(
                "Dual sign-off requires two different actors — the same "
                f"actor cannot hold both capacities (already signed as {other!r})"
            )
        # compute the post-sign-off shape in Python: UPDATE SET expressions
        # evaluate against the OLD row, so a conditional SET cannot see the
        # value being written in the same statement
        new_end_user = actor_id if capacity == "end_user" else row["end_user_signoff_by"]
        new_pic = actor_id if capacity == "pic" else row["pic_signoff_by"]
        completes = (
            new_end_user is not None and new_pic is not None and new_end_user != new_pic
        )
        cur.execute(
            """
            UPDATE standard_control_assessments
            SET end_user_signoff_by = %s,
                end_user_signoff_at = CASE WHEN %s THEN now()
                                           ELSE end_user_signoff_at END,
                pic_signoff_by = %s,
                pic_signoff_at = CASE WHEN %s THEN now()
                                      ELSE pic_signoff_at END,
                state = %s,
                signed_at = CASE WHEN %s THEN now() ELSE signed_at END,
                updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state = 'draft'
            RETURNING id, tenant_id, control_id, state, status,
                      end_user_signoff_by, end_user_signoff_at,
                      pic_signoff_by, pic_signoff_at, signed_at;
            """,
            (
                new_end_user,
                capacity == "end_user",
                new_pic,
                capacity == "pic",
                "signed" if completes else "draft",
                completes,
                str(tenant_id), str(assessment_id),
            ),
        )
        updated = cur.fetchone()
        if updated is None:
            raise StandardConflictError(
                f"Assessment {assessment_id} moved concurrently; retry"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.assessment_signed",
            asset_id=None,
            details={
                "assessment_id": str(assessment_id),
                "capacity": capacity,
                "state": updated["state"],
            },
        )
        return dict(updated)


def archive_assessment(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE standard_control_assessments
            SET state = 'archived', archived_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state <> 'archived'
            RETURNING id, state, archived_at;
            """,
            (str(tenant_id), str(assessment_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardNotFoundError(
                f"Assessment {assessment_id} not found (or already archived)"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.assessment_archived",
            asset_id=None, details={"assessment_id": str(assessment_id)},
        )
        return dict(row)


def reassess_control(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    control_id: uuid.UUID,
    status: str,
    notes: Optional[str],
    actor_id: str,
    actor_role: str,
) -> dict:
    """ATOMIC reassessment: validate → archive the live assessment → create
    the replacement, all in the caller's transaction. Any failure raises
    before the route commits, so the previous assessment (with its sign-off
    and evidence history) survives untouched."""
    if status not in ASSESSMENT_STATUSES:
        raise StandardWorkflowError(
            f"unknown assessment status {status!r} — expected one of "
            f"{list(ASSESSMENT_STATUSES)}"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, framework_code FROM standard_controls WHERE id = %s;",
            (str(control_id),),
        )
        control = cur.fetchone()
        if control is None:
            raise StandardNotFoundError(f"Control {control_id} not found")
        cur.execute(
            """
            SELECT id FROM standard_control_assessments
            WHERE tenant_id = %s AND control_id = %s AND state <> 'archived'
            FOR UPDATE;
            """,
            (str(tenant_id), str(control_id)),
        )
        standing = cur.fetchone()
        if standing is None:
            raise StandardNotFoundError(
                f"Control {control_id} has no live assessment to reassess — "
                "create one instead"
            )
        cur.execute(
            """
            UPDATE standard_control_assessments
            SET state = 'archived', archived_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state <> 'archived'
            RETURNING id;
            """,
            (str(tenant_id), str(standing["id"])),
        )
        archived = cur.fetchone()
        cur.execute(
            """
            INSERT INTO standard_control_assessments (
                tenant_id, control_id, status, notes, created_by
            ) VALUES (%s, %s, %s, %s, %s)
            RETURNING id, tenant_id, control_id, state, status, notes,
                      end_user_signoff_by, end_user_signoff_at,
                      pic_signoff_by, pic_signoff_at, signed_at, archived_at,
                      created_by, created_at;
            """,
            (str(tenant_id), str(control_id), status, notes, actor_id),
        )
        row = dict(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.assessment_reassessed",
            asset_id=None,
            details={
                "assessment_id": str(row["id"]),
                "archived_assessment_id": str(archived["id"]),
                "control_id": str(control_id),
                "status": status,
            },
        )
        return row


# ---------------------------------------------------------------------------
# Policies — registry + archive/supersede versioning
# ---------------------------------------------------------------------------


def create_policy(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    title: str,
    body: str,
    supersedes_id: Optional[uuid.UUID],
    actor_id: str,
    actor_role: str,
) -> dict:
    if not title.strip() or not body.strip():
        raise StandardWorkflowError("policy title and body are mandatory")
    with conn.cursor(row_factory=dict_row) as cur:
        group_id = uuid.uuid4()
        version = 1
        if supersedes_id is not None:
            cur.execute(
                """
                SELECT id, policy_group_id, version FROM standard_policies
                WHERE tenant_id = %s AND id = %s;
                """,
                (str(tenant_id), str(supersedes_id)),
            )
            prior = cur.fetchone()
            if prior is None:
                raise StandardNotFoundError(f"Policy {supersedes_id} not found")
            group_id = prior["policy_group_id"]
            version = prior["version"] + 1
        cur.execute(
            """
            INSERT INTO standard_policies (
                tenant_id, policy_group_id, version, title, body, state,
                supersedes_id, created_by
            ) VALUES (%s, %s, %s, %s, %s, 'draft', %s, %s)
            RETURNING id, tenant_id, policy_group_id, version, title, state,
                      supersedes_id, created_by, created_at;
            """,
            (str(tenant_id), str(group_id), version, title.strip(), body,
             str(supersedes_id) if supersedes_id else None, actor_id),
        )
        row = dict(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.policy_created",
            asset_id=None,
            details={"policy_id": str(row["id"]), "version": version},
        )
        return row


def activate_policy(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    policy_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """draft → active; any other ACTIVE policy in the same versioning family
    supersedes atomically (registry + archive/supersede versioning)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, policy_group_id, state FROM standard_policies "
            "WHERE tenant_id = %s AND id = %s FOR UPDATE;",
            (str(tenant_id), str(policy_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardNotFoundError(f"Policy {policy_id} not found")
        if row["state"] != "draft":
            raise StandardConflictError(
                f"Policy {policy_id} is not draft (state={row['state']})"
            )
        cur.execute(
            """
            UPDATE standard_policies
            SET state = 'superseded', superseded_at = now(), updated_at = now()
            WHERE tenant_id = %s AND policy_group_id = %s AND state = 'active';
            """,
            (str(tenant_id), str(row["policy_group_id"])),
        )
        cur.execute(
            """
            UPDATE standard_policies
            SET state = 'active', updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state = 'draft'
            RETURNING id, policy_group_id, version, title, state;
            """,
            (str(tenant_id), str(policy_id)),
        )
        updated = cur.fetchone()
        if updated is None:
            raise StandardConflictError(f"Policy {policy_id} moved concurrently; retry")
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.policy_activated",
            asset_id=None, details={"policy_id": str(policy_id)},
        )
        return dict(updated)


def archive_policy(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    policy_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE standard_policies
            SET state = 'archived', archived_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state <> 'archived'
            RETURNING id, state, archived_at;
            """,
            (str(tenant_id), str(policy_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardNotFoundError(
                f"Policy {policy_id} not found (or already archived)"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.policy_archived",
            asset_id=None, details={"policy_id": str(policy_id)},
        )
        return dict(row)


def list_policies(conn: psycopg.Connection, tenant_id: uuid.UUID) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, policy_group_id, version, title, body, state,
                   supersedes_id, superseded_at, archived_at, created_by, created_at
            FROM standard_policies
            WHERE tenant_id = %s
            ORDER BY policy_group_id, version DESC;
            """,
            (str(tenant_id),),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Control evidence — typed inline store; EDIP mapping BY REFERENCE
# ---------------------------------------------------------------------------


def attach_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    control_id: uuid.UUID,
    assessment_id: Optional[uuid.UUID],
    edip_verification_id: Optional[uuid.UUID],
    title: str,
    media_type: str,
    content: bytes,
    actor_id: str,
    actor_role: str,
) -> dict:
    if media_type not in EVIDENCE_MEDIA_TYPES:
        raise StandardWorkflowError(
            f"media_type {media_type!r} is not in the allowlist "
            f"{list(EVIDENCE_MEDIA_TYPES)}"
        )
    if not content or len(content) > EVIDENCE_MAX_BYTES:
        raise StandardWorkflowError(
            f"evidence content must be 1 byte to {EVIDENCE_MAX_BYTES} bytes"
        )
    if not title.strip():
        raise StandardWorkflowError("evidence title is mandatory")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id FROM standard_controls WHERE id = %s;", (str(control_id),)
        )
        if cur.fetchone() is None:
            raise StandardNotFoundError(f"Control {control_id} not found")
        if assessment_id is not None:
            cur.execute(
                """
                SELECT id, control_id FROM standard_control_assessments
                WHERE tenant_id = %s AND id = %s;
                """,
                (str(tenant_id), str(assessment_id)),
            )
            row = cur.fetchone()
            if row is None:
                raise StandardNotFoundError(f"Assessment {assessment_id} not found")
            if str(row["control_id"]) != str(control_id):
                raise StandardWorkflowError(
                    "Assessment does not belong to this control"
                )
        # EDIP remediation evidence maps BY REFERENCE — same-tenant,
        # existence-checked, never re-scored (frozen decision 6; a citation
        # of an unknown record is refused, never silently accepted)
        if edip_verification_id is not None:
            cur.execute(
                "SELECT id FROM edip_verifications WHERE tenant_id = %s AND id = %s;",
                (str(tenant_id), str(edip_verification_id)),
            )
            if cur.fetchone() is None:
                raise StandardNotFoundError(
                    f"EDIP verification {edip_verification_id} not found in "
                    "this tenant"
                )
        sha256 = hashlib.sha256(content).hexdigest()
        cur.execute(
            """
            INSERT INTO standard_control_evidence (
                tenant_id, control_id, assessment_id, edip_verification_id,
                title, media_type, content, size_bytes, sha256, uploaded_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, tenant_id, control_id, assessment_id,
                      edip_verification_id, title, media_type, size_bytes,
                      sha256, uploaded_by, created_at;
            """,
            (
                str(tenant_id), str(control_id),
                str(assessment_id) if assessment_id else None,
                str(edip_verification_id) if edip_verification_id else None,
                title.strip(), media_type, psycopg.Binary(content),
                len(content), sha256, actor_id,
            ),
        )
        row = dict(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.evidence_attached",
            asset_id=None,
            details={
                "evidence_id": str(row["id"]),
                "control_id": str(control_id),
                "media_type": media_type,
                "sha256": sha256,
                "edip_verification_id":
                    str(edip_verification_id) if edip_verification_id else None,
            },
        )
        return row


def download_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    evidence_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
    audit_event: str = "standard.evidence_downloaded",
) -> dict:
    """Evidence/artifact download is one of the audited reads (Appendix C
    Q12) — the audit event commits in the same transaction. The preview
    endpoint reuses this audited read under its own event name."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, control_id, title, media_type, content, size_bytes,
                   sha256, uploaded_by, created_at
            FROM standard_control_evidence
            WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), str(evidence_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardNotFoundError(f"Evidence {evidence_id} not found")
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name=audit_event,
            asset_id=None,
            details={"evidence_id": str(evidence_id), "sha256": row["sha256"]},
        )
        return dict(row)


def list_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    control_id: Optional[uuid.UUID],
    include_withdrawn: bool = False,
) -> list[dict]:
    """Withdrawn attachments are tombstoned, not deleted: excluded from the
    default (current-evidence) view, retained for authorized audit access via
    include_withdrawn=true."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, control_id, assessment_id, edip_verification_id, title,
                   media_type, size_bytes, sha256, uploaded_by, created_at,
                   withdrawn_at, withdrawn_by, withdrawn_reason,
                   replaces_evidence_id
            FROM standard_control_evidence
            WHERE tenant_id = %s
              AND (%s::uuid IS NULL OR control_id = %s::uuid)
              AND (%s OR withdrawn_at IS NULL)
            ORDER BY created_at DESC;
            """,
            (str(tenant_id),
             str(control_id) if control_id else None,
             str(control_id) if control_id else None,
             include_withdrawn),
        )
        return [dict(r) for r in cur.fetchall()]


def _get_editable_evidence(cur, tenant_id: uuid.UUID, evidence_id: uuid.UUID) -> dict:
    """Fetch evidence with its assessment state; evidence linked to a signed
    (or archived) assessment is immutable historical proof."""
    cur.execute(
        """
        SELECT e.id, e.control_id, e.assessment_id, e.edip_verification_id,
               e.title, e.sha256, a.state AS assessment_state
        FROM standard_control_evidence e
        LEFT JOIN standard_control_assessments a
          ON a.id = e.assessment_id AND a.tenant_id = e.tenant_id
        WHERE e.tenant_id = %s AND e.id = %s
        FOR UPDATE OF e;
        """,
        (str(tenant_id), str(evidence_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise StandardNotFoundError(f"Evidence {evidence_id} not found")
    if row["assessment_state"] in ("signed", "archived"):
        raise StandardConflictError(
            f"Evidence {evidence_id} belongs to a {row['assessment_state']} "
            "assessment and is immutable historical proof — record a new "
            "assessment cycle to supersede it"
        )
    return dict(row)


def withdraw_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    evidence_id: uuid.UUID,
    *,
    reason: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    if not reason.strip():
        raise StandardWorkflowError("a withdrawal reason is mandatory")
    with conn.cursor(row_factory=dict_row) as cur:
        evidence = _get_editable_evidence(cur, tenant_id, evidence_id)
        cur.execute(
            """
            UPDATE standard_control_evidence
            SET withdrawn_at = now(), withdrawn_by = %s, withdrawn_reason = %s
            WHERE tenant_id = %s AND id = %s AND withdrawn_at IS NULL
            RETURNING id, control_id, withdrawn_at, withdrawn_by;
            """,
            (actor_id, reason.strip(), str(tenant_id), str(evidence_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardConflictError(f"Evidence {evidence_id} is already withdrawn")
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.evidence_withdrawn",
            asset_id=None,
            details={
                "evidence_id": str(evidence_id),
                "reason": reason.strip(),
                "sha256": evidence["sha256"],
            },
        )
        return dict(row)


def restore_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    evidence_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Clear a withdrawal tombstone (draft-controlled evidence only). The row
    was never deleted, so restoring just drops the tombstone; the audit trail
    keeps both the withdrawal and the restoration."""
    with conn.cursor(row_factory=dict_row) as cur:
        evidence = _get_editable_evidence(cur, tenant_id, evidence_id)
        cur.execute(
            """
            UPDATE standard_control_evidence
            SET withdrawn_at = NULL, withdrawn_by = NULL, withdrawn_reason = NULL
            WHERE tenant_id = %s AND id = %s AND withdrawn_at IS NOT NULL
            RETURNING id, control_id;
            """,
            (str(tenant_id), str(evidence_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardConflictError(f"Evidence {evidence_id} is not withdrawn")
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.evidence_restored",
            asset_id=None,
            details={"evidence_id": str(evidence_id), "sha256": evidence["sha256"]},
        )
        return dict(row)


def replace_evidence(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    evidence_id: uuid.UUID,
    *,
    title: str,
    media_type: str,
    content: bytes,
    reason: Optional[str],
    actor_id: str,
    actor_role: str,
) -> dict:
    """Versioned replacement: the new attachment records replaces_evidence_id,
    the old one is tombstoned (never deleted). Control/assessment/EDIP links
    are inherited from the replaced row so EDIP references stay valid."""
    if media_type not in EVIDENCE_MEDIA_TYPES:
        raise StandardWorkflowError(
            f"media_type {media_type!r} is not in the allowlist "
            f"{list(EVIDENCE_MEDIA_TYPES)}"
        )
    if not content or len(content) > EVIDENCE_MAX_BYTES:
        raise StandardWorkflowError(
            f"evidence content must be 1 byte to {EVIDENCE_MAX_BYTES} bytes"
        )
    if not title.strip():
        raise StandardWorkflowError("evidence title is mandatory")
    with conn.cursor(row_factory=dict_row) as cur:
        old = _get_editable_evidence(cur, tenant_id, evidence_id)
        if old["assessment_state"] is not None and old["assessment_state"] != "draft":
            raise StandardConflictError(
                f"Evidence {evidence_id} belongs to a {old['assessment_state']} "
                "assessment and is immutable historical proof"
            )
        sha256 = hashlib.sha256(content).hexdigest()
        cur.execute(
            """
            INSERT INTO standard_control_evidence (
                tenant_id, control_id, assessment_id, edip_verification_id,
                title, media_type, content, size_bytes, sha256, uploaded_by,
                replaces_evidence_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, tenant_id, control_id, assessment_id,
                      edip_verification_id, title, media_type, size_bytes,
                      sha256, uploaded_by, created_at, replaces_evidence_id;
            """,
            (
                str(tenant_id), str(old["control_id"]), old["assessment_id"],
                old["edip_verification_id"], title.strip(), media_type,
                psycopg.Binary(content), len(content), sha256, actor_id,
                str(evidence_id),
            ),
        )
        new_row = dict(cur.fetchone())
        cur.execute(
            """
            UPDATE standard_control_evidence
            SET withdrawn_at = now(), withdrawn_by = %s, withdrawn_reason = %s
            WHERE tenant_id = %s AND id = %s AND withdrawn_at IS NULL;
            """,
            (actor_id, (reason or "replaced by a newer version").strip(),
             str(tenant_id), str(evidence_id)),
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.evidence_replaced",
            asset_id=None,
            details={
                "new_evidence_id": str(new_row["id"]),
                "replaced_evidence_id": str(evidence_id),
                "new_sha256": sha256,
                "old_sha256": old["sha256"],
                "reason": (reason or "").strip() or None,
            },
        )
        return new_row


# ---------------------------------------------------------------------------
# Exceptions — requested → approved (admin+ at v1) → expired (effective-on-read)
# ---------------------------------------------------------------------------


def create_exception(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    control_id: Optional[uuid.UUID],
    title: str,
    rationale: str,
    expires_at: datetime,
    actor_id: str,
    actor_role: str,
) -> dict:
    if not title.strip() or not rationale.strip():
        raise StandardWorkflowError("exception title and rationale are mandatory")
    if expires_at <= _now():
        raise StandardWorkflowError("expires_at must be in the future")
    with conn.cursor(row_factory=dict_row) as cur:
        if control_id is not None:
            cur.execute(
                "SELECT id FROM standard_controls WHERE id = %s;", (str(control_id),)
            )
            if cur.fetchone() is None:
                raise StandardNotFoundError(f"Control {control_id} not found")
        cur.execute(
            """
            INSERT INTO grc_exceptions (
                tenant_id, control_id, title, rationale, expires_at, requested_by
            ) VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, tenant_id, control_id, title, rationale, state,
                      expires_at, requested_by, requested_at;
            """,
            (str(tenant_id),
             str(control_id) if control_id else None,
             title.strip(), rationale.strip(), expires_at, actor_id),
        )
        row = dict(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.exception_requested",
            asset_id=None, details={"exception_id": str(row["id"])},
        )
        return row


def decide_exception(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exception_id: uuid.UUID,
    *,
    decision: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    """v1 authority: admin+ (the dual-control candidate remains an OPEN Ch.9
    decision #6 — the primitive is available when it is ratified)."""
    if decision not in ("approved", "rejected"):
        raise StandardWorkflowError("decision must be 'approved' or 'rejected'")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, state FROM grc_exceptions "
            "WHERE tenant_id = %s AND id = %s FOR UPDATE;",
            (str(tenant_id), str(exception_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardNotFoundError(f"Exception {exception_id} not found")
        if row["state"] != "requested":
            raise StandardConflictError(
                f"Exception {exception_id} is not requested (state={row['state']})"
            )
        if decision == "approved":
            cur.execute(
                """
                UPDATE grc_exceptions
                SET state = 'approved', approved_by = %s, approved_at = now()
                WHERE tenant_id = %s AND id = %s AND state = 'requested'
                RETURNING id, state, approved_by, approved_at, expires_at;
                """,
                (actor_id, str(tenant_id), str(exception_id)),
            )
        else:
            cur.execute(
                """
                UPDATE grc_exceptions
                SET state = 'rejected', rejected_by = %s, rejected_at = now()
                WHERE tenant_id = %s AND id = %s AND state = 'requested'
                RETURNING id, state, rejected_by, rejected_at;
                """,
                (actor_id, str(tenant_id), str(exception_id)),
            )
        updated = dict(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name=f"standard.exception_{decision}",
            asset_id=None, details={"exception_id": str(exception_id)},
        )
        return updated


def list_exceptions(conn: psycopg.Connection, tenant_id: uuid.UUID, *, actor_id: str) -> list[dict]:
    """Expired is an EFFECTIVE state (no scheduler): an approved exception at
    or past expires_at materializes to expired on first observation."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, control_id, title, rationale, state, expires_at,
                   requested_by, requested_at, approved_by, approved_at
            FROM grc_exceptions
            WHERE tenant_id = %s
            ORDER BY requested_at DESC;
            """,
            (str(tenant_id),),
        )
        rows = cur.fetchall()
        now = _now()
        out = []
        for row in rows:
            if row["state"] == "approved" and row["expires_at"] <= now:
                cur.execute(
                    """
                    UPDATE grc_exceptions SET state = 'expired'
                    WHERE tenant_id = %s AND id = %s AND state = 'approved'
                      AND expires_at <= %s
                    RETURNING id, state;
                    """,
                    (str(tenant_id), str(row["id"]), now),
                )
                materialized = cur.fetchone()
                if materialized is not None:
                    row = dict(row)
                    row["state"] = "expired"
                    record_audit_event(
                        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                        actor_role="system:effective_state",
                        event_name="standard.exception_expired",
                        asset_id=None,
                        details={"exception_id": str(row["id"])},
                    )
            out.append(dict(row))
        return out


# ---------------------------------------------------------------------------
# Incidents — validated, timestamped, deduped candidates
# ---------------------------------------------------------------------------


def _incident_lock(cur, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> None:
    _advisory_xact_lock(cur, f"standard-incident:{tenant_id}:{incident_id}")


def create_incident(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    source: str,
    external_event_id: Optional[str],
    title: str,
    description: Optional[str],
    event_time: datetime,
    inputs: dict,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Validated, timestamped, deduped candidate (Flow E step 1). An
    identical replay of (source, external_event_id) returns the ORIGINAL
    incident — no duplicate obligations from repeated posts. Acceptance
    durably records the input revision + expected rules + pending evaluation
    work, then evaluates synchronously (PATCH-11)."""
    if not source.strip() or not title.strip():
        raise StandardWorkflowError("incident source and title are mandatory")
    if not isinstance(inputs, dict):
        raise StandardWorkflowError("incident inputs must be a JSON object")

    with conn.cursor(row_factory=dict_row) as cur:
        if external_event_id:
            cur.execute(
                """
                SELECT id FROM standard_incidents
                WHERE tenant_id = %s AND source = %s AND external_event_id = %s;
                """,
                (str(tenant_id), source.strip(), external_event_id),
            )
            existing = cur.fetchone()
            if existing is not None:
                return {
                    "incident": _get_incident_view(cur, tenant_id, existing["id"]),
                    "outcome": "replay",
                }

        revision_inputs = dict(inputs)
        revision_inputs["event_time"] = event_time.astimezone(timezone.utc).isoformat()

        cur.execute(
            """
            INSERT INTO standard_incidents (
                tenant_id, source, external_event_id, title, description,
                event_time, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (str(tenant_id), source.strip(), external_event_id, title.strip(),
             description, event_time, actor_id),
        )
        incident_id = cur.fetchone()["id"]
        cur.execute(
            """
            INSERT INTO standard_incident_revisions (
                tenant_id, incident_id, revision_no, inputs, created_by
            ) VALUES (%s, %s, 1, %s::jsonb, %s)
            RETURNING id, revision_no;
            """,
            (str(tenant_id), str(incident_id), json.dumps(revision_inputs), actor_id),
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.incident_created",
            asset_id=None,
            details={
                "incident_id": str(incident_id),
                "source": source.strip(),
                "external_event_id": external_event_id,
            },
        )

    evaluations = _run_rule_evaluations(conn, tenant_id, incident_id, actor_id=actor_id)
    with conn.cursor(row_factory=dict_row) as cur:
        incident = _get_incident_view(cur, tenant_id, incident_id)
    return {"incident": incident, "outcome": "created", "evaluations": evaluations}


def get_incident(
    conn: psycopg.Connection, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        return _get_incident_view(cur, tenant_id, incident_id)


def _get_incident_view(cur, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> dict:
    cur.execute(
        """
        SELECT id, tenant_id, source, external_event_id, title, description,
               state, event_time, current_revision, created_by, created_at,
               updated_at, resolved_at
        FROM standard_incidents
        WHERE tenant_id = %s AND id = %s;
        """,
        (str(tenant_id), str(incident_id)),
    )
    row = cur.fetchone()
    if row is None:
        raise StandardNotFoundError(f"Incident {incident_id} not found")
    incident = dict(row)
    cur.execute(
        """
        SELECT e.id, e.rule_id, e.rule_key, e.rule_version, e.state, e.attempt,
               e.result, e.error_detail, e.obligation_id, e.evaluated_at,
               e.incident_revision_no, e.is_current
        FROM standard_incident_rule_evaluations e
        WHERE e.tenant_id = %s AND e.incident_id = %s
        ORDER BY e.created_at ASC, e.attempt ASC;
        """,
        (str(tenant_id), str(incident_id)),
    )
    incident["evaluations"] = [dict(r) for r in cur.fetchall()]
    cur.execute(
        """
        SELECT id, obligation_key, kind, title, draft_notice, state, due_at, trigger_at,
               fulfilled_at, closed_at, breached_at, revision
        FROM standard_obligations
        WHERE tenant_id = %s AND incident_id = %s
        ORDER BY created_at ASC;
        """,
        (str(tenant_id), str(incident_id)),
    )
    incident["obligations"] = [
        _obligation_view(dict(r)) for r in cur.fetchall()
    ]
    return incident


# ---------------------------------------------------------------------------
# Rule evaluation — PATCH-11/12 durability
# ---------------------------------------------------------------------------


def _condition_matches(condition: Any, inputs: dict) -> str:
    """'match' | 'negative' | 'manual_review_required'. An unreadable or
    empty condition, or a condition key absent from the input revision, is
    NOT a silent negative — it is a visible manual-review item."""
    if not isinstance(condition, dict) or len(condition) == 0:
        return "manual_review_required"
    if not isinstance(inputs, dict):
        return "manual_review_required"
    for key, value in condition.items():
        if key not in inputs:
            return "manual_review_required"
        if inputs[key] != value:
            return "negative"
    return "match"


def _run_rule_evaluations(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    *,
    actor_id: str,
) -> list[dict]:
    """Re-pend and evaluate every active rule against the CURRENT incident
    input revision, inside the incident's concurrency boundary. Each rule is
    savepoint-scoped: one rule's failure is recorded per rule (the alarm row),
    never per incident, and never as a clean negative."""
    with conn.cursor(row_factory=dict_row) as cur:
        _incident_lock(cur, tenant_id, incident_id)
        cur.execute(
            """
            SELECT id, tenant_id, current_revision, event_time, state
            FROM standard_incidents
            WHERE tenant_id = %s AND id = %s FOR UPDATE;
            """,
            (str(tenant_id), str(incident_id)),
        )
        incident = cur.fetchone()
        if incident is None:
            raise StandardNotFoundError(f"Incident {incident_id} not found")
        revision_no = incident["current_revision"]

        cur.execute(
            """
            SELECT inputs FROM standard_incident_revisions
            WHERE tenant_id = %s AND incident_id = %s AND revision_no = %s;
            """,
            (str(tenant_id), str(incident_id), revision_no),
        )
        revision_row = cur.fetchone()
        if revision_row is None:
            raise StandardNotFoundError(
                f"Incident {incident_id} input revision {revision_no} not found"
            )
        inputs = revision_row["inputs"]

        cur.execute(
            """
            SELECT id, rule_key, rule_version, title, control_code, condition,
                   obligation_template, clock_seconds
            FROM standard_rules
            WHERE is_active
            ORDER BY rule_key;
            """,
            (),
        )
        rules = cur.fetchall()

        # Demote evaluations bound to older revisions (history retained),
        # then ensure one CURRENT pending row per rule pinned to the current
        # revision + the rule's current version (PATCH-11).
        cur.execute(
            """
            UPDATE standard_incident_rule_evaluations
            SET is_current = FALSE, updated_at = now()
            WHERE tenant_id = %s AND incident_id = %s AND is_current
              AND incident_revision_no <> %s;
            """,
            (str(tenant_id), str(incident_id), revision_no),
        )
        results = []
        for rule in rules:
            cur.execute(
                """
                SELECT id, state, attempt FROM standard_incident_rule_evaluations
                WHERE tenant_id = %s AND incident_id = %s AND rule_id = %s
                  AND is_current;
                """,
                (str(tenant_id), str(incident_id), str(rule["id"])),
            )
            current_eval = cur.fetchone()
            if current_eval is None:
                cur.execute(
                    """
                    INSERT INTO standard_incident_rule_evaluations (
                        tenant_id, incident_id, rule_id, rule_key, rule_version,
                        incident_revision_no, state
                    ) VALUES (%s, %s, %s, %s, %s, %s, 'pending')
                    RETURNING id, attempt;
                    """,
                    (str(tenant_id), str(incident_id), str(rule["id"]),
                     rule["rule_key"], rule["rule_version"], revision_no),
                )
                eval_row = cur.fetchone()
            elif current_eval["state"] in ("pending",):
                eval_row = current_eval
            else:
                # a fresh attempt on the current revision: re-pend this rule
                cur.execute(
                    """
                    UPDATE standard_incident_rule_evaluations
                    SET is_current = FALSE, updated_at = now()
                    WHERE tenant_id = %s AND id = %s;
                    """,
                    (str(tenant_id), str(current_eval["id"])),
                )
                cur.execute(
                    """
                    INSERT INTO standard_incident_rule_evaluations (
                        tenant_id, incident_id, rule_id, rule_key, rule_version,
                        incident_revision_no, state, attempt
                    ) VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s + 1)
                    RETURNING id, attempt;
                    """,
                    (str(tenant_id), str(incident_id), str(rule["id"]),
                     rule["rule_key"], rule["rule_version"], revision_no,
                     current_eval["attempt"]),
                )
                eval_row = cur.fetchone()

            outcome = _evaluate_one_rule(
                conn, cur, tenant_id, incident, revision_no, inputs, rule,
                eval_row, actor_id=actor_id,
            )
            results.append(outcome)
        return results


def _evaluate_one_rule(
    conn: psycopg.Connection,
    cur,
    tenant_id: uuid.UUID,
    incident: dict,
    revision_no: int,
    inputs: dict,
    rule: dict,
    eval_row: dict,
    *,
    actor_id: str,
) -> dict:
    """One attempt: the result and its uniquely keyed obligation output commit
    only while the input revision is current (we hold the incident advisory
    lock and just read it — the commit-time check is that boundary). Failure
    fails VISIBLY on this row, never as a clean negative."""
    cur.execute("SAVEPOINT rule_evaluation;")
    try:
        verdict = _condition_matches(rule["condition"], inputs)
        obligation_id = None
        if verdict == "match":
            obligation_id = _upsert_rule_obligation(
                conn, cur, tenant_id, incident, rule, actor_id=actor_id
            )
        result = {
            "match": "obligation_ready",
            "negative": "not_applicable",
            "manual_review_required": "manual_review_required",
        }[verdict]
        cur.execute(
            """
            UPDATE standard_incident_rule_evaluations
            SET state = CASE WHEN %s = 'manual_review_required'
                             THEN 'manual_review_required' ELSE 'evaluated' END,
                result = %s,
                error_detail = NULL,
                obligation_id = %s,
                evaluated_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING id, state, result, obligation_id;
            """,
            (
                result, result, obligation_id,
                str(tenant_id), str(eval_row["id"]),
            ),
        )
        row = dict(cur.fetchone())
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role="system:rule_engine",
            event_name="standard.rule_evaluated", asset_id=None,
            details={
                "incident_id": str(incident["id"]),
                "rule_key": rule["rule_key"],
                "rule_version": rule["rule_version"],
                "incident_revision": revision_no,
                "result": result,
                "obligation_id": str(obligation_id) if obligation_id else None,
            },
        )
        cur.execute("RELEASE SAVEPOINT rule_evaluation;")
        return row
    except Exception as exc:
        cur.execute("ROLLBACK TO SAVEPOINT rule_evaluation;")
        cur.execute(
            """
            UPDATE standard_incident_rule_evaluations
            SET state = 'evaluation_error',
                error_detail = %s,
                obligation_id = NULL,
                evaluated_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s;
            """,
            (f"{type(exc).__name__}: {exc}", str(tenant_id), str(eval_row["id"])),
        )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role="system:rule_engine",
            event_name="standard.rule_evaluation_failed", asset_id=None,
            details={
                "incident_id": str(incident["id"]),
                "rule_key": rule["rule_key"],
                "incident_revision": revision_no,
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        cur.execute("RELEASE SAVEPOINT rule_evaluation;")
        return {
            "id": str(eval_row["id"]),
            "state": "evaluation_error",
            "result": None,
            "obligation_id": None,
        }


def _upsert_rule_obligation(
    conn: psycopg.Connection,
    cur,
    tenant_id: uuid.UUID,
    incident: dict,
    rule: dict,
    *,
    actor_id: str,
) -> str:
    """Create or audited-correct the rule's obligation under its STABLE
    identity (PATCH-11: reevaluation reuses it, never duplicates; PATCH-12:
    due_at persists at creation — retries never restart the clock; a
    corrected trigger fact (the event time) re-derives the deadline through
    an audited revision that preserves submission history)."""
    template = rule["obligation_template"] or {}
    kind = template.get("kind")
    title = template.get("title") or rule["title"]
    if not kind:
        # an unreadable template is a visible manual review, not an obligation
        raise StandardWorkflowError(
            f"rule {rule['rule_key']}: obligation template carries no kind"
        )
    clock = int(rule["clock_seconds"])
    trigger_at = incident["event_time"]
    due_at = trigger_at + timedelta(seconds=clock)
    obligation_key = f"{incident['id']}:{rule['rule_key']}"

    cur.execute(
        """
        SELECT id, trigger_at, due_at, state FROM standard_obligations
        WHERE tenant_id = %s AND obligation_key = %s FOR UPDATE;
        """,
        (str(tenant_id), obligation_key),
    )
    existing = cur.fetchone()

    draft_notice = {
        "kind": kind,
        "title": title,
        "rule_key": rule["rule_key"],
        "rule_version": rule["rule_version"],
        "control": rule["control_code"],
        "incident_id": str(incident["id"]),
        "trigger_at": trigger_at.astimezone(timezone.utc).isoformat(),
        "deadline": due_at.astimezone(timezone.utc).isoformat(),
        "clock_seconds": clock,
        "channel_hint": template.get("channel_hint"),
        "note": "Prepared draft — a HUMAN submits via the official channel; "
                "Tempris records the submission proof only.",
    }

    if existing is None:
        cur.execute(
            """
            INSERT INTO standard_obligations (
                tenant_id, incident_id, source_rule_id, source_rule_version,
                obligation_key, kind, title, draft_notice, trigger_at, due_at,
                clock_seconds, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                str(tenant_id), str(incident["id"]), str(rule["id"]),
                rule["rule_version"], obligation_key, kind, title,
                json.dumps(draft_notice), trigger_at, due_at, clock, actor_id,
            ),
        )
        obligation_id = cur.fetchone()["id"]
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role="system:rule_engine",
            event_name="standard.obligation_created", asset_id=None,
            details={
                "obligation_id": str(obligation_id),
                "obligation_key": obligation_key,
                "due_at": due_at.astimezone(timezone.utc).isoformat(),
                "clock_seconds": clock,
            },
        )
        return str(obligation_id)

    # Stale identity from an earlier revision: retry never restarts the
    # clock — only a corrected trigger fact moves the deadline, audited.
    if existing["trigger_at"] == trigger_at and existing["due_at"] == due_at:
        return str(existing["id"])
    cur.execute(
        """
        UPDATE standard_obligations
        SET trigger_at = %s, due_at = %s, revision = revision + 1,
            correction_note = %s, draft_notice = %s::jsonb, updated_at = now()
        WHERE tenant_id = %s AND id = %s
        RETURNING id, revision;
        """,
        (
            trigger_at, due_at,
            f"trigger fact corrected by incident revision "
            f"{incident['current_revision']} (prior values preserved in history)",
            json.dumps(draft_notice),
            str(tenant_id), str(existing["id"]),
        ),
    )
    updated = cur.fetchone()
    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
        actor_role="system:rule_engine",
        event_name="standard.obligation_corrected", asset_id=None,
        details={
            "obligation_id": str(updated["id"]),
            "revision": updated["revision"],
            "prior_trigger_at": existing["trigger_at"].astimezone(timezone.utc).isoformat(),
            "new_trigger_at": trigger_at.astimezone(timezone.utc).isoformat(),
            "prior_due_at": existing["due_at"].astimezone(timezone.utc).isoformat(),
            "new_due_at": due_at.astimezone(timezone.utc).isoformat(),
        },
    )
    return str(updated["id"])


# ---------------------------------------------------------------------------
# Incident lifecycle — edit / acknowledge / reevaluate / resolve
# ---------------------------------------------------------------------------


def edit_incident(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    *,
    title: Optional[str],
    description: Optional[str],
    event_time: Optional[datetime],
    inputs: Optional[dict],
    correction_note: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    """A rule-relevant edit atomically creates a NEW immutable input revision
    and re-pends ALL expected rules — previously completed negative
    evaluations included; a resolved incident reopens to acknowledged with
    audit (PATCH-11). The corrected trigger facts ride the revision
    (PATCH-12)."""
    if not correction_note.strip():
        raise StandardWorkflowError(
            "a correction note is mandatory (audited revision)"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        _incident_lock(cur, tenant_id, incident_id)
        cur.execute(
            """
            SELECT id, current_revision, title, description, event_time, state
            FROM standard_incidents
            WHERE tenant_id = %s AND id = %s FOR UPDATE;
            """,
            (str(tenant_id), str(incident_id)),
        )
        incident = cur.fetchone()
        if incident is None:
            raise StandardNotFoundError(f"Incident {incident_id} not found")

        cur.execute(
            """
            SELECT inputs FROM standard_incident_revisions
            WHERE tenant_id = %s AND incident_id = %s AND revision_no = %s;
            """,
            (str(tenant_id), str(incident_id), incident["current_revision"]),
        )
        base_inputs = dict(cur.fetchone()["inputs"])
        new_inputs = {**base_inputs, **(inputs or {})}
        new_event_time = event_time or incident["event_time"]
        new_inputs["event_time"] = new_event_time.astimezone(timezone.utc).isoformat()

        new_revision = incident["current_revision"] + 1
        cur.execute(
            """
            INSERT INTO standard_incident_revisions (
                tenant_id, incident_id, revision_no, inputs, correction_note,
                created_by
            ) VALUES (%s, %s, %s, %s::jsonb, %s, %s)
            RETURNING id;
            """,
            (str(tenant_id), str(incident_id), new_revision,
             json.dumps(new_inputs), correction_note.strip(), actor_id),
        )
        cur.execute(
            """
            UPDATE standard_incidents
            SET current_revision = %s,
                title = COALESCE(%s, title),
                description = COALESCE(%s, description),
                event_time = %s,
                -- a rule-relevant edit reopens a resolved incident (PATCH-11)
                state = CASE WHEN state = 'resolved' THEN 'acknowledged' ELSE state END,
                resolved_at = CASE WHEN state = 'resolved' THEN NULL ELSE resolved_at END,
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING id, state, current_revision;
            """,
            (new_revision, title, description, new_event_time,
             str(tenant_id), str(incident_id)),
        )
        cur.fetchone()
        if incident["state"] == "resolved":
            record_audit_event(
                conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                actor_role=actor_role, event_name="standard.incident_reopened",
                asset_id=None,
                details={
                    "incident_id": str(incident_id),
                    "reason": "rule-relevant edit",
                    "revision": new_revision,
                },
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.incident_revised",
            asset_id=None,
            details={
                "incident_id": str(incident_id),
                "revision": new_revision,
                "correction_note": correction_note.strip(),
            },
        )

    evaluations = _run_rule_evaluations(conn, tenant_id, incident_id, actor_id=actor_id)
    with conn.cursor(row_factory=dict_row) as cur:
        view = _get_incident_view(cur, tenant_id, incident_id)
    return {"incident": view, "evaluations": evaluations}


def acknowledge_incident(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        _incident_lock(cur, tenant_id, incident_id)
        cur.execute(
            """
            UPDATE standard_incidents
            SET state = 'acknowledged', updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state = 'open'
            RETURNING id, state;
            """,
            (str(tenant_id), str(incident_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardConflictError(
                f"Incident {incident_id} not found or not open"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.incident_acknowledged",
            asset_id=None, details={"incident_id": str(incident_id)},
        )
        return dict(row)


def reevaluate_rule(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    rule_key: str,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Retry a failed/manual-review evaluation: pending and error rows remain
    visible and retryable; the attempt history is retained (PATCH-11)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _incident_lock(cur, tenant_id, incident_id)
        cur.execute(
            """
            SELECT id, current_revision FROM standard_incidents
            WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), str(incident_id)),
        )
        incident = cur.fetchone()
        if incident is None:
            raise StandardNotFoundError(f"Incident {incident_id} not found")
        cur.execute(
            """
            SELECT id FROM standard_incident_rule_evaluations
            WHERE tenant_id = %s AND incident_id = %s AND rule_key = %s
              AND is_current
              AND incident_revision_no = %s;
            """,
            (str(tenant_id), str(incident_id), rule_key,
             incident["current_revision"]),
        )
        current_eval = cur.fetchone()
        if current_eval is None:
            raise StandardNotFoundError(
                f"No current evaluation of rule {rule_key!r} for this "
                "incident's current revision"
            )
    results = _run_rule_evaluations(conn, tenant_id, incident_id, actor_id=actor_id)
    with conn.cursor(row_factory=dict_row) as cur:
        view = _get_incident_view(cur, tenant_id, incident_id)
    return {
        "incident": view,
        "evaluations": [r for r in results],
    }


def resolve_incident(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Required unfinished evaluations or obligations — including evaluations
    not bound to the current revision's re-run — block resolution, checked
    inside the incident's concurrency boundary (PATCH-11 commit-time check)."""
    with conn.cursor(row_factory=dict_row) as cur:
        _incident_lock(cur, tenant_id, incident_id)
        cur.execute(
            """
            SELECT id, state FROM standard_incidents
            WHERE tenant_id = %s AND id = %s FOR UPDATE;
            """,
            (str(tenant_id), str(incident_id)),
        )
        incident = cur.fetchone()
        if incident is None:
            raise StandardNotFoundError(f"Incident {incident_id} not found")
        if incident["state"] == "resolved":
            raise StandardConflictError(
                f"Incident {incident_id} is already resolved"
            )

        cur.execute(
            """
            SELECT e.rule_key, e.state FROM standard_incident_rule_evaluations e
            WHERE e.tenant_id = %s AND e.incident_id = %s
              AND e.is_current
              AND e.state IN ('pending', 'evaluation_error', 'manual_review_required');
            """,
            (str(tenant_id), str(incident_id)),
        )
        blocked_evals = cur.fetchall()
        if blocked_evals:
            detail = ", ".join(
                f"{r['rule_key']}={r['state']}" for r in blocked_evals
            )
            raise StandardConflictError(
                "Resolution blocked — unfinished rule evaluations "
                f"(fail visibly, never a clean negative): {detail}"
            )
        cur.execute(
            """
            SELECT id, obligation_key FROM standard_obligations
            WHERE tenant_id = %s AND incident_id = %s
              AND state IN ('open', 'in_progress');
            """,
            (str(tenant_id), str(incident_id)),
        )
        blocked_obligations = cur.fetchall()
        if blocked_obligations:
            detail = ", ".join(r["obligation_key"] for r in blocked_obligations)
            raise StandardConflictError(
                f"Resolution blocked — open obligations: {detail}"
            )

        cur.execute(
            """
            UPDATE standard_incidents
            SET state = 'resolved', resolved_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state IN ('open', 'acknowledged')
            RETURNING id, state, resolved_at;
            """,
            (str(tenant_id), str(incident_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardConflictError(f"Incident {incident_id} moved concurrently; retry")
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.incident_resolved",
            asset_id=None, details={"incident_id": str(incident_id)},
        )
        return dict(row)


def list_incidents(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    state: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT COUNT(*) AS total FROM standard_incidents
            WHERE tenant_id = %s
              AND (%s::text IS NULL OR state = %s::text);
            """,
            (str(tenant_id), state, state),
        )
        total = cur.fetchone()["total"]
        cur.execute(
            """
            SELECT id, source, external_event_id, title, description, state,
                   event_time, current_revision, created_by, created_at,
                   updated_at, resolved_at
            FROM standard_incidents
            WHERE tenant_id = %s
              AND (%s::text IS NULL OR state = %s::text)
            ORDER BY created_at DESC, id
            LIMIT %s OFFSET %s;
            """,
            (str(tenant_id), state, state,
             max(1, min(limit, 500)), max(0, offset)),
        )
        return {"total": total, "items": [dict(r) for r in cur.fetchall()]}


# ---------------------------------------------------------------------------
# Obligations — deadline state, submissions, closure
# ---------------------------------------------------------------------------


def _obligation_view(row: dict) -> dict:
    """Derived deadline state at read time (no scheduler exists): overdue
    computes from due_at whenever read; completed-late derives separately and
    survives closure (PATCH-12)."""
    now = _now()
    view = dict(row)
    active = view["state"] in ("open", "in_progress")
    view["overdue"] = bool(view["due_at"] and view["due_at"] < now and active)
    view["completed_late"] = bool(
        view.get("fulfilled_at") and view["fulfilled_at"] > view["due_at"]
    )
    return view


def list_obligations(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    *,
    actor_id: str,
    state: Optional[str] = None,
    incident_id: Optional[uuid.UUID] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, incident_id, source_rule_id, source_rule_version,
                   obligation_key, kind, title, draft_notice, trigger_at,
                   due_at, clock_seconds, state, revision, correction_note,
                   fulfilled_at, fulfilled_by, closed_at, breached_at,
                   created_by, created_at
            FROM standard_obligations
            WHERE tenant_id = %s
              AND (%s::text IS NULL OR state = %s::text)
              AND (%s::uuid IS NULL OR incident_id = %s::uuid)
            ORDER BY due_at ASC, id
            LIMIT %s OFFSET %s;
            """,
            (str(tenant_id), state, state,
             str(incident_id) if incident_id else None,
             str(incident_id) if incident_id else None,
             max(1, min(limit, 500)), max(0, offset)),
        )
        rows = cur.fetchall()
        now = _now()
        items = []
        for row in rows:
            # breach recorded when first OBSERVED (read-time derivation
            # writes it once — the codebase has no background worker yet)
            if (
                row["state"] in OPEN_OBLIGATION_STATES
                and row["breached_at"] is None
                and row["due_at"] < now
            ):
                cur.execute(
                    """
                    UPDATE standard_obligations
                    SET breached_at = now(), updated_at = now()
                    WHERE tenant_id = %s AND id = %s
                      AND state IN ('open', 'in_progress') AND breached_at IS NULL
                    RETURNING breached_at;
                    """,
                    (str(tenant_id), str(row["id"])),
                )
                materialized = cur.fetchone()
                if materialized is not None:
                    row = dict(row)
                    row["breached_at"] = materialized["breached_at"]
                    record_audit_event(
                        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
                        actor_role="system:effective_state",
                        event_name="standard.obligation_breach_recorded",
                        asset_id=None,
                        details={
                            "obligation_id": str(row["id"]),
                            "due_at": row["due_at"].astimezone(timezone.utc).isoformat(),
                        },
                    )
            items.append(_obligation_view(row))
        return {"total": len(items), "items": items}


def transition_obligation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    obligation_id: uuid.UUID,
    *,
    to_state: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    """open → in_progress (work started). Fulfillment happens only through a
    submission; closure only from fulfilled — an obligation is never
    auto-closed (failure modes)."""
    if to_state != "in_progress":
        raise StandardWorkflowError(
            "the only direct transition is open → in_progress; fulfillment "
            "requires a submission record"
        )
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE standard_obligations
            SET state = 'in_progress', updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state = 'open'
            RETURNING id, state;
            """,
            (str(tenant_id), str(obligation_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardConflictError(
                f"Obligation {obligation_id} not found or not open"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.obligation_started",
            asset_id=None, details={"obligation_id": str(obligation_id)},
        )
        return dict(row)


def submit_obligation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    obligation_id: uuid.UUID,
    *,
    channel: str,
    reference: Optional[str],
    proof: str,
    actor_id: str,
    actor_role: str,
) -> dict:
    """The human submitted via the official channel — Tempris records the
    immutable proof (who/when/channel/reference/proof). Submission WITHOUT a
    proof reference is refused: the obligation stays open, never auto-closed.
    The submission record is immutable (DB trigger) and binds completion to
    the obligation separately from any recording time (PATCH-12)."""
    if not proof or not proof.strip():
        raise StandardWorkflowError(
            "a proof reference is mandatory — without one the obligation "
            "stays open"
        )
    if not channel or not channel.strip():
        raise StandardWorkflowError("submission channel is mandatory")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, state, due_at FROM standard_obligations
            WHERE tenant_id = %s AND id = %s FOR UPDATE;
            """,
            (str(tenant_id), str(obligation_id)),
        )
        obligation = cur.fetchone()
        if obligation is None:
            raise StandardNotFoundError(f"Obligation {obligation_id} not found")
        if obligation["state"] not in ("open", "in_progress"):
            raise StandardConflictError(
                f"Obligation {obligation_id} is {obligation['state']}; it "
                "cannot take a submission"
            )
        cur.execute(
            """
            INSERT INTO standard_submission_records (
                tenant_id, obligation_id, submitted_by, channel, reference, proof
            ) VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, submitted_by, submitted_at, channel, reference;
            """,
            (str(tenant_id), str(obligation_id), actor_id, channel.strip(),
             reference, proof.strip()),
        )
        submission = dict(cur.fetchone())
        cur.execute(
            """
            UPDATE standard_obligations
            SET state = 'fulfilled', fulfilled_at = now(), fulfilled_by = %s,
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
              AND state IN ('open', 'in_progress')
            RETURNING id, state, fulfilled_at, due_at;
            """,
            (actor_id, str(tenant_id), str(obligation_id)),
        )
        updated = cur.fetchone()
        if updated is None:
            raise StandardConflictError(
                f"Obligation {obligation_id} moved concurrently; retry"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.obligation_submitted",
            asset_id=None,
            details={
                "obligation_id": str(obligation_id),
                "submission_id": str(submission["id"]),
                "channel": channel.strip(),
            },
        )
        return {
            "obligation": dict(updated),
            "submission": submission,
            "completed_late": updated["fulfilled_at"] > updated["due_at"],
        }


def close_obligation(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    obligation_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE standard_obligations
            SET state = 'closed', closed_at = now(), updated_at = now()
            WHERE tenant_id = %s AND id = %s AND state = 'fulfilled'
            RETURNING id, state, closed_at, fulfilled_at, due_at;
            """,
            (str(tenant_id), str(obligation_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise StandardConflictError(
                f"Obligation {obligation_id} not found or not fulfilled"
            )
        record_audit_event(
            conn=conn, tenant_id=tenant_id, actor_id=actor_id,
            actor_role=actor_role, event_name="standard.obligation_closed",
            asset_id=None, details={"obligation_id": str(obligation_id)},
        )
        view = _obligation_view(dict(row))
        # lateness survives closure (PATCH-12)
        return view


def list_submissions(
    conn: psycopg.Connection, tenant_id: uuid.UUID, obligation_id: uuid.UUID
) -> list[dict]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, obligation_id, submitted_by, submitted_at, channel,
                   reference, created_at
            FROM standard_submission_records
            WHERE tenant_id = %s AND obligation_id = %s
            ORDER BY submitted_at ASC;
            """,
            (str(tenant_id), str(obligation_id)),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# V1-parity workbench reads — gap analysis, advisories, MAS report drafts.
# All derived at read time: no stored truth, no new tables.
# ---------------------------------------------------------------------------


def get_gap_analysis(conn: psycopg.Connection, tenant_id: uuid.UUID) -> dict:
    """Read-only derived view over control assessments vs framework controls
    (V1 grc.py GET /gap-analysis, adapted to the V2 substrate): a SIGNED
    assessment is completed, a DRAFT one is in review, no live assessment is
    pending. Completion is the sign-off state — never an invented percentage
    of compliance."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT f.framework_code, c.id AS control_id, c.control_code,
                   c.title, a.state AS assessment_state, a.status AS assessment_status
            FROM standard_controls c
            JOIN standard_frameworks f ON f.framework_code = c.framework_code
            LEFT JOIN standard_control_assessments a
              ON a.control_id = c.id AND a.tenant_id = %s AND a.state <> 'archived'
            ORDER BY f.framework_code, c.control_code;
            """,
            (str(tenant_id),),
        )
        rows = cur.fetchall()

    controls = []
    completed = in_review = pending = 0
    for row in rows:
        if row["assessment_state"] == "signed":
            state = "completed"
            completed += 1
        elif row["assessment_state"] == "draft":
            state = "in_review"
            in_review += 1
        else:
            state = "pending"
            pending += 1
        controls.append({
            "framework_code": row["framework_code"],
            "control_id": row["control_id"],
            "control_code": row["control_code"],
            "title": row["title"],
            "state": state,
            "assessment_status": row["assessment_status"],
        })

    total = len(controls)
    completion_pct = round((completed / total) * 100) if total > 0 else 0
    return {
        "controls": controls,
        "summary": {
            "total": total,
            "completed": completed,
            "in_review": in_review,
            "pending": pending,
            "completion_pct": completion_pct,
        },
    }


# Control codes the derived advisories speak to — the same cross-framework
# mapping the V1 advisory engine used, adapted to the V2 seed catalog.
_AUDIT_MONITORING_CONTROLS = ("MAS-TRM-9.1.1", "ISO-A.8.15", "SOC2-CC7.1")
_INCIDENT_RESPONSE_CONTROLS = ("MAS-TRM-12.1.1", "ISO-A.5.24", "SOC2-CC7.2")


def list_advisories(conn: psycopg.Connection, tenant_id: uuid.UUID) -> list[dict]:
    """Live-data advisory alerts per control code (V1 standard.py
    /advisories precedent: derived warnings that never mutate statuses or
    scores). Mapped onto the data V2 actually has: the tamper-evident audit
    chain, signed gap assessments, and overdue regulatory obligations.
    Advisories against control codes not present in any seeded catalog are
    dropped — an advisory must anchor to a real control."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT control_code FROM standard_controls;"
        )
        known_codes = {r["control_code"] for r in cur.fetchall()}

        cur.execute(
            """
            SELECT a.status, c.control_code
            FROM standard_control_assessments a
            JOIN standard_controls c ON c.id = a.control_id
            WHERE a.tenant_id = %s AND a.state = 'signed'
              AND a.status IN ('partial', 'non_compliant');
            """,
            (str(tenant_id),),
        )
        gap_rows = cur.fetchall()

        cur.execute(
            """
            SELECT id, obligation_key, due_at, breached_at
            FROM standard_obligations
            WHERE tenant_id = %s AND state IN ('open', 'in_progress')
              AND due_at < %s;
            """,
            (str(tenant_id), _now()),
        )
        overdue = cur.fetchall()

    advisories: dict[str, dict] = {}

    try:
        verification = verify_tenant_audit_chain(conn, tenant_id)
        intact = bool(verification.get("intact"))
        if not intact:
            message = "TACF audit-chain verification failed for this tenant."
            level = "critical"
        else:
            message = "TACF audit trail verified — the tamper-evident chain is intact."
            level = "ok"
        for code in _AUDIT_MONITORING_CONTROLS:
            if code in known_codes:
                advisories[code] = {"level": level, "message": message,
                                    "type": "audit_chain_integrity"}
    except Exception:
        # verification infrastructure unavailable is itself worth surfacing,
        # but never at the cost of failing the read
        pass

    for row in gap_rows:
        code = row["control_code"]
        advisories[code] = {
            "level": "warning",
            "message": (
                f"Signed assessment reports {row['status'].replace('_', ' ')} "
                "for this control — remediation review required."
            ),
            "type": "signed_gap",
        }

    if overdue:
        message = (
            f"{len(overdue)} regulatory obligation(s) past their deadline — "
            "incident response readiness and notification clocks need review."
        )
        for code in _INCIDENT_RESPONSE_CONTROLS:
            if code in known_codes:
                advisories[code] = {
                    "level": "warning", "message": message,
                    "type": "overdue_obligations",
                    "overdue_count": len(overdue),
                }

    return [
        {"control_code": code, **payload}
        for code, payload in sorted(advisories.items())
    ]


MAS_REPORT_TYPE = "MAS TRM 12.1.5 — 1-Hour Incident Notification"
MAS_NOTIFICATION_CLOCK = timedelta(hours=1)


def build_incident_report_draft(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    *,
    actor_id: str,
    actor_role: str,
) -> dict:
    """Derived MAS TRM 12.1.5 notification DRAFT from a REAL incident (V1
    standard.py POST /mas-trm/incident-report honesty rules carried over: a
    draft is only ever generated from a recorded incident — never fabricated
    from catalogue totals). Nothing is stored: the draft is derived at read
    time; a HUMAN submits through the official channel and the submission
    proof lands on the obligation, not here."""
    with conn.cursor(row_factory=dict_row) as cur:
        view = _get_incident_view(cur, tenant_id, incident_id)

    now = _now()
    trigger_at = view["event_time"]
    deadline = trigger_at + MAS_NOTIFICATION_CLOCK
    evaluations = view["evaluations"]
    obligations = view["obligations"]
    unfinished = [
        e for e in evaluations
        if e["state"] in UNFINISHED_EVALUATION_STATES and e["is_current"]
    ]
    overdue = [o for o in obligations if o.get("overdue")]

    draft = {
        "report_id": f"INR-{now.strftime('%Y%m%d%H%M%S%f')}",
        "incident_id": str(view["id"]),
        "type": MAS_REPORT_TYPE,
        "generated_at": now.astimezone(timezone.utc).isoformat(),
        "generated_by": actor_id,
        "notification_deadline": deadline.astimezone(timezone.utc).isoformat(),
        "deadline_clock_seconds": int(MAS_NOTIFICATION_CLOCK.total_seconds()),
        "status": "DRAFT — PENDING SUBMISSION TO MAS",
        "incident_summary": {
            "external_event_id": view["external_event_id"],
            "source": view["source"],
            "title": view["title"],
            "state": view["state"],
            "description": view["description"],
            "event_time": trigger_at.astimezone(timezone.utc).isoformat(),
            "current_revision": view["current_revision"],
        },
        "rule_evaluations": [
            {
                "rule_key": e["rule_key"],
                "rule_version": e["rule_version"],
                "state": e["state"],
                "result": e["result"],
                "is_current": e["is_current"],
            }
            for e in evaluations
        ],
        "related_obligations": [
            {
                "obligation_id": o["id"],
                "obligation_key": o["obligation_key"],
                "title": o["title"],
                "kind": o["kind"],
                "state": o["state"],
                "due_at": o["due_at"].astimezone(timezone.utc).isoformat(),
                "overdue": bool(o.get("overdue")),
            }
            for o in obligations
        ],
        "unfinished_evaluation_count": len(unfinished),
        "overdue_obligation_count": len(overdue),
        "scope_note": (
            "Only the recorded incident, its rule evaluations, and its "
            "obligations are included; global intelligence is excluded. "
            "This is a prepared draft — a HUMAN submits via the official "
            "channel; Tempris records the submission proof only."
        ),
    }
    record_audit_event(
        conn=conn, tenant_id=tenant_id, actor_id=actor_id,
        actor_role=actor_role,
        event_name="standard.incident_report_drafted",
        asset_id=None,
        details={
            "incident_id": str(incident_id),
            "report_id": draft["report_id"],
            "report_type": MAS_REPORT_TYPE,
        },
    )
    return draft
