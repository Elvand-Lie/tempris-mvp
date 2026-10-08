# backend/app/routes/standard.py
"""
STANDARD / GRC REST API (PRD-000 v1.11 Ch.9).

Module-gated (STANDARD entitlement, tenant-level; platform sessions blocked
at the root), analyst+ for the substrate surfaces; exception decisions and
rule-catalog changes are admin+ (rules land via platform-curated migrations
at v1 — no rule-write endpoint exists, so no analyst can change a rule).

The V1 advisory-engine precedent made explicit and module-wide: nothing in
this router mutates technical exposure state. Every percentage renders with
its assessment coverage; every submission requires proof; no endpoint
touches findings or asset_exposures.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth import AuthContext, require_module, require_roles
from app.db import get_db_connection
from app.standard import service
from app.standard.errors import (
    StandardConflictError,
    StandardNotFoundError,
    StandardWorkflowError,
)
from app.exposure.tes_read_model import _jsonify

router = APIRouter(
    prefix="/api/standard",
    tags=["STANDARD"],
    dependencies=[Depends(require_module("STANDARD"))],
)


def _require_analyst(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    return auth


def _require_admin(
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"])),
) -> AuthContext:
    return auth


def _raise_domain_error(e: Exception):
    if isinstance(e, StandardNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    if isinstance(e, StandardWorkflowError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": e.code, "message": str(e)},
        )
    if isinstance(e, StandardConflictError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )
    raise e


# --- request shapes -------------------------------------------------------


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: uuid.UUID
    status: str
    notes: Optional[str] = None


class AssessmentReassess(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: uuid.UUID
    status: str
    notes: Optional[str] = None


class SignoffIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capacity: str


class EvidenceWithdraw(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1)


class EvidenceReplace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1)
    media_type: str
    content_base64: str
    reason: Optional[str] = None


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)
    supersedes_id: Optional[uuid.UUID] = None


class EvidenceAttach(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: uuid.UUID
    assessment_id: Optional[uuid.UUID] = None
    edip_verification_id: Optional[uuid.UUID] = None
    title: str = Field(..., min_length=1)
    media_type: str
    # base64 content (JSON transport); decoded + size/type-checked in service
    content_base64: str


class ExceptionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: Optional[uuid.UUID] = None
    title: str = Field(..., min_length=1)
    rationale: str = Field(..., min_length=1)
    expires_at: datetime


class ExceptionDecideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., min_length=1)
    external_event_id: Optional[str] = None
    title: str = Field(..., min_length=1)
    description: Optional[str] = None
    event_time: datetime
    inputs: dict


class IncidentEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = None
    description: Optional[str] = None
    event_time: Optional[datetime] = None
    inputs: Optional[dict] = None
    correction_note: str = Field(..., min_length=1)


class ObligationTransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: str


class SubmissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str = Field(..., min_length=1)
    reference: Optional[str] = None
    proof: str


# --- governance substrate -------------------------------------------------


@router.get(
    "/frameworks",
    status_code=status.HTTP_200_OK,
    summary="Reference catalogs + per-tenant assessed status + compliance among assessed",
)
def list_frameworks(auth: AuthContext = Depends(_require_analyst)):
    try:
        with get_db_connection() as conn:
            payload = service.list_frameworks(conn, auth.tenant_id)
            conn.commit()
            return _jsonify({"frameworks": payload})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/assessments",
    status_code=status.HTTP_201_CREATED,
    summary="Assess a control (draft; completed by dual sign-off)",
)
def create_assessment(
    payload: AssessmentCreate,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.create_assessment(
                conn, auth.tenant_id,
                control_id=payload.control_id, status=payload.status,
                notes=payload.notes,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"assessment": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/assessments/reassess",
    status_code=status.HTTP_201_CREATED,
    summary="ATOMIC reassessment: validate, archive the live assessment, and create the replacement in one transaction",
)
def reassess_assessment(
    payload: AssessmentReassess,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.reassess_control(
                conn, auth.tenant_id,
                control_id=payload.control_id, status=payload.status,
                notes=payload.notes,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"assessment": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/assessments/{assessment_id}/signoff",
    status_code=status.HTTP_200_OK,
    summary="Sign an assessment (end_user | pic — two different actors)",
)
def signoff_assessment(
    assessment_id: uuid.UUID,
    payload: SignoffIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.signoff_assessment(
                conn, auth.tenant_id, assessment_id,
                capacity=payload.capacity,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"assessment": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/assessments/{assessment_id}/archive",
    status_code=status.HTTP_200_OK,
    summary="Archive an assessment (history retained)",
)
def archive_assessment(
    assessment_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.archive_assessment(
                conn, auth.tenant_id, assessment_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"assessment": row})
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/policies",
    status_code=status.HTTP_200_OK,
    summary="Policy registry with versioning",
)
def list_policies(auth: AuthContext = Depends(_require_analyst)):
    try:
        with get_db_connection() as conn:
            rows = service.list_policies(conn, auth.tenant_id)
            conn.commit()
            return _jsonify({"policies": rows})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/policies",
    status_code=status.HTTP_201_CREATED,
    summary="Create a policy draft (optionally superseding a prior version)",
)
def create_policy(
    payload: PolicyCreate,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.create_policy(
                conn, auth.tenant_id,
                title=payload.title, body=payload.body,
                supersedes_id=payload.supersedes_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"policy": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/policies/{policy_id}/activate",
    status_code=status.HTTP_200_OK,
    summary="Activate a draft (the prior active version supersedes atomically)",
)
def activate_policy(
    policy_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.activate_policy(
                conn, auth.tenant_id, policy_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"policy": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/policies/{policy_id}/archive",
    status_code=status.HTTP_200_OK,
    summary="Archive a policy",
)
def archive_policy(
    policy_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.archive_policy(
                conn, auth.tenant_id, policy_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"policy": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/evidence",
    status_code=status.HTTP_201_CREATED,
    summary="Attach typed control evidence (EDIP remediation evidence maps BY REFERENCE)",
)
def attach_evidence(
    payload: EvidenceAttach,
    auth: AuthContext = Depends(_require_analyst),
):
    import base64
    import binascii

    try:
        content = base64.b64decode(payload.content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="content_base64 is not valid base64",
        )
    try:
        with get_db_connection() as conn:
            row = service.attach_evidence(
                conn, auth.tenant_id,
                control_id=payload.control_id,
                assessment_id=payload.assessment_id,
                edip_verification_id=payload.edip_verification_id,
                title=payload.title,
                media_type=payload.media_type,
                content=content,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"evidence": row})
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/evidence",
    status_code=status.HTTP_200_OK,
    summary="List control evidence (metadata; withdrawn excluded unless include_withdrawn)",
)
def list_evidence(
    control_id: Optional[uuid.UUID] = Query(None),
    include_withdrawn: bool = Query(False),
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            rows = service.list_evidence(
                conn, auth.tenant_id, control_id,
                include_withdrawn=include_withdrawn,
            )
            conn.commit()
            return _jsonify({"evidence": rows})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/evidence/{evidence_id}/withdraw",
    status_code=status.HTTP_200_OK,
    summary="Withdraw evidence with a mandatory reason (tombstone; signed evidence is immutable)",
)
def withdraw_evidence(
    evidence_id: uuid.UUID,
    payload: EvidenceWithdraw,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.withdraw_evidence(
                conn, auth.tenant_id, evidence_id,
                reason=payload.reason,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"evidence": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/evidence/{evidence_id}/replace",
    status_code=status.HTTP_201_CREATED,
    summary="Replace evidence with a newly versioned attachment (old row tombstoned, links inherited)",
)
def replace_evidence(
    evidence_id: uuid.UUID,
    payload: EvidenceReplace,
    auth: AuthContext = Depends(_require_analyst),
):
    import base64
    import binascii

    try:
        content = base64.b64decode(payload.content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="content_base64 is not valid base64",
        )
    try:
        with get_db_connection() as conn:
            row = service.replace_evidence(
                conn, auth.tenant_id, evidence_id,
                title=payload.title, media_type=payload.media_type,
                content=content, reason=payload.reason,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"evidence": row})
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/evidence/{evidence_id}/download",
    status_code=status.HTTP_200_OK,
    summary="Download evidence (an AUDITED read — Q12)",
)
def download_evidence(
    evidence_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.download_evidence(
                conn, auth.tenant_id, evidence_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
        return Response(
            content=bytes(row["content"]),
            media_type=row["media_type"],
            headers={
                "X-Evidence-Sha256": row["sha256"],
                "Content-Disposition": f'attachment; filename="evidence-{evidence_id}"',
            },
        )
    except Exception as e:
        _raise_domain_error(e)


EVIDENCE_INLINE_MEDIA_TYPES = {"text/plain", "application/json", "image/png"}


@router.get(
    "/evidence/{evidence_id}/preview",
    status_code=status.HTTP_200_OK,
    summary="Inline-safe evidence preview (audited; non-previewable types force attachment)",
)
def preview_evidence(
    evidence_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    """V1 preview semantics: only inline-safe media types render inline with
    nosniff + no-store; everything else falls back to an attachment
    disposition. The read is audited under its own event name."""
    try:
        with get_db_connection() as conn:
            row = service.download_evidence(
                conn, auth.tenant_id, evidence_id,
                actor_id=auth.actor_id, actor_role=auth.role,
                audit_event="standard.evidence_previewed",
            )
            conn.commit()
        inline = row["media_type"] in EVIDENCE_INLINE_MEDIA_TYPES
        disposition = (
            f'inline; filename="evidence-{evidence_id}"' if inline
            else f'attachment; filename="evidence-{evidence_id}"'
        )
        return Response(
            content=bytes(row["content"]),
            media_type=row["media_type"] if inline else "application/octet-stream",
            headers={
                "X-Evidence-Sha256": row["sha256"],
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store, private",
                "Content-Disposition": disposition,
            },
        )
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/exceptions",
    status_code=status.HTTP_200_OK,
    summary="Exceptions (expiry materializes on read — no scheduler)",
)
def list_exceptions(auth: AuthContext = Depends(_require_analyst)):
    try:
        with get_db_connection() as conn:
            rows = service.list_exceptions(
                conn, auth.tenant_id, actor_id=auth.actor_id
            )
            conn.commit()
            return _jsonify({"exceptions": rows})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/exceptions",
    status_code=status.HTTP_201_CREATED,
    summary="Request an exception (mandatory expiry)",
)
def create_exception(
    payload: ExceptionCreate,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.create_exception(
                conn, auth.tenant_id,
                control_id=payload.control_id,
                title=payload.title, rationale=payload.rationale,
                expires_at=payload.expires_at,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"exception": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/exceptions/{exception_id}/decide",
    status_code=status.HTTP_200_OK,
    summary="Approve/reject an exception (admin+ at v1 — dual-control candidate open)",
)
def decide_exception(
    exception_id: uuid.UUID,
    payload: ExceptionDecideIn,
    auth: AuthContext = Depends(_require_admin),
):
    try:
        with get_db_connection() as conn:
            row = service.decide_exception(
                conn, auth.tenant_id, exception_id,
                decision=payload.decision,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"exception": row})
    except Exception as e:
        _raise_domain_error(e)


# --- derived workbench reads (V1 GRC parity) ------------------------------


@router.get(
    "/gap-analysis",
    status_code=status.HTTP_200_OK,
    summary="Derived gap analysis: assessment sign-off state per control (read-only)",
)
def get_gap_analysis(auth: AuthContext = Depends(_require_analyst)):
    try:
        with get_db_connection() as conn:
            payload = service.get_gap_analysis(conn, auth.tenant_id)
            conn.commit()
            return _jsonify(payload)
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/advisories",
    status_code=status.HTTP_200_OK,
    summary="Derived compliance advisories from live data (never mutates state)",
)
def list_advisories(auth: AuthContext = Depends(_require_analyst)):
    try:
        with get_db_connection() as conn:
            rows = service.list_advisories(conn, auth.tenant_id)
            conn.commit()
            return _jsonify({"advisories": rows})
    except Exception as e:
        _raise_domain_error(e)


# --- incidents, rules, obligations ---------------------------------------


@router.get(
    "/incidents",
    status_code=status.HTTP_200_OK,
    summary="Incident candidates (deduped, rule-evaluated)",
)
def list_incidents(
    state: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            payload = service.list_incidents(
                conn, auth.tenant_id, state=state, limit=limit, offset=offset
            )
            conn.commit()
            return _jsonify(payload)
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/incidents/{incident_id}",
    status_code=status.HTTP_200_OK,
    summary="Incident detail: evaluations, obligations, revision state",
)
def get_incident(
    incident_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            payload = service.get_incident(conn, auth.tenant_id, incident_id)
            conn.commit()
            return _jsonify(payload)
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/incidents",
    status_code=status.HTTP_201_CREATED,
    summary="Post an incident candidate (validated, timestamped, deduped; rules evaluate)",
)
def create_incident(
    payload: IncidentCreate,
    auth: AuthContext = Depends(_require_analyst),
):
    """Incident candidates are NOT regulatory reports. Rule evaluation runs
    synchronously; a failing rule fails VISIBLY on its evaluation row and the
    incident stays unresolved — never a clean negative."""
    try:
        with get_db_connection() as conn:
            result = service.create_incident(
                conn, auth.tenant_id,
                source=payload.source,
                external_event_id=payload.external_event_id,
                title=payload.title,
                description=payload.description,
                event_time=payload.event_time,
                inputs=payload.inputs,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify(result)
    except Exception as e:
        _raise_domain_error(e)


@router.patch(
    "/incidents/{incident_id}",
    status_code=status.HTTP_200_OK,
    summary="Edit rule-relevant facts (new input revision; rules re-pend; resolved reopens)",
)
def edit_incident(
    incident_id: uuid.UUID,
    payload: IncidentEdit,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            result = service.edit_incident(
                conn, auth.tenant_id, incident_id,
                title=payload.title,
                description=payload.description,
                event_time=payload.event_time,
                inputs=payload.inputs,
                correction_note=payload.correction_note,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify(result)
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/incidents/{incident_id}/acknowledge",
    status_code=status.HTTP_200_OK,
    summary="Acknowledge the incident (open → acknowledged)",
)
def acknowledge_incident(
    incident_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.acknowledge_incident(
                conn, auth.tenant_id, incident_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"incident": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/incidents/{incident_id}/report-draft",
    status_code=status.HTTP_200_OK,
    summary="Derive a MAS TRM 12.1.5 notification DRAFT from this real incident (nothing stored)",
)
def incident_report_draft(
    incident_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    """Honesty rules carried over from V1: a draft is generated only from a
    REAL recorded incident (never fabricated from catalogue totals), and it
    is a derived artifact — a HUMAN submits via the official channel."""
    try:
        with get_db_connection() as conn:
            draft = service.build_incident_report_draft(
                conn, auth.tenant_id, incident_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"report_draft": draft})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/incidents/{incident_id}/rules/{rule_key}/reevaluate",
    status_code=status.HTTP_200_OK,
    summary="Retry a failed/manual-review rule evaluation (attempt history retained)",
)
def reevaluate_rule(
    incident_id: uuid.UUID,
    rule_key: str,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            result = service.reevaluate_rule(
                conn, auth.tenant_id, incident_id, rule_key,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify(result)
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/incidents/{incident_id}/resolve",
    status_code=status.HTTP_200_OK,
    summary="Resolve the incident (blocked while evaluations/obligations are unfinished)",
)
def resolve_incident(
    incident_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.resolve_incident(
                conn, auth.tenant_id, incident_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"incident": row})
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/obligations",
    status_code=status.HTTP_200_OK,
    summary="Obligations with read-time derived deadline state (overdue/breached/late)",
)
def list_obligations(
    state: Optional[str] = Query(None),
    incident_id: Optional[uuid.UUID] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            payload = service.list_obligations(
                conn, auth.tenant_id,
                actor_id=auth.actor_id, state=state, incident_id=incident_id,
                limit=limit, offset=offset,
            )
            conn.commit()
            return _jsonify(payload)
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/obligations/{obligation_id}/transition",
    status_code=status.HTTP_200_OK,
    summary="Start work on the obligation (open → in_progress)",
)
def transition_obligation(
    obligation_id: uuid.UUID,
    payload: ObligationTransitionIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.transition_obligation(
                conn, auth.tenant_id, obligation_id,
                to_state=payload.to,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"obligation": row})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/obligations/{obligation_id}/submission",
    status_code=status.HTTP_201_CREATED,
    summary="Record the human submission proof (immutable; proof is mandatory)",
)
def submit_obligation(
    obligation_id: uuid.UUID,
    payload: SubmissionIn,
    auth: AuthContext = Depends(_require_analyst),
):
    """The HUMAN submitted via the official channel — Tempris never submits
    to a regulator and no submission API is claimed (Flow E step 4/5)."""
    try:
        with get_db_connection() as conn:
            result = service.submit_obligation(
                conn, auth.tenant_id, obligation_id,
                channel=payload.channel,
                reference=payload.reference,
                proof=payload.proof,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify(result)
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/obligations/{obligation_id}/submissions",
    status_code=status.HTTP_200_OK,
    summary="The obligation's immutable submission records",
)
def list_submissions(
    obligation_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            rows = service.list_submissions(conn, auth.tenant_id, obligation_id)
            conn.commit()
            return _jsonify({"submissions": rows})
    except Exception as e:
        _raise_domain_error(e)


@router.post(
    "/obligations/{obligation_id}/close",
    status_code=status.HTTP_200_OK,
    summary="Close a fulfilled obligation (lateness survives closure)",
)
def close_obligation(
    obligation_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            row = service.close_obligation(
                conn, auth.tenant_id, obligation_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return _jsonify({"obligation": row})
    except Exception as e:
        _raise_domain_error(e)


@router.get(
    "/rules",
    status_code=status.HTTP_200_OK,
    summary="The platform-curated rule catalog (read-only at v1)",
)
def list_rules(auth: AuthContext = Depends(_require_analyst)):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, rule_key, rule_version, framework_code,
                           control_code, title, is_active, condition,
                           obligation_template, clock_seconds
                    FROM standard_rules
                    ORDER BY rule_key, rule_version;
                    """
                )
                rows = [dict(r) for r in cur.fetchall()]
            conn.commit()
            return _jsonify({"rules": rows})
    except Exception as e:
        _raise_domain_error(e)
