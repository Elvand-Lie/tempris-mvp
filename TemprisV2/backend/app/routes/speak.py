# backend/app/routes/speak.py
"""
SPEAK — Reports / Deliverables REST API (PRD-000 v1.11 Ch.11).

Module-gated (SPEAK entitlement; platform sessions blocked at the root).
Analyst+ for registration/generation/reads; admin+ for approve, archive,
delete, and export (the PRD's approval + export gates). Generation runs
inside ONE REPEATABLE READ boundary and never mutates upstream state; the
chat/AI surface fails closed with no model.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth import AuthContext, require_module, require_roles
from app.db import get_db_connection
from app.exposure.exceptions import ExposureConflictError
from app.speak import service
from app.speak.errors import (
    ArtifactIntegrityError,
    LlmUnavailableError,
    PromptInjectionBlockedError,
    ReportNotFoundError,
    ReportStateError,
    ScopeValidationError,
    SpeakError,
)
from app.speak.render import sha256_bytes

router = APIRouter(
    prefix="/api/speak",
    tags=["SPEAK"],
    dependencies=[Depends(require_module("SPEAK"))],
)


def _require_analyst(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    return auth


def _require_admin(
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"])),
) -> AuthContext:
    return auth


def _snapshot_boundary(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;")


class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=300)
    exposure_ids: Optional[List[uuid.UUID]] = None


class ExportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient: Optional[str] = Field(None, max_length=300)
    note: Optional[str] = Field(None, max_length=2000)


class ChatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(..., min_length=1, max_length=4000)


_STATUS_BY_ERROR = {
    ReportNotFoundError: status.HTTP_404_NOT_FOUND,
    ReportStateError: status.HTTP_409_CONFLICT,
    ScopeValidationError: status.HTTP_422_UNPROCESSABLE_ENTITY,
    ArtifactIntegrityError: status.HTTP_409_CONFLICT,
    LlmUnavailableError: status.HTTP_503_SERVICE_UNAVAILABLE,
    PromptInjectionBlockedError: status.HTTP_422_UNPROCESSABLE_ENTITY,
}


def _http_error(e: SpeakError) -> HTTPException:
    return HTTPException(
        status_code=_STATUS_BY_ERROR.get(type(e), status.HTTP_422_UNPROCESSABLE_ENTITY),
        detail={"code": e.code, "message": str(e)},
    )


@router.post(
    "/reports/register",
    status_code=status.HTTP_201_CREATED,
    summary="Register a draft report (register-time ownership validation)",
)
def register_report(
    payload: RegisterIn,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            report = service.register_report(
                conn, auth.tenant_id,
                report_type=payload.report_type,
                title=payload.title,
                exposure_ids=payload.exposure_ids,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return report
    except SpeakError as e:
        raise _http_error(e)


@router.post(
    "/reports/{report_id}/generate",
    status_code=status.HTTP_200_OK,
    summary="Seal + publish the draft from one coherent source view",
)
def generate_report(
    report_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    """Generation is a reader: it renders the sealed values from upstream
    state and writes only its own rows. Only complete sealed artifacts are
    published — a failure anywhere rolls the whole publication back."""
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            as_of = datetime.now(timezone.utc)
            report = service.generate_report(
                conn, auth.tenant_id, report_id,
                actor_id=auth.actor_id, actor_role=auth.role, as_of=as_of,
            )
            conn.commit()
            return report
    except SpeakError as e:
        raise _http_error(e)
    except ExposureConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "tes_read_conflict", "message": str(e), "retry": True},
        )


@router.post(
    "/reports/{report_id}/regenerate",
    status_code=status.HTTP_200_OK,
    summary="Regenerate as a NEW version row (history never rewritten)",
)
def regenerate_report(
    report_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            as_of = datetime.now(timezone.utc)
            report = service.regenerate_report(
                conn, auth.tenant_id, report_id,
                actor_id=auth.actor_id, actor_role=auth.role, as_of=as_of,
            )
            conn.commit()
            return report
    except SpeakError as e:
        raise _http_error(e)
    except ExposureConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "tes_read_conflict", "message": str(e), "retry": True},
        )


@router.get(
    "/reports",
    status_code=status.HTTP_200_OK,
    summary="List reports (bounded, newest first)",
)
def list_reports(
    report_status: Optional[str] = Query(None, alias="status"),
    report_type: Optional[str] = Query(None, alias="report_type"),
    limit: int = Query(50, ge=1, le=service.REPORT_LIST_LIMIT),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(_require_analyst),
):
    with get_db_connection() as conn:
        result = service.list_reports(
            conn, auth.tenant_id, status=report_status,
            report_type=report_type, limit=limit, offset=offset,
        )
        conn.commit()
    return result


@router.get(
    "/reports/{report_id}",
    status_code=status.HTTP_200_OK,
    summary="One report (sealed values + artifact index)",
)
def get_report(
    report_id: uuid.UUID,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            report = service.get_report(conn, auth.tenant_id, report_id)
            conn.commit()
            return report
    except SpeakError as e:
        raise _http_error(e)


@router.post(
    "/reports/{report_id}/approve",
    status_code=status.HTTP_200_OK,
    summary="Approve the sealed draft (admin+)",
)
def approve_report(
    report_id: uuid.UUID,
    auth: AuthContext = Depends(_require_admin),
):
    try:
        with get_db_connection() as conn:
            report = service.approve_report(
                conn, auth.tenant_id, report_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return report
    except SpeakError as e:
        raise _http_error(e)


@router.post(
    "/reports/{report_id}/archive",
    status_code=status.HTTP_200_OK,
    summary="Archive the approved report (admin+; bytes retained)",
)
def archive_report(
    report_id: uuid.UUID,
    auth: AuthContext = Depends(_require_admin),
):
    try:
        with get_db_connection() as conn:
            report = service.archive_report(
                conn, auth.tenant_id, report_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return report
    except SpeakError as e:
        raise _http_error(e)


@router.delete(
    "/reports/{report_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a never-approved draft (approved/archived are non-deletable)",
)
def delete_report(
    report_id: uuid.UUID,
    auth: AuthContext = Depends(_require_admin),
):
    try:
        with get_db_connection() as conn:
            result = service.delete_report(
                conn, auth.tenant_id, report_id,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return result
    except SpeakError as e:
        raise _http_error(e)


_ARTIFACT_MEDIA = {
    "html": "text/html; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
}


@router.get(
    "/reports/{report_id}/artifacts/{artifact_kind}",
    status_code=status.HTTP_200_OK,
    summary="Download one sealed artifact (hash-verified; mismatch refuses + alarms)",
)
def download_artifact(
    report_id: uuid.UUID,
    artifact_kind: str,
    auth: AuthContext = Depends(_require_analyst),
):
    try:
        with get_db_connection() as conn:
            try:
                artifact = service.read_artifact(
                    conn, auth.tenant_id, report_id, artifact_kind,
                    actor_id=auth.actor_id, actor_role=auth.role,
                )
            except ArtifactIntegrityError:
                # The refusal must not swallow the alarm: the mismatch event
                # is committed before the download is refused.
                conn.commit()
                raise
            conn.commit()
    except SpeakError as e:
        raise _http_error(e)

    hash_verified = (
        sha256_bytes(artifact["content"]) == artifact["content_hash"]
    )
    filename = f"report-{report_id}.{artifact_kind}"
    return Response(
        content=artifact["content"],
        media_type=_ARTIFACT_MEDIA[artifact_kind],
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Artifact-Sha256": artifact["content_hash"],
            "X-Content-Sha256-Verified": "true" if hash_verified else "false",
        },
    )


@router.post(
    "/reports/{report_id}/export",
    status_code=status.HTTP_200_OK,
    summary="Record an export (admin+; audited provenance)",
)
def export_report(
    report_id: uuid.UUID,
    payload: Optional[ExportIn] = None,
    auth: AuthContext = Depends(_require_admin),
):
    try:
        with get_db_connection() as conn:
            result = service.export_report(
                conn, auth.tenant_id, report_id,
                actor_id=auth.actor_id, actor_role=auth.role,
                recipient=payload.recipient if payload else None,
                note=payload.note if payload else None,
            )
            conn.commit()
            return result
    except SpeakError as e:
        raise _http_error(e)


@router.post(
    "/chat",
    status_code=status.HTTP_200_OK,
    summary="SPEAK AI chat (interpretation-only; cites sources; fails closed)",
)
def speak_chat(
    payload: ChatIn,
    auth: AuthContext = Depends(_require_analyst),
):
    """The system's only LLM surface lives here. It interprets one coherent
    read-only view of THIS tenant's authoritative state, labels its answer
    as interpretation, and cites the exact source objects it was given.
    With no configured provider — or an unreachable/malformed one — it
    fails closed: 'unavailable', never invented numbers (the V1 mock-LLM
    fallback is a named defect class and is retired). No session or message
    rows are written; the only write is the tenant's own audit event.

    The snapshot is committed BEFORE the provider call: the connection pool
    is bounded, so no pooled connection is held across the outbound LLM
    round trip; the audit event takes its own short transaction after."""
    try:
        with get_db_connection() as conn:
            _snapshot_boundary(conn)
            context = service.build_chat_context(conn, auth.tenant_id)
            conn.commit()
        return service.complete_chat(
            context, message=payload.message,
            actor_id=auth.actor_id, actor_role=auth.role,
        )
    except SpeakError as e:
        raise _http_error(e)
