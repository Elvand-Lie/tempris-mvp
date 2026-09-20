# backend/app/routes/intake.py
"""
Intake & Triage REST API (PRD-000 v1.11 Ch.6).

Every route is analyst+ (confirmation authority: analyst+ — the Ch.3
dual-control gates apply where Ch.3 says; intake adds no new gate) and blocks
the platform tenant session from tenant intake data.

Connectors are transport, never authority: an adapter (or, at v1, the
operator session relaying it — real per-adapter HMAC auth is Ch.5-owned
credential wiring) writes an intake RECORD, never a finding.
"""
from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.auth import AuthContext, require_roles
from app.config import PLATFORM_TENANT_ID
from app.db import get_db_connection
from app.exposure.exceptions import (
    IdentityBoundaryStateError,
    InvalidAssetStatusError,
    InvalidEvidenceError,
)
from app.exposure.sss import SssClassificationError
from app.intake import service
from app.intake.errors import (
    IntakeAmbiguousIdentityError,
    IntakeAnchorRequiredError,
    IntakeAnchorlessClassError,
    IntakeAnchorSupersededError,
    IntakeConnectorRegistrationError,
    IntakeDuplicateExposureError,
    IntakeEventConflictError,
    IntakeNotFoundError,
    IntakePriorFalsePositiveError,
    IntakeStateError,
)
from app.intake.models import (
    ConnectorRegistration,
    ConnectorRegistrationCreate,
    IntakeClassify,
    IntakeConfirmIn,
    IntakeCreate,
    IntakeRecord,
    IntakeRecordEvent,
    IntakeReject,
    IntakeRequestInfo,
    IntakeStartReview,
)
from app.exposure.service import OUTCOME_CREATED, OUTCOME_REPLAY


def require_intake_auth(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
) -> AuthContext:
    """Analyst+ and platform-tenant block (the exposure-domain access shape)."""
    if auth.tenant_id == PLATFORM_TENANT_ID:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform sessions cannot access tenant modules.",
        )
    return auth


router = APIRouter(
    prefix="/api/intake",
    tags=["Intake & Triage"],
    dependencies=[Depends(require_intake_auth)],
)


def _record_response(record: IntakeRecord) -> dict:
    return record.model_dump(mode="json")


@router.post(
    "/connectors",
    response_model=ConnectorRegistration,
    status_code=status.HTTP_201_CREATED,
    summary="Register a connector destination (routing + payload semantics only)",
)
def register_connector(
    payload: ConnectorRegistrationCreate,
    auth: AuthContext = Depends(require_intake_auth),
):
    """Ch.6 owns destination routing and payload semantics; connector
    credentials/principals are Ch.5-managed secrets (Q19 split) — there is no
    credential field to set. Re-registering a name updates the routing."""
    with get_db_connection() as conn:
        registration = service.register_connector(
            conn,
            auth.tenant_id,
            name=payload.name,
            adapter=payload.adapter,
            destination_routing=payload.destination_routing,
            payload_semantics=payload.payload_semantics,
            actor_id=auth.actor_id,
            actor_role=auth.role,
        )
        conn.commit()
        return registration


@router.get(
    "/connectors",
    response_model=List[ConnectorRegistration],
    status_code=status.HTTP_200_OK,
    summary="List connector registrations",
)
def list_connectors(
    auth: AuthContext = Depends(require_intake_auth),
):
    with get_db_connection() as conn:
        return service.list_connectors(conn, auth.tenant_id)


@router.post(
    "",
    response_model=IntakeRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Submit an intake record (manual, connector, STRIKE discovery, VDP, threat pack)",
)
def create_intake_record(
    payload: IntakeCreate,
    response: Response,
    auth: AuthContext = Depends(require_intake_auth),
):
    """
    Create a tenant intake record — never a finding. Tenant and requester are
    server-owned. X-Intake-Outcome distinguishes 'created' from 'replay' (a
    repeating source event with the SAME payload returns the original record;
    a conflicting payload under the same event id is a 409, never a revision).
    """
    try:
        with get_db_connection() as conn:
            result = service.create_intake_record(
                conn, auth.tenant_id, payload,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            response.headers["X-Intake-Outcome"] = result.outcome
            if result.outcome == OUTCOME_REPLAY:
                response.status_code = status.HTTP_200_OK
            return result.record
    except SssClassificationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except IntakeConnectorRegistrationError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": e.code, "message": str(e)},
        )
    except IntakeEventConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )


@router.get(
    "",
    response_model=List[IntakeRecord],
    status_code=status.HTTP_200_OK,
    summary="Intake queues (filter by state / source)",
)
def list_intake_records(
    state: Optional[str] = Query(None, description="Filter by lifecycle state"),
    source: Optional[str] = Query(None, description="Filter by source"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(require_intake_auth),
):
    with get_db_connection() as conn:
        return service.list_intake_records(
            conn, auth.tenant_id, state=state, source=source,
            limit=limit, offset=offset,
        )


@router.get(
    "/{record_id}",
    response_model=IntakeRecord,
    status_code=status.HTTP_200_OK,
    summary="Get an intake record",
)
def get_intake_record(
    record_id: uuid.UUID,
    auth: AuthContext = Depends(require_intake_auth),
):
    try:
        with get_db_connection() as conn:
            return service.get_intake_record(conn, auth.tenant_id, record_id)
    except IntakeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Intake record not found")


@router.get(
    "/{record_id}/events",
    response_model=List[IntakeRecordEvent],
    status_code=status.HTTP_200_OK,
    summary="An intake record's actor trail",
)
def list_intake_record_events(
    record_id: uuid.UUID,
    auth: AuthContext = Depends(require_intake_auth),
):
    try:
        with get_db_connection() as conn:
            return service.list_intake_record_events(conn, auth.tenant_id, record_id)
    except IntakeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Intake record not found")


@router.post(
    "/{record_id}/classify",
    response_model=IntakeRecord,
    status_code=status.HTTP_200_OK,
    summary="Classify on the closed SSS spine",
)
def classify_intake_record(
    record_id: uuid.UUID,
    payload: IntakeClassify,
    auth: AuthContext = Depends(require_intake_auth),
):
    """The taxonomy is CLOSED at intake (§3.6.5): values outside the six-class
    spine (with per-class subclass/subtype presence rules) are rejected 422."""
    try:
        with get_db_connection() as conn:
            record = service.classify_intake_record(
                conn, auth.tenant_id, record_id,
                payload.taxonomy.taxonomy_class,
                payload.taxonomy.taxonomy_subclass,
                payload.taxonomy.taxonomy_subtype,
                actor_id=auth.actor_id, actor_role=auth.role, note=payload.note,
            )
            conn.commit()
            return record
    except IntakeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Intake record not found")
    except SssClassificationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except IntakeStateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )


@router.post(
    "/{record_id}/start-review",
    response_model=IntakeRecord,
    status_code=status.HTTP_200_OK,
    summary="Move a submission into review",
)
def start_intake_review(
    record_id: uuid.UUID,
    payload: Optional[IntakeStartReview] = None,
    auth: AuthContext = Depends(require_intake_auth),
):
    try:
        with get_db_connection() as conn:
            record = service.start_intake_review(
                conn, auth.tenant_id, record_id,
                actor_id=auth.actor_id, actor_role=auth.role,
                note=payload.note if payload else None,
            )
            conn.commit()
            return record
    except IntakeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Intake record not found")
    except IntakeStateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )


@router.post(
    "/{record_id}/request-info",
    response_model=IntakeRecord,
    status_code=status.HTTP_200_OK,
    summary="Hold with a named deficiency (needs_info)",
)
def request_intake_info(
    record_id: uuid.UUID,
    payload: IntakeRequestInfo,
    auth: AuthContext = Depends(require_intake_auth),
):
    try:
        with get_db_connection() as conn:
            record = service.request_intake_info(
                conn, auth.tenant_id, record_id, payload.deficiency,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return record
    except IntakeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Intake record not found")
    except IntakeStateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )


@router.post(
    "/{record_id}/reject",
    response_model=IntakeRecord,
    status_code=status.HTTP_200_OK,
    summary="Reject an intake record (reason required)",
)
def reject_intake_record(
    record_id: uuid.UUID,
    payload: IntakeReject,
    auth: AuthContext = Depends(require_intake_auth),
):
    try:
        with get_db_connection() as conn:
            record = service.reject_intake_record(
                conn, auth.tenant_id, record_id, payload.reason,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
            return record
    except IntakeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Intake record not found")
    except IntakeStateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )


@router.post(
    "/{record_id}/confirm",
    response_model=IntakeRecord,
    status_code=status.HTTP_200_OK,
    summary="Confirm: create the finding + evidence-backed exposure (the Ch.3/Ch.7 handoff)",
)
def confirm_intake_record(
    record_id: uuid.UUID,
    payload: IntakeConfirmIn,
    response: Response,
    auth: AuthContext = Depends(require_intake_auth),
):
    """
    Analyst+ confirmation from 'under_review'. Requires a closed-spine
    classification and a valid anchor; evidence is mandatory. The outcome is
    carried by X-Intake-Outcome and the status:

      * ``confirmed`` (200) — finding + exposure created via the shared Ch.3
        confirmation command;
      * ``duplicate`` (409, code 'intake_duplicate') — exact match against the
        tuple's CURRENT exposure; the record persists with
        ``duplicate_of_exposure_id`` (never a duplicate finding);
      * ``blocked_false_positive`` (409, code
        'false_positive_re_review_required') — fresh analyst re-review required;
      * ``blocked_superseded`` (409, code 'anchor_re_resolution_required') —
        the anchor must be re-resolved first.

    A resolved episode is a RECURRENCE: a new exposure episode is created and
    the record confirms (never a 409). NHI (anchorless, §3.6.6 #8) cannot be
    confirmed — named 409 'anchorless_class'.
    """
    try:
        with get_db_connection() as conn:
            result = service.confirm_intake_record(
                conn, auth.tenant_id, record_id, payload,
                actor_id=auth.actor_id, actor_role=auth.role,
            )
            conn.commit()
    except IntakeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Intake record not found")
    except IntakeStateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )
    except IntakeAnchorlessClassError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )
    except IntakeAnchorRequiredError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )
    except IntakeAmbiguousIdentityError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": e.code, "message": str(e)},
        )
    except InvalidEvidenceError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except IdentityBoundaryStateError as e:
        # §3.6.6 #7: the boundary precondition (enforced inside the shared
        # confirmation command) failed — IDENTITY_POSTURE anchors to the
        # designated boundary asset only.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "identity_boundary_state", "message": str(e)},
        )
    except InvalidAssetStatusError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    response.headers["X-Intake-Outcome"] = result.outcome
    if result.outcome == "confirmed":
        return result.record
    if result.outcome == "duplicate":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": IntakeDuplicateExposureError.code,
                "message": result.blocked_reason,
                "duplicate_of_exposure_id": str(result.duplicate_of_exposure_id),
                "record": result.record.model_dump(mode="json"),
            },
        )
    # blocked_* outcomes
    code = (
        IntakePriorFalsePositiveError.code
        if result.outcome == "blocked_false_positive"
        else IntakeAnchorSupersededError.code
    )
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "code": code,
            "message": result.blocked_reason,
            "record": result.record.model_dump(mode="json"),
        },
    )
