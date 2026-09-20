# backend/app/intake/models.py
"""
Request/response models for Intake & Triage (PRD-000 v1.11 Ch.6).

Actor identity is server-owned everywhere: requested_by/reviewed_by come from
the authenticated context, never from the client (extra='forbid' rejects any
attempt to submit them).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.exposure.exceptions import InvalidEvidenceError
from app.exposure.models import FindingSeverity, SssTaxonomyIn

IntakeSource = Literal["MANUAL", "CONNECTOR", "STRIKE_DISCOVERY", "VDP", "THREAT_PACK"]
IntakeState = Literal["submitted", "under_review", "confirmed", "rejected", "duplicate", "needs_info"]


class IntakeCreate(BaseModel):
    """Intake submission. The taxonomy is optional at submission (the analyst
    classifies during review) but validated against the closed SSS spine when
    supplied — V1's arbitrary-string defect cannot recur (§3.6.5)."""

    model_config = ConfigDict(extra="forbid")

    source: IntakeSource
    title: str = Field(..., min_length=1)
    severity: FindingSeverity
    payload: dict[str, Any]
    description: Optional[str] = None
    taxonomy: Optional[SssTaxonomyIn] = None
    canonical_cve_id: Optional[str] = None
    # proposed anchor — PROPOSED only: anchors resolve at review time, and the
    # confirmation re-validates the asset (tenant, active) before anything.
    asset_id: Optional[uuid.UUID] = None
    # PATCH-07 source-event identity; both halves supplied together or neither
    source_registration_id: Optional[str] = Field(None, min_length=1)
    source_event_id: Optional[str] = Field(None, min_length=1)

    @field_validator("source_event_id")
    @classmethod
    def _event_requires_registration(cls, v: Optional[str], info) -> Optional[str]:
        registration = info.data.get("source_registration_id")
        if v is not None and registration is None:
            raise ValueError(
                "source_event_id requires source_registration_id — the replay "
                "identity tuple is (tenant, registration, event id)"
            )
        return v


class IntakeRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    source: IntakeSource
    state: IntakeState
    payload: dict[str, Any]
    payload_digest: str
    source_registration_id: Optional[str] = None
    source_event_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: FindingSeverity
    canonical_cve_id: Optional[str] = None
    taxonomy_class: Optional[str] = None
    taxonomy_subclass: Optional[str] = None
    taxonomy_subtype: Optional[str] = None
    asset_id: Optional[uuid.UUID] = None
    anchor_state: str
    finding_id: Optional[uuid.UUID] = None
    exposure_id: Optional[uuid.UUID] = None
    duplicate_of_exposure_id: Optional[uuid.UUID] = None
    requested_by: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    deficiency: Optional[str] = None
    rejection_reason: Optional[str] = None
    duplicate_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class IntakeRecordEvent(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    record_id: uuid.UUID
    event: str
    actor: str
    actor_role: Optional[str] = None
    note: Optional[str] = None
    detail: Optional[dict[str, Any]] = None
    created_at: datetime


class IntakeClassify(BaseModel):
    """Classification decision on the closed SSS spine (§3.6.5)."""

    model_config = ConfigDict(extra="forbid")

    taxonomy: SssTaxonomyIn
    note: Optional[str] = None


class IntakeStartReview(BaseModel):
    """submitted|needs_info → under_review."""

    model_config = ConfigDict(extra="forbid")

    note: Optional[str] = None


class IntakeRequestInfo(BaseModel):
    """Hold with a NAMED deficiency (never a silent block)."""

    model_config = ConfigDict(extra="forbid")

    deficiency: str = Field(..., min_length=1)


class IntakeReject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1)


class IntakeConfirmIn(BaseModel):
    """The confirmation command. Evidence is mandatory (non-empty object);
    the anchor is mandatory and re-validated at review time. The two
    acknowledgment flags are the named, audited analyst steps the PRD's
    duplicate rules require — conservative v1, no policy engine."""

    model_config = ConfigDict(extra="forbid")

    asset_id: Optional[uuid.UUID] = None
    evidence: dict[str, Any]
    note: Optional[str] = None
    # exact match against a false_positive exposure ⇒ fresh review required:
    # the analyst explicitly re-examines the prior not-applicable judgment
    revalidate_prior_judgment: bool = False
    # history touching a superseded exposure ⇒ the current anchor must be
    # re-resolved first (e.g. boundary re-designated) before confirmation
    anchor_re_resolved: bool = False

    @field_validator("evidence")
    @classmethod
    def _validate_evidence_non_empty(cls, v: Any) -> dict[str, Any]:
        if not isinstance(v, dict) or len(v) == 0:
            raise InvalidEvidenceError("Evidence must be a non-empty dictionary/object")
        return v


class ConnectorRegistrationCreate(BaseModel):
    """Destination routing + payload semantics ONLY — Ch.5 owns connector
    credentials/principals (Q19 split); there is no credential field to give."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1)
    adapter: str = Field(..., min_length=1)
    destination_routing: dict[str, Any] = Field(default_factory=dict)
    payload_semantics: Optional[str] = None


class ConnectorRegistration(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    adapter: str
    status: str
    destination_routing: dict[str, Any]
    payload_semantics: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime
