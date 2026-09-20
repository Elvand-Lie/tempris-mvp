# backend/app/exposure/models.py
"""
Data models and schemas for the Exposure Domain.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.exposure.exceptions import InvalidEvidenceError

FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["open", "closed", "resolved", "ignored", "false_positive"]
ApplicabilityStatus = Literal["NEEDS_REVIEW", "REFERENCE", "APPLICABLE", "NOT_APPLICABLE"]


class SssTaxonomyIn(BaseModel):
    """Optional taxonomy on the manual SSS proposal path — supplied
    all-or-none and validated against the closed SSS spine presence/absence
    matrix (§3.6.5); the client can never invent values outside it.
    Subclass/subtype are Optional because they are NOT APPLICABLE for several
    classes (NULL is the representation); requiredness per class is enforced
    by the shared validator — supplied-but-unsupported and required-but-
    missing both reject 422."""

    model_config = ConfigDict(extra="forbid")

    taxonomy_class: str
    taxonomy_subclass: Optional[str] = None
    taxonomy_subtype: Optional[str] = None


class SssProposalIn(BaseModel):
    """Manual SSS proposal request (§3.6.2 path 3). Client-owned fields
    ONLY: proposed value, reason, evidence, optional valid taxonomy.
    Tenant, proposer actor/role, finding revision, status, validation state,
    version, approval state, and the derived comparison are server-owned —
    any attempt to submit them is rejected (extra='forbid' ⇒ 422)."""

    model_config = ConfigDict(extra="forbid")

    proposed_value: Decimal = Field(...)
    reason: str = Field(..., min_length=1)
    evidence: dict[str, Any]
    taxonomy: Optional[SssTaxonomyIn] = None

    @field_validator("proposed_value")
    @classmethod
    def _validate_value(cls, v: Decimal) -> Decimal:
        from decimal import Decimal as D, InvalidOperation
        if not isinstance(v, D) or not v.is_finite():
            raise ValueError("proposed_value must be a finite Decimal")
        if v != v.quantize(D("0.0001")):
            raise ValueError(
                "proposed_value carries more than four decimal places — the "
                "documented grain is four; excess precision is rejected"
            )
        if not (D("0") <= v <= D("10")):
            raise ValueError("proposed_value is outside 0–10")
        return v
# V3 exposure lifecycle (PRD-000 v1.11 §3.3.1): exactly four V3 WRITE states —
# confirmed / resolved / false_positive / superseded. 'remediated' is legacy:
# storage keeps it compatible (016 CHECK retains it; pre-existing rows are
# preserved), but every V3 application write path rejects it.
ExposureStatus = Literal["confirmed", "resolved", "remediated", "false_positive", "superseded"]


class Finding(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    canonical_cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: FindingSeverity
    status: FindingStatus = "open"
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None


class FindingCreate(BaseModel):
    title: str = Field(..., min_length=1)
    severity: FindingSeverity
    description: Optional[str] = None
    canonical_cve_id: Optional[str] = None


class FindingClose(BaseModel):
    reason: Optional[str] = None


class ApplicabilityReview(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    finding_id: uuid.UUID
    asset_id: uuid.UUID
    applicability: ApplicabilityStatus
    reviewed_by: str
    reason: Optional[str] = None
    created_at: datetime


class ReviewCreate(BaseModel):
    """
    Intake/review request body. Actor identity (`reviewed_by`) is server-owned:
    it is populated from the authenticated actor and client-supplied values are
    rejected (extra='forbid').
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: uuid.UUID
    asset_id: uuid.UUID
    applicability: ApplicabilityStatus
    reason: Optional[str] = None


class AssetExposure(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    finding_id: uuid.UUID
    asset_id: uuid.UUID
    status: ExposureStatus = "confirmed"
    evidence: dict[str, Any]
    confirmed_by: str
    confirmed_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_reason: Optional[str] = None


class ExposureConfirm(BaseModel):
    """
    Confirmation request body. Actor identity (`confirmed_by`) is server-owned:
    it is populated from the authenticated actor / service identity and
    client-supplied values are rejected (extra='forbid').
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: uuid.UUID
    asset_id: uuid.UUID
    evidence: dict[str, Any]

    @field_validator("evidence")
    @classmethod
    def validate_evidence_non_empty(cls, v: Any) -> dict[str, Any]:
        if not isinstance(v, dict) or len(v) == 0:
            raise InvalidEvidenceError("Evidence must be a non-empty dictionary/object")
        return v


class ExposureResolve(BaseModel):
    """
    INTERNAL service-level terminal transition command (resolved /
    false_positive). 'resolved' is reserved for the Chapter 8 verified-closure
    intent emitter and 'false_positive' for the Chapter 6/7 applicability
    decision; NO public route reaches either in Phase 0 (the public
    /resolve endpoint is removed and fails closed). 'superseded' is never
    requestable: supersession is produced by anchor lifecycle events (asset
    decommission, boundary replace-or-clear).
    Actor identity is a server-side command parameter, never a payload field.
    """

    status: Literal["resolved", "false_positive"] = "resolved"
    resolution_reason: Optional[str] = None


class CanonicalExposureItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    exposure_id: uuid.UUID
    tenant_id: uuid.UUID
    finding_id: uuid.UUID
    asset_id: uuid.UUID
    exposure_status: str
    evidence: dict[str, Any]
    confirmed_by: str
    confirmed_at: datetime
    canonical_cve_id: Optional[str] = None
    finding_title: str
    finding_severity: str
    finding_status: str
    asset_name: str
    asset_target_type: str
    asset_normalized_target: str
    asset_network_scope: str
    asset_status: str
