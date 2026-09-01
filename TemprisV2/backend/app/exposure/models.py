# backend/app/exposure/models.py
"""
Data models and schemas for the Exposure Domain.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator
from app.exposure.exceptions import InvalidEvidenceError

FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["open", "closed", "resolved", "ignored", "false_positive"]
ApplicabilityStatus = Literal["NEEDS_REVIEW", "REFERENCE", "APPLICABLE", "NOT_APPLICABLE"]
ExposureStatus = Literal["confirmed", "resolved", "remediated", "false_positive"]


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
    finding_id: uuid.UUID
    asset_id: uuid.UUID
    applicability: ApplicabilityStatus
    reviewed_by: Optional[str] = None
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
    finding_id: uuid.UUID
    asset_id: uuid.UUID
    evidence: dict[str, Any]
    confirmed_by: Optional[str] = None

    @field_validator("evidence")
    @classmethod
    def validate_evidence_non_empty(cls, v: Any) -> dict[str, Any]:
        if not isinstance(v, dict) or len(v) == 0:
            raise InvalidEvidenceError("Evidence must be a non-empty dictionary/object")
        return v


class ExposureResolve(BaseModel):
    resolved_by: Optional[str] = None
    status: ExposureStatus = "resolved"
    resolution_reason: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_resolved_status(cls, v: ExposureStatus) -> ExposureStatus:
        if v not in ("resolved", "remediated", "false_positive"):
            raise ValueError(f"Invalid resolution status: {v}. Must be resolved, remediated, or false_positive")
        return v


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
