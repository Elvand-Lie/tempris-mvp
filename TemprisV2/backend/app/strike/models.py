# backend/app/strike/models.py
"""Request/response models for the STRIKE API.

Client-owned fields ONLY in request bodies. Actor identity, tenant, state,
timestamps, approval bindings, hashes, and derived expiry are server-owned —
``extra='forbid'`` rejects any attempt to submit them (the D-15 fix pattern:
actors are server-populated from the AuthContext).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EngagementCreate(BaseModel):
    """Create an engagement DRAFT (analyst+). The ROE is frozen at creation
    and immutable per engagement; a revised ROE is a new engagement."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=300)
    purpose: str = Field(..., min_length=1, max_length=4000)
    # scope, methods, credential rules, cleanup, stop conditions (Ch.4 Inputs;
    # the time window lives in valid_from/valid_until)
    roe: dict[str, Any] = Field(..., min_length=1)
    valid_from: datetime
    valid_until: datetime
    # optional Ch.3 linkage for validation engagements — BY REFERENCE
    finding_id: Optional[uuid.UUID] = None
    asset_id: Optional[uuid.UUID] = None


class EngagementAbort(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=2000)


class TargetCreate(BaseModel):
    """Request a target authorization. The exact target tuple is SNAPSHOTTED
    (Ch.2 target-tuple shape); expiry is required (principle 3)."""

    model_config = ConfigDict(extra="forbid")

    target_type: str = Field(..., min_length=1, max_length=100)
    target_value: str = Field(..., min_length=1, max_length=1000)
    normalized_target: str = Field(..., min_length=1, max_length=1000)
    purpose: str = Field(..., min_length=1, max_length=2000)
    expires_at: datetime


class WorkspaceReserve(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Optional[str] = None


class OperationDispatch(BaseModel):
    """Dispatch an approved ability against an approved target. Parameters
    are carried verbatim into the bounded dispatch record; enforcement never
    derives from client input."""

    model_config = ConfigDict(extra="forbid")

    target_id: uuid.UUID
    ability_id: uuid.UUID
    workspace_id: uuid.UUID
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("params")
    @classmethod
    def _params_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json

        if len(json.dumps(v, default=str)) > 16384:
            raise ValueError("params exceed the 16 KiB dispatch bound")
        return v


class OperationComplete(BaseModel):
    """Record a collected execution result. ``outcome`` passes the
    classifier (EXPLOITABLE/PREVENTED refused — the POC A rule)."""

    model_config = ConfigDict(extra="forbid")

    outcome: str
    summary: Optional[str] = Field(None, max_length=4000)
    native_output: Optional[dict[str, Any]] = None


class ArtifactStore(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=500)
    media_type: str = Field(..., min_length=1, max_length=200)
    content_b64: str = Field(..., min_length=1)
    retention_tier: str = Field("engagement", max_length=100)


class EvidencePromote(BaseModel):
    """Promote a completed operation's validated result into the Ch.3 §3.3.3
    contract (PATCH-01). The authenticated actor IS the review authority:
    ``reviewed_by`` is server-owned. ``basis`` mirrors the Ch.3 write-time
    rule — 'validated' ⇒ controlled_validation (STRIKE-controlled testing),
    'observed' ⇒ observed_exploitation (an actually observed compromise —
    a successful test alone never qualifies and is refused)."""

    model_config = ConfigDict(extra="forbid")

    operation_id: uuid.UUID
    exposure_id: uuid.UUID
    basis: str
    attestation: str = Field(..., min_length=1, max_length=8000)
    observed_at: Optional[datetime] = None

    @field_validator("basis")
    @classmethod
    def _basis_closed(cls, v: str) -> str:
        if v not in ("validated", "observed"):
            raise ValueError(
                "basis must be 'validated' (controlled validation) or "
                "'observed' (actually observed compromise)"
            )
        return v


class DiscoveryReport(BaseModel):
    """Report a discovery from an operation (Flow C): routed as a Ch.6
    intake record carrying the operation/artifact references — never a
    direct finding."""

    model_config = ConfigDict(extra="forbid")

    operation_id: uuid.UUID
    title: str = Field(..., min_length=1, max_length=300)
    severity: str
    description: Optional[str] = Field(None, max_length=8000)
    canonical_cve_id: Optional[str] = None
    asset_id: Optional[uuid.UUID] = None
    source_event_id: Optional[str] = Field(None, max_length=200)


class RelayRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=2000)
