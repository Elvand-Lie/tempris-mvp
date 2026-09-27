# backend/app/strike/models.py
"""Request/response models for the STRIKE API.

Client-owned fields ONLY in request bodies. Actor identity, tenant, state,
timestamps, approval bindings, hashes, and derived expiry are server-owned —
``extra='forbid'`` rejects any attempt to submit them (the D-15 fix pattern:
actors are server-populated from the AuthContext).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)


def _as_utc(value: datetime) -> datetime:
    """Normalize to an aware UTC instant. Naive input is read as UTC — the
    codebase convention, mirrored from ``strike.service._aware`` so the ROE
    window comparison and the service's own lease check agree."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _nonblank_text(value: str, field: str) -> str:
    if not value.strip():
        raise ValueError(f"{field} must not be blank")
    return value


def _nonblank_entries(value: list[str], field: str) -> list[str]:
    if any(not item.strip() for item in value):
        raise ValueError(f"{field} entries must not be blank")
    return value


class RoeTimeWindow(BaseModel):
    """The ROE's declared execution window (PRD Ch.4 §4:898, "time window").

    It must be exactly the engagement's authorization window: the
    engagement's ``valid_from``/``valid_until`` IS the lease the workspace
    is held to, so an ROE declaring a different window would be a claim the
    platform never enforces."""

    model_config = ConfigDict(extra="forbid")

    valid_from: datetime
    valid_until: datetime

    @model_validator(mode="after")
    def _ordered(self) -> "RoeTimeWindow":
        if _as_utc(self.valid_until) <= _as_utc(self.valid_from):
            raise ValueError(
                "roe.time_window.valid_until must be after "
                "roe.time_window.valid_from"
            )
        return self

    @field_serializer("valid_from", "valid_until")
    def _canonical(self, value: datetime) -> str:
        """Serialize the window exactly as the Ch.3 renderer does
        (``_jsonify`` → ``datetime.isoformat()``), so the persisted ROE's
        ``time_window`` and the engagement's own ``valid_from``/``valid_until``
        render in ONE canonical form. Pydantic's default emits ``...Z`` for
        UTC while ``isoformat()`` emits ``...+00:00``; without this the two
        halves of the same lease would disagree as strings."""
        return _as_utc(value).isoformat()


class EngagementRoe(BaseModel):
    """The Rules of Engagement REQUIRED at creation (PRD Ch.4 Inputs
    §4:898): scope, methods, credential rules, time window, cleanup and stop
    conditions.

    Every term is required and bounded. The previous free-form ``dict``
    accepted the console's two-literal stub as a complete ROE — the defect
    STRIKE-ENGAGEMENT-01 names. The ROE is frozen at creation; migration 027
    makes ``roe``/``roe_version`` immutable at the DB level, so a revised ROE
    is a new engagement, never an edit."""

    model_config = ConfigDict(extra="forbid")

    scope: list[str] = Field(..., min_length=1, max_length=64)
    methods: list[str] = Field(..., min_length=1, max_length=64)
    credential_rules: str = Field(..., min_length=1, max_length=4000)
    cleanup: str = Field(..., min_length=1, max_length=4000)
    stop_conditions: list[str] = Field(..., min_length=1, max_length=64)
    time_window: RoeTimeWindow

    @field_validator("scope", "methods", "stop_conditions")
    @classmethod
    def _entries_nonblank(cls, v: list[str], info) -> list[str]:
        return _nonblank_entries(v, f"roe.{info.field_name}")

    @field_validator("credential_rules", "cleanup")
    @classmethod
    def _text_nonblank(cls, v: str, info) -> str:
        return _nonblank_text(v, f"roe.{info.field_name}")


class EngagementCreate(BaseModel):
    """Create an engagement DRAFT (analyst+). The ROE is frozen at creation
    and immutable per engagement; a revised ROE is a new engagement."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=300)
    purpose: str = Field(..., min_length=1, max_length=4000)
    # scope, methods, credential rules, cleanup, stop conditions and the
    # ROE's declared time window (Ch.4 Inputs §4:898)
    roe: EngagementRoe
    valid_from: datetime
    valid_until: datetime
    # optional Ch.3 linkage for validation engagements — BY REFERENCE
    finding_id: Optional[uuid.UUID] = None
    asset_id: Optional[uuid.UUID] = None

    @model_validator(mode="after")
    def _roe_window_matches_engagement(self) -> "EngagementCreate":
        """The ROE's declared window must equal the engagement's top-level
        window: the authorization window is the lease, and storing an ROE
        that disagrees with it would record a rule the platform does not
        enforce."""
        if (
            _as_utc(self.roe.time_window.valid_from) != _as_utc(self.valid_from)
            or _as_utc(self.roe.time_window.valid_until) != _as_utc(self.valid_until)
        ):
            raise ValueError(
                "roe.time_window must match the engagement's valid_from/"
                "valid_until — the authorization window is the lease the ROE "
                "declares"
            )
        return self


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
    """Reserve a workspace generation. Carries NO client-owned fields: which
    provider serves the workspace is a server-owned setting, and the shipped
    default configures none (PRD Ch.4 open decision #1). An unimplemented
    ``provider`` request field is therefore refused by ``extra='forbid'``
    rather than accepted and silently discarded — a field the server ignores
    must never look honored."""

    model_config = ConfigDict(extra="forbid")


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
