# backend/app/schemas.py
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator

TargetType = Literal["ip", "hostname", "domain"]
NetworkScope = Literal["internet", "internal"]
EnvironmentType = Literal["production", "staging", "development", "test", "other"]
CriticalityType = Literal["critical", "high", "medium", "low"]
AssetStatus = Literal["active", "decommissioned"]
ReachabilityStatus = Literal["unverified", "verified", "unreachable"]
AuthorizationStatus = Literal["pending", "approved", "revoked", "expired"]
EnrollmentStatus = Literal["awaiting_enrollment", "enrolled"]
OperatorStatus = Literal["active", "paused", "quarantined", "revoked"]

class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., min_length=1, max_length=255)
    asset_type: str = Field(..., min_length=1, max_length=100)
    target_type: TargetType
    target_value: str = Field(..., min_length=1)
    network_scope: NetworkScope
    environment: EnvironmentType = "production"
    criticality: CriticalityType = "medium"
    owner: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    collector_id: Optional[uuid.UUID] = None

class AssetUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    asset_type: Optional[str] = Field(None, min_length=1, max_length=100)
    target_type: Optional[TargetType] = None
    target_value: Optional[str] = Field(None, min_length=1)
    network_scope: Optional[NetworkScope] = None
    environment: Optional[EnvironmentType] = None
    criticality: Optional[CriticalityType] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    collector_id: Optional[uuid.UUID] = None

class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    asset_type: str
    target_type: TargetType
    target_value: str
    normalized_target: str
    network_scope: NetworkScope
    environment: EnvironmentType
    criticality: CriticalityType
    owner: Optional[str] = None
    tags: List[str]
    status: AssetStatus
    reachability_status: ReachabilityStatus
    verification_source: Optional[str] = None
    last_verified_at: Optional[datetime] = None
    collector_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime
    decommissioned_at: Optional[datetime] = None

class CollectorCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)

class CollectorEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    collector_id: uuid.UUID
    enrollment_code: str = Field(..., min_length=1)
    public_key: str = Field(..., min_length=1)
    platform_metadata: dict = Field(default_factory=dict)

class CollectorHostBindingRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    asset_id: uuid.UUID

class CollectorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: Optional[str] = None
    enrollment_status: EnrollmentStatus
    operator_status: OperatorStatus
    connection_status: Optional[str] = "offline"
    status: Optional[str] = None
    public_key: Optional[str] = None
    os: Optional[str] = None
    architecture: Optional[str] = None
    hostname: Optional[str] = None
    version: Optional[str] = None
    enrolled_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    platform_metadata: dict = Field(default_factory=dict)
    req_rate_per_sec: Optional[float] = 0.0
    last_toolchain_check: Optional[dict] = None
    server_url: Optional[str] = None
    capabilities: Optional[dict] = None
    created_at: datetime
    updated_at: datetime

class CollectorEnrollmentResponse(CollectorResponse):
    enrollment_code: str
    enrollment_code_expires_at: datetime

class ScanAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    request_reason: Optional[str] = Field(None, max_length=1000)

class ScanAuthorizationApprove(BaseModel):
    model_config = ConfigDict(extra="ignore")

    expires_at: datetime = Field(..., description="Authorization expiration timestamp (must be strictly in future)")

    @field_validator("expires_at")
    @classmethod
    def validate_future_expiry(cls, v: datetime) -> datetime:
        now = datetime.now(timezone.utc)
        target_dt = v if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)
        if target_dt <= now:
            raise ValueError("expires_at must be strictly in the future")
        return target_dt

class ScanAuthorizationRevoke(BaseModel):
    model_config = ConfigDict(extra="ignore")

    revocation_reason: Optional[str] = Field(None, max_length=1000)

class ScanAuthorizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    asset_id: uuid.UUID
    target_type: TargetType
    normalized_target: str
    network_scope: NetworkScope
    status: AuthorizationStatus
    requested_by: str
    requested_at: datetime
    request_reason: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None

class AssetStatsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_assets: int
    reachable_by_scout: int
    authorized_to_scan: int
    pending_authorization: int
    no_scanner_available: int

