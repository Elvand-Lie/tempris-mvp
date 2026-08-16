from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, JSON, ForeignKey, Index, UniqueConstraint
from sqlalchemy.sql import func
from services.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    user_email = Column(String(255))
    action = Column(String(100), nullable=False)
    module = Column(String(50), nullable=False)
    detail = Column(Text)
    ip_address = Column(String(45))  # IPv4 or IPv6
    metadata_ = Column("metadata", JSON, default={})
    hash = Column(String(64))


class EdipDecision(Base):
    __tablename__ = "edip_decisions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    finding_id = Column(String(50), nullable=False)
    cve = Column(String(20))
    decision = Column(String(20), nullable=False)
    rationale = Column(Text)  # Business justification for the decision
    decided_by = Column(String(255))
    decided_at = Column(DateTime(timezone=True), server_default=func.now())
    auto_classified = Column(Boolean, default=False)
    confidence = Column(Float)
    explanation = Column(Text)
    original_decision = Column(String(20))  # for tracking overrides
    override_reason = Column(Text)

    __table_args__ = (
        UniqueConstraint(tenant_id, finding_id, name="uq_edip_decisions_tenant_finding"),
    )


class StrikeAuthorization(Base):
    __tablename__ = "strike_authorizations"
    id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    target_name = Column(String(255))
    target_ip = Column(String(50))
    techniques = Column(JSON, default=[])
    rules_of_engagement = Column(String(50))
    authorized_by = Column(String(255))
    scope_notes = Column(Text, default="")
    status = Column(String(20), default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    signed_at = Column(DateTime(timezone=True))


class StrikeSimulation(Base):
    __tablename__ = "strike_simulations"
    id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    authorization_id = Column(String(50), ForeignKey("strike_authorizations.id"))
    adapter = Column(String(50))
    status = Column(String(20))
    techniques_tested = Column(JSON, default=[])
    results = Column(JSON, default=[])
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))


class ControlStatus(Base):
    __tablename__ = "control_statuses"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    framework_id = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    status = Column(String(20), default="not_assessed")
    updated_by = Column(String(255))
    updated_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            tenant_id,
            framework_id,
            control_id,
            name="uq_control_statuses_tenant_framework_control",
        ),
    )


class ControlEvidence(Base):
    __tablename__ = "control_evidence"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False)
    framework_id = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    filename = Column(String(255))
    file_path = Column(String(500))
    uploaded_by = Column(String(255))
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_evidence_tenant_framework_control", "tenant_id", "framework_id", "control_id"),
    )


class IncidentReport(Base):
    __tablename__ = "incident_reports"
    report_id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    report_type = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    generated_by = Column(String(255))
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    notification_deadline = Column(DateTime(timezone=True))
    payload = Column(JSON, nullable=False)


class SpotlightReport(Base):
    __tablename__ = "spotlight_reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    report_type = Column(String(50), nullable=False)
    narrative = Column(Text, nullable=False)
    tes_score = Column(Float)
    metadata_ = Column("metadata", JSON, default={})
    generated_by = Column(String(255))
    generated_at = Column(DateTime(timezone=True), server_default=func.now())


class SurgeResearcher(Base):
    __tablename__ = "surge_researchers"
    id = Column(String(50), primary_key=True)
    handle = Column(String(100), nullable=False)
    email = Column(String(255), nullable=False, index=True)
    nda_signed_at = Column(DateTime(timezone=True))
    reputation_score = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SurgeSubmission(Base):
    __tablename__ = "surge_submissions"
    id = Column(String(50), primary_key=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), default="medium")
    description = Column(Text, nullable=False)
    poc_url = Column(String(500))
    attachments = Column(JSON, default=[])
    researcher_id = Column(String(50), ForeignKey("surge_researchers.id"))
    status = Column(String(20), default="submitted")
    edip_decision = Column(String(30))
    bounty_amount = Column(Float)
    paid_at = Column(DateTime(timezone=True))
    finding_id = Column(String(20))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    user_email = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("chat_sessions.id"))
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class TesSnapshot(Base):
    __tablename__ = "tes_snapshots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default='tempris', index=True)
    aggregate_tes = Column(Float, nullable=False)
    finding_count = Column(Integer)
    critical_count = Column(Integer)
    snapshot_at = Column(DateTime(timezone=True), server_default=func.now())


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String(50), primary_key=True)  # e.g., "ASSET-001"
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    name = Column(String(255), nullable=False)
    asset_type = Column(String(50))  # server, application, database, network, endpoint, iot
    ip_address = Column(String(50))
    hostname = Column(String(255))
    criticality = Column(String(20), default="medium")  # critical, high, medium, low
    owner = Column(String(255))
    environment = Column(String(50))  # production, staging, development
    tags = Column(JSON, default=[])
    status = Column(String(20), default="active")  # active, decommissioned, maintenance
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanFinding(Base):
    __tablename__ = "scan_findings"
    id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    scan_id = Column(String(50))
    target = Column(String(255))
    port = Column(Integer)
    service = Column(String(50))
    risk = Column(String(20))
    detail = Column(Text)
    status = Column(String(20), default="new")
    asset_id = Column(String(50))  # link to assets table
    edip_decision = Column(String(20))
    template_id = Column(String(255), index=True)
    cve_id = Column(String(50), index=True)
    matched_at = Column(String(500))
    raw_result_hash = Column(String(64))
    normalized_finding_id = Column(String(50), index=True)
    evidence_metadata = Column(JSON, default={})
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanJob(Base):
    """One tenant-scoped scanner execution, including successful zero-result runs."""

    __tablename__ = "scan_jobs"
    id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    target = Column(String(500), nullable=False)
    normalized_target = Column(String(255), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False)
    engines = Column(JSON, default=[])
    status = Column(String(30), nullable=False, default="started", index=True)
    result_count = Column(Integer, nullable=False, default=0)
    error = Column(Text)
    authorization_context = Column(JSON, default={})
    started_by = Column(String(255))
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True))


class PostureSnapshot(Base):
    """Comparable tenant posture produced only by the canonical posture service."""

    __tablename__ = "posture_snapshots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    captured_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    scope_version = Column(String(50), nullable=False, index=True)
    active_asset_count = Column(Integer, nullable=False, default=0)
    confirmed_open_exposure_count = Column(Integer, nullable=False, default=0)
    confirmed_critical_count = Column(Integer, nullable=False, default=0)
    confirmed_high_count = Column(Integer, nullable=False, default=0)
    confirmed_ransomware_linked_count = Column(Integer, nullable=False, default=0)
    needs_classification_count = Column(Integer, nullable=False, default=0)
    reference_intelligence_count = Column(Integer, nullable=False, default=0)
    evidence_backed_link_count = Column(Integer, nullable=False, default=0)
    legacy_unverified_link_count = Column(Integer, nullable=False, default=0)
    aggregate_tenant_tes = Column(Float)
    scoreable_finding_count = Column(Integer, nullable=False, default=0)


class Incident(Base):
    """Tenant incident received from an authenticated integration or manual intake."""

    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "source", "external_event_id", name="uq_incident_external_event"),
    )

    id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    external_event_id = Column(String(255), nullable=False)
    source = Column(String(100), nullable=False)
    discovered_at = Column(DateTime(timezone=True), nullable=False)
    title = Column(String(500), nullable=False)
    summary = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(30), nullable=False, default="open")
    affected_asset_ids = Column(JSON, default=[])
    related_finding_ids = Column(JSON, default=[])
    evidence_references = Column(JSON, default=[])
    observed_impact = Column(Text)
    response_actions = Column(JSON, default=[])
    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class OperationalEvent(Base):
    """Structured, tenant-scoped operational event; no secrets or raw credentials."""

    __tablename__ = "operational_events"
    id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    occurred_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    actor_type = Column(String(30), nullable=False, default="user")
    actor_id = Column(String(255))
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(100), nullable=False, index=True)
    source_module = Column(String(50), nullable=False, index=True)
    metadata_ = Column("metadata", JSON, default={})
    correlation_id = Column(String(100), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class GrcState(Base):
    __tablename__ = "grc_states"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default='tempris', index=True)
    toggles = Column(JSON)  # {agm: [bool], drf: [bool], tef: [bool]}
    sop_state = Column(JSON)  # [{id, pic, notes, endUserAgreed, picAgreed}]
    updated_by = Column(String(255))
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class GrcSignoff(Base):
    __tablename__ = "grc_signoffs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, default='tempris', index=True)
    control_id = Column(String(20), nullable=False)
    signoff_type = Column(String(20), nullable=False)  # 'end_user' or 'pic'
    signed_by = Column(String(255))
    signed_at = Column(DateTime(timezone=True), server_default=func.now())
    notes = Column(Text)


class GrcPolicyDocument(Base):
    __tablename__ = "grc_policy_documents"
    id = Column(String(80), primary_key=True)
    tenant_id = Column(String(50), nullable=False, default='tempris', index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(100), default="Custom")
    version = Column(String(20), default="1.0")
    status = Column(String(50), default="Active")
    owner = Column(String(255), default="CSRO")
    review_cycle = Column(String(50), default="Annual")
    content = Column(Text, nullable=False)
    created_by = Column(String(255))
    archived_at = Column(DateTime(timezone=True))
    archived_by = Column(String(255))
    supersedes_id = Column(String(80))
    superseded_by_id = Column(String(80))
    deleted_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class FrameworkDefinition(Base):
    """Server-managed GRC framework catalogue entry."""

    __tablename__ = "framework_definitions"
    id = Column(String(80), primary_key=True)
    version = Column(String(40), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    server_managed = Column(Boolean, nullable=False, default=True)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class FrameworkControl(Base):
    """Server-managed control definition; customers assess but cannot create it."""

    __tablename__ = "framework_controls"
    __table_args__ = (
        UniqueConstraint("framework_id", "control_id", name="uq_framework_control"),
        Index("ix_framework_controls_framework_order", "framework_id", "display_order"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    framework_id = Column(String(80), nullable=False, index=True)
    framework_version = Column(String(40), nullable=False)
    control_id = Column(String(40), nullable=False)
    domain = Column(String(120), nullable=False)
    requirement = Column(String(500), nullable=False)
    description = Column(Text)
    modifier_group = Column(String(10), nullable=False, default="NONE")
    display_order = Column(Integer, nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class ControlAssessment(Base):
    """The tenant-owned SOP assessment for one server-defined framework control."""

    __tablename__ = "control_assessments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "framework_id", "control_id", name="uq_control_assessment_tenant_control"),
        Index("ix_control_assessments_tenant_framework", "tenant_id", "framework_id"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    framework_id = Column(String(80), nullable=False)
    control_id = Column(String(40), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    pic = Column(String(255), default="")
    notes = Column(Text, default="")
    end_user_agreed = Column(Boolean, nullable=False, default=False)
    pic_signed_off = Column(Boolean, nullable=False, default=False)
    created_by = Column(String(255))
    updated_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class PolicyControlLink(Base):
    """Explicit supporting-document link; never a scoring or completion shortcut."""

    __tablename__ = "policy_control_links"
    __table_args__ = (
        UniqueConstraint("tenant_id", "policy_id", "framework_id", "control_id", name="uq_policy_control_link"),
        Index("ix_policy_control_links_tenant_control", "tenant_id", "framework_id", "control_id"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    policy_id = Column(String(80), nullable=False, index=True)
    framework_id = Column(String(80), nullable=False)
    control_id = Column(String(40), nullable=False)
    relation_type = Column(String(40), nullable=False, default="supporting_evidence")
    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String(50), primary_key=True)
    display_name = Column(String(255), nullable=False)
    tenant_type = Column(String(30), nullable=False, default="customer", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class TenantPackage(Base):
    __tablename__ = "tenant_packages"
    tenant_id = Column(String(50), primary_key=True)
    package_code = Column(String(20), nullable=False, default="DOMINATE")
    module_overrides = Column(JSON, default={}, nullable=False)
    version = Column(Integer, nullable=False, default=1, server_default="1")
    updated_by = Column(String(255), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String(20), primary_key=True)              # F-1000, F-2000, F-3000
    tenant_id = Column(String(50), nullable=False, default="tempris", index=True)
    external_id = Column(String(100), index=True)
    cve_id = Column(String(50), index=True)
    finding_type = Column(String(50), nullable=False, default="standard")
    subtype = Column(String(50))
    sub_class = Column(String(50), index=True)
    pipeline = Column(String(50), nullable=False, default="STANDARD")
    verification = Column(String(50), nullable=False, default="CONFIRMED")
    score = Column(Float)
    decision = Column(String(50))
    sla = Column(Integer)
    patch_available = Column(Boolean, default=True)
    cve_assigned = Column(Boolean, default=True)
    exploited_in_wild = Column(Boolean, default=False)
    ai_assisted = Column(Boolean, default=False)
    engagement_id = Column(String(50), index=True)
    summary = Column(Text)
    description = Column(Text)
    public_reason_codes = Column(JSON, default=[])
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    # Legacy fields mapping
    cve = Column(String(50), index=True)                   # CVE-2026-XXXX or SSS-2026-XXXX
    title = Column(String(500), nullable=False)
    vendor = Column(String(255), index=True)
    product = Column(String(255))
    cvss = Column(Float, index=True)
    priority = Column(String(5), index=True)               # P0, P1, P2, P3
    status = Column(String(20), default="unmitigated")
    cisa_kev = Column(Boolean, default=False, index=True)
    ransomware = Column(Boolean, default=False, index=True)
    date_added = Column(String(50))
    short_description = Column(Text)
    required_action = Column(Text)
    raw_inputs = Column(JSON)                              # TES calculation inputs
    # Current CVE context is deliberately separate from legacy ``raw_inputs``.
    # It records analyst-entered impact and trusted evidence provenance only.
    cve_context = Column(JSON, default={})
    asset_id = Column(String(50))                          # linked asset FK
    asset_data = Column(JSON)                              # denormalized asset match info
    sss_data = Column(JSON)                                # SSS metadata (non-CVE only)
    source = Column(String(20), index=True)                # "kev", "poc", "sss"
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AssetExposure(Base):
    """One confirmed or reviewed occurrence of a finding on a tenant asset."""

    __tablename__ = "asset_exposures"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "finding_id", "asset_id",
            name="uq_asset_exposure_tenant_finding_asset",
        ),
        Index("ix_asset_exposures_tenant_status", "tenant_id", "status"),
    )

    id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    finding_id = Column(String(50), nullable=False, index=True)
    asset_id = Column(String(50), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="confirmed")
    match_method = Column(String(50), nullable=False, default="manual")
    confidence = Column(Float)
    evidence = Column(Text)
    evidence_metadata = Column(JSON, default={})
    recorded_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AccountQueryLog(Base):
    __tablename__ = "account_query_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    account_email = Column(String(255), nullable=False, index=True)
    endpoint_group = Column(String(50), nullable=False)    # "speak", "spotlight", "edip", "general"
    query_date = Column(String(10), nullable=False, index=True)  # YYYY-MM-DD
    daily_count = Column(Integer, default=0)
    flagged_anomaly = Column(Boolean, default=False)
    anomaly_ratio = Column(Float)                          # current / 7-day avg


class AccountSuspension(Base):
    __tablename__ = "account_suspensions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    suspended_at = Column(DateTime(timezone=True), server_default=func.now())
    suspended_by = Column(String(255))                     # "system:tos_enforcer" or admin email
    auto_suspended = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True, index=True)  # False = unsuspended
    unsuspended_at = Column(DateTime(timezone=True))


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    id = Column(Integer, primary_key=True, autoincrement=True)
    jti = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), server_default=func.now())


class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(String(50), primary_key=True)  # UUID string
    account_subject = Column(String(255), nullable=False, index=True)
    jti_hash = Column(String(64), nullable=False, index=True)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))
    revoking_actor = Column(String(255))
    revocation_reason = Column(String(500))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    user_agent = Column(String(255))


# ── Generic Finding Supporting Tables ───────────────────────────────────────

class FindingRelationship(Base):
    __tablename__ = "finding_relationships"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_id = Column(String(50), nullable=False, index=True)
    target_id = Column(String(50), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False)  # CHAIN, ACTOR_CLUSTER, META_PATTERN, ENRICHES, DUPLICATE_OF, RELATED_TO
    metadata_ = Column("metadata", JSON, default=[])  # ordering, label, breakpoint, narrative
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class FindingSource(Base):
    __tablename__ = "finding_sources"
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(50), nullable=False, index=True)
    source_id = Column(String(100), nullable=False)
    publisher = Column(String(255), nullable=False)
    retrieved_at = Column(DateTime(timezone=True), nullable=False)
    last_verified_at = Column(DateTime(timezone=True), nullable=False)
    verification_state = Column(String(50), nullable=False, default="CONFIRMED")  # CONFIRMED, DISPUTED, SINGLE_SOURCE
    expiry_date = Column(DateTime(timezone=True))
    analyst_notes = Column(Text)


class FindingDisputedClaim(Base):
    __tablename__ = "finding_disputed_claims"
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(50), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    claim_details = Column(Text, nullable=False)
    disagreement_text = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class FindingControl(Base):
    __tablename__ = "finding_controls"
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    layer_type = Column(String(50), nullable=False)  # build, identity, network, detection, response, governance, awareness, patch, compensating
    priority = Column(String(5), nullable=False, default="P1")
    status = Column(String(20), nullable=False, default="not_assessed")


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(50), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    uploaded_by = Column(String(255), nullable=False)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    verification_state = Column(String(50), nullable=False, default="CONFIRMED")  # CONFIRMED, DISPUTED, SINGLE_SOURCE


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(50), nullable=False, index=True)
    old_status = Column(String(50), nullable=False)
    new_status = Column(String(50), nullable=False)
    changed_by = Column(String(255), nullable=False)
    changed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    notes = Column(Text)


# ── Partner Program & Onboarding Tracker ─────────────────────────────────────

class PartnerOnboarding(Base):
    __tablename__ = "partner_onboarding"
    id = Column(String(50), primary_key=True)
    partner_id = Column(String(50), nullable=False, index=True)
    license_verified = Column(Boolean, default=False, nullable=False)
    agreements_signed = Column(Boolean, default=False, nullable=False)
    attendees = Column(JSON, default=[], nullable=False)
    provisioning_status = Column(String(50), default="pending", nullable=False)
    role_assigned = Column(String(50))
    attendance_checkins = Column(JSON, default=[], nullable=False)
    module_checkpoints = Column(JSON, default={}, nullable=False)
    pilot_evidence_submitted = Column(Boolean, default=False, nullable=False)
    assessment_result = Column(String(50))
    certification_number = Column(String(100))
    expiry_date = Column(DateTime(timezone=True))
    renewal_status = Column(String(50))
    release_notes_acknowledged = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ── Unified Reporting Registry ──────────────────────────────────────────────

class GeneratedReport(Base):
    __tablename__ = "generated_reports"
    id = Column(String(50), primary_key=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    engagement_id = Column(String(50))
    report_type = Column(String(50), nullable=False)  # risk, gap, evidence, combined, json
    generator_version = Column(String(20), nullable=False)
    requested_by = Column(String(255), nullable=False)
    approved_by = Column(String(255))
    source_finding_ids = Column(JSON, default=[], nullable=False)
    source_evidence_ids = Column(JSON, default=[], nullable=False)
    framework_configuration = Column(JSON, default={}, nullable=False)
    content_hash = Column(String(64), nullable=False)
    artifact_location = Column(String(500), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ── AEV Registry and Runs ───────────────────────────────────────────────────

class AevModule(Base):
    __tablename__ = "aev_modules"
    id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    enabled = Column(Boolean, default=False, nullable=False)
    contract_approved = Column(Boolean, default=False, nullable=False)
    owner = Column(String(255))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AevRun(Base):
    __tablename__ = "aev_runs"
    id = Column(String(50), primary_key=True)
    module_id = Column(String(50), ForeignKey("aev_modules.id"), nullable=False)
    tenant_id = Column(String(50), nullable=False, index=True)
    status = Column(String(50), default="DRAFT", nullable=False)  # DRAFT, AUTHORIZED, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED
    authorized_by = Column(String(255))
    target_input = Column(JSON, default={}, nullable=False)
    evidence_generated = Column(JSON, default=[], nullable=False)
    safety_gate_passed = Column(Boolean, default=False, nullable=False)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))


# ── Operations Change Queue ──────────────────────────────────────────────────

class OperationsChangeTicket(Base):
    __tablename__ = "operations_change_queue"
    id = Column(String(50), primary_key=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    runbook_reference = Column(String(255))
    backup_required = Column(Boolean, default=True, nullable=False)
    rollback_plan = Column(Text)
    dry_run_output = Column(Text)
    preflight_passed = Column(Boolean, default=False, nullable=False)
    status = Column(String(50), default="PENDING", nullable=False)  # PENDING, APPROVED, EXECUTED, FAILED, ROLLED_BACK
    approved_by = Column(String(255))
    approved_at = Column(DateTime(timezone=True))
    evidence_path = Column(String(500))
    post_verification_template = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
