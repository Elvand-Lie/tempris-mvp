from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, JSON, ARRAY, ForeignKey
from sqlalchemy.sql import func
from services.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
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
    finding_id = Column(String(50), nullable=False)
    cve = Column(String(20))
    decision = Column(String(20), nullable=False)
    rationale = Column(Text)  # Business justification for the decision
    decided_by = Column(String(255))
    decided_at = Column(DateTime(timezone=True), server_default=func.now())
    # L3: EDIP Engine enhancements
    auto_classified = Column(Boolean, default=False)
    confidence = Column(Float)
    explanation = Column(Text)
    original_decision = Column(String(20))  # for tracking overrides
    override_reason = Column(Text)


class StrikeAuthorization(Base):
    __tablename__ = "strike_authorizations"
    id = Column(String(50), primary_key=True)
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
    framework_id = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    status = Column(String(20), default="not_assessed")
    updated_by = Column(String(255))
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class ControlEvidence(Base):
    __tablename__ = "control_evidence"
    id = Column(Integer, primary_key=True, autoincrement=True)
    framework_id = Column(String(50), nullable=False)
    control_id = Column(String(50), nullable=False)
    filename = Column(String(255))
    file_path = Column(String(500))
    uploaded_by = Column(String(255))
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())


class IncidentReport(Base):
    __tablename__ = "incident_reports"
    report_id = Column(String(50), primary_key=True)
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
    aggregate_tes = Column(Float, nullable=False)
    finding_count = Column(Integer)
    critical_count = Column(Integer)
    snapshot_at = Column(DateTime(timezone=True), server_default=func.now())


# â”€â”€ Phase 2: Asset Inventory â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class Asset(Base):
    """L5-02/03/08: Asset Inventory for CTEM cycle. Links to findings and controls."""
    __tablename__ = "assets"
    id = Column(String(50), primary_key=True)  # e.g., "ASSET-001"
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


# â”€â”€ Phase 3: Scanner Findings Persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class ScanFinding(Base):
    """L1-04: Persist scan findings to DB so they survive restarts."""
    __tablename__ = "scan_findings"
    id = Column(String(50), primary_key=True)
    scan_id = Column(String(50))
    target = Column(String(255))
    port = Column(Integer)
    service = Column(String(50))
    risk = Column(String(20))
    detail = Column(Text)
    status = Column(String(20), default="new")
    asset_id = Column(String(50))  # link to assets table
    edip_decision = Column(String(20))
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())


# â”€â”€ Phase 4: GRC / ISO 42001 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class GrcState(Base):
    """ISO/IEC 42001:2023 GRC state â€” toggles and SOP builder state."""
    __tablename__ = "grc_states"
    id = Column(Integer, primary_key=True, autoincrement=True)
    toggles = Column(JSON)  # {agm: [bool], drf: [bool], tef: [bool]}
    sop_state = Column(JSON)  # [{id, pic, notes, endUserAgreed, picAgreed}]
    updated_by = Column(String(255))
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class GrcSignoff(Base):
    """Tracks individual PIC / end-user sign-offs for ISO 42001 controls."""
    __tablename__ = "grc_signoffs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(String(20), nullable=False)
    signoff_type = Column(String(20), nullable=False)  # 'end_user' or 'pic'
    signed_by = Column(String(255))
    signed_at = Column(DateTime(timezone=True), server_default=func.now())
    notes = Column(Text)


# â”€â”€ Phase 5: Findings Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class GrcPolicyDocument(Base):
    """Custom GRC policy documents created from the Policy Library."""
    __tablename__ = "grc_policy_documents"
    id = Column(String(80), primary_key=True)
    title = Column(String(255), nullable=False)
    category = Column(String(100), default="Custom")
    version = Column(String(20), default="1.0")
    status = Column(String(50), default="Active")
    owner = Column(String(255), default="CSRO")
    review_cycle = Column(String(50), default="Annual")
    content = Column(Text, nullable=False)
    created_by = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    """Vulnerability findings â€” KEV, PoC scans, and SSS supply chain threats.
    Replaces the in-memory GLOBAL_FINDINGS list with proper DB persistence."""
    __tablename__ = "findings"
    id = Column(String(20), primary_key=True)              # F-1000, F-2000, F-3000
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
    asset_id = Column(String(50))                          # linked asset FK
    asset_data = Column(JSON)                              # denormalized asset match info
    sss_data = Column(JSON)                                # SSS metadata (non-CVE only)
    source = Column(String(20), index=True)                # "kev", "poc", "sss"
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# â”€â”€ Phase 6: Anti-Distillation Defenses â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class AccountQueryLog(Base):
    """Per-account daily query counter for rate limiting + anomaly detection."""
    __tablename__ = "account_query_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    account_email = Column(String(255), nullable=False, index=True)
    endpoint_group = Column(String(50), nullable=False)    # "speak", "spotlight", "edip", "general"
    query_date = Column(String(10), nullable=False, index=True)  # YYYY-MM-DD
    daily_count = Column(Integer, default=0)
    flagged_anomaly = Column(Boolean, default=False)
    anomaly_ratio = Column(Float)                          # current / 7-day avg


class AccountSuspension(Base):
    """ToS enforcement â€” tracks suspended accounts."""
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
    """JWT IDs invalidated by logout before their normal expiry."""
    __tablename__ = "revoked_tokens"
    id = Column(Integer, primary_key=True, autoincrement=True)
    jti = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), server_default=func.now())


