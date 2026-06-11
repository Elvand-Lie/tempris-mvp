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


class SpotlightReport(Base):
    __tablename__ = "spotlight_reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_type = Column(String(50), nullable=False)
    narrative = Column(Text, nullable=False)
    tes_score = Column(Float)
    metadata_ = Column("metadata", JSON, default={})
    generated_by = Column(String(255))
    generated_at = Column(DateTime(timezone=True), server_default=func.now())


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


# ── Phase 2: Asset Inventory ─────────────────────────────────────────────────

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


# ── Phase 3: Scanner Findings Persistence ─────────────────────────────────────

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


# ── Phase 4: GRC / ISO 42001 ─────────────────────────────────────────────────

class GrcState(Base):
    """ISO/IEC 42001:2023 GRC state — toggles and SOP builder state."""
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
