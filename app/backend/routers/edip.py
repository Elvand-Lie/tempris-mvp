import asyncio
import json
from datetime import datetime, timezone
from queue import Empty, Full, Queue
from threading import Lock
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from models import Finding
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import get_auth_context, require_role
from services.database import get_db
from services.tes_engine import calculate_sss_tes, priority_from_tes, public_decision_for_finding, public_severity
from services.cvss_remap import v2_to_v31_remap
from services.scout_connectors import aev_verdict_finding, entra_authentication_method_findings
from services.sss_contract import FindingClass, FindingSubclass, deadline_state, public_sss_output, validate_subclass

router = APIRouter()

BLFLAW_SUBTYPES = frozenset({"IDOR", "BFLAW-BAC", "BFLAW-HPE", "BFLAW-BFB", "BFLAW-MSC"})
LEGACY_AGENTIC_SUBCLASSES = frozenset({"INJECTION_PATH", "MEMORY_RAG", "TOOL_MCP", "TRAINING_SUPPLY"})
INDEPENDENT_EGRESS_SOURCES = frozenset({"external siem", "independent monitor"})

# ponytail: in-process fan-out matches the single Uvicorn worker; move to Redis pub/sub before adding workers.
_sss_watch_queues: dict[str, set[Queue]] = {}
_sss_watch_lock = Lock()


def _publish_sss_event(tenant_id: str, payload: dict) -> None:
    with _sss_watch_lock:
        subscribers = tuple(_sss_watch_queues.get(tenant_id, ()))
    for subscriber in subscribers:
        try:
            subscriber.put_nowait(payload)
        except Full:
            try:
                subscriber.get_nowait()
            except Empty:
                pass
            subscriber.put_nowait(payload)


async def _sss_event_stream(tenant_id: str):
    subscriber = Queue(maxsize=10)
    with _sss_watch_lock:
        _sss_watch_queues.setdefault(tenant_id, set()).add(subscriber)
    try:
        yield ": connected\n\n"
        while True:
            try:
                payload = await asyncio.to_thread(subscriber.get, True, 15)
                body = json.dumps(payload, separators=(",", ":"))
                yield f"event: sss.watch\ndata: {body}\n\n"
            except Empty:
                yield ": keepalive\n\n"
    finally:
        with _sss_watch_lock:
            tenant_queues = _sss_watch_queues.get(tenant_id)
            if tenant_queues:
                tenant_queues.discard(subscriber)
                if not tenant_queues:
                    _sss_watch_queues.pop(tenant_id, None)


class SssIntake(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    finding_id: str | None = None
    finding_type: str = Field(default="BLFLAW", max_length=50)
    finding_class: str | None = Field(default=None, alias="class", max_length=50)
    sub_class: str | None = Field(default=None, max_length=50)
    finding_subtype: str | None = Field(default=None, alias="subtype", max_length=50)
    title: str = Field(..., max_length=255)
    description: str = Field(..., max_length=2000)
    affected_ecosystem: str = Field(default="Application", max_length=255)
    attack_vectors: list[str] = Field(default_factory=list)
    base_severity: float = Field(default=7.0, ge=0, le=10)
    agm: float = Field(default=1.0, ge=0, le=2)
    drf: float = Field(default=1.0, ge=0, le=2)
    tef: float = Field(default=1.0, ge=0, le=2)
    patch_available: bool = False
    source_tool: str = Field(default="Manual", max_length=100)
    pii_exposed: bool = False
    compensating_control_notes: str | None = Field(default=None, max_length=2000)
    recommended_action: str = "COMPENSATING_CONTROL"
    compensating_controls: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    asset_id: str | None = None
    agent_id: str | None = Field(default=None, max_length=255)
    credential_scope: str | None = Field(default=None, max_length=255)
    ingestion_paths: list[str] = Field(default_factory=list)
    egress_controlled: bool | None = None
    token_lifetime_minutes: int | None = Field(default=None, ge=0)
    cae_enabled: bool | None = None
    conditional_access_coverage: str | None = Field(default=None, pattern="^(none|partial|enforced)$")
    behavioural_detection: bool | None = None
    itdr_source: str | None = Field(default=None, max_length=255)
    escalation_date: str | None = None
    escalated_severity: str | None = Field(default=None, max_length=20)
    kev_due: str | None = None
    required_control: str | None = Field(default=None, max_length=255)
    portable_asset_priority: bool | None = None
    watch_flag: bool | None = None
    conditional_decision: dict | None = None
    validated: bool | None = None
    path_id: str | None = Field(default=None, max_length=255)
    verdict: str | None = Field(default=None, pattern="^(allowed|detected|prevented)$")
    evidence_ref: str | None = Field(default=None, max_length=1000)
    revalidate_by: str | None = None
    device_code_flow_enabled: bool | None = None
    oauth_grant_inventory: str | None = Field(default=None, pattern="^(none|partial|complete)$")
    app_consent_policy: str | None = Field(default=None, pattern="^(open|restricted|admin_only)$")
    refresh_token_lifetime_days: int | None = Field(default=None, ge=0)
    auth_transfer_blocked: bool | None = None
    ai_workload_inventory: str | None = Field(default=None, pattern="^(none|partial|complete)$")
    workload_credential_scope: str | None = Field(default=None, pattern="^(none|read|write|admin)$")
    egress_monitored_independently: bool | None = None
    containment_tested: bool | None = None
    abort_criteria_owner: str | None = Field(default=None, max_length=255)

    @field_validator("kev_due", "revalidate_by")
    @classmethod
    def validate_deadline(cls, value):
        if value:
            deadline_state(value)
        return value

    @model_validator(mode="after")
    def validate_public_contract(self):
        category = (self.finding_class or self.finding_type).upper()
        self.finding_class = category
        self.sub_class = validate_subclass(category, self.sub_class)
        if category == FindingClass.BLFLAW.value:
            subtype = (self.finding_subtype or "").upper()
            if subtype not in BLFLAW_SUBTYPES:
                raise ValueError(
                    "BLFLAW requires subtype: " + ", ".join(sorted(BLFLAW_SUBTYPES))
                )
            self.finding_subtype = subtype
        if category == FindingClass.IDENTITY_POSTURE.value and not self.sub_class:
            raise ValueError("IDENTITY_POSTURE requires sub_class")
        if category == FindingClass.AGENTIC_EXPOSURE.value:
            if not self.sub_class:
                raise ValueError("AGENTIC_EXPOSURE requires sub_class")
            if self.sub_class in LEGACY_AGENTIC_SUBCLASSES:
                missing = [name for name in ("agent_id", "credential_scope") if not getattr(self, name)]
                if missing or not self.ingestion_paths or self.egress_controlled is None:
                    raise ValueError(
                        "Existing AGENTIC_EXPOSURE sub-classes require agent_id, credential_scope, "
                        "ingestion_paths, and egress_controlled"
                    )
            if (
                self.sub_class == FindingSubclass.AUTONOMOUS_PRINCIPAL.value
                and self.egress_monitored_independently is True
                and self.source_tool.strip().lower() not in INDEPENDENT_EGRESS_SOURCES
            ):
                raise ValueError(
                    "egress_monitored_independently requires evidence from an External SIEM "
                    "or Independent Monitor outside the assessed isolation boundary"
                )
        return self


class SssUpdate(BaseModel):
    base_severity: float | None = Field(default=None, ge=0, le=10)
    patch_available: bool | None = None
    compensating_controls: list[str] | None = None
    compensating_control_notes: str | None = Field(default=None, max_length=2000)
    watch_flag: bool | None = None
    kev_due: str | None = None

    @field_validator("kev_due")
    @classmethod
    def validate_deadline(cls, value):
        if value:
            deadline_state(value)
        return value


class SssResolve(BaseModel):
    resolution_notes: str = Field(..., min_length=3, max_length=2000)


class LegacyCveIntake(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str = Field(..., max_length=255)
    description: str = Field(..., max_length=2000)
    cvss_v2_vector: str = Field(..., max_length=120)
    affected_ecosystem: str = Field(default="Legacy platform", max_length=255)
    csrf_class: bool = False
    patch_available: bool = False
    internet_exposed: bool = False
    asset_id: str | None = None


class EntraAuthenticationSnapshot(BaseModel):
    users: list[dict] = Field(default_factory=list, max_length=5000)
    escalation_date: str = "2027-02-01"


class AevVerdictIntake(BaseModel):
    finding_id: str | None = None
    path_id: str = Field(..., max_length=255)
    verdict: str = Field(..., pattern="^(allowed|detected|prevented)$")
    evidence_ref: str = Field(..., max_length=1000)
    revalidate_by: str
    engagement_token: str = Field(..., min_length=1, max_length=500)
    finding_class: str = "VALIDATION_EVIDENCE"
    sub_class: str | None = None
    title: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    affected_ecosystem: str | None = Field(default=None, max_length=255)
    base_severity: float = Field(default=7.0, ge=0, le=10)
    patch_available: bool = True
    recommended_action: str = "INVESTIGATE"


def _new_id(prefix: str) -> str:
    return f"F-{prefix}-{uuid4().hex[:8]}"


def _tacf_metadata(kind: str, evidence: str) -> dict:
    return {
        "agent_identity": "tempris-edip-intake",
        "authority_granted": f"create-{kind}-finding",
        "tool_used": "edip-intake-api",
        "evidence_generated": evidence,
        "revocation_path": "delete finding or supersede with EDIP decision",
        "under_policy_control": True,
    }


def _tenant_id(user: dict) -> str:
    tenant_id = get_auth_context(user).tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    return tenant_id


def _create_finding(
    db: Session,
    req: SssIntake,
    kind: str,
    tenant_id: str,
    *,
    engine_decision: str | None = None,
    connector_data: dict | None = None,
) -> Finding:
    fid = req.finding_id or f"SSS-{datetime.now(timezone.utc).year}-{kind}-{uuid4().hex[:6].upper()}"
    if db.query(Finding).filter(Finding.cve == fid, Finding.tenant_id == tenant_id).first():
        raise HTTPException(status_code=409, detail="Finding already exists")

    category = (req.finding_class or req.finding_type or kind).upper()
    sub_class = validate_subclass(category, req.sub_class)
    subtype = req.finding_subtype
    scoring = {"base_severity": req.base_severity, "AGM": req.agm, "DRF": req.drf, "TEF": req.tef}
    tes = calculate_sss_tes(scoring)
    public_decision = engine_decision or public_decision_for_finding(
        {"sss_data": {"patch_available": req.patch_available}, "source": "sss"},
        tes,
    )
    public_fields = {
        name: getattr(req, name)
        for name in (
            "agent_id", "credential_scope", "ingestion_paths", "egress_controlled",
            "token_lifetime_minutes", "cae_enabled", "conditional_access_coverage",
            "behavioural_detection", "itdr_source", "escalation_date",
            "escalated_severity", "kev_due", "required_control",
            "portable_asset_priority", "watch_flag", "conditional_decision",
            "validated", "path_id", "verdict", "evidence_ref", "revalidate_by",
            "device_code_flow_enabled", "oauth_grant_inventory", "app_consent_policy",
            "refresh_token_lifetime_days", "auth_transfer_blocked", "ai_workload_inventory",
            "workload_credential_scope", "egress_monitored_independently", "containment_tested",
            "abort_criteria_owner",
        )
        if getattr(req, name) not in (None, "", [])
    }
    finding = Finding(
        id=_new_id("ED"),
        tenant_id=tenant_id,
        finding_type=category,
        subtype=subtype,
        sub_class=sub_class,
        decision=public_decision,
        patch_available=req.patch_available,
        cve_assigned=False,
        cve=fid,
        title=req.title,
        vendor=req.affected_ecosystem,
        product=", ".join(req.attack_vectors),
        cvss=req.base_severity,
        priority=priority_from_tes(tes),
        status="unmitigated",
        cisa_kev=False,
        ransomware=False,
        date_added=datetime.now(timezone.utc).isoformat(),
        short_description=req.description,
        required_action=req.recommended_action,
        raw_inputs={
            "cvss": req.base_severity,
            "exploitability": 10.0,
            "business_impact": min(10.0, req.base_severity * req.drf),
            "asset_criticality": min(10.0, 7.0 * req.tef),
            "threat_actor_activity": min(10.0, 7.0 * req.agm),
        },
        asset_id=req.asset_id,
        sss_data={
            "type": category,
            "source": kind,
            "sub_class": sub_class,
            "subtype": subtype,
            "source_tool": req.source_tool,
            "pii_exposed": req.pii_exposed,
            "compensating_control_notes": req.compensating_control_notes,
            "scoring": scoring,
            "patch_available": req.patch_available,
            "compensating_controls": req.compensating_controls,
            "attack_vectors": req.attack_vectors,
            "references": req.references,
            "engine_decision": public_decision,
            "decision_sequence": [public_decision],
            **public_fields,
            **(connector_data or {}),
        },
        source="sss",
    )
    db.add(finding)
    db.flush()
    return finding


def _public(f: Finding) -> dict:
    sss = f.sss_data or {}
    data = {
        "id": f.id,
        "cve": f.cve,
        "title": f.title,
        "vendor": f.vendor,
        "product": f.product,
        "priority": f.priority,
        "status": f.status,
        "finding_type": sss.get("type") or f.finding_type,
        "class": sss.get("type") or f.finding_type,
        "sub_class": sss.get("sub_class") or f.sub_class,
        "subtype": sss.get("subtype") or f.subtype,
        "description": f.short_description,
        "affected_ecosystem": f.vendor,
        "attack_vectors": sss.get("attack_vectors", []),
        "source_tool": sss.get("source_tool"),
        "pii_exposed": bool(sss.get("pii_exposed")),
        "compensating_control_notes": sss.get("compensating_control_notes"),
        "patch_available": sss.get("patch_available"),
        "compensating_controls": sss.get("compensating_controls", []),
        "source_references": sss.get("references", []),
    }
    data.update(public_sss_output(sss))
    score = calculate_sss_tes(sss.get("scoring", {}))
    data["sss"] = round(float(sss.get("scoring", {}).get("base_severity", f.cvss or 0)), 2)
    data["tes_score"] = score
    data["tes"] = score
    data["tes_decision"] = public_decision_for_finding({"sss_data": sss, "source": f.source}, score)
    data["edip_decision"] = data["tes_decision"]
    data["severity"] = public_severity({"sss_data": sss, "source": f.source, "cve": f.cve, "cvss": f.cvss})
    return data


def _list_findings(db: Session, kind: str, tenant_id: str) -> list[dict]:
    rows = db.query(Finding).filter(
        Finding.source == "sss",
        Finding.tenant_id == tenant_id,
    ).order_by(Finding.created_at.desc()).limit(300).all()
    return [_public(f) for f in rows if ((f.sss_data or {}).get("source") == kind or (f.sss_data or {}).get("type") == kind)]


def _audit_connector(db: Session, request: Request, user: dict, action: str, detail: str) -> None:
    append_to_audit_log_db(db, AuditEntry(
        user=user.get("sub", "unknown"),
        action=action,
        module="EDIP",
        detail=detail,
        ip_address=request.client.host if request.client else None,
        metadata=_tacf_metadata(action.lower(), detail),
    ), commit=False)


@router.post("/intake/sss")
def create_sss(
    req: SssIntake,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst", "Researcher")),
):
    tenant_id = _tenant_id(user)
    try:
        finding = _create_finding(db, req, req.finding_class or "SSS", tenant_id)
        _audit_connector(db, request, user, "AUTO_EDIP_INTAKE", f"SSS intake created {finding.cve}")
        db.commit()
        db.refresh(finding)
    except HTTPException:
        db.rollback()
        raise
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _public(finding)


@router.get("/intake/sss")
def list_sss(
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer", "Researcher")),
):
    rows = db.query(Finding).filter(
        Finding.source == "sss",
        Finding.tenant_id == _tenant_id(user),
    ).order_by(Finding.created_at.desc()).limit(300).all()
    return {"data": [_public(finding) for finding in rows]}


@router.get("/intake/sss/events")
async def stream_sss_events(
    user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer", "Researcher")),
):
    tenant_id = _tenant_id(user)
    return StreamingResponse(
        _sss_event_stream(tenant_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


def _tenant_sss_finding(db: Session, finding_id: str, tenant_id: str) -> Finding:
    finding = db.query(Finding).filter(
        Finding.tenant_id == tenant_id,
        Finding.source == "sss",
        ((Finding.id == finding_id) | (Finding.cve == finding_id)),
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="SSS finding not found")
    return finding


@router.put("/intake/sss/{finding_id}")
def update_sss(
    finding_id: str,
    req: SssUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    tenant_id = _tenant_id(user)
    finding = _tenant_sss_finding(db, finding_id, tenant_id)
    sss = dict(finding.sss_data or {})
    previous_watch = sss.get("watch_flag")
    sequence = list(sss.get("decision_sequence") or [])
    if not sequence and (sss.get("engine_decision") or finding.decision):
        sequence.append(sss.get("engine_decision") or finding.decision)
    scoring = dict(sss.get("scoring") or {})
    if req.base_severity is not None:
        scoring["base_severity"] = req.base_severity
        finding.cvss = req.base_severity
    if req.patch_available is not None:
        sss["patch_available"] = req.patch_available
        finding.patch_available = req.patch_available
    if req.compensating_controls is not None:
        sss["compensating_controls"] = req.compensating_controls
    if req.compensating_control_notes is not None:
        sss["compensating_control_notes"] = req.compensating_control_notes
    if req.watch_flag is not None:
        sss["watch_flag"] = req.watch_flag
    if "kev_due" in req.model_fields_set:
        if req.kev_due:
            sss["kev_due"] = req.kev_due
        else:
            sss.pop("kev_due", None)
    sss["scoring"] = scoring
    sss.pop("engine_decision", None)
    score = calculate_sss_tes(scoring)
    decision = public_decision_for_finding({"sss_data": sss, "source": "sss"}, score)
    if not sequence or sequence[-1] != decision:
        sequence.append(decision)
    sss["decision_sequence"] = sequence
    sss["engine_decision"] = decision
    finding.sss_data = sss
    finding.decision = decision
    finding.priority = priority_from_tes(score)
    _audit_connector(db, request, user, "SSS_INTAKE_UPDATED", f"SSS intake updated {finding.cve}")
    db.commit()
    db.refresh(finding)
    if req.watch_flag is not None and req.watch_flag != previous_watch:
        _publish_sss_event(tenant_id, {
            "type": "sss.watch",
            "finding_id": finding.id,
            "watch_flag": req.watch_flag,
            "kev_due": sss.get("kev_due"),
        })
    return _public(finding)


@router.post("/intake/sss/{finding_id}/resolve")
def resolve_sss(
    finding_id: str,
    req: SssResolve,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    finding = _tenant_sss_finding(db, finding_id, _tenant_id(user))
    if finding.status == "resolved":
        raise HTTPException(status_code=409, detail="SSS finding is already resolved")
    sss = dict(finding.sss_data or {})
    sss.update({
        "resolution_notes": req.resolution_notes,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "resolved_by": get_auth_context(user).user_id,
    })
    finding.sss_data = sss
    finding.status = "resolved"
    _audit_connector(db, request, user, "SSS_INTAKE_RESOLVED", f"SSS intake resolved {finding.cve}")
    db.commit()
    db.refresh(finding)
    return _public(finding)


@router.post("/intake/legacy-cve")
def create_legacy_cve(
    req: LegacyCveIntake,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    try:
        remap = v2_to_v31_remap(req.cvss_v2_vector, csrf_class=req.csrf_class)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    decision = "ESCALATE" if req.internet_exposed else (
        "COMPENSATING_CONTROL" if not req.patch_available else "PATCH"
    )
    intake = SssIntake(
        finding_id=req.cve_id,
        finding_type="CVE",
        title=req.title,
        description=req.description,
        affected_ecosystem=req.affected_ecosystem,
        base_severity=remap["base_score"],
        patch_available=req.patch_available,
        recommended_action=decision,
        asset_id=req.asset_id,
    )
    try:
        finding = _create_finding(
            db,
            intake,
            "LEGACY_CVE",
            _tenant_id(user),
            engine_decision=decision,
            connector_data={
                "cvss_v2_vector": req.cvss_v2_vector,
                "cvss_v31_vector": remap["vector"],
                "cvss_remap_version": remap["mapping_version"],
                "internet_exposed": req.internet_exposed,
            },
        )
        _audit_connector(db, request, user, "LEGACY_CVE_INTAKE", f"Legacy CVE intake created {req.cve_id}")
        db.commit()
        db.refresh(finding)
    except HTTPException:
        db.rollback()
        raise
    response = _public(finding)
    response["cvss_remap"] = remap
    return response


@router.post("/connectors/entra/authentication-methods")
def ingest_entra_authentication_methods(
    req: EntraAuthenticationSnapshot,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    normalized = entra_authentication_method_findings(
        req.users,
        escalation_date=req.escalation_date,
    )
    created = []
    try:
        for record in normalized:
            engine_decision = record.pop("engine_decision")
            connector_data = {
                "identity_subject": record.pop("identity_subject"),
                "deprecated_methods": record.pop("deprecated_methods"),
            }
            intake = SssIntake.model_validate(record)
            finding = _create_finding(
                db,
                intake,
                "SCOUT_ENTRA",
                _tenant_id(user),
                engine_decision=engine_decision,
                connector_data=connector_data,
            )
            created.append(finding)
        _audit_connector(db, request, user, "ENTRA_POSTURE_INTAKE", f"Created {len(created)} identity posture findings")
        db.commit()
        for finding in created:
            db.refresh(finding)
    except HTTPException:
        db.rollback()
        raise
    return {"data": [_public(finding) for finding in created], "flagged_users": len(created)}


@router.post("/connectors/aev/verdicts")
def ingest_aev_verdict(
    req: AevVerdictIntake,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    try:
        normalized = aev_verdict_finding(req.model_dump())
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    engine_decision = normalized.pop("engine_decision")
    intake = SssIntake.model_validate(normalized)
    try:
        finding = _create_finding(
            db,
            intake,
            "SCOUT_AEV",
            _tenant_id(user),
            engine_decision=engine_decision,
        )
        _audit_connector(db, request, user, "AEV_VERDICT_INTAKE", f"AEV verdict created {finding.cve}")
        db.commit()
        db.refresh(finding)
    except HTTPException:
        db.rollback()
        raise
    return _public(finding)


@router.post("/intake/blflaw")
def create_blflaw(req: SssIntake, request: Request, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    req.finding_type = req.finding_type or "BLFLAW"
    req.finding_class = req.finding_type
    try:
        finding = _create_finding(db, req, "BLFLAW", _tenant_id(user))
        append_to_audit_log_db(db, AuditEntry(
            user=user.get("sub", "unknown"), action="AUTO_EDIP_INTAKE", module="EDIP",
            detail=f"BLFLAW intake created {finding.cve}", ip_address=request.client.host if request.client else None,
            metadata=_tacf_metadata("blflaw", finding.cve),
        ), commit=False)
        db.commit()
        db.refresh(finding)
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="EDIP intake failed")
    return _public(finding)


@router.get("/intake/blflaw")
def list_blflaw(db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer"))):
    return {"data": _list_findings(db, "BLFLAW", _tenant_id(user))}


@router.put("/intake/blflaw/{finding_id}")
def update_blflaw(finding_id: str, req: SssIntake, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    f = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == _tenant_id(user),
    ).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.title = req.title
    f.short_description = req.description
    f.vendor = req.affected_ecosystem
    f.product = ", ".join(req.attack_vectors)
    f.required_action = req.recommended_action
    scoring = {"base_severity": req.base_severity, "AGM": req.agm, "DRF": req.drf, "TEF": req.tef}
    f.cvss = req.base_severity
    f.priority = priority_from_tes(calculate_sss_tes(scoring))
    f.sss_data = {**(f.sss_data or {}), "type": req.finding_type or "BLFLAW", "source": "BLFLAW", "scoring": scoring, "patch_available": req.patch_available, "compensating_controls": req.compensating_controls, "attack_vectors": req.attack_vectors, "references": req.references}
    db.commit()
    db.refresh(f)
    return _public(f)


@router.post("/intake/nhi")
def create_nhi(req: SssIntake, request: Request, db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst"))):
    req.finding_type = req.finding_type if req.finding_type.startswith("NHI") else "NHI_AUTHORITY"
    req.finding_class = req.finding_type
    try:
        finding = _create_finding(db, req, "NHI", _tenant_id(user))
        append_to_audit_log_db(db, AuditEntry(
            user=user.get("sub", "unknown"), action="AUTO_EDIP_INTAKE", module="EDIP",
            detail=f"NHI intake created {finding.cve}", ip_address=request.client.host if request.client else None,
            metadata=_tacf_metadata("nhi", finding.cve),
        ), commit=False)
        db.commit()
        db.refresh(finding)
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="EDIP intake failed")
    return _public(finding)


@router.get("/intake/nhi")
def list_nhi(db: Session = Depends(get_db), user=Depends(require_role("Superadmin", "Admin", "Analyst", "Viewer"))):
    rows = db.query(Finding).filter(
        Finding.source == "sss",
        Finding.tenant_id == _tenant_id(user),
    ).order_by(Finding.created_at.desc()).limit(300).all()
    return {"data": [_public(f) for f in rows if str((f.sss_data or {}).get("type", "")).startswith("NHI") or (f.sss_data or {}).get("source") == "NHI"]}
