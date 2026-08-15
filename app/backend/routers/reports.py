from datetime import date, datetime, timezone
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session
from services.database import get_db
from models import GeneratedReport, Finding, ControlEvidence
from routers.auth import require_role, get_auth_context
from routers.audit import append_to_audit_log_db, AuditEntry
from services.operational_events import record_operational_event

from services.entitlements import require_module

router = APIRouter(dependencies=[Depends(require_module("SPOTLIGHT"))])

class ReportRegisterReq(BaseModel):
    id: str
    engagement_id: str | None = None
    report_type: str  # risk, gap, evidence, combined, json
    generator_version: str
    approved_by: str | None = None
    source_finding_ids: list[str] = Field(default_factory=list)
    source_evidence_ids: list[str] = Field(default_factory=list)
    framework_configuration: dict = Field(default_factory=dict)
    content_hash: str = Field(pattern=r'^[a-fA-F0-9]{64}$')
    artifact_location: str

class ReportGenerateReq(BaseModel):
    report_type: str  # risk, gap, evidence, combined, json
    approved_by: str | None = None
    source_finding_ids: list[str] = Field(default_factory=list)
    source_evidence_ids: list[str] = Field(default_factory=list)
    framework_configuration: dict = Field(default_factory=dict)

class PocClientReq(BaseModel):
    organisation: str = Field(min_length=1, max_length=255)
    contact: str = Field(min_length=1, max_length=255)
    environment: str = Field(min_length=1, max_length=100)


class PocPeriodReq(BaseModel):
    start: date
    end: date

    @model_validator(mode='after')
    def validate_period(self):
        if self.end < self.start:
            raise ValueError('Reporting period end must be on or after its start')
        return self


class PocDeliveryReq(BaseModel):
    recipients: list[str] = Field(default_factory=list, max_length=50)
    alliance_partner: str | None = Field(default=None, max_length=255)
    client_consent_for_partner: bool = False

    @model_validator(mode='after')
    def validate_partner_consent(self):
        if self.client_consent_for_partner and not (self.alliance_partner or '').strip():
            raise ValueError('Alliance partner name is required when partner consent is recorded')
        return self


class PocAssessmentReq(BaseModel):
    method: str | None = Field(default=None, max_length=1000)
    assessor: str | None = Field(default=None, max_length=255)
    attestation: str | None = Field(default=None, max_length=2000)
    attested_by: str | None = Field(default=None, max_length=255)
    limitations: str | None = Field(default=None, max_length=2000)


class PocCoverageReq(BaseModel):
    scope: list[str] = Field(min_length=1, max_length=100)
    out_of_scope: list[str] = Field(min_length=1, max_length=100)
    identities: list[str] = Field(default_factory=list, max_length=100)


class PocConfigurationReq(BaseModel):
    title: str = Field(default='Tempris CTEM & EDIP Client Report', max_length=255)
    engagement_id: str = Field(
        min_length=1, max_length=50, pattern=r'^[A-Za-z0-9._-]+$',
    )
    classification: str = Field(default='Client Confidential', max_length=100)
    retention: str = Field(
        default='Retain according to the client agreement', max_length=500,
    )
    client: PocClientReq
    period: PocPeriodReq
    delivery: PocDeliveryReq = Field(default_factory=PocDeliveryReq)
    assessment: PocAssessmentReq = Field(default_factory=PocAssessmentReq)
    coverage: PocCoverageReq
    executive_narrative: str | None = Field(default=None, max_length=4000)
    next_steps: list[str] = Field(default_factory=list, max_length=50)


class PocReportGenerateReq(BaseModel):
    approved_by: str | None = None
    source_finding_ids: list[str] = Field(default_factory=list, max_length=500)
    configuration: PocConfigurationReq


class ReportArchiveReq(BaseModel):
    archived: bool = True


class ReportDeleteReq(BaseModel):
    confirm_report_id: str = Field(min_length=1, max_length=50)


def _verified_approval(approved_by: str | None, auth_ctx) -> str | None:
    if not approved_by:
        return None
    if auth_ctx.role not in ('Superadmin', 'Admin'):
        raise HTTPException(status_code=403, detail='Report approval requires Admin or Superadmin')
    return auth_ctx.user_id


def _report_lifecycle(report: GeneratedReport) -> dict:
    configuration = (
        report.framework_configuration
        if isinstance(report.framework_configuration, dict)
        else {}
    )
    lifecycle = configuration.get('_lifecycle')
    lifecycle = lifecycle if isinstance(lifecycle, dict) else {}
    return {
        'archived': bool(lifecycle.get('archived')),
        'archived_at': lifecycle.get('archived_at'),
        'archived_by': lifecycle.get('archived_by'),
        'parent_report_id': lifecycle.get('parent_report_id'),
        'document_version': max(1, int(lifecycle.get('document_version') or 1)),
    }


def _safe_registered_artifact(report: GeneratedReport) -> Path | None:
    """Resolve legacy report paths without allowing arbitrary file access."""
    from services.reporting_engine import _report_storage_root

    raw_path = str(report.artifact_location or '').strip()
    if not raw_path:
        return None
    root = _report_storage_root().resolve()
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate.name
    try:
        candidate = candidate.resolve()
        candidate.relative_to(root)
    except (OSError, ValueError):
        return None
    return candidate


def _report_artifacts(report: GeneratedReport) -> dict:
    if report.report_type == 'poc':
        from services.reporting_engine import poc_artifact_path

        artifacts = {}
        for artifact_format in ('html', 'json', 'csv'):
            path = poc_artifact_path(report.id, artifact_format)
            artifacts[artifact_format] = {
                'status': 'available' if path.is_file() else 'missing',
                'url': (
                    f'/api/reports/{report.id}/artifact/{artifact_format}'
                    if path.is_file() else None
                ),
            }
        return artifacts

    path = _safe_registered_artifact(report)
    available = bool(path and path.is_file())
    return {
        'primary': {
            'status': 'available' if available else 'missing',
            'url': f'/api/reports/{report.id}/artifact' if available else None,
        }
    }


def _serialise_report(report: GeneratedReport, include_configuration: bool = False) -> dict:
    lifecycle = _report_lifecycle(report)
    artifacts = _report_artifacts(report)
    response = {
        'id': report.id,
        'engagement_id': report.engagement_id,
        'report_type': report.report_type,
        'generator_version': report.generator_version,
        'requested_by': report.requested_by,
        'approved_by': report.approved_by,
        'source_finding_ids': report.source_finding_ids or [],
        'source_evidence_ids': report.source_evidence_ids or [],
        'finding_count': len(report.source_finding_ids or []),
        'evidence_count': len(report.source_evidence_ids or []),
        'content_hash': report.content_hash,
        'created_at': report.created_at.isoformat() if report.created_at else None,
        'archived': lifecycle['archived'],
        'archived_at': lifecycle['archived_at'],
        'archived_by': lifecycle['archived_by'],
        'parent_report_id': lifecycle['parent_report_id'],
        'document_version': lifecycle['document_version'],
        'artifacts': artifacts,
        'artifact_status': (
            'available'
            if artifacts and all(item['status'] == 'available' for item in artifacts.values())
            else 'missing'
        ),
    }
    if include_configuration:
        configuration = dict(report.framework_configuration or {})
        configuration.pop('_lifecycle', None)
        response['configuration'] = configuration
    return response

@router.post("/register")
def register_report(
    req: ReportRegisterReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    tenant_id = auth_ctx.tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    approved_by = _verified_approval(req.approved_by, auth_ctx)
    from services.customer_posture import canonical_exposure_rows
    canonical_ids = {
        finding.id for finding, _, _ in canonical_exposure_rows(db, tenant_id, open_only=True)
    }
    
    # --- Data Anomalies Check ---
    # 1. Validate source findings exist and belong to correct tenant
    for fid in req.source_finding_ids:
        finding = db.query(Finding).filter(Finding.id == fid).first()
        if not finding:
            raise HTTPException(
                status_code=400, 
                detail=f"ANOMALY_DETECTED: Reference finding {fid} does not exist in the database."
            )
        if finding.tenant_id != tenant_id:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Reference finding {fid} belongs to a different tenant."
            )
        if fid not in canonical_ids:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Reference finding {fid} is not a confirmed open customer exposure.",
            )
            
    # 2. Validate source evidence files exist and belong to correct tenant
    for eid in req.source_evidence_ids:
        try:
            eid_int = int(eid)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Invalid evidence ID {eid}."
            )
        evidence = db.query(ControlEvidence).filter(ControlEvidence.id == eid_int).first()
        if not evidence:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Reference evidence {eid} does not exist in the database."
            )
        if evidence.tenant_id != tenant_id:
            raise HTTPException(
                status_code=400,
                detail=f"ANOMALY_DETECTED: Reference evidence {eid} belongs to a different tenant."
            )

    # Save to reporting registry
    report = GeneratedReport(
        id=req.id,
        tenant_id=tenant_id,
        engagement_id=req.engagement_id,
        report_type=req.report_type,
        generator_version=req.generator_version,
        requested_by=user_email,
        approved_by=approved_by,
        source_finding_ids=req.source_finding_ids,
        source_evidence_ids=req.source_evidence_ids,
        framework_configuration=req.framework_configuration,
        content_hash=req.content_hash,
        artifact_location=req.artifact_location
    )
    db.add(report)
    
    append_to_audit_log_db(db, AuditEntry(
        user=user_email,
        action="REPORT_REGISTERED",
        module="SYNTHESIS",
        detail=f"Registered report {req.id} of type {req.report_type}. Hash: {req.content_hash}."
    ), commit=False)
    
    db.commit()
    db.refresh(report)
    return report

@router.post("/generate")
def generate_report(
    req: ReportGenerateReq,
    db: Session = Depends(get_db),
    user = Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    auth_ctx = get_auth_context(user)
    user_email = auth_ctx.user_id
    tenant_id = auth_ctx.tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    approved_by = _verified_approval(req.approved_by, auth_ctx)
    
    from services.reporting_engine import generate_report_pipeline
    try:
        res = generate_report_pipeline(
            db,
            tenant_id=tenant_id,
            report_type=req.report_type,
            requested_by=user_email,
            approved_by=approved_by,
            source_finding_ids=req.source_finding_ids,
            source_evidence_ids=req.source_evidence_ids,
            framework_configuration=req.framework_configuration
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail='Report generation failed')

@router.post("/poc/generate")
def generate_poc_report(
    req: PocReportGenerateReq,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    auth_ctx = get_auth_context(user)
    if not auth_ctx.tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    approved_by = _verified_approval(req.approved_by, auth_ctx)
    from services.reporting_engine import generate_poc_report_pipeline
    try:
        return generate_poc_report_pipeline(
            db,
            tenant_id=auth_ctx.tenant_id,
            requested_by=auth_ctx.user_id,
            approved_by=approved_by,
            source_finding_ids=req.source_finding_ids,
            configuration=req.configuration.model_dump(mode='json'),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=500, detail='Client report generation failed')

@router.get("")
def list_reports(
    include_archived: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=250),
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    auth_ctx = get_auth_context(user)
    
    if not auth_ctx.tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    query = db.query(GeneratedReport).filter(
        GeneratedReport.tenant_id == auth_ctx.tenant_id
    )
    reports = query.order_by(GeneratedReport.created_at.desc()).limit(limit).all()
    serialised = [_serialise_report(report) for report in reports]
    return serialised if include_archived else [
        report for report in serialised if not report['archived']
    ]


@router.get("/{report_id}")
def get_report_details(
    report_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    auth_ctx = get_auth_context(user)
    report = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.tenant_id == auth_ctx.tenant_id,
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail='Report not found')
    return _serialise_report(report, include_configuration=True)


@router.post("/{report_id}/regenerate")
def regenerate_client_report(
    report_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    auth_ctx = get_auth_context(user)
    report = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.tenant_id == auth_ctx.tenant_id,
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail='Report not found')
    if report.report_type != 'poc':
        raise HTTPException(
            status_code=409,
            detail='Only client report packages can be regenerated',
        )
    configuration = dict(report.framework_configuration or {})
    configuration.pop('_lifecycle', None)
    required = {'client', 'period', 'coverage'}
    if not required.issubset(configuration):
        raise HTTPException(
            status_code=409,
            detail='This legacy report does not contain a reusable report configuration',
        )
    from services.reporting_engine import generate_poc_report_pipeline
    try:
        return generate_poc_report_pipeline(
            db,
            tenant_id=auth_ctx.tenant_id,
            requested_by=auth_ctx.user_id,
            approved_by=None,
            source_finding_ids=report.source_finding_ids or [],
            configuration=configuration,
            parent_report_id=report.id,
            document_version=_report_lifecycle(report)['document_version'] + 1,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=500, detail='Client report regeneration failed')


@router.patch("/{report_id}/archive")
def set_report_archive_state(
    report_id: str,
    req: ReportArchiveReq,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin")),
):
    auth_ctx = get_auth_context(user)
    report = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.tenant_id == auth_ctx.tenant_id,
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail='Report not found')
    configuration = dict(report.framework_configuration or {})
    lifecycle = _report_lifecycle(report)
    if lifecycle['archived'] == req.archived:
        return _serialise_report(report, include_configuration=True)
    lifecycle.update({
        'archived': req.archived,
        'archived_at': datetime.now(timezone.utc).isoformat() if req.archived else None,
        'archived_by': auth_ctx.user_id if req.archived else None,
    })
    configuration['_lifecycle'] = lifecycle
    report.framework_configuration = configuration
    record_operational_event(
        db, tenant_id=auth_ctx.tenant_id,
        event_type='report.archived' if req.archived else 'report.restored',
        resource_type='generated_report', resource_id=report.id,
        source_module='CLIENT_REPORTS', actor_id=auth_ctx.user_id,
    )
    append_to_audit_log_db(db, AuditEntry(
        user=auth_ctx.user_id,
        action='REPORT_ARCHIVED' if req.archived else 'REPORT_RESTORED',
        module='SYNTHESIS',
        detail=f'{"Archived" if req.archived else "Restored"} report {report.id}.',
    ), commit=False)
    db.commit()
    db.refresh(report)
    return _serialise_report(report, include_configuration=True)


@router.delete("/{report_id}")
def delete_report(
    report_id: str,
    req: ReportDeleteReq,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin")),
):
    auth_ctx = get_auth_context(user)
    if req.confirm_report_id != report_id:
        raise HTTPException(status_code=400, detail='Report ID confirmation does not match')
    report = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.tenant_id == auth_ctx.tenant_id,
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail='Report not found')
    if report.approved_by and not _report_lifecycle(report)['archived']:
        raise HTTPException(
            status_code=409,
            detail='Archive an approved report before deleting it',
        )
    artifact_paths = []
    if report.report_type == 'poc':
        from services.reporting_engine import poc_artifact_path
        artifact_paths = [poc_artifact_path(report.id, fmt) for fmt in ('html', 'json', 'csv')]
    else:
        path = _safe_registered_artifact(report)
        if path:
            artifact_paths = [path]
    content_hash = report.content_hash
    db.delete(report)
    append_to_audit_log_db(db, AuditEntry(
        user=auth_ctx.user_id,
        action='REPORT_DELETED',
        module='SYNTHESIS',
        detail=f'Deleted report {report_id}. Previous content hash: {content_hash}.',
    ), commit=False)
    db.commit()
    removed = 0
    for path in artifact_paths:
        try:
            if path.is_file():
                path.unlink()
                removed += 1
        except OSError:
            pass
    return {'status': 'deleted', 'report_id': report_id, 'artifacts_removed': removed}

@router.get("/{report_id}/artifact/{artifact_format}")
def get_poc_artifact(
    report_id: str,
    artifact_format: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    artifact_format = artifact_format.lower()
    auth_ctx = get_auth_context(user)
    report = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.tenant_id == auth_ctx.tenant_id,
        GeneratedReport.report_type == 'poc',
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail='Report artifact not found')
    from services.reporting_engine import poc_artifact_path
    try:
        artifact_path = poc_artifact_path(report_id, artifact_format.lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not artifact_path.is_file():
        raise HTTPException(status_code=404, detail='Report artifact not found')
    record_operational_event(
        db, tenant_id=auth_ctx.tenant_id, event_type='report.downloaded',
        resource_type='generated_report', resource_id=report.id,
        source_module='CLIENT_REPORTS', actor_id=auth_ctx.user_id,
        metadata={'format': artifact_format},
    )
    db.commit()
    media_types = {
        'html': 'text/html; charset=utf-8',
        'json': 'application/json',
        'csv': 'text/csv; charset=utf-8',
    }
    disposition = 'inline' if artifact_format == 'html' else 'attachment'
    headers = {
        'Cache-Control': 'private, no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Tempris-Canonical-Artifact': '1',
        'Content-Disposition': (
            f'{disposition}; filename="{report_id}.{artifact_format}"'
        ),
    }
    if artifact_format == 'html':
        headers['Content-Security-Policy'] = (
            "default-src 'none'; style-src 'unsafe-inline'; "
            "img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
        )
    return Response(
        content=artifact_path.read_bytes(),
        media_type=media_types[artifact_format],
        headers=headers,
    )


@router.get("/{report_id}/artifact")
def get_registered_report_artifact(
    report_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    auth_ctx = get_auth_context(user)
    report = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.tenant_id == auth_ctx.tenant_id,
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail='Report not found')
    if report.report_type == 'poc':
        raise HTTPException(
            status_code=400,
            detail='Select the HTML, JSON, or CSV client-report artifact',
        )
    artifact_path = _safe_registered_artifact(report)
    if not artifact_path or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail='Report artifact is missing')
    suffix = artifact_path.suffix.lower()
    media_type = {
        '.json': 'application/json',
        '.csv': 'text/csv; charset=utf-8',
        '.html': 'text/html; charset=utf-8',
    }.get(suffix, 'application/octet-stream')
    return Response(
        content=artifact_path.read_bytes(),
        media_type=media_type,
        headers={
            'Cache-Control': 'private, no-store',
            'X-Content-Type-Options': 'nosniff',
            'Content-Disposition': f'attachment; filename="{report.id}{suffix or ".bin"}"',
        },
    )

@router.get("/{report_id}/raw")
def get_raw_report(
    report_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst")),
):
    auth_ctx = get_auth_context(user)
    
    report = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.tenant_id == auth_ctx.tenant_id,
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    # Return as clean JSON (raw payload metadata)
    return {
        "id": report.id,
        "tenant_id": report.tenant_id,
        "engagement_id": report.engagement_id,
        "report_type": report.report_type,
        "generator_version": report.generator_version,
        "requested_by": report.requested_by,
        "approved_by": report.approved_by,
        "source_finding_ids": report.source_finding_ids,
        "source_evidence_ids": report.source_evidence_ids,
        "content_hash": report.content_hash,
        "created_at": report.created_at.isoformat() if report.created_at else None
    }
