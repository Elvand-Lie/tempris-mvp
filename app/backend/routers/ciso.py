'''Tenant-scoped, read-only executive security summary.'''

from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models import (
    Asset,
    ControlStatus,
    Finding,
    GeneratedReport,
    IncidentReport,
    TesSnapshot,
)
from routers.audit import AuditEntry, append_to_audit_log_db
from routers.auth import get_auth_context, require_role
from services.database import get_db


from services.entitlements import require_module
from services.workflow_connections import (
    build_deadline_summary,
    build_exposure_coverage,
    build_workflow_readiness,
)
from services.exposure_links import confirmed_asset_ids_by_finding

router = APIRouter(dependencies=[Depends(require_module("CISO"))])
EXECUTIVE_ROLES = ('Superadmin', 'Admin')
RESOLVED_STATUSES = {'resolved', 'mitigated', 'closed'}
SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}


def _tenant_id(user: dict) -> str:
    tenant_id = get_auth_context(user).tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail='Missing tenant context')
    return tenant_id


def _severity(finding: Finding) -> str:
    priority = (finding.priority or '').upper()
    if priority == 'P0':
        return 'critical'
    if priority == 'P1':
        return 'high'
    if priority == 'P2':
        return 'medium'
    if priority == 'P3':
        return 'low'

    value = finding.score if finding.score is not None else finding.cvss
    if value is None:
        return 'unknown'
    if value >= 9:
        return 'critical'
    if value >= 7:
        return 'high'
    if value >= 4:
        return 'medium'
    return 'low'


def _is_open(finding: Finding) -> bool:
    return (finding.status or '').strip().lower() not in RESOLVED_STATUSES


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)




def _risk_trend(
    snapshots: list[TesSnapshot],
    current_findings: int,
    current_critical: int,
) -> dict:
    if len(snapshots) < 2:
        if current_findings:
            return {
                'status': 'baseline',
                'current_critical': current_critical,
                'current_findings': current_findings,
                'reason': 'Current confirmed exposure is the baseline; trend appears after a second tenant snapshot.',
            }
        return {
            'status': 'unavailable',
            'reason': 'No open asset-linked finding exists to establish a customer risk baseline.',
        }

    current, previous = snapshots[0], snapshots[1]
    current_counts = (current.critical_count or 0, current.finding_count or 0)
    previous_counts = (previous.critical_count or 0, previous.finding_count or 0)
    if current_counts < previous_counts:
        direction = 'improving'
    elif current_counts > previous_counts:
        direction = 'worsening'
    else:
        direction = 'stable'
    return {
        'status': 'available',
        'direction': direction,
        'current_critical': current_counts[0],
        'previous_critical': previous_counts[0],
        'current_findings': current_counts[1],
        'previous_findings': previous_counts[1],
    }


def _highest_risk_assets(
    exposures: list[tuple[Finding, str]],
    assets: list[Asset],
) -> dict:
    asset_map = {asset.id: asset for asset in assets}
    aggregates = defaultdict(lambda: {
        'open_findings': 0,
        'critical_findings': 0,
        'high_findings': 0,
        'highest_severity': 'unknown',
    })
    for finding, asset_id in exposures:
        if asset_id not in asset_map or not _is_open(finding):
            continue
        severity = _severity(finding)
        summary = aggregates[asset_id]
        summary['open_findings'] += 1
        if severity == 'critical':
            summary['critical_findings'] += 1
        if severity == 'high':
            summary['high_findings'] += 1
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER[summary['highest_severity']]:
            summary['highest_severity'] = severity

    rows = []
    for asset_id, summary in aggregates.items():
        asset = asset_map[asset_id]
        rows.append({
            'asset_id': asset.id,
            'name': asset.name,
            'criticality': asset.criticality,
            'owner': asset.owner,
            **summary,
        })
    rows.sort(key=lambda row: (
        SEVERITY_ORDER[row['highest_severity']],
        -row['critical_findings'],
        -row['high_findings'],
        row['asset_id'],
    ))
    if not rows:
        return {'status': 'unavailable', 'reason': 'No confirmed exposure occurs on an active tenant asset', 'items': []}
    return {'status': 'available', 'items': rows[:5]}
def _compliance_gaps(controls: list[ControlStatus]) -> dict:
    if not controls:
        return {'status': 'unavailable', 'reason': 'No tenant control assessments exist'}
    compliant = {'compliant', 'implemented'}
    gaps = [row for row in controls if (row.status or '').strip().lower() not in compliant]
    by_framework = defaultdict(int)
    for row in gaps:
        by_framework[row.framework_id] += 1
    return {
        'status': 'available',
        'assessed_controls': len(controls),
        'gap_count': len(gaps),
        'by_framework': [
            {'framework_id': key, 'gap_count': by_framework[key]}
            for key in sorted(by_framework)
        ],
    }


def _safe_finding(finding: Finding) -> dict:
    return {
        'finding_id': finding.id,
        'title': finding.title,
        'severity': _severity(finding),
        'priority': finding.priority,
        'status': finding.status,
        'asset_id': finding.asset_id,
        'required_action': finding.required_action,
        'created_at': finding.created_at.isoformat() if finding.created_at else None,
        'updated_at': finding.updated_at.isoformat() if finding.updated_at else None,
    }


@router.get('/summary')
def get_ciso_summary(
    db: Session = Depends(get_db),
    user=Depends(require_role(*EXECUTIVE_ROLES)),
):
    tenant_id = _tenant_id(user)
    findings = db.query(Finding).filter(Finding.tenant_id == tenant_id).all()
    assets = db.query(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.status != 'decommissioned',
    ).all()
    asset_map = {asset.id: asset for asset in assets}
    links = confirmed_asset_ids_by_finding(db, tenant_id, asset_map)
    confirmed_findings = [finding for finding in findings if links.get(finding.id)]
    open_findings = [finding for finding in confirmed_findings if _is_open(finding)]
    open_exposures = [
        (finding, asset_id)
        for finding in open_findings
        for asset_id in sorted(links.get(finding.id, set()))
    ]
    severities = defaultdict(int)
    for finding in open_findings:
        severities[_severity(finding)] += 1

    if severities['critical']:
        posture = 'critical'
    elif severities['high']:
        posture = 'high'
    elif severities['medium']:
        posture = 'moderate'
    elif open_findings:
        posture = 'low'
    elif confirmed_findings:
        posture = 'no_open_findings'
    elif findings:
        posture = 'no_confirmed_exposure'
    else:
        posture = 'no_data'

    snapshots = (
        db.query(TesSnapshot)
        .filter(TesSnapshot.tenant_id == tenant_id)
        .order_by(TesSnapshot.snapshot_at.desc())
        .limit(2)
        .all()
    )
    controls = db.query(ControlStatus).filter(ControlStatus.tenant_id == tenant_id).all()
    incidents = (
        db.query(IncidentReport)
        .filter(IncidentReport.tenant_id == tenant_id)
        .order_by(IncidentReport.generated_at.desc())
        .limit(20)
        .all()
    )
    reports = (
        db.query(GeneratedReport)
        .filter(GeneratedReport.tenant_id == tenant_id)
        .order_by(GeneratedReport.created_at.desc())
        .limit(5)
        .all()
    )

    escalations = [
        {
            'report_id': incident.report_id,
            'severity': incident.severity,
            'status': incident.status,
            'generated_at': incident.generated_at.isoformat() if incident.generated_at else None,
        }
        for incident in incidents
        if (incident.severity or '').strip().lower() in {'critical', 'high'}
    ][:5]
    actions = sorted(
        [
            finding for finding in open_findings
            if _severity(finding) in {'critical', 'high'}
        ],
        key=lambda finding: (
            SEVERITY_ORDER[_severity(finding)],
            _as_utc(finding.created_at) or datetime.max.replace(tzinfo=timezone.utc),
            finding.id,
        ),
    )[:5]

    response = {
        'tenant_id': tenant_id,
        'metric_scope': 'confirmed_asset_linked_findings',
        'overall_risk_posture': posture,
        'findings': {
            'total': len(confirmed_findings),
            'unresolved': len(open_findings),
            'critical': severities['critical'],
            'high': severities['high'],
            'recorded_total': len(findings),
            'confirmed_asset_linked': len(confirmed_findings),
            'confirmed_exposure_occurrences': len(open_exposures),
            'unlinked_open': sum(
                1 for finding in findings if _is_open(finding) and not links.get(finding.id)
            ),
        },
        'risk_trend': _risk_trend(
            snapshots,
            current_findings=len(open_findings),
            current_critical=severities['critical'],
        ),
        'highest_risk_assets': _highest_risk_assets(open_exposures, assets),
        'compliance_gaps': _compliance_gaps(controls),
        'exposure_coverage': build_exposure_coverage(db, tenant_id),
        'deadline_summary': build_deadline_summary(db, tenant_id),
        'workflow_readiness': build_workflow_readiness(db, tenant_id),
        'recent_escalations': {
            'status': 'available' if escalations else 'unavailable',
            'items': escalations,
        },
        'executive_actions': {
            'status': 'available' if actions else 'unavailable',
            'items': [_safe_finding(finding) for finding in actions],
        },
        'report_links': {
            'status': 'available' if reports else 'unavailable',
            'items': [
                {
                    'report_id': report.id,
                    'report_type': report.report_type,
                    'created_at': report.created_at.isoformat() if report.created_at else None,
                    'api_path': f'/api/reports/{report.id}/raw',
                    'artifacts': (
                        {
                            fmt: f'/api/reports/{report.id}/artifact/{fmt}'
                            for fmt in ('html', 'json', 'csv')
                        } if report.report_type == 'poc' else {}
                    ),
                }
                for report in reports
            ],
        },
    }
    append_to_audit_log_db(db, AuditEntry(
        action='CISO_SUMMARY_VIEWED',
        module='CISO',
        detail='Viewed tenant-scoped executive security summary',
    ))
    return response


@router.get('/findings/{finding_id}')
def get_ciso_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role(*EXECUTIVE_ROLES)),
):
    tenant_id = _tenant_id(user)
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.tenant_id == tenant_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')
    return _safe_finding(finding)
