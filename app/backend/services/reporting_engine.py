'''Tenant-scoped JSON and CSV report generation.'''

import csv
import hashlib
import io
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from models import ControlEvidence, Finding, GeneratedReport
from routers.audit import AuditEntry, append_to_audit_log_db


REPORT_TYPES = {'risk', 'gap', 'evidence', 'combined', 'json'}
PRIVATE_REPORT_KEYS = {
    'agm',
    'drf',
    'tef',
    'raw_inputs',
    'formula',
    'formula_metadata',
    'intermediate_calculations',
    'modifier_table_ref',
    'sss_data',
    'tes_breakdown',
    'tes_intermediate',
    'tes_raw',
}


def _clean_report_value(value):
    if isinstance(value, dict):
        return {
            key: _clean_report_value(item)
            for key, item in value.items()
            if str(key).lower() not in PRIVATE_REPORT_KEYS
        }
    if isinstance(value, list):
        return [_clean_report_value(item) for item in value]
    return value


def _spreadsheet_safe(value):
    if value is None:
        return ''
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(('=', '+', '-', '@')):
        return f'\'{value}'
    return value


def _csv_content(headers: list[str], rows: list[list]) -> str:
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\n')
    writer.writerow(headers)
    for row in rows:
        writer.writerow([_spreadsheet_safe(value) for value in row])
    return output.getvalue()


def _report_storage_root() -> Path:
    configured = os.environ.get('REPORT_STORAGE_ROOT', '').strip()
    root = Path(configured) if configured else Path('backups') / 'reports'
    root.mkdir(parents=True, exist_ok=True)
    return root


def _load_findings(
    db: Session,
    tenant_id: str,
    source_ids: list[str],
) -> list[Finding]:
    findings = []
    for finding_id in dict.fromkeys(source_ids):
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding or finding.tenant_id != tenant_id:
            raise ValueError(f'Reference finding {finding_id} is unavailable for this tenant')
        findings.append(finding)
    return findings


def _load_evidence(
    db: Session,
    tenant_id: str,
    source_ids: list[str],
) -> list[ControlEvidence]:
    evidence_ids = []
    for source_id in source_ids:
        try:
            evidence_ids.append(int(source_id))
        except (TypeError, ValueError):
            raise ValueError(f'Invalid evidence ID {source_id}')

    evidence_rows = []
    for evidence_id in dict.fromkeys(evidence_ids):
        evidence = db.query(ControlEvidence).filter(ControlEvidence.id == evidence_id).first()
        if not evidence or evidence.tenant_id != tenant_id:
            raise ValueError(f'Reference evidence {evidence_id} is unavailable for this tenant')
        evidence_rows.append(evidence)
    return evidence_rows


def _risk_csv(report_data: dict) -> str:
    return _csv_content(
        ['Finding ID', 'CVE', 'Title', 'Vendor', 'Product', 'CVSS', 'Priority', 'Status'],
        [
            [
                finding['id'],
                finding['cve'] or 'N/A',
                finding['title'],
                finding['vendor'],
                finding['product'],
                finding['cvss'],
                finding['priority'],
                finding['status'],
            ]
            for finding in report_data['findings']
        ],
    )


def _gap_csv(report_data: dict) -> str:
    return _csv_content(
        ['Framework ID', 'Control ID', 'Filename'],
        [
            [evidence['framework_id'], evidence['control_id'], evidence['filename']]
            for evidence in report_data['evidence']
        ],
    )


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding='utf-8', newline='')


def generate_report_pipeline(
    db: Session,
    tenant_id: str,
    report_type: str,
    requested_by: str,
    approved_by: str | None = None,
    source_finding_ids: list[str] | None = None,
    source_evidence_ids: list[str] | None = None,
    framework_configuration: dict | None = None,
) -> dict:
    report_type = report_type.strip().lower()
    if report_type == 'pdf':
        raise ValueError(
            'PDF_GENERATION_BLOCKED: Safe native PDF layout dependencies are absent or disabled.'
        )
    if report_type not in REPORT_TYPES:
        raise ValueError('Unsupported report type')
    if not tenant_id:
        raise ValueError('Missing tenant context')

    finding_ids = source_finding_ids or []
    evidence_ids = source_evidence_ids or []
    configuration = _clean_report_value(framework_configuration or {})
    findings = _load_findings(db, tenant_id, finding_ids)
    evidences = _load_evidence(db, tenant_id, evidence_ids)

    report_data = {
        'report_type': report_type,
        'tenant_id': tenant_id,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'findings': [
            {
                'id': finding.id,
                'cve': finding.cve,
                'title': finding.title,
                'vendor': finding.vendor,
                'product': finding.product,
                'cvss': finding.cvss,
                'priority': finding.priority,
                'status': finding.status,
                'short_description': finding.short_description,
            }
            for finding in findings
        ],
        'evidence': [
            {
                'id': evidence.id,
                'framework_id': evidence.framework_id,
                'control_id': evidence.control_id,
                'filename': evidence.filename,
            }
            for evidence in evidences
        ],
    }
    report_id = f'REP-{uuid.uuid4().hex[:8].upper()}'
    storage_root = _report_storage_root()
    created_paths: list[Path] = []

    try:
        if report_type == 'combined':
            risk_content = _risk_csv(report_data)
            gap_content = _gap_csv(report_data)
            risk_path = storage_root / f'{report_id}_risk.csv'
            gap_path = storage_root / f'{report_id}_gap.csv'
            _write_text(risk_path, risk_content)
            _write_text(gap_path, gap_content)
            created_paths.extend([risk_path, gap_path])
            manifest_data = {
                'report_id': report_id,
                'tenant_id': tenant_id,
                'engagement_id': configuration.get('engagement_id', 'ENG-DEFAULT'),
                'report_type': 'combined',
                'generator_version': 'v2.2.0',
                'requested_by': requested_by,
                'approved_by': approved_by,
                'source_finding_ids': [finding.id for finding in findings],
                'source_evidence_ids': [str(evidence.id) for evidence in evidences],
                'framework_configuration': configuration,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'sub_reports': {
                    'risk': {
                        'path': str(risk_path),
                        'content_hash': hashlib.sha256(risk_content.encode('utf-8')).hexdigest(),
                        'format': 'csv',
                    },
                    'gap': {
                        'path': str(gap_path),
                        'content_hash': hashlib.sha256(gap_content.encode('utf-8')).hexdigest(),
                        'format': 'csv',
                    },
                },
            }
            artifact_content = json.dumps(manifest_data, sort_keys=True, indent=2)
            artifact_path = storage_root / f'{report_id}_combined.json'
        elif report_type == 'risk':
            artifact_content = _risk_csv(report_data)
            artifact_path = storage_root / f'{report_id}.csv'
        elif report_type == 'gap':
            artifact_content = _gap_csv(report_data)
            artifact_path = storage_root / f'{report_id}.csv'
        else:
            artifact_content = json.dumps(report_data, sort_keys=True, indent=2)
            artifact_path = storage_root / f'{report_id}.json'

        _write_text(artifact_path, artifact_content)
        created_paths.append(artifact_path)
        content_hash = hashlib.sha256(artifact_content.encode('utf-8')).hexdigest()
        report_record = GeneratedReport(
            id=report_id,
            tenant_id=tenant_id,
            engagement_id=configuration.get('engagement_id', 'ENG-DEFAULT'),
            report_type=report_type,
            generator_version='v2.2.0',
            requested_by=requested_by,
            approved_by=approved_by,
            source_finding_ids=[finding.id for finding in findings],
            source_evidence_ids=[str(evidence.id) for evidence in evidences],
            framework_configuration=configuration,
            content_hash=content_hash,
            artifact_location=str(artifact_path),
        )
        db.add(report_record)
        append_to_audit_log_db(db, AuditEntry(
            user=requested_by,
            action='REPORT_GENERATED',
            module='SYNTHESIS',
            detail=f'Generated {report_type} report {report_id} with hash {content_hash}.',
        ))
        db.refresh(report_record)
    except Exception:
        db.rollback()
        for path in created_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    return {
        'report_id': report_id,
        'manifest': {
            'id': report_record.id,
            'tenant_id': report_record.tenant_id,
            'engagement_id': report_record.engagement_id,
            'report_type': report_record.report_type,
            'generator_version': report_record.generator_version,
            'requested_by': report_record.requested_by,
            'approved_by': report_record.approved_by,
            'source_finding_ids': report_record.source_finding_ids,
            'source_evidence_ids': report_record.source_evidence_ids,
            'framework_configuration': report_record.framework_configuration,
            'content_hash': report_record.content_hash,
            'artifact_location': report_record.artifact_location,
        },
    }
