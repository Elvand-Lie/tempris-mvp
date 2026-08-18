'''Tenant-scoped technical and customer-facing report generation.'''

import csv
import copy
import hashlib
import html
import io
import json
import os
import re
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from models import (
    Asset,
    ControlEvidence,
    EdipDecision,
    Finding,
    FindingControl,
    FindingEvidence,
    FindingSource,
    GeneratedReport,
)
from routers.audit import AuditEntry, append_to_audit_log_db
from services.customer_posture import canonical_exposure_rows
from services.operational_events import record_operational_event


REPORT_TYPES = {'risk', 'gap', 'evidence', 'combined', 'json', 'poc'}
POC_REPORT_TYPE = 'poc'
POC_REPORT_VERSION = 'v3.0.0'
POC_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / 'templates' / 'tempris_poc_report.html'
SINGAPORE_TZ = ZoneInfo('Asia/Singapore')
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

DECISION_ALIASES = {
    'ESCALATE': 'ESCALATE', 'PATCH': 'PATCH', 'FIX': 'PATCH',
    'INVESTIGATE': 'INVESTIGATE',
    'COMPENSATING_CONTROL': 'COMPENSATING_CONTROL',
    'COMPENSATING CONTROL': 'COMPENSATING_CONTROL',
    'DEFER': 'DEFER', 'ACCEPT': 'DEFER',
}
ACTION_LABELS = {
    'ESCALATE': ('Fix now', 'red'),
    'PATCH': ('Fix now', 'red'),
    'INVESTIGATE': ('Watch', 'amber'),
    'COMPENSATING_CONTROL': ('Watch', 'amber'),
    'DEFER': ('Safe to wait', 'slate'),
    'NOT_RECORDED': ('Not assigned', 'slate'),
}
BAND_LABELS = {
    'P0': 'Critical', 'P1': 'High', 'P2': 'Medium',
    'P3': 'Low', 'P4': 'Informational',
}
BAND_ORDER = {
    'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4, 'Not recorded': 5,
}
PUBLIC_REFERENCE_PATTERN = re.compile(
    r'^(?:CVE-\d{4}-\d{4,}|CWE-\d+|GHSA-[A-Za-z0-9-]+|'
    r'MITRE-[A-Za-z0-9.-]+|CISA-KEV|IPMI-[A-Za-z0-9.-]+)$',
    re.IGNORECASE,
)


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
    # /app/data is a persistent bind mount in production.  Keeping generated
    # artifacts beneath it prevents report files from disappearing whenever
    # the backend container is rebuilt.
    root = (
        Path(configured)
        if configured
        else Path(__file__).resolve().parents[1] / 'data' / 'reports'
    )
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

def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


def _band_label(finding: Finding) -> str:
    priority = (finding.priority or '').strip().upper()
    if priority in BAND_LABELS:
        return BAND_LABELS[priority]
    score = finding.score if finding.score is not None else finding.cvss
    if score is None:
        return 'Not recorded'
    if score >= 9:
        return 'Critical'
    if score >= 7:
        return 'High'
    if score >= 4:
        return 'Medium'
    return 'Low'


def _normalise_decision(value: str | None) -> str:
    normalised = DECISION_ALIASES.get((value or '').strip().upper())
    return normalised or 'NOT_RECORDED'


def _safe_text(value, fallback='Not recorded') -> str:
    text = str(value or '').strip()
    return text if text else fallback


def _public_references(finding: Finding) -> list[str]:
    candidates = [
        getattr(finding, "canonical_cve_id", None),
        finding.cve_id,
        finding.cve,
        *(finding.public_reason_codes or []),
    ]
    references = [
        str(value).strip().upper()
        for value in candidates
        if value and PUBLIC_REFERENCE_PATTERN.match(str(value).strip())
    ]
    if finding.cisa_kev:
        references.append('CISA-KEV')
    return list(dict.fromkeys(references))


def _evidence_summary(finding, sources, evidence) -> dict:
    verified = (finding.verification or '').strip().upper()
    if evidence and verified == 'CONFIRMED':
        tier = 'Tier 1 ? verified evidence'
    elif sources or evidence:
        tier = 'Tier 2 ? corroborated evidence'
    else:
        tier = 'Tier 3 ? reported observation'
    record = {
        'finding_id': finding.id,
        'verification': verified or 'NOT_RECORDED',
        'sources': [{
            'publisher': row.publisher,
            'source_id': row.source_id,
            'verification_state': row.verification_state,
            'last_verified_at': _iso(row.last_verified_at),
        } for row in sources],
        'files': [{
            'filename': row.filename,
            'verification_state': row.verification_state,
            'uploaded_at': _iso(row.uploaded_at),
        } for row in evidence],
    }
    digest = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()
    parts = []
    if sources:
        parts.append(f'{len(sources)} source record(s)')
    if evidence:
        parts.append(f'{len(evidence)} evidence file(s)')
    return {
        'summary': '; '.join(parts) or 'No supporting file attached',
        'tier': tier,
        'record_hash': digest,
    }


def _build_poc_payload(
    db, tenant_id, requested_by, report_id, findings, configuration,
    excluded_unmapped_count=0, exposure_map=None,
):
    ids = [finding.id for finding in findings]
    exposure_map = exposure_map or {}
    asset_ids = sorted({
        asset.id for pairs in exposure_map.values() for asset, _ in pairs
    })
    assets = {
        row.id: row for row in db.query(Asset).filter(
            Asset.tenant_id == tenant_id, Asset.id.in_(asset_ids),
        ).all()
    } if asset_ids else {}
    decisions = {
        row.finding_id: row for row in db.query(EdipDecision).filter(
            EdipDecision.tenant_id == tenant_id,
            EdipDecision.finding_id.in_(ids),
        ).all()
    } if ids else {}
    sources_by_id, evidence_by_id, controls_by_id = {}, {}, {}
    if ids:
        for row in db.query(FindingSource).filter(FindingSource.finding_id.in_(ids)).all():
            sources_by_id.setdefault(row.finding_id, []).append(row)
        for row in db.query(FindingEvidence).filter(FindingEvidence.finding_id.in_(ids)).all():
            evidence_by_id.setdefault(row.finding_id, []).append(row)
        for row in db.query(FindingControl).filter(FindingControl.finding_id.in_(ids)).all():
            controls_by_id.setdefault(row.finding_id, []).append(row)

    output_findings = []
    for finding in findings:
        band = _band_label(finding)
        decision_row = decisions.get(finding.id)
        sss_data = finding.sss_data if isinstance(finding.sss_data, dict) else {}
        recorded_decision = (
            decision_row.decision if decision_row else
            finding.decision or sss_data.get('edip_decision') or sss_data.get('tes_decision')
        )
        decision = _normalise_decision(recorded_decision)
        action_label, action_colour = ACTION_LABELS[decision]
        linked_pairs = exposure_map.get(finding.id, [])
        linked_assets = [asset for asset, _ in linked_pairs]
        asset = linked_assets[0] if linked_assets else None
        controls = controls_by_id.get(finding.id, [])
        status = _safe_text(finding.status, 'not recorded').lower()
        sla_days = finding.sla if finding.sla and finding.sla > 0 else None
        created_at = finding.created_at
        if created_at and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        due_date = (
            (created_at + timedelta(days=sla_days)).date().isoformat()
            if created_at and sla_days else None
        )
        asset_data = finding.asset_data if isinstance(finding.asset_data, dict) else {}
        rationale = (
            decision_row.rationale if decision_row and decision_row.rationale
            else sss_data.get('decision_rationale') or sss_data.get('rationale')
        )
        output_findings.append({
            'id': finding.id,
            'title': _safe_text(finding.title),
            'band': band,
            'decision': decision,
            'action_label': action_label,
            'action_colour': action_colour,
            'asset': {
                'id': asset.id if asset else None,
                'name': asset.name if asset else _safe_text(asset_data.get('name'), 'Unlinked asset'),
                'environment': asset.environment if asset else None,
                'criticality': asset.criticality if asset else None,
            },
            'assets': [
                {
                    'id': linked_asset.id,
                    'name': linked_asset.name,
                    'environment': linked_asset.environment,
                    'criticality': linked_asset.criticality,
                    'exposure_source': link.match_method,
                    'evidence': link.evidence,
                    'evidence_metadata': link.evidence_metadata or {},
                }
                for linked_asset, link in linked_pairs
            ],
            'what_it_is': _safe_text(
                finding.summary or finding.short_description or finding.description,
            ),
            'why_it_matters': _safe_text(sss_data.get('business_impact') or sss_data.get('impact') or asset_data.get('impact')),
            'evidence': _evidence_summary(
                finding, sources_by_id.get(finding.id, []),
                evidence_by_id.get(finding.id, []),
            ),
            'remediation': {
                'action': _safe_text(
                    finding.required_action or (controls[0].title if controls else None),
                ),
                'guidance': _safe_text(controls[0].description if controls else None),
                'effort': str(sss_data.get('effort') or '').strip() or None,
                'owner': asset.owner if asset and asset.owner else asset_data.get('owner') or None,
                'sla_days': sla_days,
                'due_date': due_date,
                'status': status,
                'verification': sss_data.get('remediation_verification') or None,
            },
            'decision_rationale': _safe_text(rationale),
            're_evaluation_date': sss_data.get('revalidate_by') or None,
            'public_references': _public_references(finding),
        })

    output_findings.sort(key=lambda item: (
        BAND_ORDER[item['band']],
        {'Fix now': 0, 'Watch': 1, 'Safe to wait': 2, 'Not assigned': 3}[item['action_label']],
        item['id'],
    ))
    counts = {
        'act_now': sum(row['action_label'] == 'Fix now' for row in output_findings),
        'watch': sum(row['action_label'] == 'Watch' for row in output_findings),
        'safe_to_wait': sum(row['action_label'] == 'Safe to wait' for row in output_findings),
        'not_assigned': sum(row['action_label'] == 'Not assigned' for row in output_findings),
        'total': len(output_findings),
    }
    delivery = configuration.get('delivery') or {}
    partner = _safe_text(delivery.get('alliance_partner'), '')
    partner_consent = bool(delivery.get('client_consent_for_partner')) and bool(partner)
    partner_status = (
        'authorised' if partner_consent
        else 'withheld' if partner
        else 'not_requested'
    )
    client = configuration.get('client') or {}
    period = configuration.get('period') or {}
    assessment = configuration.get('assessment') or {}
    coverage = configuration.get('coverage') or {}
    scope = [str(value).strip() for value in (coverage.get('scope') or []) if str(value).strip()]
    out_of_scope = [
        str(value).strip() for value in (coverage.get('out_of_scope') or [])
        if str(value).strip()
    ]
    if not scope or not out_of_scope:
        raise ValueError('Report scope and out-of-scope boundaries must be recorded')
    next_steps = [
        str(value).strip() for value in (configuration.get('next_steps') or [])
        if str(value).strip()
    ]
    if not next_steps:
        if counts['not_assigned']:
            next_steps.append('Record an EDIP decision for each not-assigned finding.')
        if any(not row['remediation']['owner'] for row in output_findings):
            next_steps.append('Record an accountable owner for each unassigned treatment.')
        if counts['act_now']:
            next_steps.append('Complete the recorded Fix now treatments and retain verification evidence.')
        if not next_steps:
            next_steps.append('No next step is generated because no supported action-driving data is recorded.')
    payload = {
        'report': {
            'id': report_id,
            'title': _safe_text(configuration.get('title'), 'Tempris CTEM & EDIP Client Report'),
            'engagement_id': _safe_text(configuration.get('engagement_id'), 'ENG-DEFAULT'),
            'version': POC_REPORT_VERSION,
            'generated_at': datetime.now(SINGAPORE_TZ).isoformat(),
            'generated_by': requested_by,
            'snapshot_type': 'current_state',
            'assessment_period_semantics': 'contextual_metadata_only',
            'classification': _safe_text(configuration.get('classification'), 'Client Confidential'),
            'retention': _safe_text(
                configuration.get('retention'),
                'Retain according to the client agreement',
            ),
            'integrity_hash': '',
        },
        'period': {
            'start': _iso(period.get('start')),
            'end': _iso(period.get('end')),
            'timezone': 'Asia/Singapore',
        },
        'client': {
            'organisation': _safe_text(client.get('organisation'), 'Client organisation'),
            'contact': _safe_text(client.get('contact'), 'Client contact'),
            'environment': _safe_text(client.get('environment'), 'Assessed environment'),
        },
        'assessment': {
            'method': _safe_text(
                assessment.get('method'),
                'Tempris continuous threat exposure management and EDIP decision review',
            ),
            'assessor': str(assessment.get('assessor') or '').strip() or None,
            'attestation': str(assessment.get('attestation') or '').strip() or None,
            'attested_by': str(assessment.get('attested_by') or '').strip() or None,
            'limitations': _safe_text(
                assessment.get('limitations'),
                'This report is decision support, not a certification, compliance opinion, or MAS approval.',
            ),
        },
        'delivery': {
            'recipients': [
                str(value).strip() for value in (delivery.get('recipients') or [])
                if str(value).strip()
            ],
            'alliance_partner': partner or None,
            'client_consent_for_partner': partner_consent,
            'partner_delivery_status': partner_status,
        },
        'executive_summary': {
            **counts,
            'narrative': _safe_text(
                configuration.get('executive_narrative'),
                f'{counts["total"]} finding(s) were assessed: '
                f'{counts["act_now"]} require immediate action, '
                f'{counts["watch"]} require monitoring, and '
                f'{counts["safe_to_wait"]} are safe to defer. '
                f'{counts["not_assigned"]} have no recorded EDIP decision.',
            ),
        },
        'findings': output_findings,
        'coverage': {
            'scope': scope,
            'out_of_scope': out_of_scope,
            'identities': coverage.get('identities') or [],
            'finding_count': len(output_findings),
            'eligibility_rule': 'active_tenant_asset_link_required',
            'excluded_unmapped_finding_count': excluded_unmapped_count,
        },
        'next_steps': next_steps,
    }
    canonical = copy.deepcopy(payload)
    canonical['report'].pop('integrity_hash', None)
    payload['report']['integrity_hash'] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()
    return payload

def _render_poc_html(payload: dict) -> str:
    template = POC_TEMPLATE_PATH.read_text(encoding='utf-8')
    esc = lambda value: html.escape(str(value if value is not None else ''), quote=True)
    findings_html = []
    for finding in payload['findings']:
        remediation = finding['remediation']
        refs = ', '.join(finding['public_references']) or 'No public reference recorded'
        findings_html.append(
            '<article class="finding">'
            f'<div class="finding-head"><span class="pill {esc(finding["action_colour"])}">'
            f'{esc(finding["action_label"])}</span><div>'
            f'<p class="eyebrow">{esc(finding["id"])} ? {esc(finding["band"])}</p>'
            f'<h3>{esc(finding["title"])}</h3></div></div>'
            '<div class="finding-grid"><div><h4>What it is</h4>'
            f'<p>{esc(finding["what_it_is"])}</p></div>'
            f'<div><h4>Why it matters</h4><p>{esc(finding["why_it_matters"])}</p></div></div>'
            f'<dl><dt>Asset</dt><dd>{esc(finding["asset"]["name"])}</dd>'
            f'<dt>EDIP decision</dt><dd>{esc(finding["decision"])}</dd>'
            f'<dt>Evidence</dt><dd>{esc(finding["evidence"]["tier"])}; '
            f'{esc(finding["evidence"]["summary"])}</dd>'
            f'<dt>Recommended action</dt><dd>{esc(remediation["action"])}</dd>'
            f'<dt>Owner / due</dt><dd>{esc(remediation["owner"] or "Not recorded")} / '
            f'{esc(remediation["due_date"] or "Not recorded")}</dd>'
            f'<dt>Decision rationale</dt><dd>{esc(finding["decision_rationale"])}</dd>'
            f'<dt>Public references</dt><dd>{esc(refs)}</dd></dl></article>'
        )
    assessment = payload['assessment']
    attestation = ''
    if assessment.get('assessor') or assessment.get('attestation') or assessment.get('attested_by'):
        attestation = (
            '<section><h2>Assessment provenance & attestation</h2>'
            f'<p><strong>Assessor:</strong> {esc(assessment.get("assessor") or "Not recorded")}</p>'
            f'<p><strong>Attested by:</strong> {esc(assessment.get("attested_by") or "Not recorded")}</p>'
            f'<p>{esc(assessment.get("attestation") or "No attestation statement recorded.")}</p>'
            '</section>'
        )
    replacements = {
        '{{TITLE}}': esc(payload['report']['title']),
        '{{CLIENT}}': esc(payload['client']['organisation']),
        '{{CONTACT}}': esc(payload['client']['contact']),
        '{{ENVIRONMENT}}': esc(payload['client']['environment']),
        '{{REPORT_ID}}': esc(payload['report']['id']),
        '{{ENGAGEMENT_ID}}': esc(payload['report']['engagement_id']),
        '{{GENERATED_AT}}': esc(payload['report']['generated_at']),
        '{{PERIOD}}': esc(
            f'{payload["period"]["start"] or "Not recorded"} to '
            f'{payload["period"]["end"] or "Not recorded"}'
        ),
        '{{CLASSIFICATION}}': esc(payload['report']['classification']),
        '{{HASH}}': esc(payload['report']['integrity_hash']),
        '{{NARRATIVE}}': esc(payload['executive_summary']['narrative']),
        '{{ACT_NOW}}': str(payload['executive_summary']['act_now']),
        '{{WATCH}}': str(payload['executive_summary']['watch']),
        '{{SAFE_TO_WAIT}}': str(payload['executive_summary']['safe_to_wait']),
        '{{NOT_ASSIGNED}}': str(payload['executive_summary']['not_assigned']),
        '{{FINDINGS}}': ''.join(findings_html) or '<p class="empty">No findings selected.</p>',
        '{{SCOPE}}': ''.join(
            f'<li>{esc(value)}</li>' for value in payload['coverage']['scope']
        ),
        '{{OUT_OF_SCOPE}}': ''.join(
            f'<li>{esc(value)}</li>' for value in payload['coverage']['out_of_scope']
        ) + (
            f'<li>{esc(payload["coverage"]["excluded_unmapped_finding_count"])} '
            'unmapped record(s) excluded because no active customer asset link was recorded.</li>'
            if payload['coverage']['excluded_unmapped_finding_count'] else ''
        ),
        '{{NEXT_STEPS}}': ''.join(
            f'<li>{esc(value)}</li>' for value in payload['next_steps']
        ),
        '{{METHOD}}': esc(assessment['method']),
        '{{LIMITATIONS}}': esc(assessment['limitations']),
        '{{ATTESTATION}}': attestation,
        '{{PARTNER_STATUS}}': esc(payload['delivery']['partner_delivery_status']),
    }
    for key, value in replacements.items():
        template = template.replace(key, value)
    return template


def _poc_csv(payload: dict) -> str:
    headers = [
        'Finding ID', 'Title', 'Band', 'Decision', 'Action label', 'Asset',
        'Evidence tier', 'Recommended action', 'Owner', 'SLA days', 'Due date',
        'Status', 'Re-evaluation date', 'Public references',
    ]
    rows = []
    for finding in payload['findings']:
        remediation = finding['remediation']
        rows.append([
            finding['id'], finding['title'], finding['band'], finding['decision'],
            finding['action_label'], finding['asset']['name'],
            finding['evidence']['tier'], remediation['action'],
            remediation['owner'], remediation['sla_days'], remediation['due_date'],
            remediation['status'], finding['re_evaluation_date'],
            '; '.join(finding['public_references']),
        ])
    return _csv_content(headers, rows)


def poc_artifact_path(report_id: str, artifact_format: str) -> Path:
    if not re.fullmatch(r'REP-[A-F0-9]{8}', report_id):
        raise ValueError('Invalid report identifier')
    suffixes = {'html': '.html', 'json': '.json', 'csv': '_findings.csv'}
    if artifact_format not in suffixes:
        raise ValueError('Unsupported artifact format')
    return _report_storage_root() / f'{report_id}{suffixes[artifact_format]}'


def generate_poc_report_pipeline(
    db: Session,
    tenant_id: str,
    requested_by: str,
    source_finding_ids: list[str] | None,
    configuration: dict | None,
    approved_by: str | None = None,
    parent_report_id: str | None = None,
    document_version: int = 1,
) -> dict:
    if not tenant_id:
        raise ValueError('Missing tenant context')
    configuration = _clean_report_value(configuration or {})
    source_ids = list(dict.fromkeys(source_finding_ids or []))
    candidate_findings = (
        _load_findings(db, tenant_id, source_ids)
        if source_ids else
        db.query(Finding).filter(Finding.tenant_id == tenant_id).all()
    )
    canonical_rows = canonical_exposure_rows(db, tenant_id, open_only=True)
    exposure_map = {}
    for finding, asset, link in canonical_rows:
        exposure_map.setdefault(finding.id, []).append((asset, link))
    findings = [row for row in candidate_findings if row.id in exposure_map]
    report_id = f'REP-{uuid.uuid4().hex[:8].upper()}'
    payload = _build_poc_payload(
        db, tenant_id, requested_by, report_id, findings, configuration,
        excluded_unmapped_count=len(candidate_findings) - len(findings),
        exposure_map=exposure_map,
    )
    json_content = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
    html_content = _render_poc_html(payload)
    csv_content = _poc_csv(payload)
    paths = {
        fmt: poc_artifact_path(report_id, fmt) for fmt in ('html', 'json', 'csv')
    }
    created_paths = []
    try:
        for artifact_format, content in (
            ('html', html_content), ('json', json_content), ('csv', csv_content),
        ):
            _write_text(paths[artifact_format], content)
            created_paths.append(paths[artifact_format])
        content_hash = hashlib.sha256(json_content.encode('utf-8')).hexdigest()
        stored_configuration = copy.deepcopy(configuration)
        stored_configuration['_lifecycle'] = {
            'archived': False,
            'archived_at': None,
            'archived_by': None,
            'parent_report_id': parent_report_id,
            'document_version': max(1, int(document_version)),
        }
        report = GeneratedReport(
            id=report_id,
            tenant_id=tenant_id,
            engagement_id=payload['report']['engagement_id'],
            report_type=POC_REPORT_TYPE,
            generator_version=POC_REPORT_VERSION,
            requested_by=requested_by,
            approved_by=approved_by,
            source_finding_ids=[finding.id for finding in findings],
            source_evidence_ids=[],
            framework_configuration=stored_configuration,
            content_hash=content_hash,
            artifact_location=str(paths['html']),
        )
        db.add(report)
        record_operational_event(
            db,
            tenant_id=tenant_id,
            event_type='report.version_created' if parent_report_id else 'report.generated',
            resource_type='generated_report',
            resource_id=report_id,
            source_module='CLIENT_REPORTS',
            actor_id=requested_by,
            metadata={
                'report_type': POC_REPORT_TYPE,
                'finding_count': len(findings),
                'snapshot_semantics': 'current_state',
            },
        )
        append_to_audit_log_db(db, AuditEntry(
            user=requested_by,
            action='POC_REPORT_GENERATED',
            module='SYNTHESIS',
            detail=(
                f'Generated client report {report_id} with JSON hash {content_hash}.'
                + (f' Regenerated from {parent_report_id}.' if parent_report_id else '')
            ),
        ), commit=False)
        db.commit()
        db.refresh(report)
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
            'id': report.id,
            'tenant_id': report.tenant_id,
            'engagement_id': report.engagement_id,
            'report_type': report.report_type,
            'generator_version': report.generator_version,
            'requested_by': report.requested_by,
            'approved_by': report.approved_by,
            'source_finding_ids': report.source_finding_ids,
            'content_hash': report.content_hash,
            'document_version': stored_configuration['_lifecycle']['document_version'],
            'parent_report_id': parent_report_id,
            'artifacts': {
                key: f'/api/reports/{report_id}/artifact/{key}'
                for key in ('html', 'json', 'csv')
            },
        },
        'executive_summary': payload['executive_summary'],
        'delivery': payload['delivery'],
    }


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
    candidates = _load_findings(db, tenant_id, finding_ids)
    canonical_ids = {
        finding.id for finding, _, _ in canonical_exposure_rows(db, tenant_id, open_only=True)
    }
    findings = [finding for finding in candidates if finding.id in canonical_ids]
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
        record_operational_event(
            db,
            tenant_id=tenant_id,
            event_type='report.generated',
            resource_type='generated_report',
            resource_id=report_id,
            source_module='CLIENT_REPORTS',
            actor_id=requested_by,
            metadata={
                'report_type': report_type,
                'finding_count': len(findings),
                'excluded_unconfirmed_count': len(candidates) - len(findings),
                'snapshot_semantics': 'current_state',
            },
        )
        append_to_audit_log_db(db, AuditEntry(
            user=requested_by,
            action='REPORT_GENERATED',
            module='SYNTHESIS',
            detail=f'Generated {report_type} report {report_id} with hash {content_hash}.',
        ), commit=False)
        db.commit()
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
