import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
os.environ['ENVIRONMENT'] = 'test'
os.environ['AUDIT_HMAC_KEY'] = 'test_audit_hmac_secret_key_12345678'

import services.database
from index import app
from models import (
    Asset,
    AssetExposure,
    AuditLog,
    Base,
    ControlStatus,
    Finding,
    FindingStatusHistory,
    GeneratedReport,
    GrcPolicyDocument,
    IncidentReport,
    TesSnapshot,
)
from routers.auth import USERS, create_test_session
from services.database import get_db


DB_URL = 'sqlite:///./test_ciso_grc.db'
engine = create_engine(DB_URL, connect_args={'check_same_thread': False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def isolated_database(monkeypatch):
    from middleware.rate_limit import _Bucket

    monkeypatch.setattr(_Bucket, 'consume', lambda self: True)
    old_users = dict(USERS)
    old_engine = services.database.engine
    old_session_local = services.database.SessionLocal
    services.database.engine = engine
    services.database.SessionLocal = TestingSessionLocal
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    USERS.update({
        'alpha-admin@example.test': {
            'role': 'Admin',
            'name': 'Alpha Admin',
            'tenant_id': 'tenant-alpha',
        },
        'alpha-analyst@example.test': {
            'role': 'Analyst',
            'name': 'Alpha Analyst',
            'tenant_id': 'tenant-alpha',
        },
        'beta-admin@example.test': {
            'role': 'Admin',
            'name': 'Beta Admin',
            'tenant_id': 'tenant-beta',
        },
    })

    yield

    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    USERS.clear()
    USERS.update(old_users)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    if os.path.exists('./test_ciso_grc.db'):
        try:
            os.remove('./test_ciso_grc.db')
        except PermissionError:
            pass


def headers_for(email: str) -> dict:
    db = TestingSessionLocal()
    token = create_test_session(db, email)
    db.close()
    return {'Authorization': f'Bearer {token}'}


def seed_executive_data():
    now = datetime.now(timezone.utc)
    db = TestingSessionLocal()
    db.add_all([
        Asset(
            id='ASSET-ALPHA',
            tenant_id='tenant-alpha',
            name='Alpha Gateway',
            criticality='critical',
        ),
        Asset(
            id='ASSET-BETA',
            tenant_id='tenant-beta',
            name='Beta Gateway',
            criticality='critical',
        ),
        Finding(
            id='F-ALPHA',
            tenant_id='tenant-alpha',
            title='Alpha finding',
            priority='P0',
            status='unmitigated',
            sla=1,
            asset_id='ASSET-ALPHA',
            created_at=now - timedelta(days=3),
            raw_inputs={
                'cvss': 8.0,
                'exploitability': 8.0,
                'business_impact': 8.0,
                'asset_criticality': 8.0,
                'threat_actor_activity': 8.0,
            },
        ),
        Finding(
            id='F-BETA',
            tenant_id='tenant-beta',
            title='Beta finding',
            priority='P0',
            status='unmitigated',
            asset_id='ASSET-BETA',
            raw_inputs={'agm': 9.9},
        ),
        ControlStatus(
            tenant_id='tenant-alpha',
            framework_id='ISO42001',
            control_id='A.2.2',
            status='not_assessed',
        ),
        ControlStatus(
            tenant_id='tenant-beta',
            framework_id='ISO42001',
            control_id='A.2.2',
            status='compliant',
        ),
        TesSnapshot(
            tenant_id='tenant-alpha',
            aggregate_tes=8.0,
            finding_count=1,
            critical_count=1,
            snapshot_at=now,
        ),
        TesSnapshot(
            tenant_id='tenant-alpha',
            aggregate_tes=9.0,
            finding_count=2,
            critical_count=2,
            snapshot_at=now - timedelta(days=1),
        ),
        IncidentReport(
            report_id='INC-ALPHA',
            tenant_id='tenant-alpha',
            report_type='MAS_TRM',
            status='generated',
            severity='critical',
            payload={},
        ),
        IncidentReport(
            report_id='INC-BETA',
            tenant_id='tenant-beta',
            report_type='MAS_TRM',
            status='generated',
            severity='critical',
            payload={},
        ),
        GeneratedReport(
            id='REPORT-ALPHA',
            tenant_id='tenant-alpha',
            report_type='risk',
            generator_version='1',
            requested_by='alpha-admin@example.test',
            source_finding_ids=['F-ALPHA'],
            source_evidence_ids=[],
            framework_configuration={},
            content_hash='a' * 64,
            artifact_location='temporary/alpha.json',
        ),
        GeneratedReport(
            id='REPORT-BETA',
            tenant_id='tenant-beta',
            report_type='risk',
            generator_version='1',
            requested_by='beta-admin@example.test',
            source_finding_ids=['F-BETA'],
            source_evidence_ids=[],
            framework_configuration={},
            content_hash='b' * 64,
            artifact_location='temporary/beta.json',
        ),
    ])
    db.commit()
    db.close()


def assert_forbidden_keys_absent(value):
    forbidden = {
        'agm',
        'drf',
        'tef',
        'raw_inputs',
        'formula',
        'formula_metadata',
        'intermediate_calculations',
    }
    if isinstance(value, dict):
        assert forbidden.isdisjoint({str(key).lower() for key in value})
        for item in value.values():
            assert_forbidden_keys_absent(item)
    elif isinstance(value, list):
        for item in value:
            assert_forbidden_keys_absent(item)


def test_ciso_summary_is_role_restricted():
    response = TestClient(app).get(
        '/api/ciso/summary',
        headers=headers_for('alpha-analyst@example.test'),
    )
    assert response.status_code == 403


def test_ciso_summary_is_tenant_scoped_and_redacted():
    seed_executive_data()
    response = TestClient(app).get(
        '/api/ciso/summary',
        headers=headers_for('alpha-admin@example.test'),
    )
    assert response.status_code == 200
    data = response.json()
    assert data['tenant_id'] == 'tenant-alpha'
    assert data['findings'] == {
        'total': 1,
        'unresolved': 1,
        'critical': 1,
        'high': 0,
        'recorded_total': 1,
        'confirmed_asset_linked': 1,
        'confirmed_exposure_occurrences': 1,
        'unlinked_open': 0,
    }
    assert data['metric_scope'] == 'confirmed_asset_linked_findings'
    assert data['risk_trend']['status'] == 'unavailable'
    assert data['risk_trend']['legacy_snapshot_count'] == 2
    assert 'not comparable' in data['risk_trend']['reason']
    assert data['deadline_summary']['counts']['remediation_sla']['overdue'] == 1
    assert data['exposure_coverage']['asset_linked_count'] == 1
    assert data['exposure_coverage']['aggregate_tes'] == 8.0
    assert [item['asset_id'] for item in data['highest_risk_assets']['items']] == ['ASSET-ALPHA']
    assert [item['report_id'] for item in data['recent_escalations']['items']] == ['INC-ALPHA']
    assert [item['report_id'] for item in data['report_links']['items']] == ['REPORT-ALPHA']
    assert_forbidden_keys_absent(data)

    db = TestingSessionLocal()
    audit = db.query(AuditLog).filter(AuditLog.action == 'CISO_SUMMARY_VIEWED').one()
    assert audit.user_email == 'alpha-admin@example.test'
    assert audit.tenant_id == 'tenant-alpha'
    db.close()


def test_ciso_finding_rejects_cross_tenant_id():
    seed_executive_data()
    response = TestClient(app).get(
        '/api/ciso/findings/F-BETA',
        headers=headers_for('alpha-admin@example.test'),
    )
    assert response.status_code == 404
    assert response.json()['detail'] == 'Finding not found'


def test_ciso_summary_has_safe_empty_states():
    response = TestClient(app).get(
        '/api/ciso/summary',
        headers=headers_for('alpha-admin@example.test'),
    )
    assert response.status_code == 200
    data = response.json()
    assert data['overall_risk_posture'] == 'no_data'
    assert data['risk_trend']['status'] == 'unavailable'
    assert data['highest_risk_assets']['status'] == 'unavailable'
    assert data['compliance_gaps']['status'] == 'unavailable'


def test_grc_state_and_custom_policies_are_tenant_scoped():
    client = TestClient(app)
    alpha_headers = headers_for('alpha-admin@example.test')
    beta_headers = headers_for('beta-admin@example.test')
    sop_state = [
        {
            'id': control_id,
            'pic': 'Alpha Owner',
            'notes': '',
            'endUserAgreed': index == 0,
            'picAgreed': index == 0,
        }
        for index, control_id in enumerate([
            'A.2.2',
            'A.3.2',
            'A.5.2',
            'A.6.2.2',
            'A.7.4',
            'A.9.2',
            'A.10.3',
        ])
    ]
    saved = client.post(
        '/api/grc/state',
        headers=alpha_headers,
        json={
            'toggles': {
                'agm': [False, False, False, False, False],
                'drf': [False, False, False],
                'tef': [False, False],
            },
            'sop_state': sop_state,
        },
    )
    assert saved.status_code == 200

    beta_state = client.get('/api/grc/state', headers=beta_headers)
    assert beta_state.status_code == 200
    assert beta_state.json()['updated_by'] is None
    assert all(not item['endUserAgreed'] for item in beta_state.json()['sop_state'])

    created = client.post(
        '/api/grc/policies',
        headers=alpha_headers,
        json={'title': 'Alpha policy', 'content': 'Fictional tenant content'},
    )
    assert created.status_code == 200
    policy_id = created.json()['id']

    hidden = client.get(f'/api/grc/policies/{policy_id}', headers=beta_headers)
    assert hidden.status_code == 404
    beta_list = client.get('/api/grc/policies', headers=beta_headers)
    assert policy_id not in {item['id'] for item in beta_list.json()['policies']}

    bundled_update = client.put(
        '/api/grc/policies/iso42001',
        headers=alpha_headers,
        json={'content': 'Attempted shared policy mutation'},
    )
    assert bundled_update.status_code == 409


def test_audit_log_and_hash_chain_are_tenant_scoped():
    client = TestClient(app)
    alpha_headers = headers_for('alpha-admin@example.test')
    beta_headers = headers_for('beta-admin@example.test')
    for headers, detail in (
        (alpha_headers, 'alpha event'),
        (beta_headers, 'beta event'),
    ):
        response = client.post(
            '/api/audit/log',
            headers=headers,
            json={
                'user': 'spoofed@example.test',
                'action': 'TENANT_TEST',
                'module': 'AUDIT',
                'detail': detail,
            },
        )
        assert response.status_code == 200

    alpha_log = client.get('/api/audit/log', headers=alpha_headers).json()
    beta_log = client.get('/api/audit/log', headers=beta_headers).json()
    assert [entry['detail'] for entry in alpha_log] == ['alpha event']
    assert [entry['detail'] for entry in beta_log] == ['beta event']
    assert alpha_log[0]['user'] == 'alpha-admin@example.test'
    assert beta_log[0]['user'] == 'beta-admin@example.test'
    assert client.get('/api/audit/verify', headers=alpha_headers).json()['intact'] is True
    assert client.get('/api/audit/verify', headers=beta_headers).json()['intact'] is True


def test_synthesis_uses_asset_linked_tes_tenant_snapshots_and_repository_health():
    now = datetime.now(timezone.utc)
    db = TestingSessionLocal()
    db.add_all([
        Asset(
            id='ASSET-SYNTH',
            tenant_id='tenant-alpha',
            name='Synthesis test asset',
            criticality='medium',
        ),
        Finding(
            id='F-SYNTH',
            tenant_id='tenant-alpha',
            title='Asset-linked synthesis finding',
            priority='P0',
            status='unmitigated',
            asset_id='ASSET-SYNTH',
            raw_inputs={
                'cvss': 4.0,
                'exploitability': 4.0,
                'business_impact': 4.0,
                'asset_criticality': 4.0,
                'threat_actor_activity': 4.0,
            },
        ),
        TesSnapshot(
            tenant_id='tenant-alpha',
            aggregate_tes=2.0,
            finding_count=0,
            critical_count=0,
            snapshot_at=now - timedelta(days=2),
        ),
        TesSnapshot(
            tenant_id='tenant-beta',
            aggregate_tes=99.0,
            finding_count=999,
            critical_count=999,
            snapshot_at=now - timedelta(days=3),
        ),
    ])
    db.commit()
    db.close()

    client = TestClient(app)
    headers = headers_for('alpha-admin@example.test')
    response = client.get('/api/synthesis/dashboard', headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data['aggregate_tes'] == 4.0
    assert data['tes_trend'] == '+2.0'
    assert data['exposure_coverage']['asset_linked_count'] == 1
    assert data['exposure_coverage']['asset_link_coverage_pct'] == 100.0
    assert data['alerts'] == []
    assert {item['status'] for item in data['module_health']} == {'operational'}
    assert any(item['data_status'] == 'no_data' for item in data['module_health'])
    assert data['final_update']['surge_scope_status'] == 'unavailable'

    created = client.post('/api/synthesis/tes-snapshot', headers=headers)
    assert created.status_code == 200
    db = TestingSessionLocal()
    alpha_count = db.query(TesSnapshot).filter(TesSnapshot.tenant_id == 'tenant-alpha').count()
    beta_count = db.query(TesSnapshot).filter(TesSnapshot.tenant_id == 'tenant-beta').count()
    db.close()
    assert alpha_count == 2
    assert beta_count == 1


def test_workflow_connections_require_explicit_tenant_scoped_records():
    seed_executive_data()
    db = TestingSessionLocal()
    db.add(Finding(
        id='F-UNLINKED-KEV',
        tenant_id='tenant-alpha',
        title='Unlinked catalog finding',
        priority='P0',
        status='unmitigated',
        cisa_kev=True,
        source='sss',
        raw_inputs={
            'cvss': 9.0,
            'exploitability': 9.0,
            'business_impact': 9.0,
            'asset_criticality': 9.0,
            'threat_actor_activity': 9.0,
        },
    ))
    db.add(Asset(
        id='ASSET-ALPHA-2',
        tenant_id='tenant-alpha',
        name='Alpha Worker',
        hostname='worker.alpha.test',
        asset_type='server',
        criticality='high',
        owner='Platform',
        environment='production',
        status='active',
    ))

    db.commit()
    db.close()

    client = TestClient(app)
    admin = headers_for('alpha-admin@example.test')
    analyst = headers_for('alpha-analyst@example.test')

    overview = client.get('/api/workflow/overview', headers=admin)
    assert overview.status_code == 200
    exposure = overview.json()['exposure']
    assert exposure['open_finding_count'] == 2
    assert exposure['asset_linked_count'] == 1
    assert exposure['unlinked_count'] == 1
    assert exposure['unlinked_findings'] == []
    assert exposure['mapping_queue'] == []
    assert exposure['mapping_required_count'] == 0
    assert exposure['catalog_intelligence_count'] == 1
    assert exposure['mapping_queue_returned_count'] == 0
    assert exposure['asset_linked_cisa_kev_count'] == 0

    cross_tenant = client.post(
        '/api/workflow/findings/F-UNLINKED-KEV/assets',
        headers=analyst,
        json={'asset_ids': ['ASSET-BETA'], 'evidence': 'Scanner observation'},
    )
    assert cross_tenant.status_code == 422

    confirmed = client.post(
        '/api/workflow/findings/F-UNLINKED-KEV/assets',
        headers=analyst,
        json={
            'asset_ids': ['ASSET-ALPHA', 'ASSET-ALPHA-2'],
            'evidence': 'Authenticated scanner confirmed affected software on both assets',
        },
    )
    assert confirmed.status_code == 200
    assert confirmed.json()['confirmed_exposure_count'] == 2
    sss_findings = client.get('/api/edip/intake/sss', headers=admin)
    assert sss_findings.status_code == 200
    sss_record = next(item for item in sss_findings.json()['data'] if item['id'] == 'F-UNLINKED-KEV')
    assert sss_record['asset_ids'] == ['ASSET-ALPHA', 'ASSET-ALPHA-2']
    assert {asset['name'] for asset in sss_record['assets']} == {'Alpha Gateway', 'Alpha Worker'}



    recorded = client.patch(
        '/api/workflow/findings/F-UNLINKED-KEV',
        headers=analyst,
        json={
            'sla_days': 14,
            'business_impact': 'Customer portal availability',
            'effort': 'Engineering estimate recorded by the analyst',
            'revalidate_by': '2026-09-01',
            'remediation_verification': 'Retest evidence must be attached after remediation',
        },
    )
    assert recorded.status_code == 200
    assert recorded.json()['provenance'] == 'explicit_analyst_update'

    updated = client.get('/api/workflow/overview', headers=admin).json()
    assert updated['exposure']['asset_linked_count'] == 2
    assert updated['exposure']['asset_linked_cisa_kev_count'] == 1
    assert updated['exposure']['confirmed_exposure_count'] == 3
    assert updated['workflow']['business_impact']['recorded'] == 1
    assert updated['workflow']['effort']['recorded'] == 1
    assert updated['workflow']['insurance_tier']['status'] == 'not_configured'

    db = TestingSessionLocal()
    finding = db.query(Finding).filter(Finding.id == 'F-UNLINKED-KEV').one()
    assert finding.asset_id == 'ASSET-ALPHA'
    assert finding.asset_data['name'] == 'Alpha Gateway'
    assert finding.asset_data['source'] == 'tenant_asset_inventory'
    assert finding.sla == 14
    assert finding.sss_data['workflow_provenance']['business_impact']['source'] == 'explicit_analyst_update'
    exposures = db.query(AssetExposure).filter(
        AssetExposure.finding_id == 'F-UNLINKED-KEV'
    ).all()
    assert {row.asset_id for row in exposures} == {'ASSET-ALPHA', 'ASSET-ALPHA-2'}
    assert all(row.evidence for row in exposures)
    audit = db.query(AuditLog).filter(AuditLog.action == 'FINDING_WORKFLOW_UPDATED').one()
    assert audit.tenant_id == 'tenant-alpha'
    db.close()



def test_exposure_assignments_are_searchable_reversible_and_audited():
    seed_executive_data()
    db = TestingSessionLocal()
    db.add(Asset(
        id='ASSET-ALPHA-2',
        tenant_id='tenant-alpha',
        name='Alpha Worker',
        hostname='worker.alpha.test',
        asset_type='server',
        criticality='high',
        owner='Platform',
        environment='production',
        status='active',
    ))
    db.commit()
    db.close()

    client = TestClient(app)
    admin = headers_for('alpha-admin@example.test')
    analyst = headers_for('alpha-analyst@example.test')

    found = client.get(
        '/api/workflow/exposures',
        headers=admin,
        params={'q': 'F-ALPHA', 'assignment': 'confirmed'},
    )
    assert found.status_code == 200
    assert found.json()['total'] == 1
    assert found.json()['data'][0]['confirmed_asset_ids'] == ['ASSET-ALPHA']

    expanded = client.put(
        '/api/workflow/findings/F-ALPHA/assets',
        headers=analyst,
        json={'asset_ids': ['ASSET-ALPHA', 'ASSET-ALPHA-2']},
    )
    assert expanded.status_code == 200
    assert expanded.json()['added_asset_ids'] == ['ASSET-ALPHA-2']
    assert expanded.json()['removed_asset_ids'] == []

    reassigned = client.put(
        '/api/workflow/findings/F-ALPHA/assets',
        headers=analyst,
        json={
            'asset_ids': ['ASSET-ALPHA-2'],
            'evidence': 'Asset owner corrected the affected system assignment',
        },
    )
    assert reassigned.status_code == 200
    assert reassigned.json()['confirmed_asset_ids'] == ['ASSET-ALPHA-2']
    assert reassigned.json()['removed_asset_ids'] == ['ASSET-ALPHA']

    searched = client.get(
        '/api/workflow/exposures',
        headers=admin,
        params={'q': 'Alpha finding', 'assignment': 'confirmed'},
    ).json()
    assert searched['total'] == 1
    assert searched['data'][0]['confirmed_assets'][0]['name'] == 'Alpha Worker'

    cleared = client.put(
        '/api/workflow/findings/F-ALPHA/assets',
        headers=analyst,
        json={'asset_ids': [], 'evidence': 'False positive asset mapping removed'},
    )
    assert cleared.status_code == 200
    assert cleared.json()['confirmed_asset_ids'] == []
    assert cleared.json()['removed_asset_ids'] == ['ASSET-ALPHA-2']

    unassigned = client.get(
        '/api/workflow/exposures',
        headers=admin,
        params={'q': 'F-ALPHA', 'assignment': 'unassigned'},
    ).json()
    assert unassigned['total'] == 1
    assert unassigned['data'][0]['confirmed_asset_ids'] == []

    activity = client.get('/api/workflow/exposure-activity?limit=5', headers=admin)
    assert activity.status_code == 200
    assert len(activity.json()['data']) == 3
    assert activity.json()['data'][0]['change'] == 'Cleared'
    assert activity.json()['data'][0]['finding_id'] == 'F-ALPHA'

    cross_tenant = client.put(
        '/api/workflow/findings/F-ALPHA/assets',
        headers=headers_for('beta-admin@example.test'),
        json={'asset_ids': ['ASSET-BETA']},
    )
    assert cross_tenant.status_code == 404

    db = TestingSessionLocal()
    finding = db.query(Finding).filter(Finding.id == 'F-ALPHA').one()
    assert finding.asset_id is None
    exposures = db.query(AssetExposure).filter(
        AssetExposure.finding_id == 'F-ALPHA'
    ).all()
    assert {row.status for row in exposures} == {'removed'}
    events = db.query(AuditLog).filter(
        AuditLog.action == 'FINDING_ASSET_ASSIGNMENT_UPDATED'
    ).order_by(AuditLog.id.asc()).all()
    assert len(events) == 3
    assert events[-1].metadata_['after_asset_ids'] == []
    assert events[-1].metadata_['removed_asset_ids'] == ['ASSET-ALPHA-2']
    db.close()

def test_catalogue_record_becomes_actionable_only_after_asset_identity_match():
    seed_executive_data()
    db = TestingSessionLocal()
    db.add(Asset(
        id='ASSET-CITRIX', tenant_id='tenant-alpha', name='Citrix NetScaler ADC',
        hostname='adc.alpha.test', asset_type='network', criticality='critical',
        owner='Network', environment='production', status='active',
        tags=['citrix', 'netscaler', 'adc'],
    ))
    db.add(Finding(
        id='F-CITRIX-KEV', tenant_id='tenant-alpha', cve='CVE-2026-9999',
        title='Citrix NetScaler ADC remote code execution', vendor='Citrix',
        product='NetScaler ADC', priority='P0', status='unmitigated',
        cisa_kev=True, source='kev', raw_inputs={
            'cvss': 9.8, 'exploitability': 9.0, 'business_impact': 8.0,
            'asset_criticality': 10.0, 'threat_actor_activity': 9.0,
        },
    ))
    db.commit()
    db.close()

    client = TestClient(app)
    admin = headers_for('alpha-admin@example.test')
    exposure = client.get('/api/workflow/overview', headers=admin).json()['exposure']
    assert exposure['mapping_required_count'] == 1
    assert exposure['candidate_match_count'] == 1
    assert exposure['catalog_intelligence_count'] == 0
    candidate = exposure['mapping_queue'][0]
    assert candidate['mapping_reason'] == 'candidate_match'
    assert candidate['candidate_assets'][0]['asset_id'] == 'ASSET-CITRIX'
    assert candidate['candidate_assets'][0]['confidence'] >= 0.9
    assert exposure['asset_linked_count'] == 1  # Existing seeded finding only; no auto-confirmation.


def test_exposure_review_views_and_analyst_classification_are_explicit_and_audited():
    seed_executive_data()
    db = TestingSessionLocal()
    db.add_all([
        Asset(
            id='ASSET-CITRIX-REVIEW', tenant_id='tenant-alpha',
            name='Citrix NetScaler ADC', hostname='adc.alpha.test',
            status='active', tags=['citrix', 'netscaler'],
        ),
        Finding(
            id='F-REVIEW-SUGGESTED', tenant_id='tenant-alpha',
            cve='CVE-2026-9001', title='Citrix NetScaler ADC vulnerability',
            vendor='Citrix', product='NetScaler ADC', priority='P0',
            status='unmitigated', source='kev', cisa_kev=True,
        ),
        Finding(
            id='F-REVIEW-INTAKE', tenant_id='tenant-alpha',
            cve='SSS-2026-BLFLAW-TEST', title='Business logic intake',
            priority='P1', status='unmitigated', source='sss',
        ),
        Finding(
            id='F-REFERENCE-CATALOGUE', tenant_id='tenant-alpha',
            cve='CVE-2026-9002', title='Unmatched catalogue reference',
            priority='P1', status='unmitigated', source='kev', cisa_kev=True,
        ),
    ])
    db.commit()
    db.close()

    client = TestClient(app)
    admin = headers_for('alpha-admin@example.test')
    analyst = headers_for('alpha-analyst@example.test')

    review = client.get('/api/workflow/exposures?view=needs_review', headers=admin)
    assert review.status_code == 200
    assert review.json()['total'] == 2
    assert {row['mapping_reason'] for row in review.json()['data']} == {
        'candidate_match', 'unclassified_intake',
    }

    reference = client.get('/api/workflow/exposures?view=reference', headers=admin)
    assert reference.status_code == 200
    assert reference.json()['total'] == 1
    assert reference.json()['data'][0]['mapping_reason'] == 'catalogue_reference'

    classified = client.put(
        '/api/workflow/findings/F-REVIEW-INTAKE/exposure-classification',
        headers=analyst,
        json={
            'classification': 'reference_intelligence',
            'rationale': 'Research record only; no customer asset evidence exists.',
        },
    )
    assert classified.status_code == 200
    assert classified.json()['classification'] == 'reference_intelligence'

    updated_review = client.get('/api/workflow/exposures?view=needs_review', headers=admin).json()
    assert updated_review['total'] == 1
    updated_reference = client.get('/api/workflow/exposures?view=reference', headers=admin).json()
    assert updated_reference['total'] == 2
    overview = client.get('/api/workflow/overview', headers=admin).json()['exposure']
    assert overview['mapping_required_count'] == 1
    assert overview['analyst_reference_intelligence_count'] == 1
    assert overview['catalog_intelligence_count'] == 2

    db = TestingSessionLocal()
    finding = db.query(Finding).filter(Finding.id == 'F-REVIEW-INTAKE').one()
    assert finding.status == 'reference_only'
    history = db.query(FindingStatusHistory).filter(
        FindingStatusHistory.finding_id == finding.id,
    ).one()
    assert history.new_status == 'reference_only'
    assert history.changed_by == 'alpha-analyst@example.test'
    audit = db.query(AuditLog).filter(
        AuditLog.action == 'FINDING_EXPOSURE_CLASSIFIED',
    ).one()
    assert audit.tenant_id == 'tenant-alpha'
    db.close()

    linked = client.put(
        '/api/workflow/findings/F-REVIEW-INTAKE/assets',
        headers=analyst,
        json={
            'asset_ids': ['ASSET-ALPHA'],
            'evidence': 'Analyst later confirmed the affected application on Alpha Gateway.',
        },
    )
    assert linked.status_code == 200
    db = TestingSessionLocal()
    restored = db.query(Finding).filter(Finding.id == 'F-REVIEW-INTAKE').one()
    assert restored.status == 'unmitigated'
    assert db.query(FindingStatusHistory).filter(
        FindingStatusHistory.finding_id == restored.id,
    ).count() == 2
    db.close()
def test_sql_shaped_ids_and_tenant_mass_assignment_fail_closed():
    client = TestClient(app)
    alpha_headers = headers_for('alpha-admin@example.test')
    quote = chr(39)
    sql_shaped_id = 'F-X' + quote + ' OR ' + quote + '1' + quote + '=' + quote + '1'

    lookup = client.get(
        f'/api/ciso/findings/{sql_shaped_id}',
        headers=alpha_headers,
    )
    assert lookup.status_code == 404

    report = client.post(
        '/api/reports/generate',
        headers=alpha_headers,
        json={'report_type': 'risk', 'source_finding_ids': [sql_shaped_id]},
    )
    assert report.status_code == 400

    policy = client.post(
        '/api/grc/policies',
        headers=alpha_headers,
        json={
            'title': 'Policy ' + quote + ' OR 1=1 --',
            'content': 'Fictional SQL-shaped content',
            'tenant_id': 'tenant-beta',
        },
    )
    assert policy.status_code == 200
    db = TestingSessionLocal()
    stored = db.query(GrcPolicyDocument).filter(
        GrcPolicyDocument.id == policy.json()['id']
    ).one()
    assert stored.tenant_id == 'tenant-alpha'
    db.close()
