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
    AuditLog,
    Base,
    ControlStatus,
    Finding,
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
            raw_inputs={'agm': 1.2, 'drf': 0.4, 'tef': 0.7},
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
        'overdue': 1,
        'critical': 1,
        'high': 0,
    }
    assert data['risk_trend']['direction'] == 'improving'
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


def test_synthesis_uses_only_tenant_snapshots_and_no_fictional_health():
    now = datetime.now(timezone.utc)
    db = TestingSessionLocal()
    db.add_all([
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
    assert data['tes_trend'] == '-2.0'
    assert data['alerts'] == []
    assert {item['status'] for item in data['module_health']} == {'unavailable'}
    assert data['final_update']['surge_scope_status'] == 'unavailable'

    created = client.post('/api/synthesis/tes-snapshot', headers=headers)
    assert created.status_code == 200
    db = TestingSessionLocal()
    alpha_count = db.query(TesSnapshot).filter(TesSnapshot.tenant_id == 'tenant-alpha').count()
    beta_count = db.query(TesSnapshot).filter(TesSnapshot.tenant_id == 'tenant-beta').count()
    db.close()
    assert alpha_count == 2
    assert beta_count == 1


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
