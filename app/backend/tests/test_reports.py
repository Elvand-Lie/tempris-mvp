import pytest
import os
import sys
import json
import csv
from fastapi.testclient import TestClient
from passlib.hash import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ['ENVIRONMENT'] = 'test'
os.environ['AUDIT_HMAC_KEY'] = 'test_audit_hmac_secret_key_12345678'

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.database import Base, get_db
import services.database
from models import Asset, ControlStatus, EdipDecision, GeneratedReport, Finding, ControlEvidence, AuditLog, SpotlightReport
from index import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_reports.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

@pytest.fixture(autouse=True)
def setup_db(monkeypatch):
    from middleware.rate_limit import _Bucket
    monkeypatch.setattr(_Bucket, "consume", lambda self: True)

    app.dependency_overrides[get_db] = override_get_db
    old_engine = services.database.engine
    services.database.engine = engine
    old_session_local = services.database.SessionLocal
    services.database.SessionLocal = TestingSessionLocal

    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    db.query(GeneratedReport).delete()
    db.query(Finding).delete()
    db.query(ControlEvidence).delete()
    db.query(AuditLog).delete()
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    app.dependency_overrides.pop(get_db, None)
    services.database.engine = old_engine
    services.database.SessionLocal = old_session_local
    if os.path.exists("./test_reports.db"):
        try:
            os.remove("./test_reports.db")
        except Exception:
            pass

def test_reporting_pipeline_and_isolation():
    from routers.auth import USERS
    USERS["reporter_a@tempris.com"] = {
        "password": bcrypt.hash("pwd_a"),
        "role": "Admin",
        "name": "Reporter A",
        "tenant_id": "tenantA"
    }
    USERS["reporter_b@tempris.com"] = {
        "password": bcrypt.hash("pwd_b"),
        "role": "Admin",
        "name": "Reporter B",
        "tenant_id": "tenantB"
    }

    client = TestClient(app)
    
    # Login Reporter A
    resp_login_a = client.post("/api/auth/login", json={"email": "reporter_a@tempris.com", "password": "pwd_a"})
    headers_a = {"Authorization": f"Bearer {resp_login_a.json()['access_token']}"}

    # Login Reporter B
    resp_login_b = client.post("/api/auth/login", json={"email": "reporter_b@tempris.com", "password": "pwd_b"})
    headers_b = {"Authorization": f"Bearer {resp_login_b.json()['access_token']}"}

    # Seed findings & evidence for tenant A and tenant B
    db = TestingSessionLocal()
    f_a = Finding(
        id="F-A1", tenant_id="tenantA", title="Tenant A Finding", vendor="V", product="P",
        cvss=7.5, priority="P1", status="unmitigated", short_description="Desc",
        raw_inputs={"agm": 0.8, "drf": 0.5, "tef": 0.3}
    )
    f_b = Finding(
        id="F-B1", tenant_id="tenantB", title="Tenant B Finding", vendor="V", product="P",
        cvss=8.0, priority="P1", status="unmitigated", short_description="Desc"
    )
    f_formula = Finding(
        id='F-FORMULA', tenant_id='tenantA', title='=SUM(1,1)',
        vendor='+formula', product='@formula', cvss=5.0, priority='P2',
        status='unmitigated', short_description='Fictional formula-shaped content'
    )
    db.add(f_a)
    db.add(f_b)
    db.add(f_formula)
    
    e_a = ControlEvidence(id=1, tenant_id="tenantA", framework_id="ISO42001", control_id="A.1", filename="ev_a.txt", file_path="/tmp/a.txt")
    e_b = ControlEvidence(id=2, tenant_id="tenantB", framework_id="ISO42001", control_id="A.1", filename="ev_b.txt", file_path="/tmp/b.txt")
    db.add(e_a)
    db.add(e_b)
    
    db.commit()
    db.close()

    # 1. Anomaly check: Reporter A attempts to register report referencing Tenant B's finding -> 400
    register_data_bad = {
        "id": "R-100",
        "report_type": "risk",
        "generator_version": "v1.0",
        "source_finding_ids": ["F-B1"],
        "content_hash": "a" * 64,
        "artifact_location": "/tmp/a.csv"
    }
    resp_reg_bad = client.post("/api/reports/register", json=register_data_bad, headers=headers_a)
    assert resp_reg_bad.status_code == 400
    assert "belongs to a different tenant" in resp_reg_bad.json()["detail"]

    generate_bad = client.post(
        '/api/reports/generate',
        json={'report_type': 'risk', 'source_finding_ids': ['F-B1']},
        headers=headers_a,
    )
    assert generate_bad.status_code == 400
    assert 'unavailable for this tenant' in generate_bad.json()['detail']

    formula_response = client.post(
        '/api/reports/generate',
        json={
            'report_type': 'risk',
            'source_finding_ids': ['F-FORMULA'],
            'framework_configuration': {
                'engagement_id': 'ENG-FORMULA',
                'agm': 9.9,
                'nested': {'drf': 8.8},
            },
        },
        headers=headers_a,
    )
    assert formula_response.status_code == 200
    formula_manifest = formula_response.json()['manifest']
    assert formula_manifest['framework_configuration'] == {
        'engagement_id': 'ENG-FORMULA',
        'nested': {},
    }
    formula_path = formula_manifest['artifact_location']
    with open(formula_path, newline='', encoding='utf-8') as formula_file:
        formula_rows = list(csv.reader(formula_file))
    assert formula_rows[1][2].startswith(chr(39) + '=')
    assert formula_rows[1][3].startswith(chr(39) + '+')
    assert formula_rows[1][4].startswith(chr(39) + '@')
    os.remove(formula_path)

    # 2. Reporter A generates report referencing Tenant A finding & evidence -> 200
    gen_data = {
        "report_type": "risk",
        "source_finding_ids": ["F-A1"],
        "source_evidence_ids": ["1"],
        "framework_configuration": {"engagement_id": "ENG-101"}
    }
    resp_gen = client.post("/api/reports/generate", json=gen_data, headers=headers_a)
    assert resp_gen.status_code == 200
    report_manifest = resp_gen.json()["manifest"]
    assert report_manifest["tenant_id"] == "tenantA"
    assert report_manifest["engagement_id"] == "ENG-101"
    
    # 3. Verify file output exists and does NOT leak scoring internals (agm, drf, tef)
    csv_file = report_manifest["artifact_location"]
    assert os.path.exists(csv_file)
    with open(csv_file, "r") as f_csv:
        content = f_csv.read()
        assert "agm" not in content
        assert "drf" not in content
        assert "tef" not in content
        assert "Tenant A Finding" in content
        
    # Clean up generated report file
    if os.path.exists(csv_file):
        try:
            os.remove(csv_file)
        except Exception:
            pass

    # 4. Generate combined client report package (REPORT-C08)
    combined_data = {
        "report_type": "combined",
        "source_finding_ids": ["F-A1"],
        "source_evidence_ids": ["1"],
        "framework_configuration": {"engagement_id": "ENG-101"}
    }
    resp_comb = client.post("/api/reports/generate", json=combined_data, headers=headers_a)
    assert resp_comb.status_code == 200
    comb_manifest = resp_comb.json()["manifest"]
    assert comb_manifest["report_type"] == "combined"
    
    comb_file = comb_manifest["artifact_location"]
    assert os.path.exists(comb_file)
    with open(comb_file, "r") as f_json:
        comb_json_data = json.load(f_json)
        
    assert "sub_reports" in comb_json_data
    assert "risk" in comb_json_data["sub_reports"]
    assert "gap" in comb_json_data["sub_reports"]
    
    # Verify sub-report files exist
    risk_sub_path = comb_json_data["sub_reports"]["risk"]["path"]
    gap_sub_path = comb_json_data["sub_reports"]["gap"]["path"]
    assert os.path.exists(risk_sub_path)
    assert os.path.exists(gap_sub_path)
    
    # Clean up files
    for p in (risk_sub_path, gap_sub_path, comb_file):
        if os.path.exists(p):
            os.remove(p)

    # 5. Verify PDF generation is blocked (documented limitation)
    pdf_data = {
        "report_type": "pdf",
        "source_finding_ids": ["F-A1"],
        "source_evidence_ids": ["1"],
        "framework_configuration": {"engagement_id": "ENG-101"}
    }
    resp_pdf = client.post("/api/reports/generate", json=pdf_data, headers=headers_a)
    assert resp_pdf.status_code == 400
    assert "PDF_GENERATION_BLOCKED" in resp_pdf.json()["detail"]


def test_customer_report_artifacts_are_safe_deterministic_and_tenant_scoped():
    from routers.auth import USERS
    from services.reporting_engine import poc_artifact_path

    USERS['poc_a@tempris.com'] = {
        'password': bcrypt.hash('pwd_a'), 'role': 'Admin',
        'name': 'POC A', 'tenant_id': 'tenantA',
    }
    USERS['poc_b@tempris.com'] = {
        'password': bcrypt.hash('pwd_b'), 'role': 'Admin',
        'name': 'POC B', 'tenant_id': 'tenantB',
    }
    client = TestClient(app)
    login_a = client.post(
        '/api/auth/login', json={'email': 'poc_a@tempris.com', 'password': 'pwd_a'}
    )
    login_b = client.post(
        '/api/auth/login', json={'email': 'poc_b@tempris.com', 'password': 'pwd_b'}
    )
    headers_a = {'Authorization': f"Bearer {login_a.json()['access_token']}"}
    headers_b = {'Authorization': f"Bearer {login_b.json()['access_token']}"}

    db = TestingSessionLocal()
    db.add(Asset(
        id='ASSET-A', tenant_id='tenantA', name='Payments API',
        environment='production', owner='Platform Team', criticality='critical',
    ))
    db.add(Finding(
        id='F-LOW', tenant_id='tenantA', title='<script>alert(1)</script>',
        priority='P3', status='unmitigated', description='Lower impact item',
        required_action='Review configuration', raw_inputs={'agm': 99, 'tef': 88},
        score=2.4, cvss=2.4,
    ))
    db.add(Finding(
        id='F-HIGH', tenant_id='tenantA', title='Internet-facing exposure',
        cve='CVE-2026-12345', priority='P1', status='unmitigated',
        description='A reachable production weakness', required_action='Apply patch',
        asset_id='ASSET-A', raw_inputs={'drf': 77}, score=9.8, cvss=9.8,
    ))
    db.add(EdipDecision(
        tenant_id='tenantA', finding_id='F-HIGH', cve='CVE-2026-12345',
        decision='PATCH', rationale='Production exposure requires prompt treatment.',
    ))
    db.commit()
    db.close()

    response = client.post(
        '/api/reports/poc/generate',
        headers=headers_a,
        json={
            'source_finding_ids': ['F-LOW', 'F-HIGH'],
            'configuration': {
                'title': 'National Day CTEM & EDIP Report',
                'engagement_id': 'ENG-ND-001',
                'client': {
                    'organisation': 'Example Client',
                    'contact': 'Security Lead',
                    'environment': 'Production',
                },
                'period': {'start': '2026-08-01', 'end': '2026-08-05'},
                'coverage': {
                    'scope': ['Payments API findings selected for this report'],
                    'out_of_scope': ['Assets and findings not selected for this report'],
                },
                'delivery': {
                    'recipients': ['security@example.test'],
                    'alliance_partner': 'Example Alliance',
                    'client_consent_for_partner': False,
                },
                'agm': 100,
                'assessment': {'attestation': ''},
            },
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['delivery']['partner_delivery_status'] == 'withheld'
    assert result['delivery']['client_consent_for_partner'] is False
    assert result['executive_summary'] == {
        'act_now': 1, 'watch': 0, 'safe_to_wait': 0, 'not_assigned': 1, 'total': 2,
        'narrative': (
            '2 finding(s) were assessed: 1 require immediate action, '
            '0 require monitoring, and 0 are safe to defer. '
            '1 have no recorded EDIP decision.'
        ),
    }

    report_id = result['report_id']
    json_response = client.get(
        f'/api/reports/{report_id}/artifact/json', headers=headers_a,
    )
    html_response = client.get(
        f'/api/reports/{report_id}/artifact/html', headers=headers_a,
    )
    csv_response = client.get(
        f'/api/reports/{report_id}/artifact/csv', headers=headers_a,
    )
    assert json_response.status_code == html_response.status_code == csv_response.status_code == 200
    payload = json_response.json()
    assert [row['id'] for row in payload['findings']] == ['F-HIGH', 'F-LOW']
    assert payload['findings'][0]['action_label'] == 'Fix now'
    assert payload['findings'][1]['action_label'] == 'Not assigned'
    assert payload['findings'][1]['decision_rationale'] == 'Not recorded'
    assert payload['findings'][1]['why_it_matters'] == 'Not recorded'
    assert payload['findings'][1]['remediation']['owner'] is None
    assert payload['findings'][1]['remediation']['sla_days'] is None
    assert payload['findings'][1]['remediation']['due_date'] is None
    assert payload['findings'][1]['re_evaluation_date'] is None
    assert 'Record an EDIP decision' in payload['next_steps'][0]
    assert 'score' not in json_response.text.lower()
    assert 'cvss' not in json_response.text.lower()
    assert 'agm' not in json_response.text.lower()
    assert 'drf' not in json_response.text.lower()
    assert 'tef' not in json_response.text.lower()
    assert '<script>alert(1)</script>' not in html_response.text
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html_response.text
    assert "frame-ancestors 'none'" in html_response.headers['content-security-policy']
    assert 'CVSS' not in csv_response.text

    canonical = json.loads(json.dumps(payload))
    integrity_hash = canonical['report'].pop('integrity_hash')
    expected_integrity = __import__('hashlib').sha256(
        json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()
    assert integrity_hash == expected_integrity
    assert result['manifest']['content_hash'] == __import__('hashlib').sha256(
        json_response.content
    ).hexdigest()

    cross_tenant = client.get(
        f'/api/reports/{report_id}/artifact/html', headers=headers_b,
    )
    assert cross_tenant.status_code == 404

    for artifact_format in ('html', 'json', 'csv'):
        poc_artifact_path(report_id, artifact_format).unlink(missing_ok=True)


def test_spotlight_generation_and_history_are_tenant_scoped(monkeypatch):
    from routers.auth import USERS
    import services.ai_context as ai_context
    import services.llm_client as llm_client

    USERS['spotlight_a@tempris.com'] = {
        'password': bcrypt.hash('pwd_a'), 'role': 'Admin',
        'name': 'Spotlight A', 'tenant_id': 'tenantA',
    }
    USERS['spotlight_b@tempris.com'] = {
        'password': bcrypt.hash('pwd_b'), 'role': 'Admin',
        'name': 'Spotlight B', 'tenant_id': 'tenantB',
    }

    captured_tenants = []

    def fake_context(db, query='', n_results=5, extra_query='', tenant_id='tempris'):
        captured_tenants.append(tenant_id)
        return {
            'full_text': f'Tenant context: {tenant_id}',
            'structured': {'tes_score': None, 'kev_total': 0, 'asset_count': 0},
            'rag_text': '', 'rag_sources': [], 'rag_query': query,
        }

    def fake_chat_completion(*args, **kwargs):
        return (
            '## Recorded tenant posture\n'
            + ('Only tenant-scoped, explicitly recorded data is included. ' * 20)
            + '\n## Supported actions\nNo action is inferred from missing data.'
        )

    monkeypatch.setattr(ai_context, 'build_service_ai_context', fake_context)
    monkeypatch.setattr(llm_client, 'chat_completion', fake_chat_completion)

    client = TestClient(app)
    token_a = client.post(
        '/api/auth/login', json={'email': 'spotlight_a@tempris.com', 'password': 'pwd_a'},
    ).json()['access_token']
    token_b = client.post(
        '/api/auth/login', json={'email': 'spotlight_b@tempris.com', 'password': 'pwd_b'},
    ).json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    headers_b = {'Authorization': f'Bearer {token_b}'}

    generated_a = client.post('/api/spotlight/generate', json={'report_type': 'executive'}, headers=headers_a)
    generated_b = client.post('/api/spotlight/generate', json={'report_type': 'ciso'}, headers=headers_b)
    assert generated_a.status_code == generated_b.status_code == 200
    assert captured_tenants == ['tenantA', 'tenantB']

    history_a = client.get('/api/spotlight/history', headers=headers_a).json()
    history_b = client.get('/api/spotlight/history', headers=headers_b).json()
    assert [row['generated_by'] for row in history_a] == ['spotlight_a@tempris.com']
    assert [row['generated_by'] for row in history_b] == ['spotlight_b@tempris.com']

    db = TestingSessionLocal()
    stored = db.query(SpotlightReport).order_by(SpotlightReport.id).all()
    assert [(row.tenant_id, row.generated_by) for row in stored] == [
        ('tenantA', 'spotlight_a@tempris.com'),
        ('tenantB', 'spotlight_b@tempris.com'),
    ]
    assert all(row.tes_score is None for row in stored)
    db.close()


def test_ai_context_uses_recorded_tenant_data_only():
    from services.ai_context import build_full_context

    db = TestingSessionLocal()
    db.add_all([
        Finding(
            id='F-CTX-A', tenant_id='tenantA', title='Tenant A exposure',
            cve='CVE-2026-10001', cisa_kev=True, priority='P0', asset_id='ASSET-A',
        ),
        Finding(
            id='F-CTX-B', tenant_id='tenantB', title='Tenant B secret exposure',
            cve='CVE-2026-20002', cisa_kev=True, priority='P0', asset_id='ASSET-B',
        ),
        ControlStatus(
            tenant_id='tenantA', framework_id='mas_trm_2024', control_id='MAS-TRM-5.1.1',
            status='compliant',
        ),
        ControlStatus(
            tenant_id='tenantB', framework_id='mas_trm_2024', control_id='MAS-TRM-5.1.1',
            status='non_compliant',
        ),
        AuditLog(
            tenant_id='tenantA', action='A_CONTEXT_EVENT', module='TACF',
            detail='Tenant A audit detail',
        ),
        AuditLog(
            tenant_id='tenantB', action='B_SECRET_EVENT', module='TACF',
            detail='Tenant B secret audit detail',
        ),
    ])
    db.commit()

    context = build_full_context(db, tenant_id='tenantA')
    db.close()

    text_context = context['full_text']
    structured = context['structured']
    assert 'CVE-2026-10001' in text_context
    assert 'CVE-2026-20002' not in text_context
    assert 'Tenant B secret audit detail' not in text_context
    assert structured['kev_total'] == 1
    assert structured['compliance_assessed_controls'] == 1
    assert structured['compliance_compliant'] == 1
    assert structured['compliance_non_compliant'] == 0
    assert structured['tes_score'] is None
    assert structured['module_health'] == []
    assert structured['grc_tes'] is None


def test_shared_rag_sync_excludes_tenant_findings_and_audit_logs(monkeypatch):
    import services.rag_engine as rag_engine

    class FakeCollection:
        def count(self):
            return 0

        def get(self, **kwargs):
            return {'ids': []}

    embedded = []
    deleted = []
    monkeypatch.setattr(rag_engine, '_get_collection', lambda: FakeCollection())
    monkeypatch.setattr(
        rag_engine, 'embed_document',
        lambda source_id, content, metadata=None: embedded.append(source_id) or 0,
    )
    monkeypatch.setattr(rag_engine, '_delete_by_source', deleted.append)

    rag_engine.sync_knowledge_base()

    assert 'kev__critical_cves' not in embedded
    assert 'kev__summary' not in embedded
    assert 'tacf__recent_logs' not in embedded
    assert 'kev__critical_cves' in deleted
    assert 'kev__summary' in deleted
    assert 'tacf__recent_logs' in deleted
