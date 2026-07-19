#!/usr/bin/env python3
'''Non-destructive Tempris application smoke test using fictional local data.'''

import json
import os
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / 'app' / 'backend'
TEMP_ROOT = REPO_ROOT / '.tmp'
TEMP_ROOT.mkdir(exist_ok=True)


def require_status(response, expected: int, step: str):
    if response.status_code != expected:
        raise RuntimeError(
            f'{step} failed with HTTP {response.status_code}: {response.text[:200]}'
        )
    return response


def main() -> int:
    with tempfile.TemporaryDirectory(prefix='tempris-smoke-', dir=TEMP_ROOT) as temp_name:
        workspace = Path(temp_name)
        database_path = workspace / 'smoke.db'
        os.environ.update({
            'ENVIRONMENT': 'test',
            'DATABASE_URL': f'sqlite:///{database_path.as_posix()}',
            'AUDIT_HMAC_KEY': 'fictional-smoke-audit-key-32-bytes-minimum',
            'EVIDENCE_STORAGE_ROOT': str(workspace / 'evidence'),
            'REPORT_STORAGE_ROOT': str(workspace / 'reports'),
            'CORS_ORIGINS': 'http://testserver',
        })
        os.chdir(workspace)
        sys.path.insert(0, str(BACKEND_ROOT))

        from fastapi.testclient import TestClient
        from passlib.hash import bcrypt

        from index import app
        from middleware.rate_limit import _Bucket
        from models import Base
        from routers.auth import USERS
        from services.database import engine

        _Bucket.consume = lambda self: True
        Base.metadata.create_all(bind=engine)
        USERS.update({
            'alpha-admin@example.test': {
                'password': bcrypt.hash('fictional-alpha-password'),
                'role': 'Admin',
                'name': 'Alpha Admin',
                'tenant_id': 'tenant-alpha',
            },
            'beta-admin@example.test': {
                'password': bcrypt.hash('fictional-beta-password'),
                'role': 'Admin',
                'name': 'Beta Admin',
                'tenant_id': 'tenant-beta',
            },
        })
        client = TestClient(app)

        health = require_status(client.get('/api/health'), 200, 'health')
        alpha_login = require_status(
            client.post('/api/auth/login', json={
                'email': 'alpha-admin@example.test',
                'password': 'fictional-alpha-password',
            }),
            200,
            'alpha login',
        )
        beta_login = require_status(
            client.post('/api/auth/login', json={
                'email': 'beta-admin@example.test',
                'password': 'fictional-beta-password',
            }),
            200,
            'beta login',
        )
        alpha_token = alpha_login.json()['access_token']
        beta_token = beta_login.json()['access_token']
        alpha_headers = {'Authorization': f'Bearer {alpha_token}'}
        beta_headers = {'Authorization': f'Bearer {beta_token}'}

        require_status(
            client.get('/api/synthesis/dashboard', headers=alpha_headers),
            200,
            'protected request',
        )
        alpha_finding = require_status(
            client.post('/api/blflaw/intake', headers=alpha_headers, json={
                'title': 'Fictional alpha authorization gap',
                'description': 'Local smoke-test finding',
                'flaw_type': 'IDOR',
                'severity': 'high',
                'asset_id': 'ASSET-ALPHA',
                'flow_steps': ['request', 'authorization check'],
                'compensating_controls': [],
            }),
            200,
            'alpha finding creation',
        ).json()
        beta_finding = require_status(
            client.post('/api/blflaw/intake', headers=beta_headers, json={
                'title': 'Fictional beta workflow gap',
                'description': 'Local smoke-test isolation object',
                'flaw_type': 'WORKFLOW_BYPASS',
                'severity': 'medium',
                'asset_id': 'ASSET-BETA',
                'flow_steps': ['request', 'workflow check'],
                'compensating_controls': [],
            }),
            200,
            'beta finding creation',
        ).json()
        alpha_list = require_status(
            client.get('/api/blflaw', headers=alpha_headers),
            200,
            'finding retrieval',
        ).json()
        if alpha_finding['id'] not in {finding['id'] for finding in alpha_list}:
            raise RuntimeError('finding retrieval did not return the created alpha finding')

        beta_finding_id = beta_finding['id']
        require_status(
            client.get(
                f'/api/ciso/findings/{beta_finding_id}',
                headers=alpha_headers,
            ),
            404,
            'tenant isolation rejection',
        )
        audit_log = require_status(
            client.get('/api/audit/log', headers=alpha_headers),
            200,
            'audit event retrieval',
        ).json()
        if not any(entry['action'] == 'BLFLAW_INTAKE' for entry in audit_log):
            raise RuntimeError('finding creation audit event was not recorded')

        report = require_status(
            client.post('/api/reports/generate', headers=alpha_headers, json={
                'report_type': 'risk',
                'source_finding_ids': [alpha_finding['id']],
                'source_evidence_ids': [],
                'framework_configuration': {'engagement_id': 'ENG-SMOKE'},
            }),
            200,
            'report generation',
        ).json()
        report_path = Path(report['manifest']['artifact_location'])
        if not report_path.is_file() or workspace not in report_path.parents:
            raise RuntimeError('report artifact was not created in temporary storage')

        summary = require_status(
            client.get('/api/ciso/summary', headers=alpha_headers),
            200,
            'CISO summary',
        ).json()
        if summary['tenant_id'] != 'tenant-alpha':
            raise RuntimeError('CISO summary tenant mismatch')

        require_status(
            client.post('/api/auth/logout', headers=alpha_headers),
            200,
            'logout',
        )
        require_status(
            client.get('/api/synthesis/dashboard', headers=alpha_headers),
            401,
            'revoked-token rejection',
        )

        result = {
            'status': 'passed',
            'database': 'temporary',
            'fictional_tenants': 2,
            'health': health.json().get('status', 'ok'),
            'finding_created': True,
            'tenant_isolation_rejected': True,
            'audit_event_verified': True,
            'report_generated': True,
            'ciso_summary_verified': True,
            'session_revoked': True,
            'cleanup': 'automatic',
        }
        client.close()
        engine.dispose()
        os.chdir(REPO_ROOT)
        print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
