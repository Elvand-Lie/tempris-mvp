from datetime import date

import pytest
from fastapi.testclient import TestClient
from passlib.hash import bcrypt

from index import app
from models import AuditLog, Finding
from services.cvss_remap import v2_to_v31_remap
from services.database import Base, SessionLocal, engine
from services.sss_contract import deadline_state


@pytest.fixture(autouse=True)
def v62_test_state(monkeypatch):
    from middleware.rate_limit import _Bucket
    from routers import auth

    monkeypatch.setattr(_Bucket, "consume", lambda self: True)
    monkeypatch.setenv("AEV_VERDICT_ENGAGEMENT_TOKEN", "v62-test-engagement-token")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(AuditLog).delete()
    db.query(Finding).delete()
    db.commit()
    db.close()
    auth.USERS["v62.analyst@tempris.com"] = {
        "password": bcrypt.hash("v62-password"),
        "role": "Analyst",
        "name": "V62 Analyst",
        "tenant_id": "tenant-v62",
    }
    yield
    auth.USERS.pop("v62.analyst@tempris.com", None)


@pytest.fixture
def client_and_headers():
    client = TestClient(app)
    login = client.post(
        "/api/auth/login",
        json={"email": "v62.analyst@tempris.com", "password": "v62-password"},
    )
    assert login.status_code == 200
    return client, {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_cvss_v2_remap_and_legacy_cve_acceptance(client_and_headers):
    remap = v2_to_v31_remap("AV:N/AC:M/Au:N/C:N/I:P/A:N", csrf_class=True)
    assert remap["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
    assert remap["base_score"] == 4.3

    client, headers = client_and_headers
    payload = {
        "cve_id": "CVE-2008-4128",
        "title": "Cisco IOS HTTP CSRF",
        "description": "Legacy CVSS v2 CSRF record with no available patch.",
        "cvss_v2_vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
        "affected_ecosystem": "Cisco IOS 12.4",
        "csrf_class": True,
        "patch_available": False,
        "internet_exposed": False,
    }
    response = client.post("/api/edip/intake/legacy-cve", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["edip_decision"] == "COMPENSATING_CONTROL"
    assert response.json()["cvss_remap"]["ui_mapping"] == "R"

    exposed = {**payload, "cve_id": "CVE-2008-9999", "internet_exposed": True}
    response = client.post("/api/edip/intake/legacy-cve", json=exposed, headers=headers)
    assert response.status_code == 200
    assert response.json()["edip_decision"] == "ESCALATE"


def test_agentic_and_identity_posture_contracts(client_and_headers):
    client, headers = client_and_headers
    invalid = client.post(
        "/api/edip/intake/sss",
        headers=headers,
        json={
            "class": "AGENTIC_EXPOSURE",
            "sub_class": "TOOL_MCP",
            "title": "Over-privileged tool agent",
            "description": "Agent can invoke tools beyond its task scope.",
        },
    )
    assert invalid.status_code == 422

    valid = client.post(
        "/api/edip/intake/sss",
        headers=headers,
        json={
            "class": "AGENTIC_EXPOSURE",
            "sub_class": "TOOL_MCP",
            "title": "Over-privileged tool agent",
            "description": "Agent can invoke tools beyond its task scope.",
            "agent_id": "agent-7",
            "credential_scope": "tenant-read",
            "ingestion_paths": ["support-rag", "mcp-tools"],
            "egress_controlled": True,
            "base_severity": 6.5,
            "patch_available": True,
        },
    )
    assert valid.status_code == 200
    assert valid.json()["class"] == "AGENTIC_EXPOSURE"
    assert valid.json()["sub_class"] == "TOOL_MCP"
    assert valid.json()["agent_id"] == "agent-7"

    entra = client.post(
        "/api/edip/connectors/entra/authentication-methods",
        headers=headers,
        json={
            "users": [
                {
                    "id": "user-phone",
                    "userPrincipalName": "phone.user@example.test",
                    "authenticationMethods": [
                        {"@odata.type": "#microsoft.graph.phoneAuthenticationMethod", "phoneType": "mobile"}
                    ],
                },
                {
                    "id": "user-passkey",
                    "userPrincipalName": "passkey.user@example.test",
                    "authenticationMethods": [
                        {"@odata.type": "#microsoft.graph.fido2AuthenticationMethod"}
                    ],
                },
            ]
        },
    )
    assert entra.status_code == 200
    assert entra.json()["flagged_users"] == 1
    finding = entra.json()["data"][0]
    assert finding["class"] == "IDENTITY_POSTURE"
    assert finding["sub_class"] == "MFA_ENROLMENT"
    # Pending ISO 42001 assessments now provide the live tenant governance
    # context for this open non-CVE finding, so the server elevates it.
    assert finding["edip_decision"] == "ESCALATE"


def test_aev_verdict_authentication_and_server_deadline_states(client_and_headers, monkeypatch):
    from routers import edip

    events = []
    monkeypatch.setattr(edip, "_publish_sss_event", lambda tenant_id, payload: events.append((tenant_id, payload)))
    client, headers = client_and_headers
    payload = {
        "path_id": "AEV-PATH-22",
        "verdict": "prevented",
        "evidence_ref": "urn:tempris:evidence:aev-path-22",
        "revalidate_by": "2026-08-15",
        "engagement_token": "wrong-token",
        "base_severity": 6.5,
    }
    rejected = client.post("/api/edip/connectors/aev/verdicts", headers=headers, json=payload)
    assert rejected.status_code == 401
    assert client.post(
        "/api/edip/connectors/aev/verdicts",
        headers=headers,
        json={**payload, "evidence_ref": "not a uri"},
    ).status_code == 422
    missing_token = dict(payload)
    missing_token.pop("engagement_token")
    assert client.post("/api/edip/connectors/aev/verdicts", headers=headers, json=missing_token).status_code == 422

    accepted = client.post(
        "/api/edip/connectors/aev/verdicts",
        headers=headers,
        json={**payload, "engagement_token": "v62-test-engagement-token"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["validated"] is True
    assert accepted.json()["verdict"] == "prevented"
    assert accepted.json()["revalidation_countdown_state"] in {"scheduled", "due_soon", "overdue"}
    assert events[-1][0] == "tenant-v62"
    assert events[-1][1]["type"] == "sss.finding"

    updated = client.post(
        "/api/edip/connectors/aev/verdicts",
        headers=headers,
        json={**payload, "verdict": "detected", "engagement_token": "v62-test-engagement-token"},
    )
    assert updated.status_code == 200
    assert updated.json()["id"] == accepted.json()["id"]
    assert updated.json()["verdict"] == "detected"
    db = SessionLocal()
    assert db.query(Finding).filter(Finding.cve == "SSS-AEV-AEV-PATH-22").count() == 1
    db.close()

    today = date(2026, 7, 22)
    assert deadline_state("2026-08-01", today=today) == "scheduled"
    assert deadline_state("2026-07-28", today=today) == "due_soon"
    assert deadline_state("2026-07-21", today=today) == "overdue"


def test_live_entra_sync_reuses_normalizer_and_prevents_duplicates(client_and_headers, monkeypatch):
    from routers import edip

    monkeypatch.setattr(edip, "acquire_entra_authentication_snapshot", lambda tenant_id: {
        "users_discovered": 3,
        "users": [
            {
                "id": "sync-phone",
                "userPrincipalName": "sync.phone@example.test",
                "authenticationMethods": [{
                    "@odata.type": "#microsoft.graph.phoneAuthenticationMethod",
                    "phoneType": "mobile",
                }],
            },
            {
                "id": "sync-passkey",
                "userPrincipalName": "sync.passkey@example.test",
                "authenticationMethods": [{"@odata.type": "#microsoft.graph.fido2AuthenticationMethod"}],
            },
        ],
        "errors": [{"user": "unreadable", "error": "permission denied"}],
    })
    client, headers = client_and_headers

    first = client.post("/api/edip/connectors/entra/sync", headers=headers, json={})
    second = client.post("/api/edip/connectors/entra/sync", headers=headers, json={})

    assert first.status_code == second.status_code == 200
    assert first.json()["created"] == 1
    assert second.json()["created"] == 0
    assert second.json()["updated"] == 1
    assert second.json()["partial"] is True
    assert second.json()["users_discovered"] == 3
    db = SessionLocal()
    rows = db.query(Finding).filter(
        Finding.tenant_id == "tenant-v62",
        Finding.cve == "SSS-ENTRA-sync-phone",
    ).all()
    assert len(rows) == 1
    assert rows[0].decision == "ESCALATE"
    db.close()
