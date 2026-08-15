from datetime import datetime, timedelta, timezone
from queue import Empty, Queue

import pytest
from fastapi.testclient import TestClient
from passlib.hash import bcrypt

from index import app
from models import Finding
from routers import auth
from routers.edip import _sss_watch_lock, _sss_watch_queues
from services.database import Base, SessionLocal, engine


EMAIL = "v73.analyst@tempris.test"
PASSWORD = "v73-test-password"
TENANT = "tenant-v73"


@pytest.fixture(autouse=True)
def v73_state(monkeypatch):
    from middleware.rate_limit import _Bucket

    monkeypatch.setattr(_Bucket, "consume", lambda self: True)
    Base.metadata.create_all(bind=engine)
    auth.USERS[EMAIL] = {
        "password": bcrypt.hash(PASSWORD),
        "role": "Analyst",
        "name": "V73 Analyst",
        "tenant_id": TENANT,
    }
    db = SessionLocal()
    db.query(Finding).filter(Finding.tenant_id == TENANT).delete()
    db.commit()
    db.close()
    yield
    auth.USERS.pop(EMAIL, None)
    with _sss_watch_lock:
        _sss_watch_queues.pop(TENANT, None)
        _sss_watch_queues.pop("other-tenant", None)


@pytest.fixture
def client_and_headers():
    client = TestClient(app)
    login = client.post("/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert login.status_code == 200
    return client, {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_v73_subclasses_and_ten_descriptive_fields(client_and_headers):
    client, headers = client_and_headers
    identity = client.post(
        "/api/edip/intake/sss",
        headers=headers,
        json={
            "class": "IDENTITY_POSTURE",
            "sub_class": "AUTH_FLOW_ABUSE",
            "title": "Device-code flow can transfer authentication",
            "description": "Identity posture evidence supplied by the tenant connector.",
            "source_tool": "Connector",
            "device_code_flow_enabled": True,
            "oauth_grant_inventory": "partial",
            "app_consent_policy": "restricted",
            "refresh_token_lifetime_days": 30,
            "auth_transfer_blocked": False,
        },
    )
    assert identity.status_code == 200
    assert identity.json()["sub_class"] == "AUTH_FLOW_ABUSE"
    assert identity.json()["oauth_grant_inventory"] == "partial"
    assert identity.json()["auth_transfer_blocked"] is False

    adversary = client.post(
        "/api/edip/intake/sss",
        headers=headers,
        json={
            "class": "AGENTIC_EXPOSURE",
            "sub_class": "ADVERSARY_AI",
            "title": "Adversary AI activity observed",
            "description": "Descriptive threat posture without client-side scoring inputs.",
        },
    )
    assert adversary.status_code == 200

    self_reported = client.post(
        "/api/edip/intake/sss",
        headers=headers,
        json={
            "class": "AGENTIC_EXPOSURE",
            "sub_class": "AUTONOMOUS_PRINCIPAL",
            "title": "Self-reported containment",
            "description": "The assessed workload claims that it monitors its own egress.",
            "source_tool": "Agent self-report",
            "egress_monitored_independently": True,
        },
    )
    assert self_reported.status_code == 422

    autonomous = client.post(
        "/api/edip/intake/sss",
        headers=headers,
        json={
            "class": "AGENTIC_EXPOSURE",
            "sub_class": "AUTONOMOUS_PRINCIPAL",
            "title": "Autonomous workload posture",
            "description": "Independent monitoring verifies the workload containment posture.",
            "source_tool": "External SIEM",
            "ai_workload_inventory": "complete",
            "workload_credential_scope": "read",
            "egress_monitored_independently": True,
            "containment_tested": True,
            "abort_criteria_owner": "Security Operations",
        },
    )
    assert autonomous.status_code == 200
    body = autonomous.json()
    assert body["sub_class"] == "AUTONOMOUS_PRINCIPAL"
    assert body["ai_workload_inventory"] == "complete"
    assert body["workload_credential_scope"] == "read"
    assert body["egress_monitored_independently"] is True
    assert body["containment_tested"] is True
    assert body["abort_criteria_owner"] == "Security Operations"


def test_v73_ordered_decisions_and_tenant_scoped_watch_push(client_and_headers):
    client, headers = client_and_headers
    created = client.post(
        "/api/edip/intake/sss",
        headers=headers,
        json={
            "class": "IDENTITY_POSTURE",
            "sub_class": "AUTH_FLOW_ABUSE",
            "title": "Audit authentication before restriction",
            "description": "Initial engine output requires investigation before a control is applied.",
            "base_severity": 5,
            "patch_available": True,
        },
    )
    assert created.status_code == 200
    assert created.json()["decision_sequence"] == ["INVESTIGATE"]

    tenant_queue, other_queue = Queue(), Queue()
    with _sss_watch_lock:
        _sss_watch_queues[TENANT] = {tenant_queue}
        _sss_watch_queues["other-tenant"] = {other_queue}

    overdue = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
    updated = client.put(
        f"/api/edip/intake/sss/{created.json()['id']}",
        headers=headers,
        json={"patch_available": False, "watch_flag": True, "kev_due": overdue},
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["decision_sequence"] == ["INVESTIGATE", "COMPENSATING_CONTROL"]
    assert body["kev_countdown_state"] == "overdue"
    assert tenant_queue.get_nowait()["finding_id"] == body["id"]
    with pytest.raises(Empty):
        other_queue.get_nowait()

    script = client.get("/extensions/tempris-modules.js").text
    assert "/api/edip/intake/sss/events" in script
    assert "Engine decision sequence" in script
    assert "sssUi.findingViewState(finding)" in script
