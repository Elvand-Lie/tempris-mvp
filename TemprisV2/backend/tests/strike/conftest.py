# backend/tests/strike/conftest.py
"""
Test wiring for the Chapter 4 (STRIKE) suites — directory-scoped so the
shared tests/conftest.py stays untouched (parallel-safety).

The STRIKE router is domain-local (not wired into app.main by this
changeset), so these suites drive it through a local FastAPI app carrying
exactly that router — the same dependency stack (module entitlement, RBAC,
AuthContext) the final main.py wiring will serve. Ch.3 reads still go
through the shared ``client`` fixture (the full app) for cross-module
checks.

The autouse ``clean_strike`` fixture depends on the shared ``clean_database``
fixture, so ordering is: shared cleanup → strike cleanup on setup, and
strike cleanup → shared cleanup on teardown — no other suite ever sees a
STRIKE row, and no shared delete ever trips a STRIKE foreign key.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from app.collector_registry import collector_registry
from app.db import get_db_connection


class FakeStrikeSocket:
    """Stands in for the collector's WSS: captured STRIKE_JOB frames resolve
    their in-flight future with the next scripted result (or the default
    completed result), exactly like the real collector daemon would."""

    def __init__(self, completed_result=None):
        self.sent_frames = []
        self.script = []
        self._default = completed_result or {
            "job_id": None,  # filled from the frame
            "status": "completed",
            "exit_code": 0,
            "stdout": "HTTP/1.1 200 OK\n",
            "stderr": "",
            "stdout_bytes": 15,
            "stderr_bytes": 0,
            "started_at": "2026-09-24T00:00:00Z",
            "completed_at": "2026-09-24T00:00:01Z",
            "error_message": None,
        }

    async def send_text(self, payload: str) -> None:
        import json as _json

        frame = _json.loads(payload)
        self.sent_frames.append(frame)
        if frame.get("type") != "STRIKE_JOB":
            return
        result = dict(self.script.pop(0)) if self.script else dict(self._default)
        result["job_id"] = frame["job_id"]
        collector_registry.handle_strike_job_result(self.collector_id, result)

    # test scripting helpers
    collector_id = None


def make_fake_collector(tenant_id: str, *, name="fake-collector") -> dict:
    """DB row (enrolled, active) + live registry session with a fake socket.
    Returns {'id', 'socket', 'session'}."""
    collector_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO collectors (id, tenant_id, name, description,
                    enrollment_status, operator_status, public_key)
                VALUES (%s, %s, %s, 'strike test collector', 'enrolled',
                    'active', 'dGVzdC1rZXk=')
                ON CONFLICT (id) DO NOTHING;
                """,
                (str(collector_id), str(tenant_id), name),
            )
        conn.commit()

    socket = FakeStrikeSocket()
    socket.collector_id = collector_id
    session = collector_registry.register_session(
        collector_id=collector_id,
        tenant_id=uuid.UUID(str(tenant_id)),
        websocket=socket,
        operator_status="active",
    )
    session.capabilities = {
        "curl": {"available": True, "version": "8.5.0", "status": "ready"}
    }
    return {"id": collector_id, "socket": socket, "session": session}


def remove_fake_collector(handle: dict) -> None:
    collector_registry.unregister_session(handle["id"], reason="test teardown")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM collectors WHERE id = %s;", (str(handle["id"]),))
        conn.commit()


def make_strike_app() -> FastAPI:
    from app.routes.strike import router as strike_router

    app = FastAPI()
    app.include_router(strike_router)
    return app


def clean_strike_tables() -> None:
    """Clear STRIKE state between tests (test DB only). One TRUNCATE
    statement covering the whole strike cluster: TRUNCATE does not fire row
    triggers, so the production immutability triggers (permanent engagement
    history, immutable artifacts/evidence links) do not block test hygiene —
    the same pattern the shared cleaner uses for the approval primitive."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "TRUNCATE strike_run_output_chunks, strike_runs, strike_testing_scopes, "
                "strike_evidence_links, strike_artifacts, "
                "strike_operations, strike_relays, strike_workspaces, "
                "strike_targets, strike_engagements, strike_abilities;"
            )
            # the shared cleaner resets modules only for ASSETS/SPECTRUM
            cur.execute("UPDATE modules SET status = 'active' WHERE id = 'STRIKE';")
        conn.commit()


@pytest.fixture
def strike_client():
    with TestClient(make_strike_app()) as c:
        yield c


@pytest.fixture(autouse=True)
def clean_strike(clean_database):
    """Strike-scoped cleanup around every test (after the shared cleaner)."""
    clean_strike_tables()
    yield
    clean_strike_tables()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def iso(dt: datetime) -> str:
    return dt.isoformat()


def engagement_payload(
    *,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    ttl: timedelta = timedelta(days=30),
    finding_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
) -> dict:
    now = datetime.now(timezone.utc)
    start = valid_from or (now - timedelta(hours=1))
    end = valid_until or (now + ttl)
    return {
        "title": "Validation engagement for CVE-2026-70001",
        "purpose": "Controlled validation of the confirmed exposure",
        "roe": {
            "scope": ["10.0.0.60"],
            "methods": ["nuclei", "manual"],
            "credential_rules": "no credentialed execution",
            "cleanup": "workspace destroyed after completion",
            "stop_conditions": ["any out-of-scope error"],
            # the ROE's declared window must equal the engagement window below
            "time_window": {"valid_from": iso(start), "valid_until": iso(end)},
        },
        "valid_from": iso(start),
        "valid_until": iso(end),
        **({"finding_id": str(finding_id)} if finding_id else {}),
        **({"asset_id": str(asset_id)} if asset_id else {}),
    }
