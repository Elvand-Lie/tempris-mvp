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

from app.db import get_db_connection
from tests.conftest import TENANT_A


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
                "TRUNCATE strike_evidence_links, strike_artifacts, "
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
    requested_by_note: str = "roe v1",
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    ttl: timedelta = timedelta(days=30),
    finding_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "title": "Validation engagement for CVE-2026-70001",
        "purpose": "Controlled validation of the confirmed exposure",
        "roe": {
            "scope": ["10.0.0.60"],
            "methods": ["nuclei", "manual"],
            "credential_rules": "no credentialed execution",
            "cleanup": "workspace destroyed after completion",
            "stop_conditions": ["any out-of-scope error"],
            "note": requested_by_note,
        },
        "valid_from": iso(valid_from or (now - timedelta(hours=1))),
        "valid_until": iso(valid_until or (now + ttl)),
        **({"finding_id": str(finding_id)} if finding_id else {}),
        **({"asset_id": str(asset_id)} if asset_id else {}),
    }


def seed_ability(
    slug: str = "http-probe",
    engine: str = "http",
    title: str = "HTTP probe",
    active: bool = True,
) -> uuid.UUID:
    """Insert an allowlisted ability directly (catalog governance is open
    decision #6 — there is no registration endpoint to drive)."""
    ability_id = uuid.uuid4()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO strike_abilities (id, slug, title, engine, version, active)
                VALUES (%s, %s, %s, %s, '1.0.0', %s);
                """,
                (str(ability_id), slug, title, engine, active),
            )
        conn.commit()
    return ability_id


def create_engagement(
    strike_client,
    analyst_headers,
    *,
    finding_id=None,
    asset_id=None,
    ttl: timedelta = timedelta(days=30),
    valid_until: datetime | None = None,
) -> dict:
    payload = engagement_payload(
        finding_id=finding_id, asset_id=asset_id,
        ttl=ttl, valid_until=valid_until,
    )
    r = strike_client.post("/api/strike/engagements", json=payload, headers=analyst_headers)
    assert r.status_code == 201, r.text
    return r.json()


def take_engagement_active(
    strike_client,
    analyst_headers,
    admin_headers,
    *,
    target_value: str = "10.0.0.60",
    target_ttl: timedelta = timedelta(days=7),
    asset_id=None,
    finding_id=None,
) -> dict:
    """drive one engagement: create → submit → approve → target → approve →
    activate. Returns {engagement_id, target_id}."""
    engagement = create_engagement(
        strike_client, analyst_headers, asset_id=asset_id, finding_id=finding_id
    )
    engagement_id = engagement["id"]
    r = strike_client.post(
        f"/api/strike/engagements/{engagement_id}/submit", headers=analyst_headers
    )
    assert r.status_code == 201, r.text
    r = strike_client.post(
        f"/api/strike/engagements/{engagement_id}/approve",
        json={}, headers=admin_headers,
    )
    assert r.status_code == 200, r.text

    now = datetime.now(timezone.utc)
    r = strike_client.post(
        f"/api/strike/engagements/{engagement_id}/targets",
        json={
            "target_type": "ip",
            "target_value": target_value,
            "normalized_target": target_value,
            "purpose": "controlled validation",
            "expires_at": iso(now + target_ttl),
        },
        headers=analyst_headers,
    )
    assert r.status_code == 201, r.text
    target_id = r.json()["target"]["id"]
    r = strike_client.post(
        f"/api/strike/targets/{target_id}/approve", json={}, headers=admin_headers
    )
    assert r.status_code == 200, r.text

    r = strike_client.post(
        f"/api/strike/engagements/{engagement_id}/activate", headers=analyst_headers
    )
    assert r.status_code == 200, r.text
    return {"engagement_id": engagement_id, "target_id": target_id}
