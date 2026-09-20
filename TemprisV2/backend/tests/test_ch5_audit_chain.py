# backend/tests/test_ch5_audit_chain.py
"""
Chapter 5 platform hardening — audit hash-chain integrity + the sync-engine
audit-silence fix (PRD-000 Ch.5 Target architecture item 4; migration 024).

Covers:
  * appends chain per tenant: genesis prev_hash '0', each entry chaining off
    the previous entry_hash under the hmac:<key_id>: scheme
  * GET /api/audit/verify reports the caller tenant's chain intact
  * tamper detection: detail mutation, row deletion, raw unchained insert
  * verification is tenant-scoped and requires authentication
  * the vuln-sync engine writes one audit event per run under `system:sync`
"""
import uuid

import pytest
from starlette.testclient import TestClient

from app.audit import record_audit_event, GENESIS_PREV_HASH
from app.auth import create_test_token
from app.config import PLATFORM_TENANT_ID
from app.db import get_db_connection
from app.vuln_intelligence.sync_engine import FetchResult, sync_source
from tests.conftest import TENANT_A, TENANT_B


def _headers(tenant_id=TENANT_A, actor_id="admin-a", role="admin"):
    token = create_test_token(str(tenant_id), actor_id=actor_id, role=role)
    return {"Authorization": f"Bearer {token}"}


def _record(conn, event_name: str, tenant_id=TENANT_A) -> uuid.UUID:
    return record_audit_event(
        conn=conn,
        tenant_id=tenant_id,
        actor_id="ch5-audit-test",
        actor_role="admin",
        event_name=event_name,
        details={"n": event_name},
    )


def _verify(client: TestClient, headers) -> dict:
    resp = client.get("/api/audit/verify", headers=headers)
    assert resp.status_code == 200
    return resp.json()


def test_appends_chain_per_tenant_and_verify_reports_intact(client: TestClient):
    with get_db_connection() as conn:
        for name in ("evt.one", "evt.two", "evt.three"):
            _record(conn, name)
        conn.commit()

    result = _verify(client, _headers())
    assert result["intact"] is True
    assert result["status"] == "verified"
    assert result["records"] >= 3
    assert result["mismatches"] == 0
    assert result["first_break_at_index"] is None
    assert result["latest_hash"]

    # Linkage shape: genesis anchor, hmac scheme, prev chaining (chain_seq
    # order — the append-order walk used by the verifier).
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT prev_hash, entry_hash, hmac_key_id FROM audit_events
                WHERE tenant_id = %s ORDER BY chain_seq NULLS LAST, created_at, id;
                """,
                (str(TENANT_A),)
            )
            rows = cur.fetchall()
    assert rows[0]["prev_hash"] == GENESIS_PREV_HASH
    assert rows[0]["entry_hash"].startswith("hmac:") and rows[0]["hmac_key_id"]
    for prev_row, row in zip(rows, rows[1:]):
        assert row["prev_hash"] == prev_row["entry_hash"]


def test_detail_tampering_is_detected(client: TestClient):
    with get_db_connection() as conn:
        _record(conn, "evt.tamper.a")
        _record(conn, "evt.tamper.b")
        conn.commit()

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE audit_events SET details = '{"n": "forged"}'::jsonb
                WHERE tenant_id = %s AND event_name = 'evt.tamper.a';
                """,
                (str(TENANT_A),)
            )
            assert cur.rowcount == 1
        conn.commit()

    result = _verify(client, _headers())
    assert result["intact"] is False
    assert result["status"] == "TAMPERED"
    assert result["mismatches"] >= 1
    assert result["first_break_at_index"] == 0


def test_row_deletion_is_detected(client: TestClient):
    with get_db_connection() as conn:
        _record(conn, "evt.del.a")
        _record(conn, "evt.del.b")
        _record(conn, "evt.del.c")
        conn.commit()

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM audit_events WHERE tenant_id = %s AND event_name = 'evt.del.b';",
                (str(TENANT_A),)
            )
            assert cur.rowcount == 1
        conn.commit()

    result = _verify(client, _headers())
    # The survivor 'evt.del.c' still points at the deleted row's entry_hash.
    assert result["intact"] is False
    assert result["status"] == "TAMPERED"
    assert result["first_break_at_index"] == 1


def test_raw_unchained_insert_is_detected(client: TestClient):
    """A row inserted straight into the table (bypassing the writer) has no
    chain columns — verification fails closed on it."""
    with get_db_connection() as conn:
        _record(conn, "evt.raw.a")
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_events (id, tenant_id, actor_id, actor_role, event_name, details)
                VALUES (gen_random_uuid(), %s, 'bypass', 'system', 'evt.raw.b', '{}'::jsonb);
                """,
                (str(TENANT_A),)
            )
        conn.commit()

    result = _verify(client, _headers())
    assert result["intact"] is False
    assert result["status"] == "TAMPERED"
    assert result["first_break_at_index"] == 1


def test_verify_is_tenant_scoped(client: TestClient):
    with get_db_connection() as conn:
        _record(conn, "evt.tenant-a", tenant_id=TENANT_A)
        _record(conn, "evt.tenant-b", tenant_id=TENANT_B)
        conn.commit()

    result_a = _verify(client, _headers(TENANT_A))
    assert result_a["intact"] is True
    assert result_a["records"] == 1

    result_b = _verify(client, _headers(TENANT_B, actor_id="admin-b"))
    assert result_b["intact"] is True
    assert result_b["records"] == 1


def test_verify_requires_authentication(client: TestClient):
    assert client.get("/api/audit/verify").status_code == 401


# ---------------------------------------------------------------------------
# Sync-engine audit silence (PRD Ch.5 item 4: background engines write events
# under a service actor — starting with system:sync)
# ---------------------------------------------------------------------------

class _MockAdapter:
    """Minimal SourceAdapter: injectable fetch result (test_sync_engine shape)."""

    source_name = "kev"

    def __init__(self, fetch_result):
        self._fetch_result = fetch_result

    def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
        return self._fetch_result

    def validate_batch(self, records):
        return True, None

    def process_record(self, conn, record, snapshot_id):
        return True, True, None


@pytest.fixture
def clean_sync_audit_tables():
    """Scope cleanup to exactly the snapshot this test created — other
    suites leave real kev snapshots whose vuln_source_records rows must
    stay untouched."""
    box: dict = {}
    yield box
    snapshot_id = box.get("snapshot_id")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            if snapshot_id:
                # sync_state.last_snapshot_id FK-references sync_snapshots:
                # clear pointers, then the rows, scoped to this test's snapshot.
                cur.execute(
                    """
                    UPDATE sync_state SET cursor_value = NULL, last_snapshot_id = NULL,
                           last_good_snapshot_id = NULL, active_record_count = 0
                    WHERE source = 'kev'
                      AND (last_snapshot_id = %s OR last_good_snapshot_id = %s);
                    """,
                    (snapshot_id, snapshot_id)
                )
                cur.execute("DELETE FROM vuln_source_records WHERE snapshot_id = %s;", (snapshot_id,))
                cur.execute("DELETE FROM sync_snapshots WHERE id = %s;", (snapshot_id,))
        conn.commit()


def test_sync_engine_writes_system_sync_audit_event(clean_sync_audit_tables):
    with get_db_connection() as conn:
        outcome = sync_source(conn, _MockAdapter(FetchResult(records=[], cursor_after="2026")))
        assert outcome.success is True
        clean_sync_audit_tables["snapshot_id"] = outcome.snapshot_id
        conn.commit()

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT actor_id, actor_role, event_name, details
                FROM audit_events
                WHERE tenant_id = %s AND details->>'source' = 'kev'
                  AND event_name = 'vuln.sync.completed'
                ORDER BY created_at DESC LIMIT 1;
                """,
                (str(PLATFORM_TENANT_ID),)
            )
            row = cur.fetchone()
    assert row is not None
    assert row["actor_id"] == "system:sync"
    assert row["actor_role"] == "system"
    assert row["event_name"] == "vuln.sync.completed"
    assert row["details"]["records_processed"] == 0


def test_sync_engine_audits_failed_runs(clean_sync_audit_tables):
    with get_db_connection() as conn:
        outcome = sync_source(conn, _MockAdapter(FetchResult(error="source outage")))
        assert outcome.success is False
        if outcome.snapshot_id:
            clean_sync_audit_tables["snapshot_id"] = outcome.snapshot_id

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT event_name, details FROM audit_events
                WHERE tenant_id = %s AND actor_id = 'system:sync'
                  AND event_name = 'vuln.sync.failed'
                ORDER BY created_at DESC LIMIT 1;
                """,
                (str(PLATFORM_TENANT_ID),)
            )
            row = cur.fetchone()
    assert row is not None
    assert "source outage" in row["details"]["error"]
