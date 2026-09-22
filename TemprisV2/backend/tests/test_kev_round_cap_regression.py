# backend/tests/test_kev_round_cap_regression.py
"""
KEV atomic-artifact round-cap regressions (prd-finish/kev-round-cap).

Prod symptom: every KEV sync died with "Atomic-artifact drain hit the
internal round cap (1000)" — the P1-02 hash-guard rewrite dropped the
continuation resume in KevFetchClient.fetch, so every internal round
re-read batch 0 and the ~2k-entry artifact could never exhaust.

1. A small atomic artifact must complete in a handful of rounds through
   the REAL KevFetchClient (batch < artifact size forces continuations),
   committing exactly one completed snapshot and advancing the cursor.
2. A continuation that cannot advance (the stuck-offset mechanism) must
   still fail closed at a SMALL monkeypatched cap — cursor unchanged,
   snapshot failed, nothing persisted — never burning the production cap.
"""
import json

import httpx
import pytest

from app.db import get_db_connection
from app.vuln_intelligence import sync_engine as sync_engine_mod
from app.vuln_intelligence.fetch_clients import KevFetchClient
from app.vuln_intelligence.sync_adapters import KevSyncAdapter
from app.vuln_intelligence.sync_engine import sync_source
from app.vuln_intelligence.repository import (
    get_sync_snapshot,
    get_sync_state,
)

DATE_RELEASED = "2026-09-01T08:00:00.000Z"


def _kev_catalog(n: int) -> dict:
    return {
        "title": "CISA KEV",
        "catalogVersion": "2026.09.01",
        "dateReleased": DATE_RELEASED,
        "count": n,
        "vulnerabilities": [
            {
                "cveID": f"CVE-2026-{2000 + i}",
                "vendorProject": "V",
                "product": "P",
                "vulnerabilityName": f"Vuln {i}",
                "dateAdded": "2026-08-15",
                "shortDescription": "d",
                "requiredAction": "a",
                "dueDate": "2026-09-15",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
            }
            for i in range(n)
        ],
    }


class TestKevRoundCapRegression:
    @pytest.fixture(autouse=True)
    def clean_kev(self):
        with get_db_connection() as conn:
            self._reset(conn)
        yield
        with get_db_connection() as conn:
            self._reset(conn)

    @staticmethod
    def _reset(conn) -> None:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE sync_state SET last_snapshot_id = NULL, "
                "last_good_snapshot_id = NULL, cursor_value = NULL "
                "WHERE source = 'kev'"
            )
            cur.execute(
                "DELETE FROM kev_entries WHERE source_record_id IN "
                "(SELECT id FROM vuln_source_records WHERE source = 'kev')"
            )
            cur.execute("DELETE FROM vuln_source_records WHERE source = 'kev'")
            cur.execute("DELETE FROM sync_snapshots WHERE source = 'kev'")
        conn.commit()

    @staticmethod
    def _adapter(payload: bytes) -> KevSyncAdapter:
        return KevSyncAdapter(
            fetch_client=KevFetchClient(
                client=httpx.Client(transport=httpx.MockTransport(
                    lambda req: httpx.Response(200, content=payload)
                ))
            )
        )

    def test_small_artifact_completes_in_a_handful_of_rounds(self):
        """5-entry KEV artifact at batch_size=2 → 3 internal rounds, ONE
        completed snapshot, cursor advanced to dateReleased."""
        payload = json.dumps(_kev_catalog(5)).encode()
        with get_db_connection() as conn:
            outcome = sync_source(conn, self._adapter(payload), batch_size=2)

        assert outcome.success is True
        assert outcome.continuation_completed is True
        assert outcome.internal_rounds == 3, "5 entries at batch 2 = 3 rounds"
        assert outcome.records_processed == 5
        assert outcome.cursor_after == DATE_RELEASED

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM kev_entries")
                assert cur.fetchone()["n"] == 5
                cur.execute(
                    "SELECT status, count(*) AS n FROM sync_snapshots "
                    "WHERE source = 'kev' GROUP BY status"
                )
                ledger = {r["status"]: r["n"] for r in cur.fetchall()}
                assert ledger == {"completed": 1}, \
                    "the artifact is ONE shared snapshot"
            state = get_sync_state(conn, "kev")
            assert state.cursor_value == DATE_RELEASED
            assert str(state.last_good_snapshot_id) == outcome.snapshot_id

    def test_stuck_offset_continuation_fails_closed_at_small_cap(self, monkeypatch):
        """The defect mechanism: a fetch that ignores the continuation cursor
        re-reads batch 0 forever. The engine must stop at a SMALL cap and
        fail closed — cursor unchanged, snapshot failed, nothing persisted —
        instead of burning the production cap."""
        monkeypatch.setattr(sync_engine_mod, "ATOMIC_ARTIFACT_MAX_ROUNDS", 5)

        payload = json.dumps(_kev_catalog(50)).encode()
        real_client = KevFetchClient(
            client=httpx.Client(transport=httpx.MockTransport(
                lambda req: httpx.Response(200, content=payload)
            ))
        )

        class StuckOffsetClient:
            # The pre-fix behavior: the continuation cursor is dropped and
            # every round re-fetches batch 0.
            def fetch(self, cursor=None, *, batch_size=1000, timeout_seconds=300):
                return real_client.fetch(
                    cursor=None,
                    batch_size=batch_size,
                    timeout_seconds=timeout_seconds,
                )

        class StuckOffsetAdapter(KevSyncAdapter):
            def __init__(self):
                super().__init__(fetch_client=StuckOffsetClient())

        with get_db_connection() as conn:
            outcome = sync_source(conn, StuckOffsetAdapter(), batch_size=5)

        assert outcome.success is False
        assert outcome.continuation_completed is False
        assert "round cap" in (outcome.error or "").lower()
        assert outcome.internal_rounds == 5, "stopped at the small cap"

        with get_db_connection() as conn:
            snap = get_sync_snapshot(conn, outcome.snapshot_id)
            assert snap.status == "failed"
            state = get_sync_state(conn, "kev")
            assert state.cursor_value is None, "cursor unchanged (fail closed)"
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM kev_entries")
                assert cur.fetchone()["n"] == 0, "no partial artifact persisted"
