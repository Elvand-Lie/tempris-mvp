# backend/tests/test_p102_review_fixes.py
"""
P1-02 REVIEW-FIX REGRESSIONS — the six review findings.

Covers the boundary cases the first P1-02 suite did not:

1. Identity-less CVE continuation restarts at batch 0 (no offset, no
   inherited target cursor) — offset resume is allowed ONLY against the
   identical staged extraction.
2. Engine-level artifact-change isolation: a mid-run KEV/EPSS artifact
   change under a continuation cursor makes the engine roll back and FAIL
   the open shared snapshot and finish in a FRESH snapshot — no rows,
   metadata, or reconciliation inputs from artifact A survive.
3. NVD positional window pagination across a timestamp tie (records
   sharing one lastModified across a page boundary are never stranded).
4. The atomic-artifact round cap fails closed: rollback, failed snapshot,
   failure outcome — never a success with a partial artifact.
5. Shared ArchiveLimits defaults stay conservative (OSV untouched);
   only the CVE client carries the cvelistV5 preset.
6. Early shared-snapshot failures return the carried snapshot's
   identity/counts so the SYNC log line identifies the real snapshot.
"""
import io
import json
import logging
import zipfile

import httpx
import pytest

from app.db import get_db_connection
from app.vuln_intelligence import cve_staging
from app.vuln_intelligence import sync_engine as sync_engine_mod
from app.vuln_intelligence.models import ArchiveLimits
from app.vuln_intelligence.fetch_clients import (
    CveFetchClient,
    EpssFetchClient,
    KevFetchClient,
    NvdFetchClient,
    OsvFetchClient,
)
from app.vuln_intelligence.sync_adapters import (
    EpssSyncAdapter,
    KevSyncAdapter,
)
from app.vuln_intelligence.sync_engine import (
    FetchResult,
    _do_sync,
    _log_sync_snapshot,
    sync_source,
)
from app.vuln_intelligence.repository import (
    get_sync_snapshot,
    get_sync_state,
    update_sync_state,
)


def _capture_sync_lines(fn):
    """Run fn() capturing the sync engine's log records; returns
    (messages, fn_result)."""
    logger = logging.getLogger("app.vuln_intelligence.sync_engine")
    emitted: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda rec: emitted.append(rec.getMessage())
    logger.addHandler(handler)
    try:
        result = fn()
    finally:
        logger.removeHandler(handler)
    return emitted, result


def _reset_source(conn, source: str) -> None:
    """Give a source a clean bootstrap slate.

    FK order matters: vuln_source_records references sync_snapshots, and
    sync_state references both. Leftover intel rows from other suites would
    also corrupt the count assertions, so the source's rows go too.
    """
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE sync_state SET last_snapshot_id = NULL, "
            "last_good_snapshot_id = NULL, cursor_value = NULL "
            "WHERE source = %s",
            (source,),
        )
        # FK order: detail tables reference vuln_source_records, which
        # references sync_snapshots. Delete exactly the rows that block this
        # source's records (by FK column, not cve-id wildcard).
        cur.execute(
            "DELETE FROM kev_entries WHERE source_record_id IN "
            "(SELECT id FROM vuln_source_records WHERE source = %s)",
            (source,),
        )
        cur.execute(
            "DELETE FROM epss_scores WHERE source_record_id IN "
            "(SELECT id FROM vuln_source_records WHERE source = %s)",
            (source,),
        )
        cur.execute(
            "DELETE FROM vuln_source_records WHERE source = %s", (source,)
        )
        cur.execute("DELETE FROM sync_snapshots WHERE source = %s", (source,))
    conn.commit()


# ===========================================================================
# Finding 1 (P1): identity-less CVE continuation must restart at batch 0
# ===========================================================================

def _two_entry_zip() -> bytes:
    """Minimal cvelistV5-shaped zip with two CVE records."""
    rec1 = json.dumps({
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": "CVE-2026-900001", "state": "PUBLISHED"},
        "containers": {},
    }).encode()
    rec2 = json.dumps({
        "dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": "CVE-2026-900002", "state": "PUBLISHED"},
        "containers": {},
    }).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("cvelistV5-main/2026/0/CVE-2026-900001.json", rec1)
        zf.writestr("cvelistV5-main/2026/0/CVE-2026-900002.json", rec2)
    return buf.getvalue()


class TestIdentitylessCveContinuationRestarts:
    def test_legacy_cursor_without_identity_restarts_at_zero(self, tmp_path, monkeypatch):
        """A bootstrap continuation cursor with NO staging_identity downloads
        a fresh archive and serves batch 0 — the old entry_offset must never
        be applied to a different extraction (the review's reproduction)."""
        monkeypatch.setenv("TEMPRIS_VULN_STAGING_DIR", str(tmp_path / "stage"))
        zip_bytes = _two_entry_zip()
        client = httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, content=zip_bytes)
        ))
        fetcher = CveFetchClient(client=client)
        try:
            legacy_cursor = json.dumps({
                "phase": "bootstrap",
                "entry_offset": 2,
                "total_entries": 2,
                "target_sha": "old-target-2020",
            })
            res = fetcher.fetch(cursor=legacy_cursor, batch_size=2)

            assert res.error is None
            assert res.metadata.get("offset") == 0, res.metadata
            assert res.metadata.get("resumed") is False
            assert res.artifact_restarted is True
            # Two entries at batch 2: batch 0 exhausts the fresh extraction.
            assert res.is_exhausted is True
            assert [r["cveMetadata"]["cveId"] for r in res.records] == [
                "CVE-2026-900001", "CVE-2026-900002",
            ]
        finally:
            cve_staging.clear_staging()

    def test_invalid_identity_drops_inherited_target_cursor(self, tmp_path, monkeypatch):
        """An invalid staging identity restarts batch 0 AND drops the old
        target_sha — a fresh target is minted for the new extraction."""
        monkeypatch.setenv("TEMPRIS_VULN_STAGING_DIR", str(tmp_path / "stage"))
        zip_bytes = _two_entry_zip()
        client = httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, content=zip_bytes)
        ))
        fetcher = CveFetchClient(client=client)
        try:
            res1 = fetcher.fetch(cursor=None, batch_size=1)
            assert not res1.is_exhausted
            cont1 = json.loads(res1.cursor_after)
            assert cont1["staging_identity"]

            forged = json.dumps({
                "phase": "bootstrap",
                "entry_offset": 1,
                "target_sha": cont1["target_sha"],
                "staging_identity": "deadbeef-not-a-real-identity",
            })
            res2 = fetcher.fetch(cursor=forged, batch_size=1)
            assert res2.error is None
            assert res2.metadata.get("offset") == 0, res2.metadata
            assert res2.metadata.get("resumed") is False
            assert res2.artifact_restarted is True
            if not res2.is_exhausted:
                cont2 = json.loads(res2.cursor_after)
                # Fresh target + fresh identity — nothing inherited.
                assert cont2["target_sha"] != cont1["target_sha"]
                assert cont2["staging_identity"] != cont1["staging_identity"]
        finally:
            cve_staging.clear_staging()


# ===========================================================================
# Finding 2 (P1): engine-level artifact-change isolation (two-artifact e2e)
# ===========================================================================

class TestEngineArtifactRestartIsolation:
    def test_kev_mid_run_artifact_change_discards_shared_snapshot(self):
        """Round 1 applies artifact A inside the shared snapshot; round 2's
        fetch reports the artifact changed. The engine must roll back and
        FAIL the A-snapshot and finish in a FRESH snapshot: no rows from A
        survive, B's own date becomes the wire cursor, and reconciliation
        runs once against B's seen_ids only."""
        with get_db_connection() as conn:
            _reset_source(conn, "kev")

            class TwoCatalogClient:
                def __init__(self):
                    self.calls = 0

                def fetch(self, cursor=None, *, batch_size=1000, timeout_seconds=300):
                    self.calls += 1
                    if self.calls == 1:
                        # Artifact A: one entry, NOT exhausted (mid-drain).
                        return FetchResult(
                            records=[{"cveID": "CVE-2026-00001",
                                      "catalogVersion": "A",
                                      "dateAdded": "2026-09-19",
                                      "dateReleased": "2026-09-19T00:00:00Z",
                                      "description": "A",
                                      "knownRansomwareCampaignUse": "Unknown"}],
                            cursor_after=json.dumps({
                                "phase": "bootstrap", "entry_offset": 1,
                                "total_entries": 2, "catalog_hash": "hash-A",
                                "seen_ids": ["CVE-2026-00001"],
                                "target_cursor": "2026-09-19T00:00:00Z",
                            }),
                            is_bootstrap=True, is_exhausted=False,
                        )
                    # Artifact B under A's continuation cursor: RESTART.
                    return FetchResult(
                        records=[
                            {"cveID": "CVE-2026-00002", "catalogVersion": "B",
                             "dateAdded": "2026-09-20",
                             "dateReleased": "2026-09-20T00:00:00Z",
                             "description": "B2",
                             "knownRansomwareCampaignUse": "Unknown"},
                            {"cveID": "CVE-2026-00003", "catalogVersion": "B",
                             "dateAdded": "2026-09-20",
                             "dateReleased": "2026-09-20T00:00:00Z",
                             "description": "B3",
                             "knownRansomwareCampaignUse": "Unknown"},
                        ],
                        cursor_after="2026-09-20T00:00:00Z",
                        is_bootstrap=True, is_exhausted=True,
                        seen_ids=["CVE-2026-00002", "CVE-2026-00003"],
                        artifact_restarted=True,
                        metadata={"catalogVersion": "B",
                                  "dateReleased": "2026-09-20T00:00:00Z",
                                  "content_hash": "hash-B"},
                    )

            class TwoCatalogAdapter(KevSyncAdapter):
                def __init__(self):
                    super().__init__()
                    self.client = TwoCatalogClient()

                def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                    return self.client.fetch(
                        cursor=cursor, batch_size=batch_size,
                        timeout_seconds=timeout_seconds,
                    )

            outcome = sync_source(conn, TwoCatalogAdapter(), batch_size=1)

            assert outcome.success is True
            assert outcome.continuation_completed is True
            assert outcome.records_created == 2  # only artifact B's rows
            assert outcome.cursor_after == "2026-09-20T00:00:00Z"  # B's own date

            # P1-02 recheck (P2-1): TWO snapshots exist and BOTH get their
            # own SYNC log line — the failed artifact-A snapshot logged at
            # the restart boundary, artifact B's outcome logged at the end.
            # (Before the fix, only B's line was emitted.)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status, records_created, error_message "
                    "FROM sync_snapshots WHERE source = 'kev' ORDER BY created_at, id"
                )
                snaps = cur.fetchall()
            assert len(snaps) == 2
            by_status = {s["status"]: s for s in snaps}
            assert set(by_status) == {"failed", "completed"}
            snap_a = by_status["failed"]
            snap_b = by_status["completed"]
            assert "artifact" in (snap_a["error_message"] or "").lower()
            assert str(snap_b["id"]) == outcome.snapshot_id
            assert snap_b["records_created"] == 2

            # P1-02 recheck (P2-2, restart-boundary form): the operational
            # pointer ends at the COMPLETED snapshot B — the restart's
            # failure state update advanced it to A first, then B's success
            # advanced both pointers (never NULL in between on a clean run).
            state = get_sync_state(conn, "kev")
            assert state.cursor_value == "2026-09-20T00:00:00Z"
            assert str(state.last_snapshot_id) == outcome.snapshot_id

            # Zero rows from artifact A survive anywhere (KEV is enrichment:
            # rows carry declared_cve_id; cve_id is set only with a canonical
            # row, which no intel sync has created here).
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS n FROM kev_entries WHERE declared_cve_id = 'CVE-2026-00001'"
                )
                assert cur.fetchone()["n"] == 0
                cur.execute(
                    "SELECT count(*) AS n FROM kev_entries WHERE declared_cve_id = 'CVE-2026-00002'"
                )
                assert cur.fetchone()["n"] == 1

    def test_two_artifact_restart_emits_two_sync_lines(self):
        """P1-02 recheck (P2-1): a mid-run artifact change produces TWO
        snapshots and therefore TWO SYNC log lines — the failed artifact-A
        snapshot (logged at the restart boundary) and artifact B's final
        outcome (logged after sync_source returns). Exactly one line is a
        failure naming A's snapshot; the other names B's completed one."""
        with get_db_connection() as conn:
            _reset_source(conn, "kev")

            class TwoCatalogClient:
                def __init__(self):
                    self.calls = 0

                def fetch(self, cursor=None, *, batch_size=1000, timeout_seconds=300):
                    self.calls += 1
                    if self.calls == 1:
                        return FetchResult(
                            records=[{"cveID": "CVE-2026-11001",
                                      "catalogVersion": "A",
                                      "dateAdded": "2026-09-19",
                                      "dateReleased": "2026-09-19T00:00:00Z",
                                      "description": "A",
                                      "knownRansomwareCampaignUse": "Unknown"}],
                            cursor_after=json.dumps({
                                "phase": "bootstrap", "entry_offset": 1,
                                "total_entries": 2, "catalog_hash": "hash-A",
                                "seen_ids": ["CVE-2026-11001"],
                                "target_cursor": "2026-09-19T00:00:00Z",
                            }),
                            is_bootstrap=True, is_exhausted=False,
                        )
                    return FetchResult(
                        records=[{"cveID": "CVE-2026-11002", "catalogVersion": "B",
                                  "dateAdded": "2026-09-20",
                                  "dateReleased": "2026-09-20T00:00:00Z",
                                  "description": "B",
                                  "knownRansomwareCampaignUse": "Unknown"}],
                        cursor_after="2026-09-20T00:00:00Z",
                        is_bootstrap=True, is_exhausted=True,
                        seen_ids=["CVE-2026-11002"],
                        artifact_restarted=True,
                        metadata={"catalogVersion": "B",
                                  "dateReleased": "2026-09-20T00:00:00Z",
                                  "content_hash": "hash-B"},
                    )

            class TwoCatalogAdapter(KevSyncAdapter):
                def __init__(self):
                    super().__init__()
                    self.client = TwoCatalogClient()

                def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                    return self.client.fetch(
                        cursor=cursor, batch_size=batch_size,
                        timeout_seconds=timeout_seconds,
                    )

            emitted, outcome = _capture_sync_lines(
                lambda: sync_source(conn, TwoCatalogAdapter(), batch_size=1)
            )
            assert outcome.success is True

            sync_lines = [m for m in emitted if m.startswith("SYNC ")]
            assert len(sync_lines) == 2, sync_lines

            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status FROM sync_snapshots WHERE source = 'kev' "
                    "ORDER BY created_at, id"
                )
                snaps = cur.fetchall()
            assert len(snaps) == 2
            failed_id = str(next(s["id"] for s in snaps if s["status"] == "failed"))
            completed_id = str(
                next(s["id"] for s in snaps if s["status"] == "completed")
            )
            assert completed_id == outcome.snapshot_id

            failures = [ln for ln in sync_lines if "success=False" in ln]
            successes = [ln for ln in sync_lines if "success=True" in ln]
            assert len(failures) == 1 and len(successes) == 1
            assert failed_id in failures[0]
            assert completed_id in successes[0]

    def test_restart_then_invalid_B_preserves_retired_pointer(self):
        """P1-02 recheck round 2: after an in-round artifact restart, a
        validation failure on artifact B's FIRST batch must still name the
        retired artifact-A snapshot — in the returned outcome AND in
        sync_state.last_snapshot_id (previously both were None and the
        pointer regressed to NULL)."""
        with get_db_connection() as conn:
            _reset_source(conn, "kev")

            class RestartThenInvalidClient:
                def __init__(self):
                    self.calls = 0

                def fetch(self, cursor=None, *, batch_size=1000, timeout_seconds=300):
                    self.calls += 1
                    if self.calls == 1:
                        return FetchResult(
                            records=[{"cveID": "CVE-2026-12001",
                                      "catalogVersion": "A",
                                      "dateAdded": "2026-09-19",
                                      "dateReleased": "2026-09-19T00:00:00Z",
                                      "description": "A",
                                      "knownRansomwareCampaignUse": "Unknown"}],
                            cursor_after=json.dumps({
                                "phase": "bootstrap", "entry_offset": 1,
                                "total_entries": 2, "catalog_hash": "hash-A",
                                "seen_ids": ["CVE-2026-12001"],
                                "target_cursor": "2026-09-19T00:00:00Z",
                            }),
                            is_bootstrap=True, is_exhausted=False,
                        )
                    # Artifact B arrives under A's cursor (restart signal)
                    # but its batch is INVALID — the review's exact edge.
                    return FetchResult(
                        records=[{"cveID": "not-a-cve",
                                  "catalogVersion": "B"}],
                        cursor_after="2026-09-20T00:00:00Z",
                        is_bootstrap=True, is_exhausted=True,
                        artifact_restarted=True,
                    )

            class RestartThenInvalidAdapter(KevSyncAdapter):
                def __init__(self):
                    super().__init__()
                    self.client = RestartThenInvalidClient()

                def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                    return self.client.fetch(
                        cursor=cursor, batch_size=batch_size,
                        timeout_seconds=timeout_seconds,
                    )

            outcome = sync_source(
                conn, RestartThenInvalidAdapter(), batch_size=1,
            )

            assert outcome.success is False
            assert outcome.snapshot_id, "outcome must name the retired A snapshot"

            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, status, error_message FROM sync_snapshots "
                    "WHERE source = 'kev'"
                )
                snaps = cur.fetchall()
            # Exactly ONE snapshot exists — A's, failed at the restart
            # boundary with the restart reason (NOT re-completed with the
            # validation error, and no phantom completed snapshot).
            assert len(snaps) == 1
            snap_a = snaps[0]
            assert snap_a["status"] == "failed"
            assert "artifact" in (snap_a["error_message"] or "").lower()
            assert str(snap_a["id"]) == outcome.snapshot_id

            # The operational pointer STILL names A's failed snapshot.
            state = get_sync_state(conn, "kev")
            assert state.cursor_value is None  # cursor untouched
            assert str(state.last_snapshot_id) == outcome.snapshot_id
            conn.rollback()

    def test_epss_mid_run_artifact_change_never_inherits_label(self):
        """An EPSS drain whose served file changes mid-run must not write any
        row under artifact A's score_date: the restart lands in a fresh
        snapshot and the wire cursor is B's own date."""
        with get_db_connection() as conn:
            _reset_source(conn, "epss")

            class TwoFileClient:
                def __init__(self):
                    self.calls = 0

                def fetch(self, cursor=None, *, batch_size=1000, timeout_seconds=300):
                    self.calls += 1
                    if self.calls == 1:
                        return FetchResult(
                            records=[{"raw_line": "CVE-2026-700001,0.5,50",
                                      "model_version": "v3",
                                      "score_date": "2026-09-19"}],
                            cursor_after=json.dumps({
                                "phase": "bootstrap", "line_offset": 1,
                                "total_lines": 2, "score_date": "2026-09-19",
                                "file_hash": "hash-19",
                                "target_cursor": "2026-09-19",
                            }),
                            is_bootstrap=True, is_exhausted=False,
                        )
                    return FetchResult(
                        records=[{"raw_line": "CVE-2026-700002,0.6,60",
                                  "model_version": "v3",
                                  "score_date": "2026-09-20"}],
                        cursor_after="2026-09-20",
                        is_bootstrap=True, is_exhausted=True,
                        artifact_restarted=True,
                        metadata={"score_date": "2026-09-20", "model_version": "v3"},
                    )

            class TwoFileAdapter(EpssSyncAdapter):
                def __init__(self):
                    super().__init__()
                    self.client = TwoFileClient()

                def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                    return self.client.fetch(
                        cursor=cursor, batch_size=batch_size,
                        timeout_seconds=timeout_seconds,
                    )

            outcome = sync_source(conn, TwoFileAdapter(), batch_size=1)

            assert outcome.success is True
            assert outcome.continuation_completed is True
            assert outcome.records_created == 1
            assert outcome.cursor_after == "2026-09-20"

            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS n FROM epss_scores WHERE score_date = '2026-09-19'"
                )
                assert cur.fetchone()["n"] == 0  # artifact A fully discarded
                cur.execute(
                    "SELECT count(*) AS n FROM epss_scores WHERE score_date = '2026-09-20'"
                )
                assert cur.fetchone()["n"] == 1


# ===========================================================================
# Finding 3 (P1): NVD timestamp-tie pagination
# ===========================================================================

class TestNvdTimestampTiePagination:
    def test_records_sharing_lastmodified_across_page_boundary_are_not_stranded(self):
        """Three records sharing one lastModified with the page boundary
        between them: page 2 must return the tied record — the window is
        positional, not a timestamp jump (the review's livelock repro)."""
        recs = [
            {"cve": {"id": "CVE-2026-300001", "lastModified": "2026-09-19T10:00:00.000"}},
            {"cve": {"id": "CVE-2026-300002", "lastModified": "2026-09-19T10:00:00.000"}},
            {"cve": {"id": "CVE-2026-300003", "lastModified": "2026-09-19T10:00:00.000"}},
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            idx = int(request.url.params.get("startIndex", "0"))
            page = recs[idx: idx + 2]
            return httpx.Response(200, json={
                "totalResults": 3,
                "resultsPerPage": 2,
                "startIndex": idx,
                "timestamp": "2026-09-19T11:00:00.000",
                "vulnerabilities": page,
            })

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = NvdFetchClient(client=client)

        res1 = fetcher.fetch(cursor="2026-09-19T09:00:00.000", batch_size=2)
        assert res1.is_exhausted is False
        cont = json.loads(res1.cursor_after)
        assert cont["nvd_window"] is True
        assert cont["startIndex"] == 2

        res2 = fetcher.fetch(cursor=res1.cursor_after, batch_size=2)
        assert res2.is_exhausted is True
        assert [r["cve"]["id"] for r in res2.records] == ["CVE-2026-300003"]
        # The promoted clean cursor is the WINDOW END — records modified
        # after the window remain due; nothing is skipped to now().
        assert res2.cursor_after == cont["window_end"]

    def test_zero_width_window_skips_upstream_call(self):
        """A same-second completed window yields an empty, exhausted result
        without an upstream request (no livelock, no wasted call)."""
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = NvdFetchClient(client=client)
        cursor = json.dumps({
            "nvd_window": True,
            "window_start": "2026-09-19T10:00:00.000",
            "window_end": "2026-09-19T10:00:00.000",
            "startIndex": 0,
        })
        res = fetcher.fetch(cursor=cursor, batch_size=2)
        assert calls["n"] == 0
        assert res.is_exhausted is True
        assert res.records == []


# ===========================================================================
# Finding 4 (P1): atomic round cap fails closed
# ===========================================================================

class TestAtomicRoundCapFailsClosed:
    def test_cap_exhaustion_rolls_back_and_fails_snapshot(self, monkeypatch):
        """An artifact that never exhausts hits the round cap: the run must
        return FAILURE, roll the partial artifact back (cursor untouched),
        and leave the shared snapshot failed — a caller's commit cannot
        persist a partial artifact."""
        monkeypatch.setattr(sync_engine_mod, "ATOMIC_ARTIFACT_MAX_ROUNDS", 2)

        def never_exhausted(conn, cursor, *, batch_size=1000, timeout_seconds=300):
            return FetchResult(
                records=[{"cveID": "CVE-2026-500001", "catalogVersion": "X",
                          "dateAdded": "2026-09-19",
                          "dateReleased": "2026-09-19T00:00:00Z",
                          "description": "cap",
                          "knownRansomwareCampaignUse": "Unknown"}],
                cursor_after=json.dumps({
                    "phase": "bootstrap", "entry_offset": batch_size,
                    "total_entries": 10_000_000, "catalog_hash": "h",
                    "seen_ids": [], "target_cursor": "2026-09-19T00:00:00Z",
                }),
                is_bootstrap=True,
                is_exhausted=False,  # never exhausts -> the cap must fire
            )

        with get_db_connection() as conn:
            _reset_source(conn, "kev")

            class CapAdapter(KevSyncAdapter):
                def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                    return never_exhausted(
                        conn, cursor, batch_size=batch_size,
                        timeout_seconds=timeout_seconds,
                    )

            outcome = sync_source(conn, CapAdapter(), batch_size=1)

            assert outcome.success is False
            assert outcome.continuation_completed is False
            assert "round cap" in (outcome.error or "").lower()
            assert outcome.snapshot_id  # the log line can identify it

            snap = get_sync_snapshot(conn, outcome.snapshot_id)
            assert snap.status == "failed"

            # Cursor untouched; nothing from the partial artifact persisted
            # (a caller committing after this run cannot resurrect it).
            state = get_sync_state(conn, "kev")
            assert state.cursor_value is None
            # P1-02 recheck (P2-2): the operational pointer ADVANCES to the
            # failed attempt — it must not regress to NULL while the ledger
            # row and the outcome both name a real failed snapshot.
            assert str(state.last_snapshot_id) == outcome.snapshot_id
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) AS n FROM kev_entries WHERE declared_cve_id = 'CVE-2026-500001'"
                )
                assert cur.fetchone()["n"] == 0
            conn.rollback()


# ===========================================================================
# Finding 5 (P2): conservative shared defaults; CVE-only preset
# ===========================================================================

class TestSharedLimitsStayConservative:
    def test_shared_defaults_are_the_pre_p102_bounds(self):
        limits = ArchiveLimits()
        assert limits.max_compressed_bytes == 500 * 1024 * 1024
        assert limits.max_expanded_bytes == 2 * 1024 * 1024 * 1024
        assert limits.max_file_count == 500_000
        assert limits.extraction_timeout_seconds == 300.0

    def test_only_cve_client_carries_the_preset(self):
        from app.vuln_intelligence.models import CVE_ARCHIVE_LIMITS
        assert CveFetchClient(client=httpx.Client()).archive_limits is CVE_ARCHIVE_LIMITS
        assert CVE_ARCHIVE_LIMITS.max_expanded_bytes >= 5 * 1024 * 1024 * 1024
        # Out-of-scope archive consumers keep the shared conservative
        # bounds (KEV downloads plain JSON — no archive stage at all).
        assert OsvFetchClient().archive_limits == ArchiveLimits()
        assert EpssFetchClient().archive_limits == ArchiveLimits()
        assert not hasattr(KevFetchClient(), "archive_limits")


# ===========================================================================
# Finding 6 (P2): failure outcomes carry the failed snapshot's identity
# ===========================================================================

class TestFailureOutcomeCarriesSnapshotIdentity:
    def test_fetch_failure_on_shared_snapshot_carries_identity_and_counts(self):
        """Round 2 of an atomic drain fails at fetch: the returned failure
        outcome must name the carried snapshot, its mode, and the accumulated
        counts — so the SYNC log line identifies the real failed snapshot."""
        with get_db_connection() as conn:
            _reset_source(conn, "kev")

            class FailRound2Adapter(KevSyncAdapter):
                def __init__(self):
                    super().__init__()
                    self.calls = 0

                def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                    self.calls += 1
                    if self.calls == 1:
                        return FetchResult(
                            records=[{"cveID": "CVE-2026-600001",
                                      "catalogVersion": "A",
                                      "dateAdded": "2026-09-19",
                                      "dateReleased": "2026-09-19T00:00:00Z",
                                      "description": "f6",
                                      "knownRansomwareCampaignUse": "Unknown"}],
                            cursor_after=json.dumps({
                                "phase": "bootstrap", "entry_offset": 1,
                                "total_entries": 5, "catalog_hash": "h",
                                "seen_ids": ["CVE-2026-600001"],
                                "target_cursor": "t",
                            }),
                            is_bootstrap=True, is_exhausted=False,
                        )
                    raise RuntimeError("upstream outage mid-artifact")

            # Drive the two rounds directly through _do_sync (the engine's
            # shared-snapshot contract), exactly as sync_source would — one
            # adapter instance across both rounds.
            adapter = FailRound2Adapter()
            outcome1 = _do_sync(
                conn, adapter, batch_size=1, timeout_seconds=300,
                start_ms=0,
            )
            assert outcome1.success and not outcome1.continuation_completed
            snap1_id = outcome1.snapshot_id
            assert outcome1.records_processed == 1

            outcome2 = _do_sync(
                conn, adapter, batch_size=1, timeout_seconds=300,
                start_ms=0, _outcome_override=outcome1,
            )
            assert outcome2.success is False
            assert outcome2.snapshot_id == snap1_id
            assert outcome2.sync_mode == "bootstrap"
            assert outcome2.records_processed == 1
            assert "upstream outage" in (outcome2.error or "")

            snap = get_sync_snapshot(conn, snap1_id)
            assert snap.status == "failed"

            # The emitted log line must identify the real failed snapshot.
            logger = logging.getLogger("app.vuln_intelligence.sync_engine")
            emitted: list[str] = []
            handler = logging.Handler()
            handler.emit = lambda rec: emitted.append(rec.getMessage())
            logger.addHandler(handler)
            try:
                _log_sync_snapshot(outcome2)
            finally:
                logger.removeHandler(handler)
            assert emitted, "expected a SYNC log line"
            assert snap1_id in emitted[0]
            assert "processed=1" in emitted[0]


# ===========================================================================
# Finding 7 (P2 recheck): inline CVE pagination is ONE exhausted batch
# ===========================================================================

class TestInlineCveSingleBatch:
    def test_inline_json_list_is_one_exhausted_batch(self, tmp_path, monkeypatch):
        """The tiny-inline branch (non-zip, body already in memory) serves
        the WHOLE list as ONE exhausted batch. It must never emit a
        multi-batch continuation: such cursors carry no staging identity, so
        the identity gate restarts them at zero forever (the review's repro:
        batch_size=1 over a 3-record list returned the same record on every
        page with offset 0)."""
        monkeypatch.setenv("TEMPRIS_VULN_STAGING_DIR", str(tmp_path / "stage"))
        recs = [
            {
                "dataType": "CVE_RECORD", "dataVersion": "5.1",
                "cveMetadata": {
                    "cveId": f"CVE-2026-80000{i}", "state": "PUBLISHED",
                },
                "containers": {},
            }
            for i in range(3)
        ]
        client = httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=recs)
        ))
        # A non-.zip base_url (and a JSON content-type) routes the response
        # to the tiny-inline branch instead of the staged zip path.
        fetcher = CveFetchClient(
            client=client, base_url="https://cve.example.test/records.json",
        )

        res = fetcher.fetch(cursor=None, batch_size=1)
        assert res.error is None
        assert res.is_exhausted is True  # ONE batch — no second round
        assert [r["cveMetadata"]["cveId"] for r in res.records] == [
            "CVE-2026-800000", "CVE-2026-800001", "CVE-2026-800002",
        ]
        # A clean completion cursor, NOT a bootstrap continuation — there is
        # no resumable offset an identity gate could reject.
        assert res.cursor_after
        assert not res.cursor_after.startswith("{")


# ===========================================================================
# Finding 8 (P2 recheck): NVD window cursors fail closed on any schema
# defect — malformed own-schema AND foreign structured cursors
# ===========================================================================

class TestNvdWindowCursorSchemaValidation:
    @pytest.mark.parametrize("bad_cursor", [
        # The review's exact repro: truthy nvd_window, no bounds — used to
        # send an UNFILTERED request and traverse the full catalog.
        '{"nvd_window": true, "startIndex": 10}',
        '{"nvd_window": true}',
        # Marker present but not boolean True (recheck round 2).
        json.dumps({"nvd_window": "yes",
                    "window_start": "2026-09-19T10:00:00.000",
                    "window_end": "2026-09-19T11:00:00.000", "startIndex": 0}),
        # Bounds present but NOT timestamps (recheck round 2) — garbage was
        # previously forwarded upstream as lastModStart/End filter params.
        json.dumps({"nvd_window": True,
                    "window_start": "garbage",
                    "window_end": "still-garbage", "startIndex": 0}),
        json.dumps({"nvd_window": True,
                    "window_start": "2026-09-19T10:00:00.000",
                    "window_end": "garbage", "startIndex": 0}),
        # Whitespace-only bounds must not pass the strip-and-parse gate.
        json.dumps({"nvd_window": True,
                    "window_start": "   ",
                    "window_end": "2026-09-19T11:00:00.000", "startIndex": 0}),
        json.dumps({"nvd_window": True,
                    "window_end": "2026-09-19T11:00:00.000", "startIndex": 0}),
        json.dumps({"nvd_window": True,
                    "window_start": "2026-09-19T10:00:00.000", "startIndex": 0}),
        json.dumps({"nvd_window": True,
                    "window_start": "2026-09-19T10:00:00.000",
                    "window_end": "2026-09-19T11:00:00.000", "startIndex": -1}),
        json.dumps({"nvd_window": True,
                    "window_start": "2026-09-19T10:00:00.000",
                    "window_end": "2026-09-19T11:00:00.000", "startIndex": "5"}),
        # bool is an int subclass in Python — must still be rejected.
        json.dumps({"nvd_window": True,
                    "window_start": "2026-09-19T10:00:00.000",
                    "window_end": "2026-09-19T11:00:00.000", "startIndex": True}),
    ])
    def test_malformed_window_cursor_fails_closed_without_a_request(
        self, bad_cursor,
    ):
        """A window cursor missing/malforming ANY schema field must fail
        closed with the invalid-cursor error BEFORE an upstream request —
        never send an unconstrained request."""
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json={
                "totalResults": 1, "vulnerabilities": [],
            })

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = NvdFetchClient(client=client)

        res = fetcher.fetch(cursor=bad_cursor, batch_size=2)
        assert res.error is not None
        assert "cursor" in res.error.lower()
        assert res.records == []
        assert calls["n"] == 0, "no upstream request may leave the client"
        # Nothing was promoted — no fabricated clean cursor.
        assert res.cursor_after is None

    def test_foreign_structured_cursor_still_fails_closed(self):
        """A structured cursor that is neither a window nor a bootstrap
        continuation is foreign (legacy/rolled-back writer): fail closed
        with a visible error, never interpret it as a timestamp."""
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json={
                "totalResults": 1, "vulnerabilities": [],
            })

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = NvdFetchClient(client=client)

        res = fetcher.fetch(
            cursor=json.dumps({"legacy": "pre-p102-writer"}), batch_size=2,
        )
        assert res.error is not None
        assert "Unrecognized NVD cursor format" in res.error
        assert calls["n"] == 0
        assert res.cursor_after is None
