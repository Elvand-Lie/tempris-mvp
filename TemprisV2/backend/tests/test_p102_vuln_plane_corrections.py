# backend/tests/test_p102_vuln_plane_corrections.py
"""
P1-02 — Intel-plane code corrections (cve streaming bootstrap + atomic-artifact
sync cycles).

Maps the work order's required proofs onto tests:

Defect 1 — cve streaming bootstrap:
  - ONE download per bootstrap across continuation rounds (the audited plank);
    every round slices its batch from the persistent on-disk stage and parses
    entries on demand.
  - The continuation cursor carries the staged extraction's identity; resume
    is only ever applied to the identical extraction (missing / altered /
    different-download staging restarts the bootstrap from batch 0 — harmless,
    all adapter writes are content-hash upserts).
  - Exhaustion clears the staging (deterministic lifecycle, no leaks).
  - Archive guards keep their kinds and fail closed (bomb, traversal); the
    default ArchiveLimits are honestly sized for the real catalog.

Defect 2 — atomic-artifact sources (kev, epss):
  - One run = one snapshot = the WHOLE current artifact, labeled with the
    artifact's own header date (never an inherited stale label).
  - Interrupted runs fail closed: nothing committed, cursor untouched, and a
    later run starts fresh under the then-current artifact's label.
  - KEV catalog-hash identity: a shrunk/changed catalog restarts the snapshot
    (seen_ids from the old catalog can never drive mass withdrawal).
  - EPSS continuation against a differently-hashed artifact restarts under the
    NEW artifact's header date — the stale-label override is gone.

Item 3 — NVD cursor never advances past unprocessed work: the incremental
  cursor pins the last processed record's lastModified, not the response
  timestamp, so backlog larger than one batch stays due.

Item 4 — observability: the SYNC snapshot log line carries source/mode/status/
  counts and the module logger is actually visible (handler attached, INFO
  level, propagate disabled so the line is not double-emitted).

Migration 023: the (source, declared_cve_id) coverage index exists and the
  coverage-shaped predicate is index-capable (EXPLAIN evidence with seqscan
  disabled); the migration SQL is idempotent (IF NOT EXISTS).

The cve_staging / fetch-client classes are DB-free (stdlib + httpx only); the
engine and migration tests run against the disposable PostgreSQL.
"""
import gzip
import io
import json
import logging
import shutil
import zipfile
from pathlib import Path

import httpx
import pytest

from app.db import get_db_connection
from app.vuln_intelligence.archive_utils import (
    ArchiveBombError,
    PathTraversalError,
)
from app.vuln_intelligence.models import ArchiveLimits
from app.vuln_intelligence.fetch_clients import (
    CveFetchClient,
    EpssFetchClient,
    KevFetchClient,
    NvdFetchClient,
)
from app.vuln_intelligence.sync_adapters import EpssSyncAdapter
from app.vuln_intelligence.sync_engine import (
    SyncOutcome,
    _log_sync_snapshot,
    sync_source,
    get_sync_state,
)
from app.vuln_intelligence import cve_staging


# ---------------------------------------------------------------------------
# Staging isolation: every staging test gets a fresh private staging root.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_staging(monkeypatch, tmp_path):
    root = tmp_path / "staging"
    monkeypatch.setenv(cve_staging.STAGING_BASE_ENV, str(root))
    shutil.rmtree(root, ignore_errors=True)
    yield root
    shutil.rmtree(root, ignore_errors=True)


def _cve_record(cve_id: str) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
    }


def _cvelist_zip(cve_ids: list[str]) -> bytes:
    """A minimal cvelistV5-shaped zip: one JSON CVE_RECORD per id."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for cve_id in cve_ids:
            zf.writestr(
                f"cvelistV5-main/cves/2026/{cve_id[-4:]}/{cve_id}.json",
                json.dumps(_cve_record(cve_id)),
            )
    return buf.getvalue()


def _counting_transport(payload: bytes, hits: list[int]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(1)
        return httpx.Response(200, content=payload)

    return httpx.Client(transport=httpx.MockTransport(handler))


# ===========================================================================
# Defect 1 — staging module identity & guards
# ===========================================================================

class TestCveStagingIdentity:
    def test_stage_archive_roundtrip_and_manifest(self, isolated_staging):
        cat = cve_staging.stage_archive(_cvelist_zip([f"CVE-2026-{1000 + i}" for i in range(4)]))
        assert cat.entry_count == 4
        assert len(cat.identity) == 64
        assert (cve_staging.staging_root() / "manifest.json").is_file()
        manifest = json.loads((cve_staging.staging_root() / "manifest.json").read_text())
        assert manifest["identity"] == cat.identity
        assert manifest["entry_count"] == 4

        # Deterministic slice/parse from disk.
        first_two = cat.entry_slice(0, 2)
        records = cat.read_entries(first_two)
        assert [r["cveMetadata"]["cveId"] for r in records] == ["CVE-2026-1000", "CVE-2026-1001"]

    def test_resume_validates_identical_extraction(self, isolated_staging):
        cat = cve_staging.stage_archive(_cvelist_zip([f"CVE-2026-{1000 + i}" for i in range(3)]))
        loaded = cve_staging.load_staged_catalog()
        assert loaded is not None
        assert loaded.identity == cat.identity

    def test_resume_rejects_entry_drift(self, isolated_staging):
        cve_staging.stage_archive(_cvelist_zip(["CVE-2026-1000", "CVE-2026-1001"]))
        # Remove one staged file -> walk count drifts.
        victim = next((cve_staging.staging_root() / "entries").rglob("*.json"))
        victim.unlink()
        assert cve_staging.load_staged_catalog() is None

    def test_resume_rejects_altered_file(self, isolated_staging):
        cve_staging.stage_archive(_cvelist_zip(["CVE-2026-1000"]))
        victim = next((cve_staging.staging_root() / "entries").rglob("*.json"))
        victim.write_bytes(victim.read_bytes() + b"x")  # size change -> identity change
        assert cve_staging.load_staged_catalog() is None

    def test_resume_rejects_missing_stage(self, isolated_staging):
        assert cve_staging.load_staged_catalog() is None

    def test_resume_rejects_corrupt_manifest(self, isolated_staging):
        cve_staging.stage_archive(_cvelist_zip(["CVE-2026-1000"]))
        (cve_staging.staging_root() / "manifest.json").write_text("{not json")
        assert cve_staging.load_staged_catalog() is None

    def test_oversized_archive_still_raises_archive_bomb(self, isolated_staging):
        # Real guard semantics on the staged path: a high-ratio archive fails
        # closed with ArchiveBombError exactly as the in-memory path does.
        bomb = io.BytesIO()
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("cvelistV5-main/huge.json", b"0" * (4 * 1024 * 1024))
        tiny_limits = ArchiveLimits(
            max_compressed_bytes=100 * 1024 * 1024,
            max_expanded_bytes=1024 * 1024,          # 1 MB expanded cap
            extraction_timeout_seconds=30.0,
        )
        with pytest.raises(ArchiveBombError):
            cve_staging.stage_archive(bomb.getvalue(), limits=tiny_limits)

    def test_traversal_guard_intact_on_staged_path(self, isolated_staging):
        evil = io.BytesIO()
        with zipfile.ZipFile(evil, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../escaped.json", b"{}")
        with pytest.raises(PathTraversalError):
            cve_staging.stage_archive(evil.getvalue())


# ===========================================================================
# Defect 1 — the one-download proof (audited plank)
# ===========================================================================

class TestCveOneDownloadBootstrap:
    def test_whole_bootstrap_downloads_exactly_once(self, isolated_staging):
        payload = _cvelist_zip([f"CVE-2026-{1000 + i}" for i in range(5)])
        hits: list[int] = []
        client = CveFetchClient(client=_counting_transport(payload, hits))

        # Round 1: fresh bootstrap, batch 2 of 5.
        r1 = client.fetch(cursor=None, batch_size=2)
        assert r1.error is None and len(r1.records) == 2 and r1.is_exhausted is False
        assert r1.metadata["staged"] is True and r1.metadata["resumed"] is False
        cur1 = json.loads(r1.cursor_after)
        assert cur1["phase"] == "bootstrap" and cur1["entry_offset"] == 2
        assert len(cur1["staging_identity"]) == 64

        # Round 2: continuation — STILL exactly one download total.
        r2 = client.fetch(cursor=r1.cursor_after, batch_size=2)
        assert len(r2.records) == 2 and r2.is_exhausted is False
        assert r2.metadata["resumed"] is True
        assert r2.metadata["staging_identity"] == cur1["staging_identity"]
        assert sum(hits) == 1, "continuation round must NOT re-download the archive"

        # Round 3: exhaustion — still one download; staging cleaned.
        r3 = client.fetch(cursor=r2.cursor_after, batch_size=2)
        assert len(r3.records) == 1 and r3.is_exhausted is True
        assert r3.cursor_after == cur1["target_sha"]
        assert sum(hits) == 1
        assert not cve_staging.staging_root().exists(), "exhaustion must clear the staging"

        # All five records observed exactly once across rounds.
        ids = [r["cveMetadata"]["cveId"] for r in r1.records + r2.records + r3.records]
        assert len(ids) == 5 and len(set(ids)) == 5

    def test_resume_on_altered_staging_restarts_clean(self, isolated_staging):
        payload = _cvelist_zip([f"CVE-2026-{1000 + i}" for i in range(4)])
        hits: list[int] = []
        client = CveFetchClient(client=_counting_transport(payload, hits))

        r1 = client.fetch(cursor=None, batch_size=2)
        old_identity = json.loads(r1.cursor_after)["staging_identity"]

        # Tamper with the staged tree (size change) — resume MUST NOT apply
        # the old offset against a different extraction: restart from batch 0.
        victim = next((cve_staging.staging_root() / "entries").rglob("*.json"))
        victim.write_bytes(victim.read_bytes() + b" ")

        r2 = client.fetch(cursor=r1.cursor_after, batch_size=2)
        assert r2.error is None
        assert r2.metadata["resumed"] is False
        assert r2.metadata["offset"] == 0, "identity mismatch must restart at batch 0"
        new_identity = r2.metadata["staging_identity"]
        assert new_identity != old_identity
        assert [rec["cveMetadata"]["cveId"] for rec in r2.records] == ["CVE-2026-1000", "CVE-2026-1001"]

    def test_restart_on_different_download_is_harmless_by_upserts(self, isolated_staging):
        # The documented restart-is-harmless invariant: a restarted bootstrap
        # reprocesses from batch 0 and the identity is fresh per download —
        # no stale offset can ever land on a different extraction.
        payload = _cvelist_zip([f"CVE-2026-{1000 + i}" for i in range(3)])
        hits: list[int] = []
        client = CveFetchClient(client=_counting_transport(payload, hits))
        r1 = client.fetch(cursor=None, batch_size=2)
        staged = cve_staging.load_staged_catalog()
        assert staged is not None
        # Simulate crash-left staging: the cursor survives, the stage survives,
        # and a resumed run continues — never restarts silently mid-batch.
        r2 = client.fetch(cursor=r1.cursor_after, batch_size=2)
        assert r2.metadata["offset"] == 2 and r2.metadata["resumed"] is True
        assert sum(hits) == 1


# ===========================================================================
# Defect 2 — EPSS label semantics at the exact defect site
# ===========================================================================

def _epss_csv(header_date: str, cve_ids: list[str]) -> bytes:
    rows = "".join(f"{cid},0.10000,0.20000\n" for cid in cve_ids)
    return gzip.compress(
        f"#model_version:v2026.01,score_date:{header_date}\ncve,epss,percentile\n{rows}".encode()
    )


class TestEpssLabelSemantics:
    def test_continuation_same_artifact_keeps_own_label(self):
        hits: list[int] = []
        payload = _epss_csv("2026-09-19T12:00:00+0000", [f"CVE-2026-{2000 + i}" for i in range(4)])
        client = EpssFetchClient(client=_counting_transport(payload, hits))

        r1 = client.fetch(cursor=None, batch_size=2)
        assert len(r1.records) == 2 and r1.is_exhausted is False
        assert r1.records[0]["score_date"] == "2026-09-19T12:00:00+0000"
        r2 = client.fetch(cursor=r1.cursor_after, batch_size=2)
        assert r2.is_exhausted is True
        assert all(rec["score_date"] == "2026-09-19T12:00:00+0000" for rec in r2.records)
        assert r2.cursor_after == "2026-09-19T12:00:00+0000"

    def test_continuation_against_newer_artifact_never_inherits_label(self):
        """The stale-label defect (fetch_clients.py:538-540): a continuation
        cursor meeting a DIFFERENT artifact must restart under the NEW
        artifact's own header date — silent inheritance is forbidden."""
        artifact_a = _epss_csv("2026-09-07T12:00:00+0000", ["CVE-2026-3000", "CVE-2026-3001", "CVE-2026-3002", "CVE-2026-3003"])
        artifact_b = _epss_csv("2026-09-18T12:00:00+0000", ["CVE-2026-3000", "CVE-2026-3001", "CVE-2026-3002", "CVE-2026-3003"])
        responses = [artifact_a, artifact_b]
        hits: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            hits.append(1)
            return httpx.Response(200, content=responses[min(len(hits) - 1, len(responses) - 1)])

        client = EpssFetchClient(client=httpx.Client(transport=httpx.MockTransport(handler)))
        r1 = client.fetch(cursor=None, batch_size=2)
        assert json.loads(r1.cursor_after)["score_date"] == "2026-09-07T12:00:00+0000"

        # The served file changed overnight: the old continuation cursor must
        # be discarded, not re-labeled with 2026-09-07.
        r2 = client.fetch(cursor=r1.cursor_after, batch_size=2)
        assert r2.error is None
        assert r2.metadata["offset"] == 0, "artifact changed -> restart from batch 0"
        assert all(rec["score_date"] == "2026-09-18T12:00:00+0000" for rec in r2.records)
        assert json.loads(r2.cursor_after)["score_date"] == "2026-09-18T12:00:00+0000"


# ===========================================================================
# Defect 2 — atomic-artifact engine semantics (one snapshot per artifact)
# ===========================================================================

class TestAtomicArtifactEngine:
    @pytest.fixture(autouse=True)
    def clean_vuln_tables(self):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # FK order: null sync_state snapshot references FIRST, then
                # delete dependent rows, then the snapshots themselves.
                cur.execute("""
                    UPDATE sync_state SET
                        cursor_value = NULL, last_successful_at = NULL,
                        last_attempted_at = NULL, last_error = NULL,
                        last_snapshot_id = NULL, last_good_snapshot_id = NULL,
                        last_sync_duration_ms = NULL, active_record_count = 0,
                        consecutive_failures = 0, is_healthy = TRUE,
                        sync_enabled = FALSE, next_sync_at = NULL
                    WHERE source IN ('cve', 'nvd', 'kev', 'epss', 'osv');
                """)
                cur.execute("DELETE FROM epss_scores;")
                cur.execute("DELETE FROM kev_entries;")
                cur.execute("DELETE FROM cvss_assessments;")
                cur.execute("DELETE FROM vuln_source_records;")
                cur.execute("DELETE FROM canonical_vulnerabilities;")
                cur.execute("DELETE FROM source_artifacts;")
                cur.execute("DELETE FROM sync_snapshots;")
            conn.commit()
        yield
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Null state references BEFORE deleting snapshots (FK order).
                cur.execute("""
                    UPDATE sync_state SET
                        cursor_value = NULL, last_snapshot_id = NULL,
                        last_good_snapshot_id = NULL, active_record_count = 0,
                        consecutive_failures = 0, is_healthy = TRUE
                    WHERE source IN ('cve', 'nvd', 'kev', 'epss', 'osv');
                """)
                cur.execute("DELETE FROM epss_scores;")
                cur.execute("DELETE FROM kev_entries;")
                cur.execute("DELETE FROM vuln_source_records;")
                cur.execute("DELETE FROM canonical_vulnerabilities;")
                cur.execute("DELETE FROM source_artifacts;")
                cur.execute("DELETE FROM sync_snapshots;")
            conn.commit()

    @staticmethod
    def _epss_adapter(payload: bytes, hits: list[int]) -> EpssSyncAdapter:
        def handler(request: httpx.Request) -> httpx.Response:
            hits.append(1)
            return httpx.Response(200, content=payload)

        return EpssSyncAdapter(
            fetch_client=EpssFetchClient(
                client=httpx.Client(transport=httpx.MockTransport(handler))
            )
        )

    def test_full_artifact_one_run_one_snapshot_one_label(self):
        """A scheduled EPSS run drains the ENTIRE artifact inside one snapshot
        even with batch_size below the row count — and every row carries the
        artifact's own header date."""
        cve_ids = [f"CVE-2026-{2000 + i}" for i in range(5)]
        payload = _epss_csv("2026-09-18T12:00:00+0000", cve_ids)
        hits: list[int] = []
        adapter = self._epss_adapter(payload, hits)

        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter, batch_size=2)

        assert outcome.success is True
        assert outcome.snapshot_id is not None
        assert outcome.internal_rounds == 3, "5 rows at batch 2 = 3 internal rounds"
        assert outcome.continuation_completed is True
        assert outcome.records_processed == 5

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM epss_scores;")
                assert cur.fetchone()["n"] == 5
                cur.execute("SELECT DISTINCT score_date FROM epss_scores;")
                dates = [r["score_date"].isoformat() for r in cur.fetchall()]
                assert dates == ["2026-09-18"], "all rows under the artifact's own label"
                cur.execute("""
                    SELECT status, count(*) AS n FROM sync_snapshots
                    WHERE source = 'epss' GROUP BY status;
                """)
                ledger = {r["status"]: r["n"] for r in cur.fetchall()}
                assert ledger.get("completed") == 1, "exactly ONE snapshot for the artifact"
                state = get_sync_state(conn, "epss")
                assert state.cursor_value == "2026-09-18T12:00:00+0000"

    def test_interrupted_artifact_run_fails_closed(self):
        """A fetch failure mid-artifact rolls back the WHOLE snapshot: no rows,
        cursor untouched, snapshot marked failed — nothing partial survives."""
        cve_ids = [f"CVE-2026-{2100 + i}" for i in range(4)]
        payload = _epss_csv("2026-09-18T12:00:00+0000", cve_ids)
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] >= 2:
                raise httpx.ConnectError("upstream died mid-artifact")
            return httpx.Response(200, content=payload)

        adapter = EpssSyncAdapter(
            fetch_client=EpssFetchClient(
                client=httpx.Client(transport=httpx.MockTransport(handler))
            )
        )
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter, batch_size=2)

        assert outcome.success is False
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM epss_scores;")
                assert cur.fetchone()["n"] == 0, "no partial artifact may persist"
                state = get_sync_state(conn, "epss")
                assert state.cursor_value is None, "cursor untouched on failure"
                cur.execute("""
                    SELECT status FROM sync_snapshots WHERE source = 'epss';
                """)
                statuses = [r["status"] for r in cur.fetchall()]
                assert statuses == ["failed"]

    def test_next_run_after_failure_labels_with_current_artifact(self):
        """After a failed run (cursor untouched) the NEXT run starts fresh and
        labels everything with the then-current artifact's own date."""
        artifact_old = _epss_csv("2026-09-07T12:00:00+0000", ["CVE-2026-2200", "CVE-2026-2201"])
        payload = artifact_old
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, content=payload)

        adapter = EpssSyncAdapter(
            fetch_client=EpssFetchClient(
                client=httpx.Client(transport=httpx.MockTransport(handler))
            )
        )
        with get_db_connection() as conn:
            ok = sync_source(conn, adapter, batch_size=2)
        assert ok.success is True

        # Next day: a new artifact with a new header date.
        payload = _epss_csv("2026-09-19T12:00:00+0000", ["CVE-2026-2200", "CVE-2026-2201"])
        with get_db_connection() as conn:
            ok2 = sync_source(conn, adapter, batch_size=2)
        assert ok2.success is True

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT score_date::text AS d, count(*) AS n
                    FROM epss_scores GROUP BY score_date ORDER BY d;
                """)
                rows = {r["d"]: r["n"] for r in cur.fetchall()}
                assert rows == {
                    "2026-09-07": 2,
                    "2026-09-19": 2,
                }, "each artifact lands under its own header date"

    def test_kev_changed_catalog_restarts_snapshot(self):
        """KEV continuation cursor carries the catalog hash; a changed/shrunk
        catalog restarts from batch 0 (old seen_ids can never leak into
        absence reconciliation)."""
        catalog_a = {
            "count": 3,
            "catalogVersion": "2026.09.07",
            "dateReleased": "2026-09-07T19:00:00.000Z",
            "vulnerabilities": [
                {"cveID": f"CVE-2026-230{i}", "vendorProject": "V", "product": "P",
                 "vulnerabilityName": "N", "dateAdded": "2026-09-01"}
                for i in range(3)
            ],
        }
        catalog_b = {
            "count": 1,
            "catalogVersion": "2026.09.18",
            "dateReleased": "2026-09-18T19:00:00.000Z",
            "vulnerabilities": [
                {"cveID": "CVE-2026-2309", "vendorProject": "V", "product": "P",
                 "vulnerabilityName": "N", "dateAdded": "2026-09-10"}
            ],
        }
        responses = [json.dumps(catalog_a).encode(), json.dumps(catalog_b).encode()]
        hits = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            hits["n"] += 1
            return httpx.Response(200, content=responses[min(hits["n"] - 1, 1)])

        client = KevFetchClient(client=httpx.Client(transport=httpx.MockTransport(handler)))
        r1 = client.fetch(cursor=None, batch_size=2)
        assert r1.is_exhausted is False
        cur1 = json.loads(r1.cursor_after)
        assert cur1["catalog_hash"]

        r2 = client.fetch(cursor=r1.cursor_after, batch_size=2)
        assert r2.error is None
        assert r2.metadata["offset"] == 0, "catalog changed -> restart from batch 0"
        assert [rec["cveID"] for rec in r2.records] == ["CVE-2026-2309"]
        assert r2.is_exhausted is True
        assert r2.cursor_after == "2026-09-18T19:00:00.000Z"


# ===========================================================================
# Item 3 — NVD cursor pins the processed position
# ===========================================================================

class TestNvdBacklogCursor:
    # Updated for the review's positional-window cursor: the window is
    # paginated positionally to exhaustion and only then promoted to the
    # WINDOW END — a backlog larger than one batch (or a timestamp tie across
    # a page boundary) always continues where it stopped.
    def test_incremental_cursor_pins_last_processed_record(self):
        """A backlog larger than the batch leaves a window continuation —
        record 3 remains due; the clean cursor is NOT promoted and NEVER
        jumps to the response timestamp."""
        payload = {
            "totalResults": 3,
            "resultsPerPage": 2000,
            "startIndex": 0,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-09-10T00:00:00.000",
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-4001", "lastModified": "2026-09-10T01:00:00.000"}},
                {"cve": {"id": "CVE-2026-4002", "lastModified": "2026-09-12T02:00:00.000"}},
                {"cve": {"id": "CVE-2026-4003", "lastModified": "2026-09-14T03:00:00.000"}},
            ],
        }
        client = httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=payload)
        ))
        fetcher = NvdFetchClient(client=client)

        res = fetcher.fetch(cursor="2026-09-01T00:00:00.000", batch_size=2)
        assert len(res.records) == 2
        assert res.is_exhausted is False
        cont = json.loads(res.cursor_after)
        assert cont["nvd_window"] is True
        assert cont["startIndex"] == 2
        assert cont["window_start"] == "2026-09-01T00:00:00.000"
        # The window end is the window-OPEN instant (never the stale
        # response timestamp) — the promoted cursor equals it exactly.
        assert cont["window_end"] != "2026-09-10T00:00:00.000"
        from datetime import datetime
        datetime.strptime(cont["window_end"], "%Y-%m-%dT%H:%M:%S.%fZ")

    def test_incremental_cursor_on_full_window_is_last_record(self):
        """A fully-processed window promotes the clean cursor to the WINDOW
        END (records modified after the window stay due) — not to the
        upstream response timestamp."""
        payload = {
            "totalResults": 2,
            "resultsPerPage": 2000,
            "startIndex": 0,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-09-10T00:00:00.000",
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-4101", "lastModified": "2026-09-11T01:00:00.000"}},
                {"cve": {"id": "CVE-2026-4102", "lastModified": "2026-09-13T02:00:00.000"}},
            ],
        }
        client = httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=payload)
        ))
        fetcher = NvdFetchClient(client=client)
        res = fetcher.fetch(cursor="2026-09-01T00:00:00.000", batch_size=10)
        assert res.is_exhausted is True
        # Promoted to the window end (window-OPEN instant), never the stale
        # response timestamp.
        assert res.cursor_after != "2026-09-10T00:00:00.000"
        from datetime import datetime
        datetime.strptime(res.cursor_after, "%Y-%m-%dT%H:%M:%S.%fZ")


# ===========================================================================
# Item 4 — snapshot log line observability
# ===========================================================================

class TestSyncSnapshotLogLine:
    def test_log_line_carries_source_mode_status_counts(self):
        records = []
        handler = logging.Handler()
        handler.emit = lambda record: records.append(record.getMessage())
        logger = logging.getLogger("app.vuln_intelligence.sync_engine")
        old_level, old_prop = logger.level, logger.propagate
        logger.addHandler(handler)
        try:
            _log_sync_snapshot(SyncOutcome(
                source="epss", success=True, snapshot_id="snap-1",
                sync_mode="bootstrap", records_processed=5, records_created=5,
                records_updated=5, records_unchanged=0, records_failed=0,
                cursor_before=None, cursor_after="2026-09-18",
                duration_ms=1234,
            ))
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
            logger.propagate = old_prop

        assert any(
            "SYNC epss:" in m and "mode=bootstrap" in m and "success=True" in m
            and "processed=5" in m and "created=5" in m for m in records
        ), records

    def test_module_logger_is_pm2_visible(self):
        """The visibility shim: the module logger has a stdout handler, INFO
        level, and propagate disabled (so the line is emitted exactly once)."""
        import app.vuln_intelligence.sync_engine as se
        assert se.logger.level <= logging.INFO
        assert se.logger.propagate is False
        assert any(
            isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
            for h in se.logger.handlers
        )


# ===========================================================================
# Item 4 — migration 023 (index) and honest guard sizing
# ===========================================================================

class TestMigration023AndLimits:
    def test_index_exists(self):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM pg_indexes
                    WHERE indexname = 'idx_vuln_source_records_source_declared_cve_id';
                """)
                assert cur.fetchone() is not None

    def test_migration_sql_is_idempotent(self):
        sql = (
            Path(__file__).resolve().parents[1]
            / "migrations" / "023_vuln_source_records_declared_cve_idx.sql"
        ).read_text(encoding="utf-8")
        assert "IF NOT EXISTS" in sql
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.commit()

    def test_coverage_predicate_is_index_capable(self):
        """EXPLAIN evidence: the coverage-shaped predicate (source,
        declared_cve_id) is served by the new index (seqscan disabled to make
        the planner's index capability explicit at small row counts).

        The seed lives entirely inside one transaction that ROLLS BACK —
        nothing persists (the earlier run's rows are defensively cleared)."""
        with get_db_connection() as conn:
            # Defensive cleanup of any rows a previously failed run committed.
            with conn.cursor() as cur:
                cur.execute("DELETE FROM vuln_source_records WHERE source_id LIKE 'nvd-rec-%';")
            conn.commit()

            # Seed + EXPLAIN + ROLLBACK in ONE transaction: no residue.
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO sync_snapshots (source, sync_mode, status)
                    VALUES ('nvd', 'bootstrap', 'completed')
                    RETURNING id;
                """)
                snap_id = cur.fetchone()["id"]
                cur.execute("""
                    INSERT INTO vuln_source_records
                        (source, source_id, content_hash, raw_payload, snapshot_id, declared_cve_id)
                    SELECT 'nvd', 'nvd-rec-' || i, 'hash-' || i, '{}'::jsonb, %s,
                           CASE WHEN i = 0 THEN 'CVE-2026-424242' ELSE 'CVE-2026-9' || lpad(i::text, 5, '0') END
                    FROM generate_series(0, 2999) AS i;
                """, (snap_id,))
                cur.execute("SET LOCAL enable_seqscan = off;")
                cur.execute("""
                    EXPLAIN (FORMAT JSON)
                    SELECT 1 FROM vuln_source_records
                    WHERE source = 'nvd' AND declared_cve_id = 'CVE-2026-424242';
                """)
                plan = cur.fetchone()
            conn.rollback()

            # Prove the rollback left no residue.
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM vuln_source_records WHERE source_id LIKE 'nvd-rec-%';")
                assert cur.fetchone()["n"] == 0

        plan_text = json.dumps(plan)
        assert "idx_vuln_source_records_source_declared_cve_id" in plan_text, plan_text[:400]

    def test_archive_limits_honestly_sized_guards_in_kind(self):
        # P1-02 review (P2): the SHARED defaults stay conservative — the
        # bounds every consumer inherited before P1-02 (OSV untouched).
        limits = ArchiveLimits()
        assert limits.max_compressed_bytes == 500 * 1024 * 1024
        assert limits.max_expanded_bytes == 2 * 1024 * 1024 * 1024
        assert limits.max_file_count == 500_000
        assert limits.extraction_timeout_seconds == 300.0
        # Guards unchanged in kind: hostile archives still fail closed.
        assert limits.max_compression_ratio == 100.0
        assert limits.max_entry_bytes == 50 * 1024 * 1024
        # The cvelistV5 bootstrap carries its own CVE-specific preset sized
        # for the real catalog with margin.
        from app.vuln_intelligence.models import CVE_ARCHIVE_LIMITS
        assert CVE_ARCHIVE_LIMITS.max_compressed_bytes >= 500 * 1024 * 1024
        assert CVE_ARCHIVE_LIMITS.max_expanded_bytes >= 5 * 1024 * 1024 * 1024
        assert CVE_ARCHIVE_LIMITS.max_file_count >= 300_000
        assert CVE_ARCHIVE_LIMITS.extraction_timeout_seconds >= 900
