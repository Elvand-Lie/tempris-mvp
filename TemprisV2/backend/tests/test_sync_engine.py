# backend/tests/test_sync_engine.py
"""
Contract tests for Sprint 03 — Sync Orchestration Engine.

Covers:
  - Full bootstrap from each source's supported bulk/snapshot path
  - Incremental/delta mode where available
  - Fetch -> validate -> stage/reconcile -> atomically activate -> advance cursor
  - Source identity + canonical content hash dedup
  - Changed records create traceable revisions/current pointers
  - Explicit REJECTED/withdrawn states persist
  - Absence from incremental response is never deletion
  - Failed validation/activation leaves active data and cursor unchanged
  - Last-known-good remains after failure
  - Sources fail independently
  - Observable per-source state: last attempt/success, active snapshot, cursor, etc.
  - Advisory lock overlap prevention
  - Configurable scheduling defaults
  - Scheduling disabled unless explicitly configured
  - Bounded behavior (batch_size, timeout)
  - Health fields correctness

All tests run offline against checked-in fixtures and a local PostgreSQL 17.
No network calls. The sync engine is exercised by injecting fixture data
through mock adapters that bypass HTTP fetch.
"""
import json
import threading
import time
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional
from unittest.mock import patch

import psycopg
import pytest

from app.db import get_db_connection
from app.vuln_intelligence.models import (
    CanonicalVulnerability,
    SyncSnapshot,
    SyncState,
    validate_cve_id,
)
from app.vuln_intelligence.repository import (
    content_hash,
    get_canonical_vulnerability,
    get_sync_state,
    get_all_sync_states,
    get_sync_snapshot,
    get_current_source_record,
    get_source_record_revisions,
    get_cvss_assessments,
    get_cve_affected,
    get_kev_entry,
    get_epss_scores,
    get_osv_record,
    get_osv_aliases,
    create_sync_snapshot,
    update_sync_state,
    upsert_canonical_vulnerability,
)
from app.vuln_intelligence.sync_engine import (
    FetchResult,
    ProcessResult,
    SyncOutcome,
    sync_source,
    try_advisory_lock,
    release_advisory_lock,
    get_schedule_config,
    set_schedule_config,
    get_sources_due_for_sync,
    advance_next_sync,
    get_source_health,
    get_all_source_health,
    DEFAULT_INTERVALS,
    _source_lock_key,
)
from app.vuln_intelligence.sync_adapters import (
    CveSyncAdapter,
    NvdSyncAdapter,
    KevSyncAdapter,
    EpssSyncAdapter,
    OsvSyncAdapter,
    ALL_ADAPTERS,
)


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "vuln_intelligence"


def load_json(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_text(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def clean_vuln_tables():
    """Truncate all vuln intelligence tables before each test."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE sync_state SET
                    cursor_value = NULL,
                    last_successful_at = NULL,
                    last_attempted_at = NULL,
                    last_error = NULL,
                    last_snapshot_id = NULL,
                    last_good_snapshot_id = NULL,
                    last_sync_duration_ms = NULL,
                    active_record_count = 0,
                    consecutive_failures = 0,
                    is_healthy = TRUE,
                    sync_enabled = FALSE,
                    next_sync_at = NULL,
                    sync_interval_seconds = CASE sync_state.source
                        WHEN 'epss' THEN 86400
                        ELSE 1200
                    END;
                DELETE FROM cve_weaknesses;
                DELETE FROM cve_references;
                DELETE FROM osv_aliases;
                DELETE FROM osv_records;
                DELETE FROM cve_adp_entries;
                DELETE FROM cve_affected;
                DELETE FROM cve_relationships;
                DELETE FROM cvss_assessments;
                DELETE FROM kev_entries;
                DELETE FROM epss_scores;
                DELETE FROM source_artifacts;
                DELETE FROM vuln_source_records;
                DELETE FROM canonical_vulnerabilities;
                DELETE FROM sync_snapshots;
                INSERT INTO sync_state (source) VALUES
                    ('cve'), ('nvd'), ('kev'), ('epss'), ('osv')
                ON CONFLICT (source) DO UPDATE SET
                    cursor_value = NULL,
                    last_successful_at = NULL,
                    last_attempted_at = NULL,
                    last_error = NULL,
                    last_snapshot_id = NULL,
                    last_good_snapshot_id = NULL,
                    last_sync_duration_ms = NULL,
                    active_record_count = 0,
                    consecutive_failures = 0,
                    is_healthy = TRUE,
                    sync_enabled = FALSE,
                    next_sync_at = NULL,
                    sync_interval_seconds = CASE sync_state.source
                        WHEN 'epss' THEN 86400
                        ELSE 1200
                    END;
            """)
        conn.commit()
    yield


# ---------------------------------------------------------------------------
# Mock adapters for offline testing
# ---------------------------------------------------------------------------

class MockAdapter:
    """Base mock adapter that accepts injected records."""

    def __init__(self, source_name: str, records=None, cursor_after=None,
                 is_bootstrap=False, fetch_error=None, validate_error=None,
                 process_errors=None):
        self.source_name = source_name
        self._records = records or []
        self._cursor_after = cursor_after
        self._is_bootstrap = is_bootstrap
        self._fetch_error = fetch_error
        self._validate_error = validate_error
        self._process_errors = process_errors or {}  # index -> error_msg
        self.fetch_count = 0

    def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
        self.fetch_count += 1
        if self._fetch_error:
            return FetchResult(error=self._fetch_error)
        return FetchResult(
            records=self._records,
            cursor_after=self._cursor_after,
            is_bootstrap=self._is_bootstrap or cursor is None,
            metadata={"test": True},
        )

    def validate_batch(self, records):
        if self._validate_error:
            return False, self._validate_error
        return True, None

    def process_record(self, conn, record, snapshot_id):
        idx = self._records.index(record) if record in self._records else -1
        if idx in self._process_errors:
            return False, False, self._process_errors[idx]
        # Simulate successful processing
        return True, True, None


class FixtureCveAdapter:
    """CVE adapter that processes real fixture records through the real adapter."""
    source_name = "cve"

    def __init__(self, records=None, cursor_after=None, fetch_error=None):
        self._records = records or []
        self._cursor_after = cursor_after
        self._fetch_error = fetch_error

    def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
        if self._fetch_error:
            return FetchResult(error=self._fetch_error)
        return FetchResult(
            records=self._records,
            cursor_after=self._cursor_after,
            is_bootstrap=cursor is None,
        )

    def validate_batch(self, records):
        adapter = CveSyncAdapter()
        return adapter.validate_batch(records)

    def process_record(self, conn, record, snapshot_id):
        adapter = CveSyncAdapter()
        return adapter.process_record(conn, record, snapshot_id)


class FixtureKevAdapter:
    """KEV adapter that processes real fixture records."""
    source_name = "kev"

    def __init__(self, records=None, cursor_after=None, fetch_error=None):
        self._records = records or []
        self._cursor_after = cursor_after
        self._fetch_error = fetch_error

    def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
        if self._fetch_error:
            return FetchResult(error=self._fetch_error)
        return FetchResult(
            records=self._records,
            cursor_after=self._cursor_after,
            is_bootstrap=cursor is None,
        )

    def validate_batch(self, records):
        adapter = KevSyncAdapter()
        return adapter.validate_batch(records)

    def process_record(self, conn, record, snapshot_id):
        adapter = KevSyncAdapter()
        return adapter.process_record(conn, record, snapshot_id)


class FixtureEpssAdapter:
    """EPSS adapter that processes real fixture CSV."""
    source_name = "epss"

    def __init__(self, csv_texts=None, cursor_after=None, fetch_error=None):
        self._csv_texts = csv_texts or []
        self._cursor_after = cursor_after
        self._fetch_error = fetch_error

    def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
        if self._fetch_error:
            return FetchResult(error=self._fetch_error)
        return FetchResult(
            records=self._csv_texts,
            cursor_after=self._cursor_after,
            is_bootstrap=cursor is None,
        )

    def validate_batch(self, records):
        adapter = EpssSyncAdapter()
        return adapter.validate_batch(records)

    def process_record(self, conn, record, snapshot_id):
        adapter = EpssSyncAdapter()
        return adapter.process_record(conn, record, snapshot_id)


# ===========================================================================
# 1. FULL BOOTSTRAP
# ===========================================================================

class TestFullBootstrap:
    """Full bootstrap from each source's supported bulk/snapshot path."""

    def test_cve_bootstrap(self):
        """Bootstrap CVE: processes fixture records, creates snapshot, advances cursor."""
        fixture = load_json("cve_published.json")
        adapter = FixtureCveAdapter(
            records=[fixture],
            cursor_after="2024-04-15T12:00:00Z",
        )
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)

        assert outcome.success is True
        assert outcome.sync_mode == "bootstrap"
        assert outcome.records_processed == 1
        assert outcome.records_created == 1
        assert outcome.cursor_after == "2024-04-15T12:00:00Z"

        with get_db_connection() as conn:
            vuln = get_canonical_vulnerability(conn, "CVE-2024-1234")
            assert vuln is not None
            assert vuln.state == "PUBLISHED"
            state = get_sync_state(conn, "cve")
            assert state.cursor_value == "2024-04-15T12:00:00Z"
            assert state.is_healthy is True

    def test_kev_bootstrap(self):
        """Bootstrap KEV: full catalog processed."""
        catalog = load_json("kev_catalog.json")
        adapter = FixtureKevAdapter(
            records=catalog["vulnerabilities"],
            cursor_after="2024-04-15",
        )
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)

        assert outcome.success is True
        assert outcome.records_processed == 2
        assert outcome.records_created == 2

        with get_db_connection() as conn:
            kev = get_kev_entry(conn, "CVE-2024-1234")
            assert kev is not None
            assert kev.known_ransomware == "Known"

    def test_epss_bootstrap(self):
        """Bootstrap EPSS: bulk CSV processed."""
        csv_text = load_text("epss_scores.csv")
        adapter = FixtureEpssAdapter(
            csv_texts=[csv_text],
            cursor_after="2024-04-15",
        )
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)

        assert outcome.success is True
        assert outcome.records_processed == 1
        assert outcome.records_created == 1

        with get_db_connection() as conn:
            scores = get_epss_scores(conn, "CVE-2024-1234")
            assert len(scores) == 1
            assert scores[0].score == Decimal("0.95432")


# ===========================================================================
# 2. INCREMENTAL UPDATE
# ===========================================================================

class TestIncrementalUpdate:
    """Incremental/delta mode where available."""

    def test_incremental_after_bootstrap(self):
        """After bootstrap, next sync is incremental with cursor."""
        fixture_v1 = load_json("cve_published.json")
        fixture_v2 = load_json("cve_published_updated.json")

        # Bootstrap
        adapter1 = FixtureCveAdapter(
            records=[fixture_v1],
            cursor_after="2024-04-15T12:00:00Z",
        )
        with get_db_connection() as conn:
            sync_source(conn, adapter1)

        # Incremental
        adapter2 = FixtureCveAdapter(
            records=[fixture_v2],
            cursor_after="2024-04-16T12:00:00Z",
        )
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter2)

        assert outcome.success is True
        assert outcome.sync_mode == "incremental"  # cursor existed
        assert outcome.cursor_after == "2024-04-16T12:00:00Z"

        with get_db_connection() as conn:
            state = get_sync_state(conn, "cve")
            assert state.cursor_value == "2024-04-16T12:00:00Z"
            revisions = get_source_record_revisions(conn, "cve", "CVE-2024-1234")
            assert len(revisions) == 2


# ===========================================================================
# 3. UNCHANGED RERUN (dedup)
# ===========================================================================

class TestUnchangedRerun:
    """Source identity + canonical content hash dedup."""

    def test_unchanged_records_stored_once(self):
        """Re-syncing identical content creates no new revisions."""
        fixture = load_json("cve_published.json")
        adapter = FixtureCveAdapter(
            records=[fixture],
            cursor_after="2024-04-15T12:00:00Z",
        )
        with get_db_connection() as conn:
            o1 = sync_source(conn, adapter)

        # Same adapter, same data
        with get_db_connection() as conn:
            o2 = sync_source(conn, adapter)

        assert o1.records_created == 1
        assert o2.records_unchanged == 1
        assert o2.records_created == 0

        with get_db_connection() as conn:
            revisions = get_source_record_revisions(conn, "cve", "CVE-2024-1234")
            assert len(revisions) == 1  # Only one revision stored

    def test_snapshots_do_not_copy_catalogues(self):
        """Unchanged records stored once; snapshots don't duplicate."""
        fixture = load_json("cve_published.json")
        adapter = FixtureCveAdapter(records=[fixture], cursor_after="c1")
        with get_db_connection() as conn:
            o1 = sync_source(conn, adapter)

        adapter2 = FixtureCveAdapter(records=[fixture], cursor_after="c2")
        with get_db_connection() as conn:
            o2 = sync_source(conn, adapter2)

        assert o1.snapshot_id != o2.snapshot_id
        with get_db_connection() as conn:
            revisions = get_source_record_revisions(conn, "cve", "CVE-2024-1234")
            assert len(revisions) == 1  # Content stored only once


# ===========================================================================
# 4. REVISION MOVE
# ===========================================================================

class TestRevisionMove:
    """Changed records create traceable revisions/current pointers."""

    def test_revision_move_traceable(self):
        """Updated content creates new revision, prior remains traceable."""
        v1 = load_json("cve_published.json")
        v2 = load_json("cve_published_updated.json")

        adapter1 = FixtureCveAdapter(records=[v1], cursor_after="c1")
        with get_db_connection() as conn:
            sync_source(conn, adapter1)

        adapter2 = FixtureCveAdapter(records=[v2], cursor_after="c2")
        with get_db_connection() as conn:
            sync_source(conn, adapter2)

        with get_db_connection() as conn:
            revisions = get_source_record_revisions(conn, "cve", "CVE-2024-1234")
            assert len(revisions) == 2
            assert revisions[0].is_current is True
            assert revisions[1].is_current is False
            current = get_current_source_record(conn, "cve", "CVE-2024-1234")
            assert current.content_hash == revisions[0].content_hash

    def test_rejected_state_persists(self):
        """Explicit REJECTED state persists through sync."""
        fixture = load_json("cve_rejected.json")
        adapter = FixtureCveAdapter(records=[fixture], cursor_after="c1")
        with get_db_connection() as conn:
            sync_source(conn, adapter)

        with get_db_connection() as conn:
            vuln = get_canonical_vulnerability(conn, "CVE-2023-0001")
            assert vuln is not None
            assert vuln.state == "REJECTED"


# ===========================================================================
# 5. MALFORMED CANDIDATE ROLLBACK
# ===========================================================================

class TestMalformedCandidateRollback:
    """Failed validation/activation leaves active data and cursor unchanged."""

    def test_validation_failure_no_cursor_advance(self):
        """Malformed batch fails validation → cursor unchanged."""
        adapter = MockAdapter(
            source_name="cve",
            records=[{"bad": "data"}],
            validate_error="Invalid batch: missing dataType",
            cursor_after="should-not-advance",
        )
        with get_db_connection() as conn:
            # First set a known cursor
            update_sync_state(conn, "cve", cursor_value="before", success=True)
            conn.commit()

        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)

        assert outcome.success is False
        assert "Invalid batch" in outcome.error

        with get_db_connection() as conn:
            state = get_sync_state(conn, "cve")
            assert state.cursor_value == "before"  # Unchanged!
            assert state.is_healthy is False

    def test_process_error_partial_failure(self):
        """Some records fail processing → partial status, cursor not advanced."""
        good_rec = load_json("cve_published.json")
        # Use a record that passes validation (has CVE_RECORD dataType and valid CVE ID)
        # but will fail during process_record due to bad internal structure
        bad_rec = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": "CVE-2024-9876",
                "state": "INVALID_STATE",  # Will fail: state not in PUBLISHED/RESERVED/REJECTED
            },
            "containers": {},
        }
        adapter = FixtureCveAdapter(
            records=[good_rec, bad_rec],
            cursor_after="should-not-advance",
        )
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)

        assert outcome.success is False  # Has failures
        assert outcome.records_failed >= 1
        assert outcome.cursor_after is None  # Not advanced


# ===========================================================================
# 6. ACTIVATION FAILURE
# ===========================================================================

class TestActivationFailure:
    """Activation failure leaves active data and cursor unchanged."""

    def test_activation_failure_rollback(self):
        """If snapshot completion raises, cursor stays unchanged."""
        adapter = MockAdapter(
            source_name="nvd",
            records=["record1"],
            cursor_after="new-cursor",
        )

        # Set initial state
        with get_db_connection() as conn:
            update_sync_state(conn, "nvd", cursor_value="old-cursor", success=True)
            conn.commit()

        # Patch complete_sync_snapshot to raise
        with patch("app.vuln_intelligence.sync_engine.complete_sync_snapshot",
                    side_effect=Exception("DB write failed")):
            with get_db_connection() as conn:
                outcome = sync_source(conn, adapter)

        assert outcome.success is False
        assert "Activation failed" in outcome.error

        with get_db_connection() as conn:
            state = get_sync_state(conn, "nvd")
            # Cursor unchanged — last known good
            assert state.cursor_value == "old-cursor"


# ===========================================================================
# 7. OUTAGE / FETCH FAILURE
# ===========================================================================

class TestOutage:
    """Source outage leaves last known good active."""

    def test_fetch_error_preserves_last_good(self):
        """Source outage: fetch fails, cursor unchanged, health degraded."""
        # Establish initial good state
        fixture = load_json("cve_published.json")
        adapter_good = FixtureCveAdapter(records=[fixture], cursor_after="good-cursor")
        with get_db_connection() as conn:
            sync_source(conn, adapter_good)

        # Now simulate outage
        adapter_bad = FixtureCveAdapter(fetch_error="Connection refused")
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter_bad)

        assert outcome.success is False
        assert "Connection refused" in outcome.error

        with get_db_connection() as conn:
            state = get_sync_state(conn, "cve")
            assert state.cursor_value == "good-cursor"  # Preserved!
            assert state.is_healthy is False
            assert state.consecutive_failures == 1
            # Data still accessible
            vuln = get_canonical_vulnerability(conn, "CVE-2024-1234")
            assert vuln is not None

    def test_fetch_exception_handled(self):
        """Fetch raising an exception is caught gracefully."""
        class CrashAdapter:
            source_name = "kev"
            def fetch(self, conn, cursor, **kw):
                raise ConnectionError("Network unreachable")
            def validate_batch(self, records):
                return True, None
            def process_record(self, conn, record, snapshot_id):
                return True, True, None

        with get_db_connection() as conn:
            outcome = sync_source(conn, CrashAdapter())

        assert outcome.success is False
        assert "Network unreachable" in outcome.error


# ===========================================================================
# 8. CURSOR SAFETY
# ===========================================================================

class TestCursorSafety:
    """Cursor advances ONLY after successful activation."""

    def test_cursor_only_advances_on_full_success(self):
        """No failures → cursor advances."""
        adapter = MockAdapter(
            source_name="osv",
            records=["r1", "r2"],
            cursor_after="new-cursor",
        )
        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)

        assert outcome.success is True
        with get_db_connection() as conn:
            state = get_sync_state(conn, "osv")
            assert state.cursor_value == "new-cursor"

    def test_cursor_frozen_on_any_failure(self):
        """Any failure → cursor stays at previous value."""
        adapter = MockAdapter(
            source_name="osv",
            records=["r1", "r2"],
            cursor_after="new-cursor",
            process_errors={1: "Record 2 corrupt"},
        )
        with get_db_connection() as conn:
            update_sync_state(conn, "osv", cursor_value="old-cursor", success=True)
            conn.commit()

        with get_db_connection() as conn:
            outcome = sync_source(conn, adapter)

        assert outcome.success is False
        with get_db_connection() as conn:
            state = get_sync_state(conn, "osv")
            assert state.cursor_value == "old-cursor"  # Frozen!

    def test_absence_not_deletion(self):
        """Absence from incremental response is never deletion."""
        v1 = load_json("cve_published.json")
        rejected = load_json("cve_rejected.json")

        # Bootstrap with two CVEs
        adapter1 = FixtureCveAdapter(records=[v1, rejected], cursor_after="c1")
        with get_db_connection() as conn:
            sync_source(conn, adapter1)

        # Incremental mentions only CVE-2024-1234 — CVE-2023-0001 absent
        v2 = load_json("cve_published_updated.json")
        adapter2 = FixtureCveAdapter(records=[v2], cursor_after="c2")
        with get_db_connection() as conn:
            sync_source(conn, adapter2)

        with get_db_connection() as conn:
            # CVE-2023-0001 must still exist (absence != deletion)
            still_exists = get_canonical_vulnerability(conn, "CVE-2023-0001")
            assert still_exists is not None
            assert still_exists.state == "REJECTED"


# ===========================================================================
# 9. SOURCE INDEPENDENCE
# ===========================================================================

class TestSourceIndependence:
    """Sources fail independently; one failure never blocks another."""

    def test_one_source_failure_others_succeed(self):
        """NVD fails, KEV succeeds — independent."""
        # NVD fails
        nvd_adapter = MockAdapter(
            source_name="nvd",
            fetch_error="NVD API 503",
        )
        with get_db_connection() as conn:
            nvd_outcome = sync_source(conn, nvd_adapter)

        # KEV succeeds
        catalog = load_json("kev_catalog.json")
        kev_adapter = FixtureKevAdapter(
            records=catalog["vulnerabilities"],
            cursor_after="2024-04-15",
        )
        with get_db_connection() as conn:
            kev_outcome = sync_source(conn, kev_adapter)

        assert nvd_outcome.success is False
        assert kev_outcome.success is True

        with get_db_connection() as conn:
            nvd_state = get_sync_state(conn, "nvd")
            kev_state = get_sync_state(conn, "kev")
            assert nvd_state.is_healthy is False
            assert kev_state.is_healthy is True
            assert kev_state.cursor_value == "2024-04-15"


# ===========================================================================
# 10. ADVISORY LOCK OVERLAP
# ===========================================================================

class TestLockOverlap:
    """Prevent overlapping runs for the same source using advisory locks."""

    def test_lock_prevents_concurrent_sync(self):
        """Second sync for same source is rejected while lock held."""
        with get_db_connection() as conn:
            # Manually acquire lock
            assert try_advisory_lock(conn, "cve") is True

            # Try to sync — should fail (lock held)
            adapter = MockAdapter(source_name="cve", records=["r1"])
            with get_db_connection() as conn2:
                outcome = sync_source(conn2, adapter)

            assert outcome.success is False
            assert outcome.skipped_overlap is True
            assert "advisory lock" in outcome.error.lower()

            # Release lock
            release_advisory_lock(conn, "cve")

    def test_lock_key_unique_per_source(self):
        """Different sources have different lock keys."""
        key_cve = _source_lock_key("cve")
        key_nvd = _source_lock_key("nvd")
        key_kev = _source_lock_key("kev")
        assert key_cve != key_nvd
        assert key_nvd != key_kev

    def test_lock_released_after_sync(self):
        """Lock is released after sync completes (success or failure)."""
        adapter = MockAdapter(source_name="epss", records=["r1"])
        with get_db_connection() as conn:
            sync_source(conn, adapter)

        # Should be able to acquire lock now
        with get_db_connection() as conn:
            assert try_advisory_lock(conn, "epss") is True
            release_advisory_lock(conn, "epss")

    def test_lock_released_on_failure(self):
        """Lock is released even when sync fails."""
        adapter = MockAdapter(
            source_name="osv",
            fetch_error="Connection timeout",
        )
        with get_db_connection() as conn:
            sync_source(conn, adapter)

        with get_db_connection() as conn:
            assert try_advisory_lock(conn, "osv") is True
            release_advisory_lock(conn, "osv")


# ===========================================================================
# 11. SCHEDULE CONFIGURATION
# ===========================================================================

class TestScheduleConfiguration:
    """Configurable scheduling defaults and cadences."""

    def test_default_intervals(self):
        """Default intervals match spec: CVE/NVD/KEV/OSV 20m, EPSS daily."""
        assert DEFAULT_INTERVALS["cve"] == 1200
        assert DEFAULT_INTERVALS["nvd"] == 1200
        assert DEFAULT_INTERVALS["kev"] == 1200
        assert DEFAULT_INTERVALS["osv"] == 1200
        assert DEFAULT_INTERVALS["epss"] == 86400

    def test_scheduling_disabled_by_default(self):
        """Scheduling is disabled unless explicitly configured."""
        with get_db_connection() as conn:
            for source in ["cve", "nvd", "kev", "epss", "osv"]:
                config = get_schedule_config(conn, source)
                assert config["enabled"] is False

    def test_no_sources_due_when_disabled(self):
        """With scheduling disabled, no sources are due."""
        with get_db_connection() as conn:
            due = get_sources_due_for_sync(conn)
            assert due == []

    def test_enable_scheduling(self):
        """Enabling scheduling for a source."""
        with get_db_connection() as conn:
            set_schedule_config(conn, "cve", enabled=True, interval_seconds=600)
            conn.commit()

            config = get_schedule_config(conn, "cve")
            assert config["enabled"] is True
            assert config["interval_seconds"] == 600

    def test_enabled_source_appears_due(self):
        """Enabled source with no next_sync_at is immediately due."""
        with get_db_connection() as conn:
            set_schedule_config(conn, "kev", enabled=True)
            conn.commit()

            due = get_sources_due_for_sync(conn)
            assert "kev" in due

    def test_advance_next_sync_sets_future(self):
        """After sync, next_sync_at is set to now + interval."""
        with get_db_connection() as conn:
            set_schedule_config(conn, "nvd", enabled=True, interval_seconds=1200)
            conn.commit()

            advance_next_sync(conn, "nvd")
            conn.commit()

            config = get_schedule_config(conn, "nvd")
            assert config["next_sync_at"] is not None
            # After advancing, source should NOT be immediately due
            due = get_sources_due_for_sync(conn)
            assert "nvd" not in due

    def test_custom_interval_per_source(self):
        """Each source can have its own interval."""
        with get_db_connection() as conn:
            set_schedule_config(conn, "cve", interval_seconds=300)
            set_schedule_config(conn, "epss", interval_seconds=86400)
            conn.commit()

            cve_config = get_schedule_config(conn, "cve")
            epss_config = get_schedule_config(conn, "epss")
            assert cve_config["interval_seconds"] == 300
            assert epss_config["interval_seconds"] == 86400

    def test_tests_startup_never_call_internet(self):
        """Scheduling disabled by default → tests/startup never call internet."""
        with get_db_connection() as conn:
            states = get_all_sync_states(conn)
            for state in states:
                # sync_enabled should be False in the DB
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT sync_enabled FROM sync_state WHERE source = %s;",
                        (state.source,),
                    )
                    row = cur.fetchone()
                    assert row["sync_enabled"] is False, \
                        f"Source {state.source} has sync_enabled=True — tests could call internet!"


# ===========================================================================
# 12. BOUNDED BEHAVIOR
# ===========================================================================

class TestBoundedBehavior:
    """Pagination, batches, and timeouts are bounded."""

    def test_batch_size_passed_to_fetch(self):
        """batch_size parameter is passed through to the adapter."""
        received_batch_size = None

        class CapturingAdapter:
            source_name = "cve"
            def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                nonlocal received_batch_size
                received_batch_size = batch_size
                return FetchResult(records=[], cursor_after=None)
            def validate_batch(self, records):
                return True, None
            def process_record(self, conn, record, snapshot_id):
                return True, True, None

        with get_db_connection() as conn:
            sync_source(conn, CapturingAdapter(), batch_size=500)

        assert received_batch_size == 500

    def test_timeout_passed_to_fetch(self):
        """timeout_seconds parameter is passed through."""
        received_timeout = None

        class CapturingAdapter:
            source_name = "nvd"
            def fetch(self, conn, cursor, *, batch_size=1000, timeout_seconds=300):
                nonlocal received_timeout
                received_timeout = timeout_seconds
                return FetchResult(records=[], cursor_after=None)
            def validate_batch(self, records):
                return True, None
            def process_record(self, conn, record, snapshot_id):
                return True, True, None

        with get_db_connection() as conn:
            sync_source(conn, CapturingAdapter(), timeout_seconds=60)

        assert received_timeout == 60


# ===========================================================================
# 13. HEALTH FIELDS
# ===========================================================================

class TestHealthFields:
    """Observable per-source state: last attempt/success, cursor, etc."""

    def test_health_after_success(self):
        """After successful sync, health fields are populated."""
        adapter = MockAdapter(
            source_name="cve",
            records=["r1", "r2"],
            cursor_after="cursor-1",
        )
        with get_db_connection() as conn:
            sync_source(conn, adapter)

        with get_db_connection() as conn:
            health = get_source_health(conn, "cve")
            assert health is not None
            assert health.is_healthy is True
            assert health.last_attempted_at is not None
            assert health.last_successful_at is not None
            assert health.cursor_value == "cursor-1"
            assert health.consecutive_failures == 0
            assert health.last_error is None
            assert health.last_snapshot_id is not None

    def test_health_after_failure(self):
        """After failed sync, health shows degradation."""
        adapter = MockAdapter(
            source_name="nvd",
            fetch_error="API rate limited",
        )
        with get_db_connection() as conn:
            sync_source(conn, adapter)

        with get_db_connection() as conn:
            health = get_source_health(conn, "nvd")
            assert health.is_healthy is False
            assert health.last_attempted_at is not None
            assert health.consecutive_failures == 1
            assert health.last_error == "API rate limited"

    def test_consecutive_failures_increment(self):
        """Multiple failures increment consecutive_failures."""
        adapter = MockAdapter(source_name="kev", fetch_error="Timeout")
        for _ in range(3):
            with get_db_connection() as conn:
                sync_source(conn, adapter)

        with get_db_connection() as conn:
            health = get_source_health(conn, "kev")
            assert health.consecutive_failures == 3

    def test_success_resets_failures(self):
        """Successful sync resets consecutive_failures to 0."""
        # Fail twice
        fail_adapter = MockAdapter(source_name="osv", fetch_error="Down")
        for _ in range(2):
            with get_db_connection() as conn:
                sync_source(conn, fail_adapter)

        # Then succeed
        ok_adapter = MockAdapter(source_name="osv", records=["r1"], cursor_after="c1")
        with get_db_connection() as conn:
            sync_source(conn, ok_adapter)

        with get_db_connection() as conn:
            health = get_source_health(conn, "osv")
            assert health.is_healthy is True
            assert health.consecutive_failures == 0

    def test_all_source_health(self):
        """get_all_source_health returns all five sources."""
        with get_db_connection() as conn:
            all_health = get_all_source_health(conn)
            sources = {h.source for h in all_health}
            assert sources == {"cve", "nvd", "kev", "epss", "osv"}

    def test_data_age_computed(self):
        """data_age_seconds is computed from last_successful_at."""
        adapter = MockAdapter(source_name="cve", records=["r1"], cursor_after="c1")
        with get_db_connection() as conn:
            sync_source(conn, adapter)

        with get_db_connection() as conn:
            health = get_source_health(conn, "cve")
            assert health.data_age_seconds is not None
            assert health.data_age_seconds >= 0
            assert health.data_age_seconds < 60  # Just synced

    def test_health_schedule_fields(self):
        """Health includes scheduling information."""
        with get_db_connection() as conn:
            set_schedule_config(conn, "epss", enabled=True, interval_seconds=86400)
            conn.commit()

            health = get_source_health(conn, "epss")
            assert health.sync_enabled is True
            assert health.sync_interval_seconds == 86400


# ===========================================================================
# 14. ADAPTER VALIDATION
# ===========================================================================

class TestAdapterValidation:
    """Sync adapter validate_batch correctness."""

    def test_cve_adapter_validates_envelope(self):
        """CveSyncAdapter rejects records without CVE_RECORD dataType."""
        adapter = CveSyncAdapter()
        valid, err = adapter.validate_batch([{"dataType": "NOT_CVE", "cveMetadata": {"cveId": "CVE-2024-1234"}}])
        assert valid is False
        assert "dataType" in err

    def test_cve_adapter_validates_cve_id(self):
        """CveSyncAdapter rejects invalid CVE IDs."""
        adapter = CveSyncAdapter()
        valid, err = adapter.validate_batch([{"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "INVALID"}}])
        assert valid is False

    def test_kev_adapter_validates_cve_id(self):
        """KevSyncAdapter rejects entries with invalid CVE IDs."""
        adapter = KevSyncAdapter()
        valid, err = adapter.validate_batch([{"cveID": "INVALID"}])
        assert valid is False

    def test_epss_adapter_validates_format(self):
        """EpssSyncAdapter validates CSV text format."""
        adapter = EpssSyncAdapter()
        # Must be exactly 1 CSV string
        valid, err = adapter.validate_batch([])
        assert valid is False
        # Must have metadata header
        valid, err = adapter.validate_batch(["cve,epss,percentile\n"])
        assert valid is False

    def test_osv_adapter_validates_id(self):
        """OsvSyncAdapter rejects records without id."""
        adapter = OsvSyncAdapter()
        valid, err = adapter.validate_batch([{"id": ""}])
        assert valid is False

    def test_valid_batches_pass(self):
        """Valid fixture data passes validation."""
        cve_adapter = CveSyncAdapter()
        valid, err = cve_adapter.validate_batch([load_json("cve_published.json")])
        assert valid is True

        kev_adapter = KevSyncAdapter()
        catalog = load_json("kev_catalog.json")
        valid, err = kev_adapter.validate_batch(catalog["vulnerabilities"])
        assert valid is True


# ===========================================================================
# 15. ADAPTER REGISTRY
# ===========================================================================

class TestAdapterRegistry:
    """All five adapters registered."""

    def test_all_five_registered(self):
        assert set(ALL_ADAPTERS.keys()) == {"cve", "nvd", "kev", "epss", "osv"}

    def test_source_names_match_keys(self):
        for key, adapter in ALL_ADAPTERS.items():
            assert adapter.source_name == key


# ===========================================================================
# 16. MIGRATION 009
# ===========================================================================

class TestMigration009:
    """Migration 009 adds scheduling columns to sync_state."""

    def test_sync_state_has_scheduling_columns(self):
        """sync_state has sync_enabled, sync_interval_seconds, next_sync_at."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'sync_state'
                    AND column_name IN (
                        'sync_enabled', 'sync_interval_seconds', 'next_sync_at',
                        'last_sync_duration_ms', 'active_record_count', 'last_good_snapshot_id'
                    )
                    ORDER BY column_name;
                """)
                cols = {r["column_name"] for r in cur.fetchall()}
                expected = {
                    "sync_enabled", "sync_interval_seconds", "next_sync_at",
                    "last_sync_duration_ms", "active_record_count", "last_good_snapshot_id",
                }
                assert cols == expected

    def test_default_intervals_in_db(self):
        """Migration seeds default interval values."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT source, sync_interval_seconds FROM sync_state ORDER BY source;")
                rows = {r["source"]: r["sync_interval_seconds"] for r in cur.fetchall()}
                assert rows["cve"] == 1200
                assert rows["nvd"] == 1200
                assert rows["kev"] == 1200
                assert rows["osv"] == 1200
                assert rows["epss"] == 86400

    def test_sync_enabled_default_false(self):
        """All sources have sync_enabled=FALSE by default."""
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT source, sync_enabled FROM sync_state;")
                for row in cur.fetchall():
                    assert row["sync_enabled"] is False

    def test_migration_009_idempotent(self):
        """Running migration 009 again does not error."""
        migration_path = Path(__file__).parent.parent / "migrations" / "009_sync_orchestration.sql"
        sql = migration_path.read_text(encoding="utf-8")
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.commit()
        # Should not raise
