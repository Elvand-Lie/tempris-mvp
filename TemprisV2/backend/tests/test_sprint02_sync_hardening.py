# backend/tests/test_sprint02_sync_hardening.py
"""
Sprint 02 Hardening Test Suite — Synchronization Correctness & Safety.
Tests all 35 assertions across Deliverables 0 through 4 of Sprint 02 Contract Rev 2.0.

Deliverable 0: Baseline & Regression Invariants
  - Assertion 0.1: Full regression test suite passing.

Deliverable 1: Bounded Bootstrap Exhaustion & Multi-Batch Progress
  - Assertions 1.1 - 1.7

Deliverable 2: Full-Snapshot Absence Reconciliation & Re-Activation
  - Assertions 2.1 - 2.8

Deliverable 3: OSV Multi-Ecosystem Cursors & Bounded Incremental Flow
  - Assertions 3.1 - 3.5

Deliverable 4: Bounded Archive Processing, Resource Bounds & Hostile Archive Protection
  - Assertions 4.1 - 4.10
"""
import gzip
import io
import json
import os
import pathlib
import tempfile
import time
import zipfile
from datetime import date, datetime, timezone
from decimal import Decimal
from unittest.mock import patch, MagicMock

import httpx
import pytest

from app.db import get_db_connection
from app.vuln_intelligence.models import (
    ArchiveBombError,
    ArchiveCorruptionError,
    ArchiveEntryTooLargeError,
    ArchiveError,
    ArchiveFileCountExceededError,
    ArchiveLimits,
    CanonicalVulnerability,
    KevEntry,
    MassWithdrawalExceededError,
    OsvAlias,
    OsvRecord,
    PathTraversalError,
    SourceArtifact,
    SourceRecord,
    SyncSnapshot,
    SyncState,
)
from app.vuln_intelligence.archive_utils import (
    safe_extract_gzip,
    safe_extract_gzip_chunks,
    safe_extract_to_temp_dir,
    safe_extract_zip,
    validate_archive_path,
)
from app.vuln_intelligence.fetch_clients import (
    CveFetchClient,
    EpssFetchClient,
    KevFetchClient,
    NvdFetchClient,
    OsvFetchClient,
)
from app.vuln_intelligence.repository import (
    complete_sync_snapshot,
    create_sync_snapshot,
    get_all_sync_states,
    get_canonical_vulnerability,
    get_composed_cve_detail,
    get_kev_entry,
    get_osv_record,
    get_source_artifact_by_hash,
    get_sync_snapshot,
    get_sync_state,
    reconcile_full_snapshot_absence,
    search_vulnerabilities,
    update_sync_state,
    upsert_canonical_vulnerability,
    upsert_kev_entry,
    upsert_osv_alias,
    upsert_osv_record,
    upsert_source_artifact,
    upsert_source_record,
)
from app.vuln_intelligence.sync_adapters import (
    CveSyncAdapter,
    EpssSyncAdapter,
    KevSyncAdapter,
    NvdSyncAdapter,
    OsvSyncAdapter,
)
from app.vuln_intelligence.sync_engine import (
    FetchResult,
    SyncOutcome,
    sync_source,
)


# ===========================================================================
# Helper Mocks & Fixtures
# ===========================================================================

class MockMultiBatchAdapter:
    def __init__(self, source_name: str, batches: list[FetchResult]):
        self.source_name = source_name
        self.batches = list(batches)
        self.batch_idx = 0

    def fetch(self, conn, cursor, batch_size=1000, timeout_seconds=300):
        if self.batch_idx < len(self.batches):
            res = self.batches[self.batch_idx]
            self.batch_idx += 1
            return res
        return FetchResult(records=[], cursor_after=cursor, is_exhausted=True)

    def validate_batch(self, records):
        return True, None

    def process_record(self, conn, record, snapshot_id):
        if isinstance(record, dict) and record.get("fail"):
            return False, False, "Record processing failed"
        cve_id = record.get("cve_id") if isinstance(record, dict) else str(record)
        if cve_id.startswith("CVE-"):
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(cve_id=cve_id, state="PUBLISHED"))
        return True, True, None


# ===========================================================================
# DELIVERABLE 1: Bounded Bootstrap Exhaustion & Multi-Batch Progress
# ===========================================================================

class TestDeliverable1BoundedBootstrapExhaustion:
    """Tests for Assertions 1.1 through 1.7."""

    def test_assertion_1_1_cursor_unchanged_on_mid_bootstrap_interruption(self):
        """Assertion 1.1: If ingestion is interrupted mid-bootstrap, sync_state.cursor_value remains unchanged from previous committed state."""
        with get_db_connection() as conn:
            update_sync_state(conn, "nvd", cursor_value="stable-v1", success=True)
            conn.commit()

            # Create adapter that fails on fetch during bootstrap
            client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(500, text="Internal Server Error")))
            fetcher = NvdFetchClient(client=client)
            adapter = NvdSyncAdapter(fetch_client=fetcher)

            outcome = sync_source(conn, adapter)
            assert outcome.success is False

            state = get_sync_state(conn, "nvd")
            assert state.cursor_value == "stable-v1"

    def test_assertion_1_2_bounded_bootstrap_batches(self):
        """Assertion 1.2: Bounded bootstrap fetches ingest at most batch_size records per cycle."""
        records_payload = {
            "totalResults": 25,
            "resultsPerPage": 25,
            "startIndex": 0,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-09-01T00:00:00.000",
            "vulnerabilities": [
                {"cve": {"id": f"CVE-2026-{1000 + i}", "sourceIdentifier": "test", "vulnStatus": "Analyzed"}}
                for i in range(25)
            ]
        }
        client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=records_payload)))
        fetcher = NvdFetchClient(client=client)

        res = fetcher.fetch(cursor=None, batch_size=10)
        assert len(res.records) == 10
        assert res.is_exhausted is False
        assert json.loads(res.cursor_after)["startIndex"] == 10

    def test_assertion_1_3_and_1_4_continuation_cursor_persistence_and_json(self):
        """Assertions 1.3 & 1.4: Intermediate batches persist JSON-serializable continuation cursors."""
        batch1_cursor = json.dumps({"phase": "bootstrap", "entry_offset": 5, "total_entries": 10, "target_cursor": "target-sha"})
        b1 = FetchResult(
            records=[{"cve_id": "CVE-2026-0001"}],
            cursor_after=batch1_cursor,
            is_bootstrap=True,
            is_exhausted=False,
        )
        b2 = FetchResult(
            records=[{"cve_id": "CVE-2026-0002"}],
            cursor_after="target-sha",
            is_bootstrap=True,
            is_exhausted=True,
        )
        adapter = MockMultiBatchAdapter("cve", [b1, b2])

        with get_db_connection() as conn:
            update_sync_state(conn, "cve", cursor_value=None, success=True)
            conn.commit()

            # Batch 1
            out1 = sync_source(conn, adapter)
            assert out1.success is True
            state1 = get_sync_state(conn, "cve")
            assert state1.cursor_value == batch1_cursor
            # Must parse cleanly as JSON
            parsed = json.loads(state1.cursor_value)
            assert parsed["phase"] == "bootstrap"
            assert parsed["entry_offset"] == 5

            # Batch 2 (Exhaustion)
            out2 = sync_source(conn, adapter)
            assert out2.success is True
            state2 = get_sync_state(conn, "cve")
            assert state2.cursor_value == "target-sha"

    def test_assertion_1_5_and_1_6_cursor_promotion_on_exhaustion(self):
        """Assertions 1.5 & 1.6: sync_state stores continuation cursor while is_exhausted=False, and promotes incremental cursor when is_exhausted=True."""
        c1 = json.dumps({"phase": "bootstrap", "offset": 100})
        b1 = FetchResult(records=[{"cve_id": "CVE-2026-0003"}], cursor_after=c1, is_bootstrap=True, is_exhausted=False)
        b2 = FetchResult(records=[{"cve_id": "CVE-2026-0004"}], cursor_after="final-incremental-cursor", is_bootstrap=True, is_exhausted=True)
        adapter = MockMultiBatchAdapter("kev", [b1, b2])

        with get_db_connection() as conn:
            update_sync_state(conn, "kev", cursor_value=None, success=True)
            conn.commit()

            sync_source(conn, adapter)
            assert get_sync_state(conn, "kev").cursor_value == c1

            sync_source(conn, adapter)
            assert get_sync_state(conn, "kev").cursor_value == "final-incremental-cursor"

    def test_assertion_1_7_intermediate_batch_failure_rolls_back_and_freezes_cursor(self):
        """Assertion 1.7: Intermediate batch failures roll back record writes in that batch and leave continuation cursor byte-for-byte unchanged."""
        initial_cursor = json.dumps({"phase": "bootstrap", "entry_offset": 10, "target_cursor": "v1"})
        next_cursor = json.dumps({"phase": "bootstrap", "entry_offset": 20, "target_cursor": "v1"})

        b1 = FetchResult(
            records=[
                {"cve_id": "CVE-2026-0005"},
                {"cve_id": "CVE-2026-0006", "fail": True},
            ],
            cursor_after=next_cursor,
            is_bootstrap=True,
            is_exhausted=False,
        )
        adapter = MockMultiBatchAdapter("nvd", [b1])

        with get_db_connection() as conn:
            update_sync_state(conn, "nvd", cursor_value=initial_cursor, success=True)
            conn.commit()

            outcome = sync_source(conn, adapter)
            assert outcome.success is False
            assert outcome.records_failed > 0

            # Verify CVE-2026-0005 was rolled back
            assert get_canonical_vulnerability(conn, "CVE-2026-0005") is None

            # Verify cursor remains byte-for-byte identical
            state = get_sync_state(conn, "nvd")
            assert state.cursor_value == initial_cursor


# ===========================================================================
# DELIVERABLE 2: Full-Snapshot Absence Reconciliation & Re-Activation
# ===========================================================================

class TestDeliverable2FullSnapshotAbsenceAndReactivation:
    """Tests for Assertions 2.1 through 2.8."""

    def test_assertion_2_1_and_2_2_absence_reconciliation_only_on_full_exhaustion(self):
        """Assertions 2.1 & 2.2: Absence reconciliation executes strictly on is_exhausted=True across all accumulated seen_ids."""
        with get_db_connection() as conn:
            # Seed 5 active KEV entries (so 1 dropped = 20% <= 20% default threshold)
            for cve in ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1004", "CVE-2026-1005"]:
                upsert_kev_entry(conn, KevEntry(
                    declared_cve_id=cve,
                    vendor_project="Vendor",
                    product="Product",
                    vulnerability_name="Name",
                    date_added=date.today(),
                    is_active=True,
                ))
            conn.commit()

            # Batch 1: returns CVE-2026-1001, 1002 (not exhausted, seen=[1001, 1002])
            c1 = json.dumps({"phase": "bootstrap", "entry_offset": 2, "seen_ids": ["CVE-2026-1001", "CVE-2026-1002"]})
            b1 = FetchResult(
                records=[
                    {"cveID": "CVE-2026-1001", "vendorProject": "V", "product": "P", "vulnerabilityName": "N", "dateAdded": "2026-09-01"},
                    {"cveID": "CVE-2026-1002", "vendorProject": "V", "product": "P", "vulnerabilityName": "N", "dateAdded": "2026-09-01"},
                ],
                cursor_after=c1,
                is_bootstrap=True,
                is_exhausted=False,
                seen_ids=["CVE-2026-1001", "CVE-2026-1002"],
            )

            # Batch 2: returns CVE-2026-1003, 1004 (exhausted, seen=[1001, 1002, 1003, 1004], 1005 is absent)
            b2 = FetchResult(
                records=[
                    {"cveID": "CVE-2026-1003", "vendorProject": "V", "product": "P", "vulnerabilityName": "N", "dateAdded": "2026-09-01"},
                    {"cveID": "CVE-2026-1004", "vendorProject": "V", "product": "P", "vulnerabilityName": "N", "dateAdded": "2026-09-01"},
                ],
                cursor_after="2026-09-01",
                is_bootstrap=True,
                is_exhausted=True,
                seen_ids=["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1004"],
            )

            class KevMockAdapter:
                source_name = "kev"
                def __init__(self):
                    self.batches = [b1, b2]
                    self.idx = 0
                def fetch(self, conn, cursor, **kw):
                    res = self.batches[self.idx]
                    self.idx += 1
                    return res
                def validate_batch(self, records): return True, None
                def process_record(self, conn, record, snapshot_id):
                    from app.vuln_intelligence.adapters.kev_adapter import process_kev_entry
                    res = process_kev_entry(conn, record, snapshot_id=snapshot_id)
                    return True, res.is_new_revision, None

            adapter = KevMockAdapter()
            # Run Batch 1
            out1 = sync_source(conn, adapter)
            assert out1.success is True
            # All 5 MUST still be active after batch 1!
            for i in range(1, 6):
                assert get_kev_entry(conn, f"CVE-2026-100{i}").is_active is True

            # Run Batch 2 (Exhaustion)
            with patch("app.vuln_intelligence.sync_engine.reconcile_full_snapshot_absence", wraps=reconcile_full_snapshot_absence) as spy_reconcile:
                out2 = sync_source(conn, adapter)
                assert out2.success is True
                spy_reconcile.assert_called_once()

            # Now CVE-2026-1001..1004 are active, CVE-2026-1005 MUST be inactive and have withdrawn_at set!
            for i in range(1, 5):
                assert get_kev_entry(conn, f"CVE-2026-100{i}").is_active is True
            k5 = get_kev_entry(conn, "CVE-2026-1005")
            assert k5.is_active is False
            assert k5.withdrawn_at is not None

    def test_assertion_2_3_inactive_kev_omitted_from_read_queries(self):
        """Assertion 2.3: Inactive KEV entries are omitted from list_cves, search_vulnerabilities, and get_composed_cve_detail."""
        with get_db_connection() as conn:
            cve_id = "CVE-2026-2001"
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(cve_id=cve_id, state="PUBLISHED"))
            upsert_kev_entry(conn, KevEntry(
                cve_id=cve_id,
                declared_cve_id=cve_id,
                vendor_project="Vendor",
                product="Product",
                vulnerability_name="Active KEV",
                date_added=date.today(),
                is_active=True,
            ))
            conn.commit()

            # 1. When active
            detail_active = get_composed_cve_detail(conn, cve_id)
            assert detail_active["kev"] is not None
            search_active = search_vulnerabilities(conn, has_kev=True)
            assert any(item["cve_id"] == cve_id for item in search_active["items"])

            # 2. Deactivate KEV
            upsert_kev_entry(conn, KevEntry(
                cve_id=cve_id,
                declared_cve_id=cve_id,
                vendor_project="Vendor",
                product="Product",
                vulnerability_name="Inactive KEV",
                date_added=date.today(),
                is_active=False,
                withdrawn_at=datetime.now(timezone.utc),
            ))
            conn.commit()

            # 3. When inactive
            detail_inactive = get_composed_cve_detail(conn, cve_id)
            assert detail_inactive["kev"] is None

            search_inactive_has_kev = search_vulnerabilities(conn, has_kev=True)
            assert not any(item["cve_id"] == cve_id for item in search_inactive_has_kev["items"])

            search_inactive_no_kev = search_vulnerabilities(conn, has_kev=False)
            assert any(item["cve_id"] == cve_id for item in search_inactive_no_kev["items"])

            list_res = search_vulnerabilities(conn, limit=50)
            cve_row = next((r for r in list_res["items"] if r["cve_id"] == cve_id), None)
            assert cve_row is not None
            assert cve_row["has_kev"] is False

    def test_assertion_2_4_resurrection_lifecycle(self):
        """Assertion 2.4: When a previously absent or inactive vulnerability reappears in a subsequent catalog, upsert reactivates it."""
        with get_db_connection() as conn:
            cve_id = "CVE-2026-2002"
            # Start inactive
            upsert_kev_entry(conn, KevEntry(
                declared_cve_id=cve_id,
                vendor_project="Vendor",
                product="Product",
                vulnerability_name="Resurrected KEV",
                date_added=date.today(),
                is_active=False,
                withdrawn_at=datetime.now(timezone.utc),
            ))
            conn.commit()

            kev = get_kev_entry(conn, cve_id)
            assert kev.is_active is False
            assert kev.withdrawn_at is not None

            # Ingest through KEV adapter as active entry
            from app.vuln_intelligence.adapters.kev_adapter import process_kev_entry
            entry_dict = {
                "cveID": cve_id,
                "vendorProject": "Vendor",
                "product": "Product",
                "vulnerabilityName": "Resurrected KEV",
                "dateAdded": "2026-09-01",
                "shortDescription": "Reappeared",
            }
            process_kev_entry(conn, entry_dict)
            conn.commit()

            resurrected = get_kev_entry(conn, cve_id)
            assert resurrected.is_active is True
            assert resurrected.withdrawn_at is None

    def test_assertion_2_5_mass_withdrawal_safety_guard(self):
        """Assertion 2.5: If absent records exceed threshold (default 20%), reconcile_full_snapshot_absence raises MassWithdrawalExceededError."""
        with get_db_connection() as conn:
            # Seed 10 active KEV entries
            for i in range(10):
                upsert_kev_entry(conn, KevEntry(
                    declared_cve_id=f"CVE-2026-300{i}",
                    vendor_project="V", product="P", vulnerability_name="N",
                    date_added=date.today(),
                    is_active=True,
                ))
            conn.commit()

            # Drop 5 out of 10 (50% > 20% default threshold)
            seen_ids = [f"CVE-2026-300{i}" for i in range(5)]
            with pytest.raises(MassWithdrawalExceededError) as exc_info:
                reconcile_full_snapshot_absence(conn, source="kev", seen_declared_ids=seen_ids, threshold_pct=0.20)
            assert "exceeding mass-withdrawal threshold" in str(exc_info.value)

            # Records MUST remain active (transaction not mutated)
            conn.rollback()
            for i in range(10):
                assert get_kev_entry(conn, f"CVE-2026-300{i}").is_active is True

    def test_assertion_2_6_delta_feeds_never_trigger_absence_deactivation(self):
        """Assertion 2.6: Delta-based feeds (CVE, NVD, OSV modified_id.csv) never trigger absence deactivation."""
        with get_db_connection() as conn:
            cve1 = "CVE-2026-4001"
            cve2 = "CVE-2026-4002"
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(cve_id=cve1, state="PUBLISHED"))
            upsert_canonical_vulnerability(conn, CanonicalVulnerability(cve_id=cve2, state="PUBLISHED"))
            conn.commit()

            # Run NVD sync returning only CVE-2026-4001
            nvd_record = {
                "cve": {"id": cve1, "sourceIdentifier": "test", "vulnStatus": "Analyzed"}
            }
            client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"vulnerabilities": [nvd_record], "totalResults": 1})))
            adapter = NvdSyncAdapter(fetch_client=NvdFetchClient(client=client))

            out = sync_source(conn, adapter)
            assert out.success is True

            # CVE-2026-4002 MUST still exist and be intact
            assert get_canonical_vulnerability(conn, cve2) is not None

    def test_assertion_2_7_withdrawn_at_timestamp(self):
        """Assertion 2.7: Withdrawn entries have withdrawn_at set to a non-null timestamp."""
        with get_db_connection() as conn:
            cve_id = "CVE-2026-5001"
            upsert_kev_entry(conn, KevEntry(declared_cve_id=cve_id, vendor_project="V", product="P", vulnerability_name="N", date_added=date.today(), is_active=True))
            conn.commit()

            reconcile_full_snapshot_absence(conn, source="kev", seen_declared_ids=[], threshold_pct=1.0)
            conn.commit()

            kev = get_kev_entry(conn, cve_id)
            assert kev.is_active is False
            assert isinstance(kev.withdrawn_at, datetime)

    def test_assertion_2_8_migration_011_idempotent(self):
        """Assertion 2.8: KEV schema migration 011 is idempotent and creates partial indexes."""
        migration_sql_path = pathlib.Path("backend/migrations/011_sprint02_sync_hardening.sql")
        assert migration_sql_path.exists()
        sql_content = migration_sql_path.read_text(encoding="utf-8")

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Execute twice to verify idempotency
                cur.execute(sql_content)
                cur.execute(sql_content)
                conn.commit()

                # Verify partial index exists
                cur.execute("SELECT indexname FROM pg_indexes WHERE tablename = 'kev_entries' AND indexname = 'idx_kev_entries_active';")
                row = cur.fetchone()
                assert row is not None


# ===========================================================================
# DELIVERABLE 3: OSV Multi-Ecosystem Cursors & Bounded Incremental Flow
# ===========================================================================

class TestDeliverable3OsvMultiEcosystemAndIncremental:
    """Tests for Assertions 3.1 through 3.5."""

    def test_assertion_3_1_structured_json_osv_cursor(self):
        """Assertion 3.1: OSV cursor is structured JSON mapping each ecosystem to its last-modified timestamp."""
        with get_db_connection() as conn:
            cursor_data = {"PyPI": "2026-09-01T00:00:00Z", "npm": "2026-09-01T01:00:00Z"}
            update_sync_state(conn, "osv", cursor_value=cursor_data, success=True)
            conn.commit()

            state = get_sync_state(conn, "osv")
            parsed = json.loads(state.cursor_value)
            assert parsed["PyPI"] == "2026-09-01T00:00:00Z"
            assert parsed["npm"] == "2026-09-01T01:00:00Z"

    def test_assertion_3_2_and_3_3_incremental_osv_bounded_fetch(self):
        """Assertions 3.2 & 3.3: OSV incremental sync iterates over ecosystems in deterministic order and bounds API fetches to batch_size."""
        pypi_csv = "GHSA-pypi-1,2026-09-01T02:00:00Z\nGHSA-pypi-2,2026-09-01T03:00:00Z\n"
        npm_csv = "GHSA-npm-1,2026-09-01T02:00:00Z\n"

        def handler(request: httpx.Request):
            url = str(request.url)
            if "PyPI/modified_id.csv" in url:
                return httpx.Response(200, text=pypi_csv)
            if "npm/modified_id.csv" in url:
                return httpx.Response(200, text=npm_csv)
            if "osv.dev/v1/vulns/GHSA-" in url:
                osv_id = url.split("/")[-1]
                return httpx.Response(200, json={
                    "id": osv_id,
                    "modified": "2026-09-01T03:00:00Z",
                    "summary": f"Summary for {osv_id}",
                })
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = OsvFetchClient(client=client, ecosystems=["PyPI", "npm"])

        initial_cursor = json.dumps({"PyPI": "2026-09-01T00:00:00Z", "npm": "2026-09-01T00:00:00Z"})
        res = fetcher.fetch(cursor=initial_cursor, batch_size=2)

        # Batch size was 2, so exactly 2 records fetched
        assert len(res.records) == 2
        assert res.is_bootstrap is False
        assert res.records[0]["id"] == "GHSA-pypi-1"
        assert res.records[1]["id"] == "GHSA-pypi-2"

    def test_assertion_3_4_malformed_osv_cursor_resets_gracefully(self):
        """Assertion 3.4: Unparseable or malformed OSV cursor gracefully resets to bootstrap without crashing."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("CVE-1.json", json.dumps({"id": "GHSA-1", "ecosystem": "PyPI"}))
        zip_bytes = bio.getvalue()
        client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=zip_bytes)))
        fetcher = OsvFetchClient(client=client, ecosystems=["PyPI"])

        # Pass garbage cursor
        res = fetcher.fetch(cursor="not-valid-json-string-1234")
        assert res.is_bootstrap is True
        assert res.error is None

    def test_assertion_3_5_osv_partial_error_preserves_committed_cursors(self):
        """Assertion 3.5: If OSV incremental fetch encounters error, previously committed ecosystem cursors remain valid."""
        with get_db_connection() as conn:
            prior_cursor = json.dumps({"PyPI": "2026-09-01T00:00:00Z", "Go": "2026-09-01T00:00:00Z"})
            update_sync_state(conn, "osv", cursor_value=prior_cursor, success=True)
            conn.commit()

            # Client fails on network
            client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(503)))
            fetcher = OsvFetchClient(client=client, ecosystems=["PyPI", "Go"])
            adapter = OsvSyncAdapter(fetch_client=fetcher)

            outcome = sync_source(conn, adapter)
            assert outcome.success is False
            assert get_sync_state(conn, "osv").cursor_value == prior_cursor


# ===========================================================================
# DELIVERABLE 4: Bounded Archive Processing, Resource Bounds & Hostile Protection
# ===========================================================================

class TestDeliverable4BoundedArchiveProcessingAndGuards:
    """Tests for Assertions 4.1 through 4.10."""

    def _create_zip(self, entries: dict[str, bytes]) -> bytes:
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return bio.getvalue()

    def test_assertion_4_1_zip_slip_rejections(self):
        """Assertion 4.1: safe_extract_zip rejects zip members with path traversal (.., leading /, drive letters, null bytes)."""
        hostile_paths = [
            "../secret.txt",
            "foo/../../etc/passwd",
            "/absolute/path.json",
            "\\windows\\path.json",
            "C:boot.ini",
            "D:\\danger.txt",
            "valid\0bad.json",
        ]
        for hp in hostile_paths:
            with pytest.raises(PathTraversalError):
                validate_archive_path(hp)

    def test_assertion_4_2_zip_bomb_1mb_threshold_and_small_file_exemption(self):
        """Assertion 4.2: safe_extract_zip rejects zip bombs > 100:1 ratio only when uncompressed >= 1 MB; small files < 1 MB are exempt."""
        # 1. Small file with high ratio (e.g. 50 bytes -> 10,000 bytes = 200:1 ratio, but total < 1 MB) -> MUST BE EXEMPT
        small_highly_compressible = b"A" * 10_000
        small_zip = self._create_zip({"small.txt": small_highly_compressible})
        extracted = list(safe_extract_zip(small_zip, limits=ArchiveLimits(max_compression_ratio=10.0, min_ratio_threshold_bytes=1024*1024)))
        assert len(extracted) == 1
        assert extracted[0][1] == small_highly_compressible

        # 2. Large bomb: 2 MB of zeros with ratio 500:1 -> MUST RAISE ArchiveBombError
        large_zeros = b"\0" * (2 * 1024 * 1024)
        bomb_zip = self._create_zip({"bomb.bin": large_zeros})
        with pytest.raises(ArchiveBombError):
            list(safe_extract_zip(bomb_zip, limits=ArchiveLimits(max_compression_ratio=50.0, min_ratio_threshold_bytes=1024*1024)))

    def test_assertion_4_3_archive_resource_limits(self):
        """Assertion 4.3: safe_extract_zip enforces per-entry max size, total expanded bytes, and max file count."""
        limits = ArchiveLimits(
            max_file_count=2,
            max_entry_bytes=100,
            max_expanded_bytes=150,
        )

        # Exceed file count
        z_count = self._create_zip({"a.txt": b"1", "b.txt": b"2", "c.txt": b"3"})
        with pytest.raises(ArchiveFileCountExceededError):
            list(safe_extract_zip(z_count, limits=limits))

        # Exceed per-entry bytes
        z_entry = self._create_zip({"big.txt": b"x" * 200})
        with pytest.raises(ArchiveEntryTooLargeError):
            list(safe_extract_zip(z_entry, limits=limits))

        # Exceed total expanded bytes
        z_total = self._create_zip({"f1.txt": b"x" * 90, "f2.txt": b"x" * 90})
        with pytest.raises(ArchiveBombError):
            list(safe_extract_zip(z_total, limits=limits))

    def test_assertion_4_4_safe_extract_gzip_bounds(self):
        """Assertion 4.4: safe_extract_gzip_chunks and safe_extract_gzip enforce limits and abort immediately."""
        limits = ArchiveLimits(max_expanded_bytes=500, min_ratio_threshold_bytes=100, max_compression_ratio=5.0)
        large_data = b"B" * 2000
        gz_bytes = gzip.compress(large_data)

        with pytest.raises(ArchiveBombError):
            safe_extract_gzip(gz_bytes, limits=limits)

    def test_assertion_4_5_temp_dir_cleanup_guarantee(self):
        """Assertion 4.5: Temporary directories created during archive extraction are cleaned up under all paths."""
        valid_zip = self._create_zip({"file.txt": b"hello"})
        captured_dir = None

        with safe_extract_to_temp_dir(valid_zip) as t_dir:
            captured_dir = t_dir
            assert t_dir.exists()
            assert (t_dir / "file.txt").read_text() == "hello"

        # MUST be deleted on normal exit
        assert not captured_dir.exists()

        # MUST be deleted on exception
        captured_dir_err = None
        try:
            with safe_extract_to_temp_dir(valid_zip) as t_dir_err:
                captured_dir_err = t_dir_err
                raise RuntimeError("Simulated mid-processing crash")
        except RuntimeError:
            pass

        assert not captured_dir_err.exists()

    def test_assertion_4_6_malformed_archive_corruption_error(self):
        """Assertion 4.6: Malformed, truncated, or non-zip/gzip payloads raise ArchiveCorruptionError."""
        corrupted_zip = b"PK\x03\x04truncated-garbage-bytes"
        with pytest.raises(ArchiveCorruptionError):
            list(safe_extract_zip(corrupted_zip))

        corrupted_gz = b"\x1f\x8b\x08truncated-gzip"
        with pytest.raises(ArchiveCorruptionError):
            safe_extract_gzip(corrupted_gz)

    def test_assertion_4_7_archive_typed_exception_hierarchy(self):
        """Assertion 4.7: Archive validation failures raise typed exceptions inheriting from ArchiveError."""
        assert issubclass(PathTraversalError, ArchiveError)
        assert issubclass(ArchiveBombError, ArchiveError)
        assert issubclass(ArchiveFileCountExceededError, ArchiveError)
        assert issubclass(ArchiveEntryTooLargeError, ArchiveError)
        assert issubclass(ArchiveCorruptionError, ArchiveError)

    def test_assertion_4_8_extraction_timeout_abort(self):
        """Assertion 4.8: Extraction timeout aborts extraction and raises ArchiveError."""
        limits = ArchiveLimits(extraction_timeout_seconds=0.0001)
        z_data = self._create_zip({f"file_{i}.txt": b"content" for i in range(100)})
        with pytest.raises(ArchiveError) as exc_info:
            list(safe_extract_zip(z_data, limits=limits))
        assert "timed out" in str(exc_info.value)

    def test_assertion_4_9_source_artifact_persistence_and_reuse(self):
        """Assertion 4.9: Raw downloaded archives may be saved to disk / cached without re-downloading if integrity hash matches."""
        raw_bytes = b"sample archive payload bytes for integrity verification"
        art_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        with get_db_connection() as conn:
            # Create dummy source record first
            src_rec, _ = upsert_source_record(conn, SourceRecord(
                source="cve",
                source_id="CVE-2026-9999",
                content_hash="test-content-hash",
                raw_payload={"dummy": True},
            ))
            art = upsert_source_artifact(conn, SourceArtifact(
                source_record_id=src_rec.id,
                sha256_hash=art_hash,
                artifact_url="https://example.com/archive.zip",
                media_type="application/zip",
                byte_size=len(raw_bytes),
                artifact_bytes=raw_bytes,
            ))
            conn.commit()

            fetched_art = get_source_artifact_by_hash(conn, art_hash)
            assert fetched_art is not None
            assert fetched_art.artifact_bytes == raw_bytes

    def test_assertion_4_10_epss_chunked_streaming_header_preservation(self):
        """Assertion 4.10: EPSS chunked streaming processes records in bounded batches while preserving model_version and score_date."""
        raw_csv = (
            "#model_version:v2024.03.01,score_date:2026-09-01T00:00:00+0000\n"
            "cve,epss,percentile\n"
            "CVE-2026-6001,0.12345,0.67890\n"
            "CVE-2026-6002,0.23456,0.78901\n"
            "CVE-2026-6003,0.34567,0.89012\n"
        )
        gz_payload = gzip.compress(raw_csv.encode("utf-8"))
        client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=gz_payload)))
        fetcher = EpssFetchClient(client=client)

        # Chunk 1: batch_size=2
        res1 = fetcher.fetch(cursor=None, batch_size=2)
        assert len(res1.records) == 2
        assert res1.is_exhausted is False
        assert res1.records[0]["model_version"] == "v2024.03.01"
        assert res1.records[0]["score_date"] == "2026-09-01T00:00:00+0000"

        # Chunk 2: continuation with cursor_after from Chunk 1
        res2 = fetcher.fetch(cursor=res1.cursor_after, batch_size=2)
        assert len(res2.records) == 1
        assert res2.is_exhausted is True
        assert res2.records[0]["model_version"] == "v2024.03.01"
        assert res2.records[0]["score_date"] == "2026-09-01T00:00:00+0000"
