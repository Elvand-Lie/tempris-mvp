# backend/tests/test_cve_bootstrap_streaming.py
"""
Focused regression tests for the P1-03 CVE bootstrap hotfix:

  1. The CVE-only compressed-archive cap accepts the measured live cvelistV5
     catalog (673,227,801 bytes on 2026-09-20) — the previous 600 MB cap
     failed closed in production ("Compressed archive size (673214058 bytes)
     exceeds limit (629145600 bytes)") and blocked the Wave 1 CVE bootstrap.
  2. The bootstrap download STREAMS to the staging volume instead of
     buffering the whole body via resp.content (the buffer OOM-killed the
     bootstrap on the ~4 GB production VPS).
  3. The download happens exactly ONCE per bootstrap: continuation rounds
     slice from the staged extraction, never re-fetch the archive.
  4. Oversized streams still fail closed (ArchiveBombError) with no stage
     and no temp download leftover.
  5. The tiny inline (non-zip) body path is behaviorally unchanged.

All tests are offline (httpx.MockTransport) and use a temp staging dir via
TEMPRIS_VULN_STAGING_DIR, mirroring test_p102_* conventions.
"""
import io
import json
import zipfile

import httpx
import pytest

from app.vuln_intelligence import cve_staging
from app.vuln_intelligence.fetch_clients import CveFetchClient
from app.vuln_intelligence.models import ArchiveLimits, CVE_ARCHIVE_LIMITS

# Measured live on 2026-09-20 from
# https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip
# (production failure reported 673,214,058 bytes earlier the same day).
LIVE_CATALOG_COMPRESSED_BYTES = 673_227_801
LIVE_CATALOG_EXPANDED_BYTES = 3_314_010_817


def _cve_record(cve_id: str) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {"cna": {"title": f"Test {cve_id}"}},
    }


def _zip_bytes(records: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for rec in records:
            cve_id = rec["cveMetadata"]["cveId"]
            z.writestr(f"cves/{cve_id}.json", json.dumps(rec))
        z.writestr("README.md", "# cvelistV5")
    return buf.getvalue()


@pytest.fixture(autouse=True)
def _temp_staging_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("TEMPRIS_VULN_STAGING_DIR", str(tmp_path / "stage"))
    yield


class TestCveArchiveLimitPreset:
    def test_compressed_cap_accepts_measured_live_catalog(self):
        # The hotfix value: 1 GiB — the tested cap that admits the live feed
        # with ~1.5x headroom over the measured 673,227,801-byte catalog.
        assert CVE_ARCHIVE_LIMITS.max_compressed_bytes == 1024 * 1024 * 1024
        assert CVE_ARCHIVE_LIMITS.max_compressed_bytes >= LIVE_CATALOG_COMPRESSED_BYTES

    def test_expanded_and_entry_guards_still_admit_live_catalog(self):
        # Measured: ~3.1 GB expanded (ratio ~5.6:1), largest entry 23.5 MB,
        # ~396k files — every other guard keeps headroom, unchanged.
        assert CVE_ARCHIVE_LIMITS.max_expanded_bytes >= LIVE_CATALOG_EXPANDED_BYTES
        assert CVE_ARCHIVE_LIMITS.max_file_count >= 395_613
        assert CVE_ARCHIVE_LIMITS.max_entry_bytes >= 23_505_415

    def test_shared_defaults_are_unchanged_cve_only_bump(self):
        # The limit bump is CVE-ONLY: every other consumer keeps the
        # conservative shared defaults (P1-02 invariant).
        shared = ArchiveLimits()
        assert shared.max_compressed_bytes == 500 * 1024 * 1024
        assert shared.max_expanded_bytes == 2 * 1024 * 1024 * 1024
        assert shared.max_file_count == 500_000


class TestCveBootstrapStreaming:
    def test_bootstrap_streams_zip_to_staging_volume(self, tmp_path):
        records = [_cve_record("CVE-2023-1001"), _cve_record("CVE-2023-1002")]
        zip_bytes = _zip_bytes(records)
        requested = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(request.url.path)
            return httpx.Response(200, content=zip_bytes, headers={"Content-Type": "application/zip"})

        fetcher = CveFetchClient(client=httpx.Client(transport=httpx.MockTransport(handler)))
        # batch_size=1 with 2 records keeps the bootstrap MID-FLIGHT: the
        # stage exists only between rounds (exhaustion clears it).
        result = fetcher.fetch(cursor=None, batch_size=1)

        assert result.error is None
        assert result.is_bootstrap is True
        assert result.is_exhausted is False
        assert [r["cveMetadata"]["cveId"] for r in result.records] == [
            "CVE-2023-1001",
        ]
        assert result.metadata["staged"] is True
        assert result.metadata["bytes_downloaded"] == len(zip_bytes)

        # The staged extraction is on the staging volume (not RAM-only).
        stage_root = cve_staging.staging_root()
        assert (stage_root / "manifest.json").is_file()
        staged_entries = list((stage_root / "entries").rglob("*.json"))
        assert len(staged_entries) == 2

        # No temp download leftover next to the stage dir.
        leftovers = [p.name for p in stage_root.parent.glob("cvelistv5-download-*")]
        assert leftovers == []

    def test_bootstrap_downloads_exactly_once_across_batches(self):
        records = [_cve_record("CVE-2023-2001"), _cve_record("CVE-2023-2002")]
        zip_bytes = _zip_bytes(records)
        hits = []

        def handler(request: httpx.Request) -> httpx.Response:
            hits.append(request.url.path)
            return httpx.Response(200, content=zip_bytes, headers={"Content-Type": "application/zip"})

        fetcher = CveFetchClient(client=httpx.Client(transport=httpx.MockTransport(handler)))

        first = fetcher.fetch(cursor=None, batch_size=1)
        assert first.error is None
        assert first.is_exhausted is False
        cursor = json.loads(first.cursor_after)
        assert cursor["phase"] == "bootstrap"
        assert cursor["staging_identity"]

        second = fetcher.fetch(cursor=first.cursor_after, batch_size=1)
        assert second.error is None
        assert second.is_exhausted is True
        assert [r["cveMetadata"]["cveId"] for r in second.records] == ["CVE-2023-2002"]

        # Exactly ONE network download for the whole bootstrap: the second
        # round sliced from the staged extraction. A regression back to
        # per-round downloads (or a stage-identity mismatch restart) breaks
        # this count.
        assert len(hits) == 1

        # Chain exhaustion cleared the stage (engine contract).
        assert not cve_staging.staging_root().exists()

    def test_oversized_stream_fails_closed_without_stage(self, tmp_path):
        records = [_cve_record("CVE-2023-3001"), _cve_record("CVE-2023-3002")]
        zip_bytes = _zip_bytes(records)
        tight = ArchiveLimits(
            max_compressed_bytes=256,  # far below the test zip's size
            max_expanded_bytes=2 * 1024 * 1024 * 1024,
            max_file_count=500_000,
            max_entry_bytes=50 * 1024 * 1024,
            max_compression_ratio=100.0,
            min_ratio_threshold_bytes=1 * 1024 * 1024,
            extraction_timeout_seconds=1800.0,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=zip_bytes, headers={"Content-Type": "application/zip"})

        fetcher = CveFetchClient(
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            archive_limits=tight,
        )
        result = fetcher.fetch(cursor=None, batch_size=10)

        assert result.records == []
        assert result.error is not None
        assert "exceeds limit" in result.error

        # Fail closed: no stage, no temp download leftover.
        stage_root = cve_staging.staging_root()
        assert not stage_root.exists()
        leftovers = [p.name for p in stage_root.parent.glob("cvelistv5-download-*")]
        assert leftovers == []

    def test_tiny_inline_non_zip_body_unchanged(self):
        body = json.dumps([_cve_record("CVE-2023-4001")]).encode()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body, headers={"Content-Type": "application/json"})

        # A base_url NOT ending in .zip mirrors the original is_zip logic:
        # only then is the tiny inline (non-archive) branch reachable.
        fetcher = CveFetchClient(
            base_url="https://example.test/records",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        result = fetcher.fetch(cursor=None, batch_size=10)

        assert result.error is None
        assert [r["cveMetadata"]["cveId"] for r in result.records] == ["CVE-2023-4001"]
        assert result.is_exhausted is True
        assert result.metadata["bytes_downloaded"] == len(body)
        # Inline bodies never stage.
        assert not cve_staging.staging_root().exists()
