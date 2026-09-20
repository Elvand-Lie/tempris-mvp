# backend/app/vuln_intelligence/fetch_clients.py
"""
Bounded official-source fetch clients for the five vulnerability intelligence sources:
  1. CVE (cvelistV5 / cve.org / GitHub releases & API)
  2. NVD 2.0 REST API (paginated, rate-limited, optional NVD_API_KEY)
  3. CISA KEV JSON catalog (bounded batching, exhaustion tracking)
  4. FIRST EPSS bulk CSV (streaming gzip decompression, header metadata carryover)
  5. OSV GCS ecosystem archives, modified_id.csv incrementals & API

All clients:
  - Use httpx with strict timeout and custom User-Agent
  - Support dependency injection of httpx.Client for offline/mock testing
  - Bounded batch sizes and safe memory limits via archive_utils
  - Support both fresh bootstrap and incremental/delta modes
  - Support structured continuation cursors for resumable multi-batch bootstrap
  - Never log or leak secrets (NVD API key)
  - Return FetchResult(records=..., cursor_after=..., is_bootstrap=..., error=...)
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import logging
import os
import pathlib
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Optional, Union

import httpx

from app.vuln_intelligence.sync_engine import FetchResult
from app.vuln_intelligence.archive_utils import (
    safe_extract_zip,
    safe_extract_gzip,
    safe_extract_gzip_chunks,
)
from app.vuln_intelligence.models import (
    ArchiveLimits,
    ArchiveError,
    PathTraversalError,
    ArchiveBombError,
    ArchiveCorruptionError,
    CVE_ARCHIVE_LIMITS,
)
from app.vuln_intelligence.cve_staging import (
    stage_archive,
    load_staged_catalog,
    clear_staging,
    staging_root,
)

logger = logging.getLogger(__name__)

USER_AGENT = "Tempris-Vulnerability-Intelligence/2.0 (Security Research & Defense)"
DEFAULT_TIMEOUT = 300  # seconds


@contextmanager
def _get_http_client(
    timeout_seconds: int = DEFAULT_TIMEOUT,
    custom_client: Optional[httpx.Client] = None,
) -> Iterator[httpx.Client]:
    """Yield custom_client without closing it, or create and manage a new bounded client."""
    if custom_client is not None:
        yield custom_client
    else:
        with httpx.Client(
            headers={"User-Agent": USER_AGENT},
            timeout=httpx.Timeout(timeout_seconds, connect=30.0),
            follow_redirects=True,
        ) as client:
            yield client


def _parse_cursor_json(cursor: Optional[str]) -> Optional[dict]:
    """Parse JSON string cursor into a dict if valid, else None."""
    if not cursor or not isinstance(cursor, str):
        return None
    try:
        data = json.loads(cursor)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    return None


# ---------------------------------------------------------------------------
# 1. CVE / cvelistV5 Fetch Client
# ---------------------------------------------------------------------------

class CveFetchClient:
    """
    Fetch client for official CVE records from cvelistV5.

    Supports:
      - Bootstrap: STAGED STREAMING download (P1-02 Defect 1) — the zip is
        downloaded exactly ONCE per bootstrap and extracted to a persistent
        on-disk stage (see app.vuln_intelligence.cve_staging); every
        continuation round slices its batch from disk and parses entries on
        demand, so the full parsed catalog is never resident in RAM and no
        round ever re-downloads the archive. The continuation cursor carries
        the staged extraction's identity; resume validates it and RESTARTS
        from batch 0 on any mismatch (missing/altered stage, different
        download) — offset resume is only ever applied to the identical
        extraction it was created from. Reprocessing is harmless: all writes
        are content-hash upserts. Staging is cleared on chain exhaustion.
      - Incremental: GitHub commits delta or modified since cursor.
    """
    DEFAULT_ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
    GITHUB_API_COMMITS_URL = "https://api.github.com/repos/CVEProject/cvelistV5/commits"
    RAW_BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"

    def __init__(
        self,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        archive_limits: Optional[ArchiveLimits] = None,
    ):
        self.base_url = base_url or self.DEFAULT_ZIP_URL
        self.client = client
        # P1-02 review: the shared ArchiveLimits defaults stay conservative
        # (500 MB / 2 GB — OSV's bounds); the cvelistV5 catalog is the ONE
        # consumer that needs the larger, CVE-specific preset.
        self.archive_limits = archive_limits or CVE_ARCHIVE_LIMITS

    def fetch(
        self,
        cursor: Optional[str] = None,
        *,
        batch_size: int = 1000,
        timeout_seconds: int = DEFAULT_TIMEOUT,
    ) -> FetchResult:
        """
        Fetch CVE records.
        If cursor is provided:
          - If cursor is a structured continuation dict -> resume bootstrap batch
          - If cursor is a clean timestamp/SHA -> perform incremental sync
        If cursor is None -> start bootstrap sync (batch 1)
        """
        cursor_dict = _parse_cursor_json(cursor)
        is_continuation = cursor_dict is not None and cursor_dict.get("phase") == "bootstrap"
        is_bootstrap = cursor is None or is_continuation

        try:
            with _get_http_client(timeout_seconds, self.client) as http:
                if not is_bootstrap and cursor and not is_continuation:
                    return self._fetch_incremental(http, cursor, batch_size)
                else:
                    return self._fetch_bootstrap(http, batch_size, cursor_dict)
        except httpx.HTTPStatusError as e:
            logger.error("CVE HTTP error %s: %s", e.response.status_code, e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"HTTP {e.response.status_code}: {e}")
        except ArchiveError as e:
            logger.error("CVE archive error: %s", e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"Archive error: {e}")
        except Exception as e:
            logger.error("CVE fetch failed: %s", e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"Fetch failed: {e}")

    def _fetch_bootstrap(
        self,
        http: httpx.Client,
        batch_size: int,
        cursor_dict: Optional[dict] = None,
    ) -> FetchResult:
        """Staged streaming bootstrap: one download, disk-resident batches."""
        offset = 0
        target_sha = datetime.now(timezone.utc).isoformat()
        cursor_identity: Optional[str] = None
        # P1-02 review fix: staged/resumed MUST be initialized — a cursor
        # that cannot be honored (missing/invalid identity) leaves staged
        # unset and the download path would raise UnboundLocalError.
        staged = None
        resumed = False
        # P1-02 review: set when a continuation cursor cannot be honored
        # (missing/invalid staging identity) and the bootstrap RESTARTS from
        # batch 0 — the engine must discard the open snapshot (artifact A's
        # writes) and open a fresh one at batch 0.
        artifact_restarted = False
        if cursor_dict:
            cursor_identity = cursor_dict.get("staging_identity")
            if cursor_identity:
                # P1-02 review: offset resume is allowed ONLY against the
                # identical extraction the cursor was created from — and a
                # cursor WITHOUT an identity is legacy/malformed and must
                # never resume by offset or inherit its old target cursor.
                target_sha = cursor_dict.get("target_sha", target_sha)
                candidate = load_staged_catalog()
                if candidate is not None and candidate.identity == cursor_identity:
                    offset = int(cursor_dict.get("entry_offset", 0))
                    staged = candidate
                    resumed = True
                else:
                    logger.warning(
                        "CVE staging identity invalid; restarting bootstrap from batch 0"
                    )
                    # P1-02 review: the restart must also DROP the inherited
                    # target cursor — the old target names the abandoned
                    # extraction, and a premature clean cursor would strand
                    # the restart's own rounds. Fresh target from now().
                    target_sha = datetime.now(timezone.utc).isoformat()
                    artifact_restarted = True
            else:
                logger.warning(
                    "CVE continuation cursor carries no staging identity; "
                    "restarting bootstrap from batch 0"
                )
                # P1-02 review: same as invalid identity — restart drops the
                # inherited target cursor and signals the engine.
                target_sha = datetime.now(timezone.utc).isoformat()
                artifact_restarted = True

        download_bytes = 0
        download_hash: Optional[str] = None
        response_url = self.base_url
        inline_body: Optional[bytes] = None
        if staged is None:
            # P1-03 hotfix: stream the download to the staging volume instead
            # of buffering the whole body via resp.content. The live cvelistV5
            # catalog is ~673 MB compressed; the full-body buffer OOM-killed
            # the bootstrap on the ~4 GB production VPS. Chunks stream to a
            # temp file NEXT TO the stage dir (stage_archive wipes and
            # recreates staging_root itself), hashed incrementally, and capped
            # at the same compressed limit the extractor enforces.
            with http.stream("GET", self.base_url) as resp:
                resp.raise_for_status()
                content_type = resp.headers.get("content-type", "")
                chunks = resp.iter_bytes(chunk_size=1024 * 1024)
                first_chunk = next(chunks, b"")
                is_zip = (
                    first_chunk.startswith(b"PK")
                    or "zip" in content_type
                    or self.base_url.endswith(".zip")
                )
                if is_zip:
                    download_dir = staging_root().parent
                    download_dir.mkdir(parents=True, exist_ok=True)
                    tmp_path: Optional[pathlib.Path] = None
                    try:
                        with tempfile.NamedTemporaryFile(
                            dir=download_dir,
                            prefix="cvelistv5-download-",
                            suffix=".zip",
                            delete=False,
                        ) as tmp:
                            tmp_path = pathlib.Path(tmp.name)
                            hasher = hashlib.sha256()
                            tmp.write(first_chunk)
                            hasher.update(first_chunk)
                            downloaded = len(first_chunk)
                            if downloaded > self.archive_limits.max_compressed_bytes:
                                raise ArchiveBombError(
                                    f"Compressed archive download ({downloaded} bytes) exceeds limit ({self.archive_limits.max_compressed_bytes} bytes)"
                                )
                            for chunk in chunks:
                                tmp.write(chunk)
                                hasher.update(chunk)
                                downloaded += len(chunk)
                                if downloaded > self.archive_limits.max_compressed_bytes:
                                    raise ArchiveBombError(
                                        f"Compressed archive download ({downloaded} bytes) exceeds limit ({self.archive_limits.max_compressed_bytes} bytes)"
                                    )
                        download_bytes = downloaded
                        download_hash = hasher.hexdigest()
                        response_url = str(resp.url)
                        staged = stage_archive(
                            tmp_path,
                            limits=self.archive_limits,
                            source_url=response_url,
                        )
                    finally:
                        if tmp_path is not None:
                            tmp_path.unlink(missing_ok=True)
                else:
                    # Tiny inline bodies (single JSON record / small lists):
                    # keep the historical in-memory path; no staging needed.
                    inline_body = first_chunk + b"".join(chunks)
                    download_bytes = len(inline_body)
                    download_hash = hashlib.sha256(inline_body).hexdigest()
                    response_url = str(resp.url)
            if inline_body is not None:
                all_records: list[dict] = []
                if inline_body.startswith(b"{"):
                    data = json.loads(inline_body)
                    if isinstance(data, dict) and data.get("dataType") == "CVE_RECORD":
                        all_records = [data]
                    elif isinstance(data, list):
                        all_records = [r for r in data if isinstance(r, dict) and r.get("dataType") == "CVE_RECORD"]
                elif inline_body.startswith(b"["):
                    data = json.loads(inline_body)
                    if isinstance(data, list):
                        all_records = [r for r in data if isinstance(r, dict) and r.get("dataType") == "CVE_RECORD"]
                # P1-02 recheck: this branch exists ONLY for tiny inline
                # bodies (single JSON record / small lists, already fully in
                # memory). It must NEVER emit a multi-batch continuation: its
                # cursors carry no staging identity, so the identity gate
                # treats every one as untrusted and would restart batch 0
                # forever (an inline list larger than batch_size could never
                # advance). Serve the whole list as ONE exhausted batch —
                # matching the branch's stated purpose.
                batch_records = all_records[offset:]
                cursor_after = target_sha
                is_exhausted = True
                return FetchResult(
                    records=batch_records,
                    cursor_after=cursor_after,
                    is_bootstrap=True,
                    is_exhausted=is_exhausted,
                    metadata={
                        "source": "cvelistV5",
                        "count": len(batch_records),
                        "total_entries": len(all_records),
                        "offset": offset,
                        "url": response_url,
                        "bytes_downloaded": download_bytes,
                        "content_hash": download_hash,
                    },
                )

        batch_paths = staged.entry_slice(offset, batch_size)
        batch_records = staged.read_entries(batch_paths)
        next_offset = offset + len(batch_paths)
        total_entries = staged.entry_count

        if next_offset < total_entries:
            # Intermediate batch -> continuation cursor carrying the stage
            # identity (resume validates it; mismatch restarts from batch 0).
            cursor_after = json.dumps({
                "phase": "bootstrap",
                "entry_offset": next_offset,
                "total_entries": total_entries,
                "target_sha": target_sha,
                "staging_identity": staged.identity,
            })
            is_exhausted = False
        else:
            # Final batch -> clean target cursor; the stage is now consumed.
            cursor_after = target_sha
            is_exhausted = True
            clear_staging()

        return FetchResult(
            records=batch_records,
            cursor_after=cursor_after,
            is_bootstrap=True,
            is_exhausted=is_exhausted,
            artifact_restarted=artifact_restarted,
            metadata={
                "source": "cvelistV5",
                "staged": True,
                "resumed": resumed,
                "staging_identity": staged.identity,
                "count": len(batch_records),
                "total_entries": total_entries,
                "offset": offset,
                "url": response_url,
                "bytes_downloaded": download_bytes,
                "content_hash": download_hash,
            },
        )

    def _fetch_incremental(self, http: httpx.Client, cursor: str, batch_size: int) -> FetchResult:
        """Fetch records modified since cursor."""
        params = {"since": cursor, "per_page": min(batch_size, 100)}
        resp = http.get(self.GITHUB_API_COMMITS_URL, params=params)
        now_iso = datetime.now(timezone.utc).isoformat()

        if resp.status_code == 200:
            commits = resp.json()
            records: list[dict] = []
            if isinstance(commits, list):
                for commit in commits[:min(batch_size, 20)]:
                    commit_sha = commit.get("sha")
                    if commit_sha:
                        detail_resp = http.get(f"{self.GITHUB_API_COMMITS_URL}/{commit_sha}")
                        if detail_resp.status_code == 200:
                            files = detail_resp.json().get("files", [])
                            for f in files:
                                raw_url = f.get("raw_url")
                                filename = f.get("filename", "")
                                if filename.endswith(".json") and raw_url:
                                    cve_resp = http.get(raw_url)
                                    if cve_resp.status_code == 200:
                                        try:
                                            cve_json = cve_resp.json()
                                            if cve_json.get("dataType") == "CVE_RECORD":
                                                records.append(cve_json)
                                                if len(records) >= batch_size:
                                                    break
                                        except Exception:
                                            pass
                            if len(records) >= batch_size:
                                break
            return FetchResult(
                records=records,
                cursor_after=now_iso,
                is_bootstrap=False,
                metadata={"since": cursor, "commits_checked": len(commits) if isinstance(commits, list) else 0},
            )
        else:
            return self._fetch_bootstrap(http, batch_size)


# ---------------------------------------------------------------------------
# 2. NVD 2.0 API Fetch Client
# ---------------------------------------------------------------------------

# NVD lastModFilter timestamp shapes seen at this boundary: the client
# itself writes millisecond precision with Z (window ends, promoted
# cursors); stored cursor values may be bare NVD API timestamps (milli-
# second or seconds precision, no Z). Garbage still fails to parse.
_NVD_WINDOW_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
)


def _parse_nvd_window_bound(value) -> Optional[datetime]:
    """Parse an NVD window bound strictly; None when absent/malformed.

    P1-02 recheck round 2: window bounds are FILTER PARAMETERS sent to the
    NVD API — a non-timestamp string (e.g. "garbage") must fail closed at
    the cursor boundary instead of being forwarded upstream.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    for fmt in _NVD_WINDOW_TS_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


class NvdFetchClient:
    """
    Fetch client for NIST National Vulnerability Database (NVD) 2.0 API.
    Supports paginated bootstrap exhaustion and incremental querying.
    """
    DEFAULT_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
    ):
        self.api_url = api_url or self.DEFAULT_API_URL
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.client = client

    def fetch(
        self,
        cursor: Optional[str] = None,
        *,
        batch_size: int = 1000,
        timeout_seconds: int = DEFAULT_TIMEOUT,
    ) -> FetchResult:
        cursor_dict = _parse_cursor_json(cursor)
        is_continuation = cursor_dict is not None and cursor_dict.get("phase") == "bootstrap"
        is_bootstrap = cursor is None or is_continuation

        headers = {"User-Agent": USER_AGENT}
        if self.api_key and self.api_key.strip():
            headers["apiKey"] = self.api_key.strip()

        start_index = 0
        target_timestamp: Optional[str] = None
        if is_continuation and cursor_dict:
            start_index = cursor_dict.get("startIndex", 0)
            target_timestamp = cursor_dict.get("target_timestamp")

        # P1-02 review: an incremental window is POSITIONAL. The previous
        # cursor design replaced the window with only max(lastModified) of
        # the processed page — records SHARING that timestamp with the page
        # boundary were stranded forever (next request restarted at the same
        # timestamp and the engine stopped on cursor_after == cursor_before).
        # A window cursor pins a FIXED window end plus a startIndex and is
        # paginated positionally to exhaustion; only then is the clean
        # timestamp cursor promoted to the window end.
        window_start: Optional[str] = None
        window_end: Optional[str] = None
        if not is_bootstrap and cursor and not is_continuation:
            window_cursor = _parse_cursor_json(cursor)
            if isinstance(window_cursor, dict) and "nvd_window" in window_cursor:
                # P1-02 recheck: a window cursor must carry the COMPLETE
                # schema before it may constrain a request. A partial window
                # (missing bounds) previously fell through to an UNFILTERED
                # NVD request and could begin a positional traversal of the
                # full catalog. Fail closed exactly like a foreign cursor.
                # P1-02 recheck round 2: presence is not schema either — the
                # marker must be boolean True and both bounds must PARSE as
                # NVD timestamps, or garbage strings would be forwarded
                # upstream as lastModStartDate/lastModEndDate filters.
                raw_start = window_cursor.get("window_start")
                raw_end = window_cursor.get("window_end")
                raw_index = window_cursor.get("startIndex", 0)
                parsed_start = _parse_nvd_window_bound(raw_start)
                parsed_end = _parse_nvd_window_bound(raw_end)
                schema_valid = (
                    window_cursor.get("nvd_window") is True
                    and parsed_start is not None
                    and parsed_end is not None
                    and isinstance(raw_index, int)
                    and not isinstance(raw_index, bool)
                    and raw_index >= 0
                )
                if not schema_valid:
                    return FetchResult(
                        records=[],
                        is_bootstrap=False,
                        error=(
                            "Malformed NVD window cursor; refusing to send "
                            f"an unconstrained request: {cursor[:80]}"
                        ),
                    )
                window_start = raw_start.strip()
                window_end = raw_end.strip()
                start_index = raw_index
            elif isinstance(window_cursor, dict):
                # P1-02 review: a structured cursor that is neither a window
                # nor a bootstrap continuation is foreign (legacy/rolled-back
                # writer). Fail closed with a clear error — silently treating
                # it as a timestamp would strand work or 400 forever.
                return FetchResult(
                    records=[],
                    is_bootstrap=False,
                    error=(
                        "Unrecognized NVD cursor format; refusing to "
                        f"interpret it as a timestamp: {cursor[:80]}"
                    ),
                )
            else:
                window_start = cursor
                window_end = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z"
                )

        params: dict[str, Any] = {
            "resultsPerPage": min(batch_size, 2000),
            "startIndex": start_index,
        }

        if window_start is not None and window_end is not None:
            if window_end <= window_start:
                # Zero-width window (a previous drain completed within the
                # same second): nothing can be due — skip the upstream call.
                return FetchResult(
                    records=[],
                    cursor_after=window_start,
                    is_bootstrap=False,
                    is_exhausted=True,
                    metadata={"window_start": window_start, "window_end": window_end, "empty_window": True},
                )
            params["lastModStartDate"] = window_start
            params["lastModEndDate"] = window_end

        try:
            with _get_http_client(timeout_seconds, self.client) as http:
                max_retries = 3
                for attempt in range(max_retries):
                    resp = http.get(self.api_url, params=params, headers=headers)
                    if resp.status_code in (429, 403) and attempt < max_retries - 1:
                        sleep_time = 6.0 if not self.api_key else 1.5
                        time.sleep(sleep_time)
                        continue
                    resp.raise_for_status()
                    break

                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    return FetchResult(records=[], is_bootstrap=is_bootstrap, error="Invalid NVD response: 'vulnerabilities' is not a list")

                resp_timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
                final_target_ts = target_timestamp or resp_timestamp
                total_results = data.get("totalResults", len(vulnerabilities))

                records = vulnerabilities[:batch_size]
                next_index = start_index + len(records)

                if is_bootstrap:
                    if next_index < total_results and len(records) > 0:
                        cursor_after = json.dumps({
                            "phase": "bootstrap",
                            "startIndex": next_index,
                            "totalResults": total_results,
                            "target_timestamp": final_target_ts,
                        })
                        is_exhausted = False
                    else:
                        cursor_after = final_target_ts
                        is_exhausted = True
                else:
                    # P1-02 review: paginate the FIXED window positionally.
                    # The cursor only reaches the window end when the window
                    # is exhausted (startIndex + returned >= totalResults),
                    # so a backlog larger than one batch — or a timestamp tie
                    # across a page boundary — always continues where it
                    # stopped; nothing is stranded and nothing is skipped.
                    next_index = start_index + len(records)
                    if next_index < total_results and len(records) > 0:
                        cursor_after = json.dumps({
                            "nvd_window": True,
                            "window_start": window_start,
                            "window_end": window_end,
                            "startIndex": next_index,
                        })
                        is_exhausted = False
                    else:
                        # Window exhausted positionally — promote the clean
                        # cursor to the WINDOW END (not the response
                        # timestamp): a record modified after window_end has
                        # lastModified > window_end and remains due next
                        # cycle; promoting to now() would strand it.
                        cursor_after = window_end or final_target_ts
                        is_exhausted = True

                return FetchResult(
                    records=records,
                    cursor_after=cursor_after,
                    is_bootstrap=is_bootstrap,
                    is_exhausted=is_exhausted,
                    metadata={
                        "totalResults": total_results,
                        "resultsPerPage": data.get("resultsPerPage"),
                        "startIndex": start_index,
                        "timestamp": final_target_ts,
                        "url": str(resp.url),
                        "bytes_downloaded": len(resp.content),
                        "content_hash": hashlib.sha256(resp.content).hexdigest(),
                    },
                )
        except httpx.HTTPStatusError as e:
            logger.error("NVD HTTP error %s: %s", e.response.status_code, e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"HTTP {e.response.status_code}: {e}")
        except Exception as e:
            logger.error("NVD fetch failed: %s", e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"Fetch failed: {e}")


# ---------------------------------------------------------------------------
# 3. CISA KEV Catalog Fetch Client
# ---------------------------------------------------------------------------

class KevFetchClient:
    """
    Fetch client for CISA Known Exploited Vulnerabilities (KEV) catalog.
    Supports bounded chunked bootstrap with accumulated seen_ids across continuation state.
    """
    DEFAULT_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(
        self,
        catalog_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
    ):
        self.catalog_url = catalog_url or self.DEFAULT_CATALOG_URL
        self.client = client

    def fetch(
        self,
        cursor: Optional[str] = None,
        *,
        batch_size: int = 1000,
        timeout_seconds: int = DEFAULT_TIMEOUT,
    ) -> FetchResult:
        cursor_dict = _parse_cursor_json(cursor)
        is_continuation = cursor_dict is not None and cursor_dict.get("phase") == "bootstrap"
        is_bootstrap = cursor is None or is_continuation

        # P1-02 review: set when the upstream catalog changed under a
        # continuation cursor — the engine discards the open shared snapshot
        # and restarts at batch 0 in a fresh snapshot.
        artifact_restarted = False

        try:
            with _get_http_client(timeout_seconds, self.client) as http:
                resp = http.get(self.catalog_url)
                resp.raise_for_status()

                data = resp.json()
                if not isinstance(data, dict):
                    return FetchResult(records=[], is_bootstrap=is_bootstrap, error="Invalid KEV payload: root is not a JSON object")

                vulnerabilities = data.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    return FetchResult(records=[], is_bootstrap=is_bootstrap, error="Invalid KEV payload: missing 'vulnerabilities' array")

                total_count = data.get("count", len(vulnerabilities))
                date_released = data.get("dateReleased") or datetime.now(timezone.utc).isoformat()
                catalog_version = data.get("catalogVersion", "")
                catalog_hash = hashlib.sha256(resp.content).hexdigest()

                offset = 0
                previous_seen_ids: list[str] = []
                if cursor_dict and is_continuation:
                    resumed_catalog_hash = cursor_dict.get("catalog_hash")
                    if not resumed_catalog_hash:
                        # P1-02 review: a continuation cursor WITHOUT the
                        # artifact hash (legacy/malformed) can never be
                        # honored — offset/seen_ids from a re-downloaded
                        # catalog are meaningless. Restart at batch 0; the
                        # run's fresh snapshot discards nothing (there is
                        # nothing carried yet) and no stale seen_ids leak
                        # into reconciliation.
                        logger.warning(
                            "KEV continuation cursor carries no catalog hash; "
                            "restarting bootstrap from batch 0"
                        )
                        offset = 0
                        previous_seen_ids = []
                    elif resumed_catalog_hash != catalog_hash:
                        # Different catalog since the cursor was written:
                        # restart from batch 0. seen_ids accumulated from the
                        # old catalog must never leak into reconciliation.
                        logger.warning(
                            "KEV catalog changed since continuation cursor "
                            "(%s != %s); restarting snapshot from batch 0",
                            resumed_catalog_hash[:12], catalog_hash[:12],
                        )
                        offset = 0
                        previous_seen_ids = []
                        # P1-02 review: signal the engine — the open shared
                        # snapshot belongs to the ABANDONED catalog and must
                        # be discarded (fresh snapshot at batch 0).
                        artifact_restarted = True

                batch_records = vulnerabilities[offset : offset + batch_size]
                new_seen_ids = [v.get("cveID") for v in batch_records if v.get("cveID")]
                all_seen_ids = previous_seen_ids + new_seen_ids
                next_offset = offset + len(batch_records)

                if next_offset < total_count and len(batch_records) > 0:
                    # KEV is ONE atomic artifact: the reconciliation (seen_ids)
                    # and batching only make sense against the identical
                    # catalog this cursor was built from. A continuation
                    # cursor therefore carries the artifact hash; any
                    # differently-dated catalog at resume RESTARTS the
                    # snapshot from batch 0 (no stale-label, no cross-catalog
                    # seen_ids). The artifact is re-downloaded on restart by
                    # design — it is a single small JSON, not a heavy pull.
                    cursor_after = json.dumps({
                        "phase": "bootstrap",
                        "entry_offset": next_offset,
                        "total_entries": total_count,
                        "target_cursor": date_released,
                        "catalog_hash": hashlib.sha256(resp.content).hexdigest(),
                        "seen_ids": all_seen_ids,
                    })
                    is_exhausted = False
                else:
                    cursor_after = date_released
                    is_exhausted = True

                return FetchResult(
                    records=batch_records,
                    cursor_after=cursor_after,
                    is_bootstrap=is_bootstrap,
                    is_exhausted=is_exhausted,
                    seen_ids=all_seen_ids if is_exhausted else None,
                    artifact_restarted=artifact_restarted,
                    metadata={
                        "catalogVersion": catalog_version,
                        "dateReleased": date_released,
                        "total_count": total_count,
                        "offset": offset,
                        "seen_ids": all_seen_ids,
                        "url": str(resp.url),
                        "bytes_downloaded": len(resp.content),
                        "content_hash": hashlib.sha256(resp.content).hexdigest(),
                        "artifact_bytes": resp.content,
                    },
                )
        except httpx.HTTPStatusError as e:
            logger.error("KEV HTTP error %s: %s", e.response.status_code, e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"HTTP {e.response.status_code}: {e}")
        except Exception as e:
            logger.error("KEV fetch failed: %s", e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"Fetch failed: {e}")


# ---------------------------------------------------------------------------
# 4. FIRST EPSS Bulk CSV Fetch Client
# ---------------------------------------------------------------------------

class EpssFetchClient:
    """
    Fetch client for FIRST Exploit Prediction Scoring System (EPSS).
    Extracts header metadata (#model_version:...,score_date:...) on chunk 0
    and carries it across continuation chunks.
    """
    DEFAULT_CSV_GZ_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    FALLBACK_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv"

    def __init__(
        self,
        csv_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        archive_limits: Optional[ArchiveLimits] = None,
    ):
        self.csv_url = csv_url or self.DEFAULT_CSV_GZ_URL
        self.client = client
        self.archive_limits = archive_limits or ArchiveLimits()

    def fetch(
        self,
        cursor: Optional[str] = None,
        *,
        batch_size: int = 1000,
        timeout_seconds: int = DEFAULT_TIMEOUT,
    ) -> FetchResult:
        cursor_dict = _parse_cursor_json(cursor)
        is_continuation = cursor_dict is not None and cursor_dict.get("phase") == "bootstrap"
        is_bootstrap = cursor is None or is_continuation

        # P1-02 review: set when the upstream CSV changed under a continuation
        # cursor — the engine discards the open shared snapshot and restarts
        # at batch 0 in a fresh snapshot under the CURRENT artifact's date.
        artifact_restarted = False

        try:
            with _get_http_client(timeout_seconds, self.client) as http:
                resp = http.get(self.csv_url)
                if resp.status_code == 404 and self.csv_url.endswith(".gz"):
                    resp = http.get(self.FALLBACK_CSV_URL)
                resp.raise_for_status()

                raw_bytes = resp.content
                if raw_bytes.startswith(b"\x1f\x8b"):
                    csv_text = safe_extract_gzip(raw_bytes, limits=self.archive_limits).decode("utf-8", errors="replace")
                else:
                    csv_text = resp.text

                lines = csv_text.splitlines()
                if not lines:
                    return FetchResult(records=[], is_bootstrap=is_bootstrap, error="Empty EPSS response")

                # Extract header metadata
                first_line = lines[0]
                score_date = None
                model_version = None
                if first_line.startswith("#"):
                    parts = first_line.lstrip("#").split(",")
                    for part in parts:
                        if ":" in part:
                            k, v = part.split(":", 1)
                            if k.strip() == "score_date":
                                score_date = v.strip()
                            elif k.strip() == "model_version":
                                model_version = v.strip()

                file_hash = hashlib.sha256(raw_bytes).hexdigest()

                # P1-02 Defect 2: the previous code OVERRODE the freshly
                # parsed header date with the continuation cursor's stored
                # (possibly stale) score_date — each day's chunk of a newer
                # file was labeled with the old file's date. That inheritance
                # is GONE. A continuation cursor is valid only against the
                # identical artifact it was created from (file_hash); a
                # differently-dated served file RESTARTS the bootstrap from
                # batch 0, and every record is processed under the CURRENT
                # artifact's own header date.
                if cursor_dict and is_continuation:
                    resumed_hash = cursor_dict.get("file_hash")
                    if not resumed_hash:
                        # P1-02 review: a continuation cursor WITHOUT the file
                        # hash (legacy/malformed) must not resume by offset —
                        # and must not inherit its stored score_date label
                        # (that is the stale-label defect re-entering through
                        # an old cursor). Restart at batch 0 under the CURRENT
                        # artifact's own header date.
                        logger.warning(
                            "EPSS continuation cursor carries no file hash; "
                            "restarting bootstrap from batch 0 under the "
                            "current artifact's header date"
                        )
                        cursor_dict = None
                    elif resumed_hash != file_hash:
                        logger.warning(
                            "EPSS artifact changed since continuation cursor "
                            "(%s != %s); restarting bootstrap from batch 0 "
                            "under the new artifact's header date",
                            resumed_hash[:12], file_hash[:12],
                        )
                        cursor_dict = None
                        # P1-02 review: signal the engine — the open shared
                        # snapshot belongs to the ABANDONED artifact (stale
                        # score_date label); it must be discarded so the
                        # restart lands in a fresh snapshot.
                        artifact_restarted = True
                    else:
                        score_date = cursor_dict.get("score_date") or score_date
                        model_version = cursor_dict.get("model_version") or model_version

                if not score_date:
                    score_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

                # Find data rows (skipping comment and column header lines)
                data_rows: list[str] = []
                for line in lines:
                    line_s = line.strip()
                    if line_s.startswith("#") or line_s.lower().startswith("cve,"):
                        continue
                    if line_s:
                        data_rows.append(line_s)

                total_rows = len(data_rows)

                # Single full batch when cursor is None and fits in batch_size
                if not is_continuation and batch_size >= total_rows:
                    return FetchResult(
                        records=[csv_text],
                        cursor_after=score_date,
                        is_bootstrap=is_bootstrap,
                        is_exhausted=True,
                        metadata={
                            "model_version": model_version,
                            "score_date": score_date,
                            "url": str(resp.url),
                            "bytes_downloaded": len(raw_bytes),
                            "content_hash": hashlib.sha256(raw_bytes).hexdigest(),
                            "artifact_bytes": raw_bytes,
                        },
                    )

                offset = 0
                if cursor_dict and is_continuation:
                    offset = cursor_dict.get("line_offset", 0)

                batch_rows = data_rows[offset : offset + batch_size]
                next_offset = offset + len(batch_rows)

                # Format records as structured score lines or dicts carrying header metadata
                formatted_records = []
                for row_str in batch_rows:
                    formatted_records.append({
                        "raw_line": row_str,
                        "model_version": model_version,
                        "score_date": score_date,
                    })

                if next_offset < total_rows and len(batch_rows) > 0:
                    cursor_after = json.dumps({
                        "phase": "bootstrap",
                        "line_offset": next_offset,
                        "total_lines": total_rows,
                        "model_version": model_version,
                        "score_date": score_date,
                        "file_hash": file_hash,
                        "target_cursor": score_date,
                    })
                    is_exhausted = False
                else:
                    cursor_after = score_date
                    is_exhausted = True

                return FetchResult(
                    records=formatted_records,
                    cursor_after=cursor_after,
                    is_bootstrap=is_bootstrap,
                    is_exhausted=is_exhausted,
                    artifact_restarted=artifact_restarted,
                    metadata={
                        "model_version": model_version,
                        "score_date": score_date,
                        "total_lines": total_rows,
                        "offset": offset,
                        "url": str(resp.url),
                        "bytes_downloaded": len(raw_bytes),
                        "content_hash": hashlib.sha256(raw_bytes).hexdigest(),
                        "artifact_bytes": raw_bytes,
                    },
                )
        except httpx.HTTPStatusError as e:
            logger.error("EPSS HTTP error %s: %s", e.response.status_code, e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"HTTP {e.response.status_code}: {e}")
        except ArchiveError as e:
            logger.error("EPSS archive error: %s", e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"Archive error: {e}")
        except Exception as e:
            logger.error("EPSS fetch failed: %s", e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"Fetch failed: {e}")


# ---------------------------------------------------------------------------
# 5. OSV Fetch Client
# ---------------------------------------------------------------------------

DEFAULT_OSV_ECOSYSTEMS = ["npm", "PyPI", "Go", "crates.io", "Maven"]


class OsvFetchClient:
    """
    Fetch client for Open Source Vulnerabilities (OSV).
    Supports:
      - Multi-ecosystem coverage manifest
      - Bootstrap: bounded all.zip extraction per ecosystem with continuation tracking
      - Incremental: modified_id.csv bounded parsing + individual API requests
    """
    GCS_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
    API_BASE_URL = "https://api.osv.dev/v1/vulns"

    def __init__(
        self,
        ecosystems: Optional[list[str]] = None,
        ecosystem: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        archive_limits: Optional[ArchiveLimits] = None,
    ):
        if ecosystems:
            self.ecosystems = ecosystems
        elif ecosystem:
            self.ecosystems = [ecosystem]
        else:
            self.ecosystems = list(DEFAULT_OSV_ECOSYSTEMS)
        self.client = client
        self.archive_limits = archive_limits or ArchiveLimits()

    def fetch(
        self,
        cursor: Optional[str] = None,
        *,
        batch_size: int = 1000,
        timeout_seconds: int = DEFAULT_TIMEOUT,
    ) -> FetchResult:
        cursor_dict = _parse_cursor_json(cursor)
        is_continuation = cursor_dict is not None and cursor_dict.get("phase") == "bootstrap"
        is_bootstrap = cursor is None or cursor_dict is None or is_continuation

        try:
            with _get_http_client(timeout_seconds, self.client) as http:
                if not is_bootstrap and cursor_dict and not is_continuation:
                    # Incremental mode across ecosystems
                    return self._fetch_incremental(http, cursor_dict, batch_size)
                else:
                    return self._fetch_bootstrap(http, batch_size, cursor_dict)
        except httpx.HTTPStatusError as e:
            logger.error("OSV HTTP error %s: %s", e.response.status_code, e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"HTTP {e.response.status_code}: {e}")
        except ArchiveError as e:
            logger.error("OSV archive error: %s", e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"Archive error: {e}")
        except Exception as e:
            logger.error("OSV fetch failed: %s", e)
            return FetchResult(records=[], is_bootstrap=is_bootstrap, error=f"Fetch failed: {e}")

    def _fetch_bootstrap(
        self,
        http: httpx.Client,
        batch_size: int,
        cursor_dict: Optional[dict] = None,
    ) -> FetchResult:
        eco_idx = 0
        entry_offset = 0
        completed_ecosystems: dict[str, str] = {}
        seen_ids: list[str] = []

        if cursor_dict:
            eco_idx = cursor_dict.get("ecosystem_idx", 0)
            entry_offset = cursor_dict.get("entry_offset", 0)
            completed_ecosystems = cursor_dict.get("completed_ecosystems", {})
            seen_ids = cursor_dict.get("seen_ids", [])

        if eco_idx >= len(self.ecosystems):
            # All ecosystems bootstrapped
            final_cursor = json.dumps(completed_ecosystems)
            return FetchResult(records=[], cursor_after=final_cursor, is_bootstrap=True)

        current_eco = self.ecosystems[eco_idx]
        zip_url = f"{self.GCS_BASE_URL}/{current_eco}/all.zip"
        resp = http.get(zip_url)
        resp.raise_for_status()

        all_records: list[dict] = []
        if resp.content.startswith(b"PK") or "zip" in resp.headers.get("content-type", "") or zip_url.endswith(".zip"):
            for name, content in safe_extract_zip(resp.content, limits=self.archive_limits):
                if name.endswith(".json") and not name.startswith("__MACOSX"):
                    try:
                        data = json.loads(content.decode("utf-8"))
                        if isinstance(data, dict) and data.get("id"):
                            if not data.get("ecosystem"):
                                data["ecosystem"] = current_eco
                            all_records.append(data)
                    except Exception as parse_err:
                        logger.warning("Failed parsing OSV zip entry %s: %s", name, parse_err)
        elif resp.content.startswith(b"{"):
            data = resp.json()
            if isinstance(data, dict) and data.get("id"):
                if not data.get("ecosystem"):
                    data["ecosystem"] = current_eco
                all_records = [data]
        elif resp.content.startswith(b"["):
            data = resp.json()
            if isinstance(data, list):
                for r in data:
                    if isinstance(r, dict) and r.get("id"):
                        if not r.get("ecosystem"):
                            r["ecosystem"] = current_eco
                        all_records.append(r)

        total_entries = len(all_records)
        batch_records = all_records[entry_offset : entry_offset + batch_size]
        new_seen = [r["id"] for r in batch_records if r.get("id")]
        current_seen_ids = seen_ids + new_seen
        next_offset = entry_offset + len(batch_records)

        now_iso = datetime.now(timezone.utc).isoformat()

        if next_offset < total_entries:
            # More records remain in current ecosystem
            cursor_after = json.dumps({
                "phase": "bootstrap",
                "ecosystem_idx": eco_idx,
                "ecosystem": current_eco,
                "entry_offset": next_offset,
                "total_entries": total_entries,
                "seen_ids": current_seen_ids,
                "completed_ecosystems": completed_ecosystems,
            })
            metadata_seen = None
            is_exhausted = False
        else:
            # Current ecosystem finished
            completed_ecosystems[current_eco] = now_iso
            next_eco_idx = eco_idx + 1
            if next_eco_idx < len(self.ecosystems):
                cursor_after = json.dumps({
                    "phase": "bootstrap",
                    "ecosystem_idx": next_eco_idx,
                    "ecosystem": self.ecosystems[next_eco_idx],
                    "entry_offset": 0,
                    "seen_ids": [],
                    "completed_ecosystems": completed_ecosystems,
                })
                is_exhausted = False
            else:
                cursor_after = json.dumps(completed_ecosystems)
                is_exhausted = True
            metadata_seen = current_seen_ids

        return FetchResult(
            records=batch_records,
            cursor_after=cursor_after,
            is_bootstrap=True,
            is_exhausted=is_exhausted,
            seen_ids=metadata_seen if (next_offset >= total_entries) else None,
            metadata={
                "ecosystem": current_eco,
                "count": len(batch_records),
                "total_entries": total_entries,
                "seen_ids": metadata_seen,
                "url": str(resp.url),
                "bytes_downloaded": len(resp.content),
                "content_hash": hashlib.sha256(resp.content).hexdigest(),
                "artifact_bytes": resp.content,
            },
        )

    def _fetch_incremental(
        self,
        http: httpx.Client,
        cursor_dict: dict[str, str],
        batch_size: int,
    ) -> FetchResult:
        """
        Fetch incremental modifications from modified_id.csv across configured ecosystems.
        Bounds API fetches to batch_size records per run.
        """
        updated_cursor_dict = dict(cursor_dict)
        all_records: list[dict] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Check each ecosystem's modified_id.csv
        for eco in self.ecosystems:
            if len(all_records) >= batch_size:
                break

            eco_cursor = cursor_dict.get(eco, "")
            csv_url = f"{self.GCS_BASE_URL}/{eco}/modified_id.csv"
            resp = http.get(csv_url)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()

            csv_text = resp.text
            modified_entries: list[tuple[str, str]] = []
            for line in csv_text.splitlines():
                parts = line.strip().split(",", 1)
                if len(parts) == 2:
                    osv_id, mod_iso = parts[0].strip(), parts[1].strip()
                    if not eco_cursor or mod_iso > eco_cursor:
                        modified_entries.append((osv_id, mod_iso))

            # Bound fetch to remaining batch capacity
            remaining = batch_size - len(all_records)
            slice_to_fetch = modified_entries[:remaining]

            last_ts = eco_cursor
            for osv_id, mod_iso in slice_to_fetch:
                api_url = f"{self.API_BASE_URL}/{osv_id}"
                item_resp = http.get(api_url)
                if item_resp.status_code == 404:
                    continue
                item_resp.raise_for_status()
                try:
                    record_data = item_resp.json()
                    if isinstance(record_data, dict) and record_data.get("id"):
                        if not record_data.get("ecosystem"):
                            record_data["ecosystem"] = eco
                        all_records.append(record_data)
                        last_ts = max(last_ts, mod_iso) if last_ts else mod_iso
                except Exception as e:
                    logger.warning("Failed parsing OSV API record %s: %s", osv_id, e)

            if last_ts:
                updated_cursor_dict[eco] = last_ts

        return FetchResult(
            records=all_records,
            cursor_after=json.dumps(updated_cursor_dict),
            is_bootstrap=False,
            is_exhausted=True,
            metadata={
                "count": len(all_records),
                "cursor": updated_cursor_dict,
            },
        )
