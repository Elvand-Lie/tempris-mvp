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
      - Bootstrap: download release / repository zip snapshot or bulk bundle with bounded batching & continuation
      - Incremental: GitHub commits delta or modified since cursor
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
        self.archive_limits = archive_limits or ArchiveLimits()

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
        """Download bulk archive and extract a bounded slice of CVE JSON files."""
        resp = http.get(self.base_url)
        resp.raise_for_status()

        content_type = resp.headers.get("content-type", "")
        all_records: list[dict] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        if resp.content.startswith(b"PK") or "zip" in content_type or self.base_url.endswith(".zip"):
            for name, content in safe_extract_zip(resp.content, limits=self.archive_limits):
                if name.endswith(".json") and not name.startswith("__MACOSX"):
                    try:
                        data = json.loads(content.decode("utf-8"))
                        if isinstance(data, dict) and data.get("dataType") == "CVE_RECORD":
                            all_records.append(data)
                    except Exception as parse_err:
                        logger.warning("Failed parsing CVE zip entry %s: %s", name, parse_err)
        elif resp.content.startswith(b"{"):
            data = resp.json()
            if isinstance(data, dict) and data.get("dataType") == "CVE_RECORD":
                all_records = [data]
            elif isinstance(data, list):
                all_records = [r for r in data if isinstance(r, dict) and r.get("dataType") == "CVE_RECORD"]
        elif resp.content.startswith(b"["):
            data = resp.json()
            if isinstance(data, list):
                all_records = [r for r in data if isinstance(r, dict) and r.get("dataType") == "CVE_RECORD"]

        total_entries = len(all_records)
        offset = 0
        target_sha = now_iso
        if cursor_dict:
            offset = cursor_dict.get("entry_offset", 0)
            target_sha = cursor_dict.get("target_sha", now_iso)

        batch_records = all_records[offset : offset + batch_size]
        next_offset = offset + len(batch_records)

        if next_offset < total_entries:
            # Intermediate batch -> continuation cursor
            cursor_after = json.dumps({
                "phase": "bootstrap",
                "entry_offset": next_offset,
                "total_entries": total_entries,
                "target_sha": target_sha,
            })
            is_exhausted = False
        else:
            # Final batch -> clean target cursor
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
                "total_entries": total_entries,
                "offset": offset,
                "url": self.base_url,
                "bytes_downloaded": len(resp.content),
                "content_hash": hashlib.sha256(resp.content).hexdigest(),
                "artifact_bytes": resp.content,
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

        params: dict[str, Any] = {
            "resultsPerPage": min(batch_size, 2000),
            "startIndex": start_index,
        }

        if not is_bootstrap and cursor and not is_continuation:
            params["lastModStartDate"] = cursor
            params["lastModEndDate"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

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
                    cursor_after = final_target_ts
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

                offset = 0
                previous_seen_ids: list[str] = []
                if cursor_dict and is_continuation:
                    offset = cursor_dict.get("entry_offset", 0)
                    previous_seen_ids = cursor_dict.get("seen_ids", [])

                batch_records = vulnerabilities[offset : offset + batch_size]
                new_seen_ids = [v.get("cveID") for v in batch_records if v.get("cveID")]
                all_seen_ids = previous_seen_ids + new_seen_ids
                next_offset = offset + len(batch_records)

                if next_offset < total_count and len(batch_records) > 0:
                    cursor_after = json.dumps({
                        "phase": "bootstrap",
                        "entry_offset": next_offset,
                        "total_entries": total_count,
                        "target_cursor": date_released,
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

                if cursor_dict and is_continuation:
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
