"""NVD Snapshot Synchronization Service.

Provides explicit, standalone synchronization of vulnerability records from the official
NIST NVD API 2.0 endpoint into immutable local JSON snapshot files.

INVARIANTS:
- Never runs during application startup or migration.
- Writes an immutable local JSON snapshot before database ingestion.
- Never logs or serializes API keys or secrets.
- Supports pagination, resuming, rate-limiting, and exponential backoff.
- Purely offline in unit tests (injectable requester/session or mock).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

import requests
from sqlalchemy.orm import Session

from models import CanonicalVulnerability, VulnerabilityCvssAssessment

logger = logging.getLogger("tempris.nvd_sync")

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_DELAY_WITH_KEY = 0.6
DEFAULT_DELAY_WITHOUT_KEY = 6.0
MAX_RETRIES = 3


class NvdSyncError(Exception):
    """Raised when an NVD API synchronization operation fails."""


def fetch_nvd_cve_by_id(
    cve_id: str,
    *,
    api_key: str | None = None,
    requester: Callable[..., requests.Response] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any] | None:
    """Fetch a single CVE record from NIST NVD API 2.0."""
    normalized_cve = cve_id.strip().upper()
    headers: dict[str, str] = {}
    key = api_key or os.environ.get("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key

    params = {"cveId": normalized_cve}
    url = f"{NVD_API_BASE_URL}?{urlencode(params)}"
    request_func = requester or requests.get

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = request_func(url, headers=headers, timeout=timeout)
            if resp.status_code == 404:
                return None
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < MAX_RETRIES:
                    sleep_time = (2 ** attempt) * (1.0 if key else 2.0)
                    time.sleep(sleep_time)
                    continue
                resp.raise_for_status()
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            return vulns[0] if vulns else None
        except Exception as ex:
            if attempt >= MAX_RETRIES:
                raise NvdSyncError(f"Failed to fetch {normalized_cve} from NVD after {MAX_RETRIES} attempts: {ex}") from ex
            time.sleep(2 ** attempt)
    return None


def sync_nvd_snapshots(
    *,
    output_file: str | Path,
    cve_ids: list[str] | None = None,
    api_key: str | None = None,
    results_per_page: int = 50,
    max_pages: int | None = None,
    resume_from_index: int = 0,
    state_file: str | Path | None = None,
    requester: Callable[..., requests.Response] | None = None,
    delay_seconds: float | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Fetch CVE records from NVD API 2.0 and save an immutable JSON snapshot.

    Writes the snapshot to `output_file` upon completion.
    """
    out_path = Path(output_file).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    key = api_key or os.environ.get("NVD_API_KEY", "").strip()
    headers: dict[str, str] = {}
    if key:
        headers["apiKey"] = key

    delay = delay_seconds if delay_seconds is not None else (DEFAULT_DELAY_WITH_KEY if key else DEFAULT_DELAY_WITHOUT_KEY)
    request_func = requester or requests.get

    all_vulnerabilities: list[dict[str, Any]] = []
    start_time = datetime.now(timezone.utc)
    current_index = resume_from_index
    total_results_reported = None
    pages_fetched = 0

    if cve_ids is not None:
        # Targeted fetch for specific CVE IDs
        unique_cves = sorted(list({c.strip().upper() for c in cve_ids if c.strip()}))
        for idx, cve in enumerate(unique_cves):
            if idx > 0 and delay > 0:
                time.sleep(delay)
            item = fetch_nvd_cve_by_id(cve, api_key=key, requester=request_func, timeout=timeout)
            if item:
                all_vulnerabilities.append(item)
        total_results_reported = len(all_vulnerabilities)
    else:
        # Paginated catalogue fetch
        while True:
            params = {
                "resultsPerPage": min(results_per_page, 2000),
                "startIndex": current_index,
            }
            url = f"{NVD_API_BASE_URL}?{urlencode(params)}"

            success = False
            data: dict[str, Any] = {}
            for attempt in range(1, MAX_RETRIES + 1):
                try:
                    resp = request_func(url, headers=headers, timeout=timeout)
                    if resp.status_code == 429 or resp.status_code >= 500:
                        if attempt < MAX_RETRIES:
                            time.sleep((2 ** attempt) * delay)
                            continue
                        resp.raise_for_status()
                    resp.raise_for_status()
                    data = resp.json()
                    success = True
                    break
                except Exception as ex:
                    if attempt >= MAX_RETRIES:
                        raise NvdSyncError(f"NVD API request failed at startIndex {current_index}: {ex}") from ex
                    time.sleep(2 ** attempt)

            if not success:
                break

            total_results_reported = int(data.get("totalResults", 0))
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            all_vulnerabilities.extend(vulns)
            pages_fetched += 1
            current_index += len(vulns)

            if state_file:
                try:
                    st_path = Path(state_file)
                    st_path.write_text(
                        json.dumps({
                            "next_start_index": current_index,
                            "total_results": total_results_reported,
                            "fetched_count": len(all_vulnerabilities),
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        }, indent=2),
                        encoding="utf-8",
                    )
                except Exception as e:
                    logger.warning(f"Failed to write state file {state_file}: {e}")

            if current_index >= total_results_reported:
                break
            if max_pages and pages_fetched >= max_pages:
                break
            if delay > 0:
                time.sleep(delay)

    serialized_vulns = json.dumps(all_vulnerabilities, sort_keys=True, ensure_ascii=False)
    snapshot_payload_sha256 = hashlib.sha256(serialized_vulns.encode("utf-8")).hexdigest()

    snapshot_document = {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "retrieval_metadata": {
            "api_endpoint": NVD_API_BASE_URL,
            "started_at": start_time.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "records_retrieved": len(all_vulnerabilities),
            "total_results_reported": total_results_reported,
            "filter_mode": "cve_list" if cve_ids is not None else "paginated_catalogue",
            "api_key_used": bool(key),
            "payload_sha256": snapshot_payload_sha256,
        },
        "vulnerabilities": all_vulnerabilities,
    }

    out_path.write_text(json.dumps(snapshot_document, indent=2, ensure_ascii=False), encoding="utf-8")
    file_bytes = out_path.read_bytes()
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()

    return {
        "status": "success",
        "output_file": str(out_path),
        "file_sha256": file_sha256,
        "payload_sha256": snapshot_payload_sha256,
        "records_retrieved": len(all_vulnerabilities),
        "total_results_reported": total_results_reported,
        "api_key_used": bool(key),
    }


def get_unassessed_canonical_cve_ids(db: Session, limit: int | None = None) -> list[str]:
    """Return canonical CVE IDs that have no CVSS assessments stored."""
    assessed_subq = db.query(VulnerabilityCvssAssessment.cve_id).distinct().subquery()
    query = (
        db.query(CanonicalVulnerability.cve_id)
        .filter(~CanonicalVulnerability.cve_id.in_(assessed_subq))
        .order_by(CanonicalVulnerability.cve_id)
    )
    if limit:
        query = query.limit(limit)
    return [r[0] for r in query.all()]
