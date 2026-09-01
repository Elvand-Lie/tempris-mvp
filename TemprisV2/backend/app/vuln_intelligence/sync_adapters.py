# backend/app/vuln_intelligence/sync_adapters.py
"""
Source-specific sync adapter implementations wrapping the Sprint 02 parsing
adapters with fetch/validate/process for the sync engine.

Each adapter implements the SourceAdapter protocol:
  - fetch(): retrieve candidates (bootstrap or incremental)
  - validate_batch(): validate the complete batch before processing
  - process_record(): parse one record through the Sprint 02 adapter

Fetch clients use bounded HTTP clients with strict timeouts, rate limiting,
and support for mock transport injection in tests.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

import psycopg

from app.vuln_intelligence.sync_engine import FetchResult, SourceAdapter
from app.vuln_intelligence.models import validate_cve_id
from app.vuln_intelligence.fetch_clients import (
    CveFetchClient,
    NvdFetchClient,
    KevFetchClient,
    EpssFetchClient,
    OsvFetchClient,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CVE sync adapter (cvelistV5 — includes embedded CISA ADP/SSVC)
# ---------------------------------------------------------------------------

class CveSyncAdapter:
    """
    Sync adapter for CVE/cvelistV5.

    Bootstrap: fetches full cvelistV5 repository snapshot.
    Incremental: fetches delta by dateUpdated cursor.
    """
    source_name = "cve"

    def __init__(self, fetch_client: Optional[CveFetchClient] = None):
        self.fetch_client = fetch_client or CveFetchClient()

    def fetch(
        self,
        conn: psycopg.Connection,
        cursor: Optional[str],
        *,
        batch_size: int = 1000,
        timeout_seconds: int = 300,
    ) -> FetchResult:
        """Fetch CVE records using official cvelistV5 client."""
        return self.fetch_client.fetch(
            cursor=cursor,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )

    def validate_batch(self, records: list[Any]) -> tuple[bool, Optional[str]]:
        """Validate CVE record batch."""
        if not isinstance(records, list):
            return False, "Expected list of CVE records"
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                return False, f"Record {i}: not a dict"
            if rec.get("dataType") != "CVE_RECORD":
                return False, f"Record {i}: missing or invalid dataType"
            meta = rec.get("cveMetadata", {})
            cve_id = meta.get("cveId", "")
            if not validate_cve_id(cve_id):
                return False, f"Record {i}: invalid CVE ID: {cve_id!r}"
        return True, None

    def process_record(
        self,
        conn: psycopg.Connection,
        record: Any,
        snapshot_id: str,
    ) -> tuple[bool, bool, Optional[str]]:
        """Process a single CVE record through the Sprint 02 CVE adapter."""
        from app.vuln_intelligence.adapters.cve_adapter import process_cve_record
        result = process_cve_record(conn, record, snapshot_id=snapshot_id)
        if result.error:
            return False, False, result.error
        return True, result.is_new_revision, None


# ---------------------------------------------------------------------------
# NVD sync adapter
# ---------------------------------------------------------------------------

class NvdSyncAdapter:
    """
    Sync adapter for NVD 2.0 API.

    Bootstrap: fetches all CVEs via paginated API.
    Incremental: fetches by lastModStartDate/lastModEndDate.
    """
    source_name = "nvd"

    def __init__(self, fetch_client: Optional[NvdFetchClient] = None):
        self.fetch_client = fetch_client or NvdFetchClient()

    def fetch(
        self,
        conn: psycopg.Connection,
        cursor: Optional[str],
        *,
        batch_size: int = 1000,
        timeout_seconds: int = 300,
    ) -> FetchResult:
        return self.fetch_client.fetch(
            cursor=cursor,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )

    def validate_batch(self, records: list[Any]) -> tuple[bool, Optional[str]]:
        if not isinstance(records, list):
            return False, "Expected list of NVD vulnerability wrappers"
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                return False, f"Record {i}: not a dict"
            cve_data = rec.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not validate_cve_id(cve_id):
                return False, f"Record {i}: invalid CVE ID: {cve_id!r}"
        return True, None

    def process_record(
        self,
        conn: psycopg.Connection,
        record: Any,
        snapshot_id: str,
    ) -> tuple[bool, bool, Optional[str]]:
        from app.vuln_intelligence.adapters.nvd_adapter import process_nvd_cve
        cve_data = record.get("cve", record)
        result = process_nvd_cve(conn, cve_data, snapshot_id=snapshot_id)
        if result.error:
            return False, False, result.error
        return True, result.is_new_revision, None


# ---------------------------------------------------------------------------
# KEV sync adapter
# ---------------------------------------------------------------------------

class KevSyncAdapter:
    """
    Sync adapter for CISA KEV catalog.

    Bootstrap: fetches full KEV catalog JSON.
    Incremental: KEV is a full catalog — re-fetches and deduplicates.
    """
    source_name = "kev"

    def __init__(self, fetch_client: Optional[KevFetchClient] = None):
        self.fetch_client = fetch_client or KevFetchClient()

    def fetch(
        self,
        conn: psycopg.Connection,
        cursor: Optional[str],
        *,
        batch_size: int = 1000,
        timeout_seconds: int = 300,
    ) -> FetchResult:
        return self.fetch_client.fetch(
            cursor=cursor,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )

    def validate_batch(self, records: list[Any]) -> tuple[bool, Optional[str]]:
        if not isinstance(records, list):
            return False, "Expected list of KEV entries"
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                return False, f"Record {i}: not a dict"
            cve_id = rec.get("cveID", "")
            if not validate_cve_id(cve_id):
                return False, f"Record {i}: invalid CVE ID: {cve_id!r}"
        return True, None

    def process_record(
        self,
        conn: psycopg.Connection,
        record: Any,
        snapshot_id: str,
    ) -> tuple[bool, bool, Optional[str]]:
        from app.vuln_intelligence.adapters.kev_adapter import process_kev_entry
        result = process_kev_entry(conn, record, snapshot_id=snapshot_id)
        if result.error:
            return False, False, result.error
        return True, result.is_new_revision, None


# ---------------------------------------------------------------------------
# EPSS sync adapter
# ---------------------------------------------------------------------------

class EpssSyncAdapter:
    """
    Sync adapter for FIRST EPSS.

    Bootstrap: fetches full or chunked EPSS CSV.
    Incremental: EPSS is daily bulk — re-fetches and deduplicates by score_date.
    """
    source_name = "epss"

    def __init__(self, fetch_client: Optional[EpssFetchClient] = None):
        self.fetch_client = fetch_client or EpssFetchClient()

    def fetch(
        self,
        conn: psycopg.Connection,
        cursor: Optional[str],
        *,
        batch_size: int = 1000,
        timeout_seconds: int = 300,
    ) -> FetchResult:
        return self.fetch_client.fetch(
            cursor=cursor,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )

    def validate_batch(self, records: list[Any]) -> tuple[bool, Optional[str]]:
        """
        Validate EPSS batch: accepts single full CSV string or list of record dicts/lines.
        """
        if not isinstance(records, list):
            return False, "Expected list of EPSS records"
        if len(records) == 0:
            return False, "Expected at least 1 EPSS record"
        if len(records) == 1 and isinstance(records[0], str):
            if "#" not in records[0].split("\n")[0]:
                return False, "Missing EPSS metadata header (# comment line)"
            return True, None
        for i, rec in enumerate(records):
            if isinstance(rec, str):
                if not rec.strip():
                    continue
                parts = rec.strip().split(",")
                if len(parts) < 3 or not validate_cve_id(parts[0].strip()):
                    return False, f"Record {i}: invalid EPSS CSV line: {rec!r}"
            elif isinstance(rec, dict):
                raw_line = rec.get("raw_line")
                if raw_line:
                    parts = raw_line.strip().split(",")
                    if len(parts) < 3 or not validate_cve_id(parts[0].strip()):
                        return False, f"Record {i}: invalid EPSS CSV line: {raw_line!r}"
                else:
                    cve_id = rec.get("cve_id") or rec.get("cve", "")
                    if not validate_cve_id(cve_id):
                        return False, f"Record {i}: invalid CVE ID: {cve_id!r}"
            else:
                return False, f"Record {i}: expected str or dict, got {type(rec)}"
        return True, None

    def process_record(
        self,
        conn: psycopg.Connection,
        record: Any,
        snapshot_id: str,
    ) -> tuple[bool, bool, Optional[str]]:
        """Process an EPSS record (single CSV string or record dict)."""
        from app.vuln_intelligence.adapters.epss_adapter import process_epss_record
        return process_epss_record(conn, record, snapshot_id=snapshot_id)


# ---------------------------------------------------------------------------
# OSV sync adapter
# ---------------------------------------------------------------------------

class OsvSyncAdapter:
    """
    Sync adapter for OSV.

    Bootstrap: fetches full OSV database dump per ecosystem.
    Incremental: uses modified timestamp cursor and modified_id.csv.
    """
    source_name = "osv"

    def __init__(self, fetch_client: Optional[OsvFetchClient] = None, ecosystems: Optional[list[str]] = None):
        self.fetch_client = fetch_client or OsvFetchClient(ecosystems=ecosystems)

    def fetch(
        self,
        conn: psycopg.Connection,
        cursor: Optional[str],
        *,
        batch_size: int = 1000,
        timeout_seconds: int = 300,
    ) -> FetchResult:
        return self.fetch_client.fetch(
            cursor=cursor,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )

    def validate_batch(self, records: list[Any]) -> tuple[bool, Optional[str]]:
        if not isinstance(records, list):
            return False, "Expected list of OSV records"
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                return False, f"Record {i}: not a dict"
            osv_id = rec.get("id", "")
            if not osv_id:
                return False, f"Record {i}: missing OSV id"
        return True, None

    def process_record(
        self,
        conn: psycopg.Connection,
        record: Any,
        snapshot_id: str,
    ) -> tuple[bool, bool, Optional[str]]:
        from app.vuln_intelligence.adapters.osv_adapter import process_osv_record
        result = process_osv_record(conn, record, snapshot_id=snapshot_id)
        if result.error:
            return False, False, result.error
        return True, result.is_new_revision, None


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------

ALL_ADAPTERS: dict[str, SourceAdapter] = {
    "cve": CveSyncAdapter(),
    "nvd": NvdSyncAdapter(),
    "kev": KevSyncAdapter(),
    "epss": EpssSyncAdapter(),
    "osv": OsvSyncAdapter(),
}

def get_adapter(source: str) -> Optional[SourceAdapter]:
    """Get the sync adapter for a source name."""
    return ALL_ADAPTERS.get(source)
