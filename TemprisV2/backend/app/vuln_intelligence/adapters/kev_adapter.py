# backend/app/vuln_intelligence/adapters/kev_adapter.py
"""
CISA KEV adapter — parses KEV catalog JSON into the repository.

KEV is enrichment, not tenant exposure state. Preserves all native KEV fields.
CVE association is exact cveID match only — no fuzzy matching.
"""
from __future__ import annotations

from datetime import date
from typing import Optional

import psycopg

from app.vuln_intelligence.models import (
    KevEntry,
    SourceRecord,
    validate_cve_id,
)
from app.vuln_intelligence.repository import (
    content_hash,
    get_canonical_vulnerability,
    upsert_source_record,
    upsert_kev_entry,
)


class KevAdapterResult:
    __slots__ = ("cve_id", "is_new_revision", "error")

    def __init__(self, cve_id: str, is_new_revision: bool = False, error: Optional[str] = None):
        self.cve_id = cve_id
        self.is_new_revision = is_new_revision
        self.error = error


def process_kev_catalog(
    conn: psycopg.Connection,
    catalog: dict,
    *,
    snapshot_id: Optional[str] = None,
) -> list[KevAdapterResult]:
    """
    Parse a CISA KEV catalog JSON and store all entries.

    Expects the full catalog with `vulnerabilities` array.
    Returns a list of per-CVE processing results.
    """
    results = []
    for vuln in catalog.get("vulnerabilities", []):
        result = process_kev_entry(conn, vuln, snapshot_id=snapshot_id)
        results.append(result)
    return results


def process_kev_entry(
    conn: psycopg.Connection,
    entry: dict,
    *,
    snapshot_id: Optional[str] = None,
) -> KevAdapterResult:
    """Process a single KEV vulnerability entry."""
    cve_id = entry.get("cveID", "")
    if not validate_cve_id(cve_id):
        return KevAdapterResult(cve_id=cve_id, error=f"Invalid CVE ID: {cve_id!r}")

    # Check if canonical row exists (KEV is enrichment, NOT authority)
    canonical = get_canonical_vulnerability(conn, cve_id)

    # --- Source record (content-addressed dedup) ---
    # cve_id FK is set only if canonical row exists; declared_cve_id always set
    src_rec, is_new = upsert_source_record(conn, SourceRecord(
        source="kev",
        source_id=cve_id,
        cve_id=cve_id if canonical else None,
        declared_cve_id=cve_id,
        content_hash=content_hash(entry),
        raw_payload=entry,
        snapshot_id=snapshot_id,
    ))

    # --- KEV entry with all native fields (guarantees is_active = TRUE, withdrawn_at = NULL on reappearance) ---
    date_added = entry.get("dateAdded")
    due_date = entry.get("dueDate")

    upsert_kev_entry(conn, KevEntry(
        cve_id=cve_id if canonical else None,
        declared_cve_id=cve_id,
        vendor_project=entry.get("vendorProject", ""),
        product=entry.get("product", ""),
        vulnerability_name=entry.get("vulnerabilityName", ""),
        date_added=date.fromisoformat(date_added) if date_added else date.today(),
        short_description=entry.get("shortDescription"),
        required_action=entry.get("requiredAction"),
        due_date=date.fromisoformat(due_date) if due_date else None,
        known_ransomware=entry.get("knownRansomwareCampaignUse"),
        notes=entry.get("notes"),
        source_record_id=src_rec.id,
    ))

    return KevAdapterResult(cve_id=cve_id, is_new_revision=is_new)
