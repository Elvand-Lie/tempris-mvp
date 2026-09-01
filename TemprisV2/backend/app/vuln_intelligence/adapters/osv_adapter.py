# backend/app/vuln_intelligence/adapters/osv_adapter.py
"""
OSV adapter — parses OSV format records into the repository.

Preserves native OSV identity (GHSA-*, PYSEC-*, etc.), aliases/related/upstream
separation, affected packages with ecosystem/ranges/purl, severity,
database_specific, references, schema_version.

Only exact declared CVE-* aliases link to CVE spine.
Supports withdrawn state.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

import psycopg

from app.vuln_intelligence.models import (
    OsvAlias,
    OsvRecord,
    SourceRecord,
    validate_cve_id,
)
from app.vuln_intelligence.repository import (
    content_hash,
    get_canonical_vulnerability,
    upsert_source_record,
    upsert_osv_record,
    upsert_osv_alias,
)


def _parse_ts(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    return datetime.fromisoformat(val.replace("Z", "+00:00"))


class OsvAdapterResult:
    __slots__ = ("osv_id", "is_new_revision", "linked_cve_ids", "error")

    def __init__(
        self,
        osv_id: str,
        is_new_revision: bool = False,
        linked_cve_ids: Optional[list[str]] = None,
        error: Optional[str] = None,
    ):
        self.osv_id = osv_id
        self.is_new_revision = is_new_revision
        self.linked_cve_ids = linked_cve_ids or []
        self.error = error


def process_osv_record(
    conn: psycopg.Connection,
    record: dict,
    *,
    snapshot_id: Optional[str] = None,
) -> OsvAdapterResult:
    """
    Parse and store a single OSV record.

    Expects a full OSV JSON record with `id`, `aliases`, `related`, `affected`, etc.
    Returns OsvAdapterResult with processing outcome.
    """
    osv_id = record.get("id", "")
    if not osv_id:
        return OsvAdapterResult(osv_id="", error="Missing OSV id")

    # --- Source record (content-addressed dedup) ---
    # OSV source_id is the OSV native ID (GHSA-*, PYSEC-*, etc.)
    # cve_id on the source record is NULL — OSV is its own identity
    src_rec, is_new = upsert_source_record(conn, SourceRecord(
        source="osv",
        source_id=osv_id,
        cve_id=None,  # OSV identity is not CVE
        content_hash=content_hash(record),
        raw_payload=record,
        source_updated_at=_parse_ts(record.get("modified")),
        snapshot_id=snapshot_id,
    ))

    if not is_new:
        return OsvAdapterResult(osv_id=osv_id, is_new_revision=False)

    # --- Extract first affected package for denormalized fields ---
    ecosystem = None
    package_name = None
    package_purl = None
    affected = record.get("affected", [])
    if affected:
        pkg = affected[0].get("package", {})
        ecosystem = pkg.get("ecosystem")
        package_name = pkg.get("name")
        package_purl = pkg.get("purl")

    # --- OSV record upsert ---
    upsert_osv_record(conn, OsvRecord(
        osv_id=osv_id,
        summary=record.get("summary"),
        details=record.get("details"),
        published=_parse_ts(record.get("published")),
        modified=_parse_ts(record.get("modified")),
        withdrawn=_parse_ts(record.get("withdrawn")),
        ecosystem=ecosystem,
        package_name=package_name,
        package_purl=package_purl,
        affected_ranges=affected if affected else None,
        severity=record.get("severity"),
        database_specific=record.get("database_specific"),
        references=record.get("references"),
        raw_payload=record,
        source_record_id=src_rec.id,
        schema_version=record.get("schema_version"),
    ))

    # --- Process aliases (exact CVE-* aliases link to spine only if canonical exists) ---
    linked_cves = []
    for alias_val in record.get("aliases", []):
        linked_cve = None
        declared_linked = None
        if validate_cve_id(alias_val):
            declared_linked = alias_val
            # Only set the FK if the canonical row already exists
            canonical = get_canonical_vulnerability(conn, alias_val)
            if canonical:
                linked_cve = alias_val
            linked_cves.append(alias_val)
        upsert_osv_alias(conn, OsvAlias(
            osv_id=osv_id,
            alias=alias_val,
            alias_type="alias",
            linked_cve_id=linked_cve,
            declared_linked_cve_id=declared_linked,
        ))

    # --- Process related (distinct from aliases — no spine link) ---
    for related_val in record.get("related", []):
        # related entries do NOT create CVE spine links, even if they
        # look like CVE IDs. Only exact declared aliases link.
        upsert_osv_alias(conn, OsvAlias(
            osv_id=osv_id,
            alias=related_val,
            alias_type="related",
            linked_cve_id=None,  # related → no spine link
        ))

    return OsvAdapterResult(
        osv_id=osv_id,
        is_new_revision=True,
        linked_cve_ids=linked_cves,
    )
