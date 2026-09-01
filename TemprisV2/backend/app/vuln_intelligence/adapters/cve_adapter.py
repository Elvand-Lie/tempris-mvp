# backend/app/vuln_intelligence/adapters/cve_adapter.py
"""
CVE/cvelistV5 adapter — parses CVE JSON 5.x records (including embedded
CISA ADP/SSVC containers) into the repository.

Extracts: cveMetadata, CNA container (descriptions, affected, metrics/CVSS,
references, problemTypes), and all ADP containers (provider metadata, SSVC
data, affected/CPEs). Authorship from exact source metadata fields — no
substring inference.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

import psycopg

from app.vuln_intelligence.models import (
    CanonicalVulnerability,
    CvssAssessment,
    CveAffected,
    CveAdpEntry,
    CveRelationship,
    OsvAlias,
    SourceRecord,
    validate_cve_id,
)
from app.vuln_intelligence.repository import (
    content_hash,
    upsert_canonical_vulnerability,
    upsert_source_record,
    upsert_cvss_assessment,
    retire_and_insert_cve_affected,
    upsert_adp_entry,
    upsert_cve_relationship,
    upsert_cve_references,
    upsert_cve_weaknesses,
    _backfill_unresolved_references,
)


def _parse_ts(val: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string, stripping trailing Z."""
    if not val:
        return None
    return datetime.fromisoformat(val.replace("Z", "+00:00"))


class CveAdapterResult:
    """Result of processing a single CVE record."""
    __slots__ = ("cve_id", "is_new_revision", "error")

    def __init__(self, cve_id: str, is_new_revision: bool = False, error: Optional[str] = None):
        self.cve_id = cve_id
        self.is_new_revision = is_new_revision
        self.error = error


def process_cve_record(
    conn: psycopg.Connection,
    record: dict,
    *,
    snapshot_id: Optional[str] = None,
) -> CveAdapterResult:
    """
    Parse and store a single CVE JSON 5.x record.

    Expects the full CVE_RECORD envelope with dataType, dataVersion,
    cveMetadata, and containers.

    Returns CveAdapterResult with processing outcome.
    """
    # Validate envelope
    data_type = record.get("dataType")
    if data_type != "CVE_RECORD":
        return CveAdapterResult(
            cve_id="",
            error=f"Unexpected dataType: {data_type!r}, expected 'CVE_RECORD'",
        )

    meta = record.get("cveMetadata")
    if not meta:
        return CveAdapterResult(cve_id="", error="Missing cveMetadata")

    cve_id = meta.get("cveId", "")
    if not validate_cve_id(cve_id):
        return CveAdapterResult(cve_id=cve_id, error=f"Invalid CVE ID: {cve_id!r}")

    state = meta.get("state", "")
    if state not in ("PUBLISHED", "RESERVED", "REJECTED"):
        return CveAdapterResult(cve_id=cve_id, error=f"Unknown state: {state!r}")

    # --- Canonical vulnerability upsert (MUST precede source record for FK) ---
    upsert_canonical_vulnerability(conn, CanonicalVulnerability(
        cve_id=cve_id,
        state=state,
        date_published=_parse_ts(meta.get("datePublished")),
        date_updated=_parse_ts(meta.get("dateUpdated")),
        date_reserved=_parse_ts(meta.get("dateReserved")),
        date_rejected=_parse_ts(meta.get("dateRejected")),
        assigner_org_id=meta.get("assignerOrgId"),
        assigner_short_name=meta.get("assignerShortName"),
    ), source="cve")

    # Backfill and normalize any enrichment that arrived before this canonical row.
    _backfill_unresolved_references(conn, cve_id)
    from app.vuln_intelligence.adapters.nvd_adapter import reconcile_current_nvd_enrichment
    reconcile_current_nvd_enrichment(conn, cve_id)

    # --- Source record (content-addressed dedup) ---
    src_rec, is_new = upsert_source_record(conn, SourceRecord(
        source="cve",
        source_id=cve_id,
        cve_id=cve_id,
        declared_cve_id=cve_id,
        content_hash=content_hash(record),
        raw_payload=record,
        source_updated_at=_parse_ts(meta.get("dateUpdated")),
        snapshot_id=snapshot_id,
    ))

    if not is_new:
        # Content unchanged — nothing more to do
        return CveAdapterResult(cve_id=cve_id, is_new_revision=False)

    containers = record.get("containers", {})

    # --- CNA container ---
    cna = containers.get("cna", {})
    if cna:
        _process_cna_container(conn, cve_id, cna, src_rec.id)

    # --- ADP containers (including CISA ADP/SSVC) ---
    for adp_container in containers.get("adp", []):
        _process_adp_container(conn, cve_id, adp_container, src_rec.id)

    return CveAdapterResult(cve_id=cve_id, is_new_revision=True)


def _process_cna_container(
    conn: psycopg.Connection,
    cve_id: str,
    cna: dict,
    source_record_id: Optional[str],
) -> None:
    """Extract all structured data from a CNA container."""
    provider = cna.get("providerMetadata", {})
    # Assessor for CVSS is the CNA's exact shortName from providerMetadata
    cna_assessor = provider.get("shortName", provider.get("orgId", ""))
    cna_org_id = provider.get("orgId")

    # --- CVSS metrics ---
    for metric in cna.get("metrics", []):
        # Determine scenario
        scenarios = metric.get("scenarios", [])
        scenario = "GENERAL"
        if scenarios:
            scenario_val = scenarios[0].get("value", "GENERAL")
            if scenario_val:
                scenario = scenario_val

        # Extract CVSS data from any version key
        for cvss_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            cvss_data = metric.get(cvss_key)
            if cvss_data:
                version = cvss_data.get("version", "")
                if version not in ("2.0", "3.0", "3.1", "4.0"):
                    continue
                upsert_cvss_assessment(conn, CvssAssessment(
                    cve_id=cve_id,
                    source="cve",
                    assessor=cna_assessor,
                    assessment_type="cna",
                    container_role="cna",
                    provider_org_id=cna_org_id,
                    cvss_version=version,
                    vector_string=cvss_data.get("vectorString", ""),
                    base_score=Decimal(str(cvss_data.get("baseScore", 0))),
                    base_severity=cvss_data.get("baseSeverity"),
                    scenario=scenario,
                    raw_data=cvss_data,
                    source_record_id=source_record_id,
                ))

    # --- Affected products ---
    affected_list = []
    for aff_data in cna.get("affected", []):
        affected_list.append(CveAffected(
            vendor=aff_data.get("vendor"),
            product=aff_data.get("product"),
            versions=aff_data.get("versions"),
            default_status=aff_data.get("defaultStatus"),
            raw_data=aff_data,
        ))
    if affected_list:
        retire_and_insert_cve_affected(
            conn, cve_id, "cve", affected_list,
            source_record_id=source_record_id,
        )

    # --- References ---
    refs = cna.get("references", [])
    if refs:
        upsert_cve_references(conn, cve_id, "cve", refs, source_record_id)

    # --- Problem types / CWE ---
    weaknesses = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            weaknesses.append({
                "cwe_id": desc.get("cweId"),
                "description": desc.get("description"),
                "type": desc.get("type"),
            })
    if weaknesses:
        upsert_cve_weaknesses(conn, cve_id, "cve", weaknesses, source_record_id)

    # --- Replacement relationships (REJECTED CVEs) ---
    for replacement in cna.get("replacedBy", []):
        upsert_cve_relationship(conn, CveRelationship(
            cve_id=cve_id,
            related_cve_id=replacement,
            relationship_type="replaced_by",
            source="cve",
            source_record_id=source_record_id,
        ))


def _process_adp_container(
    conn: psycopg.Connection,
    cve_id: str,
    adp: dict,
    source_record_id: Optional[str],
) -> None:
    """Extract ADP enrichment including SSVC decision data and CVSS metrics."""
    provider = adp.get("providerMetadata", {})
    org_id = provider.get("orgId", "")
    if not org_id:
        return  # Cannot attribute without org ID

    adp_assessor = provider.get("shortName", org_id)

    # Extract CVSS metrics if present (Sprint 03 - WEAK-1)
    for metric in adp.get("metrics", []):
        scenarios = metric.get("scenarios", [])
        scenario = "GENERAL"
        if scenarios:
            scenario_val = scenarios[0].get("value", "GENERAL")
            if scenario_val:
                scenario = scenario_val

        for cvss_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            cvss_data = metric.get(cvss_key)
            if cvss_data:
                version = cvss_data.get("version", "")
                if version not in ("2.0", "3.0", "3.1", "4.0"):
                    continue
                upsert_cvss_assessment(conn, CvssAssessment(
                    cve_id=cve_id,
                    source="cve",
                    assessor=adp_assessor,
                    assessment_type="adp",
                    container_role="adp",
                    provider_org_id=org_id,
                    cvss_version=version,
                    vector_string=cvss_data.get("vectorString", ""),
                    base_score=Decimal(str(cvss_data.get("baseScore", 0))),
                    base_severity=cvss_data.get("baseSeverity"),
                    scenario=scenario,
                    raw_data=cvss_data,
                    source_record_id=source_record_id,
                ))

    # Extract SSVC data if present
    ssvc_data = None
    for metric in adp.get("metrics", []):
        other = metric.get("other", {})
        if other.get("type") == "ssvc":
            ssvc_data = other.get("content")
            break

    upsert_adp_entry(conn, CveAdpEntry(
        cve_id=cve_id,
        provider_org_id=org_id,
        provider_short_name=provider.get("shortName"),
        date_updated=_parse_ts(provider.get("dateUpdated")),
        title=adp.get("title"),
        ssvc_data=ssvc_data,
        raw_data=adp,
        source_record_id=source_record_id,
    ))
