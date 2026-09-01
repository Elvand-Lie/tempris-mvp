# backend/app/vuln_intelligence/adapters/nvd_adapter.py
"""
NVD adapter — parses NVD 2.0 API response shapes into the repository.

NVD is enrichment, never CVE identity authority. Extracts:
- CVSS metrics (all versions, multiple assessors)
- CWE/weakness mappings
- CPE configurations (as affected data)
- References

Assessor authorship from NVD `source` field, assessment_type from NVD `type` field.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

import psycopg

from app.vuln_intelligence.models import (
    CvssAssessment,
    CveAffected,
    SourceRecord,
    validate_cve_id,
)
from app.vuln_intelligence.repository import (
    content_hash,
    get_canonical_vulnerability,
    get_current_source_record,
    upsert_source_record,
    upsert_cvss_assessment,
    retire_and_insert_cve_affected,
    upsert_cve_references,
    upsert_cve_weaknesses,
)


def _parse_ts(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    # NVD timestamps may lack timezone — treat as UTC
    s = val.replace("Z", "+00:00")
    if "+" not in s and s.count("-") <= 2:
        s += "+00:00"
    return datetime.fromisoformat(s)


class NvdAdapterResult:
    __slots__ = ("cve_id", "is_new_revision", "error")

    def __init__(self, cve_id: str, is_new_revision: bool = False, error: Optional[str] = None):
        self.cve_id = cve_id
        self.is_new_revision = is_new_revision
        self.error = error


def process_nvd_response(
    conn: psycopg.Connection,
    response: dict,
    *,
    snapshot_id: Optional[str] = None,
) -> list[NvdAdapterResult]:
    """
    Parse an NVD 2.0 API response and store all vulnerability records.

    Expects the full NVD response envelope with `vulnerabilities` array.
    Returns a list of per-CVE processing results.
    """
    results = []
    for vuln_wrapper in response.get("vulnerabilities", []):
        cve_data = vuln_wrapper.get("cve", {})
        result = process_nvd_cve(conn, cve_data, snapshot_id=snapshot_id)
        results.append(result)
    return results


def process_nvd_cve(
    conn: psycopg.Connection,
    cve_data: dict,
    *,
    snapshot_id: Optional[str] = None,
) -> NvdAdapterResult:
    """Process a single NVD CVE object (the `cve` key within a vulnerability wrapper)."""
    cve_id = cve_data.get("id", "")
    if not validate_cve_id(cve_id):
        return NvdAdapterResult(cve_id=cve_id, error=f"Invalid CVE ID: {cve_id!r}")

    # Check if canonical row exists (NVD is enrichment, NOT authority)
    canonical = get_canonical_vulnerability(conn, cve_id)

    # --- Source record (content-addressed dedup) ---
    # cve_id FK is set only if canonical row exists; declared_cve_id always set
    src_rec, is_new = upsert_source_record(conn, SourceRecord(
        source="nvd",
        source_id=cve_id,
        cve_id=cve_id if canonical else None,
        declared_cve_id=cve_id,
        content_hash=content_hash(cve_data),
        raw_payload=cve_data,
        source_updated_at=_parse_ts(cve_data.get("lastModified")),
        snapshot_id=snapshot_id,
    ))

    if not is_new:
        return NvdAdapterResult(cve_id=cve_id, is_new_revision=False)

    # Skip dependent data extraction when canonical row is absent —
    # all dependent tables have hard non-nullable FKs to canonical_vulnerabilities.
    # The preserved raw_payload is reconciled when CVE Program later creates
    # the canonical row.
    if not canonical:
        return NvdAdapterResult(cve_id=cve_id, is_new_revision=True)

    _normalize_nvd_enrichment(conn, cve_id, cve_data, src_rec.id)

    return NvdAdapterResult(cve_id=cve_id, is_new_revision=True)


def reconcile_current_nvd_enrichment(
    conn: psycopg.Connection,
    cve_id: str,
) -> bool:
    """Normalize a preserved current NVD record after its canonical CVE arrives."""
    source_record = get_current_source_record(conn, "nvd", cve_id)
    if (
        source_record is None
        or source_record.cve_id != cve_id
        or not source_record.raw_payload
        or _has_normalized_enrichment(conn, source_record.id)
    ):
        return False

    _normalize_nvd_enrichment(
        conn,
        cve_id,
        source_record.raw_payload,
        source_record.id,
    )
    return True


def _has_normalized_enrichment(
    conn: psycopg.Connection,
    source_record_id: Optional[str],
) -> bool:
    """Return whether this exact NVD source revision has already been normalized."""
    if source_record_id is None:
        return False
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                EXISTS (SELECT 1 FROM cvss_assessments WHERE source_record_id = %s)
             OR EXISTS (SELECT 1 FROM cve_affected WHERE source_record_id = %s)
             OR EXISTS (SELECT 1 FROM cve_weaknesses WHERE source_record_id = %s)
             OR EXISTS (SELECT 1 FROM cve_references WHERE source_record_id = %s)
                AS normalized;
            """,
            (source_record_id,) * 4,
        )
        return bool(cur.fetchone()["normalized"])


def _normalize_nvd_enrichment(
    conn: psycopg.Connection,
    cve_id: str,
    cve_data: dict,
    source_record_id: Optional[str],
) -> None:
    """Populate normalized NVD indexes from one preserved source-native payload."""
    # --- CVSS metrics (all versions) ---
    metrics = cve_data.get("metrics", {})
    _process_nvd_metrics(conn, cve_id, metrics, source_record_id)

    # --- Weaknesses ---
    for weakness in cve_data.get("weaknesses", []):
        _process_nvd_weakness(conn, cve_id, weakness, source_record_id)

    # --- Configurations / CPE (as affected data) ---
    configurations = cve_data.get("configurations", [])
    if configurations:
        _process_nvd_configurations(conn, cve_id, configurations, source_record_id)

    # --- References ---
    refs = cve_data.get("references", [])
    if refs:
        upsert_cve_references(conn, cve_id, "nvd", refs, source_record_id)


def _process_nvd_metrics(
    conn: psycopg.Connection,
    cve_id: str,
    metrics: dict,
    source_record_id: Optional[str],
) -> None:
    """Extract all CVSS metrics from NVD format."""
    # Map NVD metric keys to CVSS versions
    version_map = {
        "cvssMetricV2": "2.0",
        "cvssMetricV30": "3.0",
        "cvssMetricV31": "3.1",
        "cvssMetricV40": "4.0",
    }
    for metric_key, cvss_version in version_map.items():
        for m in metrics.get(metric_key, []):
            cvss_data = m.get("cvssData", {})
            nvd_source = m.get("source", "nvd@nist.gov")
            upsert_cvss_assessment(conn, CvssAssessment(
                cve_id=cve_id,
                source="nvd",
                assessor=nvd_source,
                assessment_type=m.get("type"),  # Primary or Secondary
                container_role="nvd",
                provider_org_id=nvd_source,
                cvss_version=cvss_version,
                vector_string=cvss_data.get("vectorString", ""),
                base_score=Decimal(str(cvss_data.get("baseScore", 0))),
                base_severity=cvss_data.get("baseSeverity"),
                exploitability_score=(
                    Decimal(str(m["exploitabilityScore"]))
                    if m.get("exploitabilityScore") is not None else None
                ),
                impact_score=(
                    Decimal(str(m["impactScore"]))
                    if m.get("impactScore") is not None else None
                ),
                scenario="GENERAL",
                raw_data=cvss_data,
                source_record_id=source_record_id,
            ))


def _process_nvd_weakness(
    conn: psycopg.Connection,
    cve_id: str,
    weakness: dict,
    source_record_id: Optional[str],
) -> None:
    """Process a single NVD weakness entry."""
    weakness_type = weakness.get("type")  # Primary or Secondary
    weakness_source = weakness.get("source", "nvd@nist.gov")
    entries = []
    for desc in weakness.get("description", []):
        entries.append({
            "cwe_id": desc.get("value"),
            "description": desc.get("value"),
            "type": weakness_type,
        })
    if entries:
        upsert_cve_weaknesses(conn, cve_id, "nvd", entries, source_record_id)


def _process_nvd_configurations(
    conn: psycopg.Connection,
    cve_id: str,
    configurations: list[dict],
    source_record_id: Optional[str],
) -> None:
    """Extract CPE-based affected data from NVD configurations."""
    affected_list = []
    for config in configurations:
        for node in config.get("nodes", []):
            cpes = []
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    cpes.append(match.get("criteria", ""))
            if cpes:
                affected_list.append(CveAffected(
                    cpes=cpes,
                    raw_data=node,
                ))
    if affected_list:
        retire_and_insert_cve_affected(
            conn, cve_id, "nvd", affected_list,
            source_record_id=source_record_id,
        )
