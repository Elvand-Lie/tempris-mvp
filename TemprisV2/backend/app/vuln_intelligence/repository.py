# backend/app/vuln_intelligence/repository.py
"""
Repository primitives for the vulnerability intelligence library.

Uses the existing psycopg pool and raw SQL — no ORM. All public methods
accept a psycopg Connection (borrowed from the pool by the caller) so
transactions are explicit and composable.

Content-addressed deduplication: a source record with an identical
(source, source_id, content_hash) is not re-inserted. A new content_hash
creates a new revision and atomically moves is_current.
"""
from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Optional, Union

import psycopg
from psycopg.rows import dict_row

from app.vuln_intelligence.models import (
    AuthorityError,
    CanonicalVulnerability,
    CvssAssessment,
    CveRelationship,
    CveAffected,
    CveAdpEntry,
    EpssScore,
    KevEntry,
    MassWithdrawalExceededError,
    OsvAlias,
    OsvRecord,
    SourceArtifact,
    SourceRecord,
    SyncSnapshot,
    SyncState,
    TesResolution,
    validate_cve_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def content_hash(payload: Any) -> str:
    """SHA-256 of the canonical JSON serialization of *payload*."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ts(val: Any) -> Optional[str]:
    """Coerce a datetime/str/None to ISO string for parameterised SQL."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


def _d(val: Any) -> Optional[str]:
    """Coerce a date/str/None to ISO string."""
    if val is None:
        return None
    if isinstance(val, date):
        return val.isoformat()
    return str(val)


def _json(val: Any) -> Optional[str]:
    """Serialize a dict/list to JSON string for JSONB columns, or None."""
    if val is None:
        return None
    return json.dumps(val, default=str)


# ---------------------------------------------------------------------------
# Canonical vulnerabilities
# ---------------------------------------------------------------------------

def upsert_canonical_vulnerability(
    conn: psycopg.Connection,
    vuln: CanonicalVulnerability,
    *,
    source: str = "cve",
) -> CanonicalVulnerability:
    """Insert or update a canonical CVE record. Returns the stored row.

    Only the CVE Program adapter (source="cve") is authoritative for
    canonical vulnerability identity. All other sources must use
    declared_cve_id on their respective tables instead.
    """
    if source != "cve":
        raise AuthorityError(
            f"Source {source!r} is not authoritative for canonical_vulnerabilities. "
            f"Only source='cve' may write canonical CVE identity."
        )
    if not validate_cve_id(vuln.cve_id):
        raise ValueError(f"Invalid CVE ID syntax: {vuln.cve_id}")
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO canonical_vulnerabilities
                (cve_id, state, date_published, date_updated, date_reserved,
                 date_rejected, assigner_org_id, assigner_short_name)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET
                state = EXCLUDED.state,
                date_published = COALESCE(EXCLUDED.date_published, canonical_vulnerabilities.date_published),
                date_updated = EXCLUDED.date_updated,
                date_reserved = COALESCE(EXCLUDED.date_reserved, canonical_vulnerabilities.date_reserved),
                date_rejected = EXCLUDED.date_rejected,
                assigner_org_id = COALESCE(EXCLUDED.assigner_org_id, canonical_vulnerabilities.assigner_org_id),
                assigner_short_name = COALESCE(EXCLUDED.assigner_short_name, canonical_vulnerabilities.assigner_short_name),
                updated_at = now()
            RETURNING *;
            """,
            (
                vuln.cve_id,
                vuln.state,
                _ts(vuln.date_published),
                _ts(vuln.date_updated),
                _ts(vuln.date_reserved),
                _ts(vuln.date_rejected),
                vuln.assigner_org_id,
                vuln.assigner_short_name,
            ),
        )
        row = cur.fetchone()
    return _row_to_canonical(row)


def get_canonical_vulnerability(
    conn: psycopg.Connection,
    cve_id: str,
) -> Optional[CanonicalVulnerability]:
    """Fetch a single canonical vulnerability by CVE ID."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM canonical_vulnerabilities WHERE cve_id = %s;",
            (cve_id,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return _row_to_canonical(row)


def _row_to_canonical(row: dict) -> CanonicalVulnerability:
    return CanonicalVulnerability(
        cve_id=row["cve_id"],
        state=row["state"],
        date_published=row.get("date_published"),
        date_updated=row.get("date_updated"),
        date_reserved=row.get("date_reserved"),
        date_rejected=row.get("date_rejected"),
        assigner_org_id=row.get("assigner_org_id"),
        assigner_short_name=row.get("assigner_short_name"),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


# ---------------------------------------------------------------------------
# Source records — content-addressed deduplication
# ---------------------------------------------------------------------------

def upsert_source_record(
    conn: psycopg.Connection,
    rec: SourceRecord,
) -> tuple[SourceRecord, bool]:
    """
    Insert or deduplicate a source record by content hash.

    Returns (record, is_new) where is_new is False when the identical
    content_hash already existed (no new row created).
    """
    computed_hash = content_hash(rec.raw_payload) if not rec.content_hash else rec.content_hash
    with conn.cursor() as cur:
        # Check if identical content already exists
        cur.execute(
            """
            SELECT id, is_current FROM vuln_source_records
            WHERE source = %s AND source_id = %s AND content_hash = %s;
            """,
            (rec.source, rec.source_id, computed_hash),
        )
        existing = cur.fetchone()
        if existing is not None:
            # Content-addressed dedup: identical payload already stored
            rec.id = str(existing["id"])
            rec.content_hash = computed_hash
            rec.is_current = existing["is_current"]
            return rec, False

        # Retire previous current record for this (source, source_id)
        cur.execute(
            """
            UPDATE vuln_source_records
            SET is_current = FALSE
            WHERE source = %s AND source_id = %s AND is_current = TRUE;
            """,
            (rec.source, rec.source_id),
        )

        # Insert new revision
        declared_cve = rec.declared_cve_id or rec.cve_id
        cur.execute(
            """
            INSERT INTO vuln_source_records
                (source, source_id, cve_id, declared_cve_id, content_hash, raw_payload,
                 source_updated_at, is_current, snapshot_id)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, TRUE, %s)
            RETURNING id, created_at;
            """,
            (
                rec.source,
                rec.source_id,
                rec.cve_id,
                declared_cve,
                computed_hash,
                _json(rec.raw_payload),
                _ts(rec.source_updated_at),
                rec.snapshot_id,
            ),
        )
        new_row = cur.fetchone()
        rec.id = str(new_row["id"])
        rec.content_hash = computed_hash
        rec.is_current = True
        rec.created_at = new_row["created_at"]
    return rec, True


def get_current_source_record(
    conn: psycopg.Connection,
    source: str,
    source_id: str,
) -> Optional[SourceRecord]:
    """Get the current (active) source record for a given source+id."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM vuln_source_records
            WHERE source = %s AND source_id = %s AND is_current = TRUE;
            """,
            (source, source_id),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return _row_to_source_record(row)


def get_source_record_revisions(
    conn: psycopg.Connection,
    source: str,
    source_id: str,
) -> list[SourceRecord]:
    """Get all revisions (current and historical) for a source record."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM vuln_source_records
            WHERE source = %s AND source_id = %s
            ORDER BY created_at DESC;
            """,
            (source, source_id),
        )
        rows = cur.fetchall()
    return [_row_to_source_record(r) for r in rows]


def _row_to_source_record(row: dict) -> SourceRecord:
    return SourceRecord(
        id=str(row["id"]),
        source=row["source"],
        source_id=row["source_id"],
        cve_id=row.get("cve_id"),
        declared_cve_id=row.get("declared_cve_id"),
        content_hash=row["content_hash"],
        raw_payload=row.get("raw_payload"),
        source_updated_at=row.get("source_updated_at"),
        is_current=row["is_current"],
        snapshot_id=str(row["snapshot_id"]) if row.get("snapshot_id") else None,
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# CVSS assessments
# ---------------------------------------------------------------------------

def upsert_cvss_assessment(
    conn: psycopg.Connection,
    assessment: CvssAssessment,
) -> CvssAssessment:
    """Insert or update a CVSS assessment. Retires previous current for same key."""
    with conn.cursor() as cur:
        # Retire previous current assessment for this exact key
        cur.execute(
            """
            UPDATE cvss_assessments
            SET is_current = FALSE
            WHERE cve_id = %s AND assessor = %s AND cvss_version = %s
                  AND COALESCE(scenario, '') = COALESCE(%s, '')
                  AND is_current = TRUE;
            """,
            (assessment.cve_id, assessment.assessor, assessment.cvss_version, assessment.scenario),
        )
        cur.execute(
            """
            INSERT INTO cvss_assessments
                (cve_id, source, assessor, assessment_type, container_role, provider_org_id,
                 cvss_version, vector_string, base_score, base_severity,
                 exploitability_score, impact_score, scenario,
                 raw_data, source_record_id, is_current)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, TRUE)
            RETURNING id, created_at;
            """,
            (
                assessment.cve_id,
                assessment.source,
                assessment.assessor,
                assessment.assessment_type,
                assessment.container_role,
                assessment.provider_org_id,
                assessment.cvss_version,
                assessment.vector_string,
                str(assessment.base_score),
                assessment.base_severity,
                str(assessment.exploitability_score) if assessment.exploitability_score is not None else None,
                str(assessment.impact_score) if assessment.impact_score is not None else None,
                assessment.scenario,
                _json(assessment.raw_data),
                assessment.source_record_id,
            ),
        )
        row = cur.fetchone()
        assessment.id = str(row["id"])
        assessment.created_at = row["created_at"]
    return assessment


def get_cvss_assessments(
    conn: psycopg.Connection,
    cve_id: str,
    *,
    current_only: bool = True,
) -> list[CvssAssessment]:
    """Get all CVSS assessments for a CVE, optionally including historical."""
    clause = " AND is_current = TRUE" if current_only else ""
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM cvss_assessments WHERE cve_id = %s{clause} ORDER BY created_at;",
            (cve_id,),
        )
        rows = cur.fetchall()
    return [_row_to_cvss(r) for r in rows]


def _row_to_cvss(row: dict) -> CvssAssessment:
    return CvssAssessment(
        id=str(row["id"]),
        cve_id=row["cve_id"],
        source=row["source"],
        assessor=row["assessor"],
        assessment_type=row.get("assessment_type"),
        container_role=row.get("container_role"),
        provider_org_id=row.get("provider_org_id"),
        cvss_version=row["cvss_version"],
        vector_string=row["vector_string"],
        base_score=Decimal(str(row["base_score"])),
        base_severity=row.get("base_severity"),
        exploitability_score=Decimal(str(row["exploitability_score"])) if row.get("exploitability_score") is not None else None,
        impact_score=Decimal(str(row["impact_score"])) if row.get("impact_score") is not None else None,
        scenario=row.get("scenario", "GENERAL"),
        raw_data=row.get("raw_data"),
        source_record_id=str(row["source_record_id"]) if row.get("source_record_id") else None,
        is_current=row["is_current"],
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# TES-input CVSS resolver
# ---------------------------------------------------------------------------

def resolve_tes_cvss(
    conn: psycopg.Connection,
    cve_id: str,
) -> TesResolution:
    """
    Deterministic TES-input resolver (Sprint 03 - VI-QA-09):
      1. One unambiguous current general/default Base CVSS 3.1 authored by the
         assigning CNA container (container_role = 'cna') → use it (Tier 1).
      2. Else one unambiguous current general/default Base CVSS 3.1 authored by
         NVD/NIST (container_role = 'nvd' or source = 'nvd') → use it (Tier 2).
      3. Else → unscoreable with reason.

    CVSS 4.0, 3.0, and 2.0 and ADP containers remain available evidence but are never TES inputs.
    No CVSS version conversion occurs.
    """
    # Get the canonical vulnerability
    vuln = get_canonical_vulnerability(conn, cve_id)
    if vuln is None:
        return TesResolution(cve_id=cve_id, unscoreable_reason="CVE not found")

    # Get all current CVSS 3.1 assessments with GENERAL scenario
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM cvss_assessments
            WHERE cve_id = %s
              AND cvss_version = '3.1'
              AND COALESCE(scenario, 'GENERAL') = 'GENERAL'
              AND is_current = TRUE
            ORDER BY assessor;
            """,
            (cve_id,),
        )
        rows = cur.fetchall()

    if not rows:
        return TesResolution(cve_id=cve_id, unscoreable_reason="No eligible CNA or NVD CVSS 3.1 GENERAL assessment")

    # Tier 1: assigning CNA assessment via structural container_role == 'cna'
    # Fallback to source == 'cve' AND (assessment_type == 'cna' OR assessment_type IS NULL) for backwards compatibility
    cna_assessments = [
        r for r in rows
        if r.get("container_role") == "cna"
        or (r.get("container_role") is None and r.get("source") == "cve" and r.get("assessment_type") in ("cna", None))
    ]
    if len(cna_assessments) == 1:
        a = cna_assessments[0]
        return TesResolution(
            cve_id=cve_id,
            resolved_score=Decimal(str(a["base_score"])),
            resolved_vector=a["vector_string"],
            resolved_severity=a.get("base_severity"),
            resolved_assessor=a["assessor"],
            resolution_tier="cna",
        )
    if len(cna_assessments) > 1:
        return TesResolution(cve_id=cve_id, unscoreable_reason="Ambiguous: multiple CNA CVSS 3.1 GENERAL assessments")

    # Tier 2: NVD assessment via structural container_role == 'nvd' or source == 'nvd'
    nvd_assessments = [
        r for r in rows
        if r.get("container_role") == "nvd"
        or (r.get("container_role") is None and r.get("source") == "nvd")
        or (r.get("source") == "nvd")
    ]
    if len(nvd_assessments) == 1:
        a = nvd_assessments[0]
        return TesResolution(
            cve_id=cve_id,
            resolved_score=Decimal(str(a["base_score"])),
            resolved_vector=a["vector_string"],
            resolved_severity=a.get("base_severity"),
            resolved_assessor=a["assessor"],
            resolution_tier="nvd",
        )
    if len(nvd_assessments) > 1:
        return TesResolution(cve_id=cve_id, unscoreable_reason="Ambiguous: multiple NVD CVSS 3.1 GENERAL assessments")

    # No eligible tier matched (e.g. only ADP containers)
    return TesResolution(cve_id=cve_id, unscoreable_reason="No eligible CNA or NVD CVSS 3.1 GENERAL assessment")


resolve_tes_cvss_assessment = resolve_tes_cvss


# ---------------------------------------------------------------------------
# CVE relationships
# ---------------------------------------------------------------------------

def upsert_cve_relationship(
    conn: psycopg.Connection,
    rel: CveRelationship,
) -> CveRelationship:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_relationships
                (cve_id, related_cve_id, relationship_type, source, source_record_id)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (cve_id, related_cve_id, relationship_type, source) DO NOTHING
            RETURNING id, created_at;
            """,
            (rel.cve_id, rel.related_cve_id, rel.relationship_type, rel.source, rel.source_record_id),
        )
        row = cur.fetchone()
        if row:
            rel.id = str(row["id"])
            rel.created_at = row["created_at"]
    return rel


def get_cve_relationships(
    conn: psycopg.Connection,
    cve_id: str,
) -> list[CveRelationship]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM cve_relationships WHERE cve_id = %s ORDER BY created_at;",
            (cve_id,),
        )
        rows = cur.fetchall()
    return [_row_to_rel(r) for r in rows]


def _row_to_rel(row: dict) -> CveRelationship:
    return CveRelationship(
        id=str(row["id"]),
        cve_id=row["cve_id"],
        related_cve_id=row["related_cve_id"],
        relationship_type=row["relationship_type"],
        source=row["source"],
        source_record_id=str(row["source_record_id"]) if row.get("source_record_id") else None,
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# CVE affected products
# ---------------------------------------------------------------------------

def retire_and_insert_cve_affected(
    conn: psycopg.Connection,
    cve_id: str,
    source: str,
    affected_list: list[CveAffected],
    source_record_id: Optional[str] = None,
) -> list[CveAffected]:
    """
    Idempotently replace all current affected rows for (cve_id, source)
    with a new set. Retires prior current rows first, then inserts new ones.
    This ensures revision handling is safe and prior rows are traceable.
    """
    with conn.cursor() as cur:
        # Retire all prior current affected rows for this (cve_id, source)
        cur.execute(
            """
            UPDATE cve_affected SET is_current = FALSE
            WHERE cve_id = %s AND source = %s AND is_current = TRUE;
            """,
            (cve_id, source),
        )
    results = []
    for aff in affected_list:
        aff.cve_id = cve_id
        aff.source = source
        aff.source_record_id = source_record_id
        inserted = upsert_cve_affected(conn, aff)
        results.append(inserted)
    return results


def upsert_cve_affected(
    conn: psycopg.Connection,
    aff: CveAffected,
) -> CveAffected:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_affected
                (cve_id, source, vendor, product, versions, cpes,
                 default_status, raw_data, source_record_id, is_current)
            VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, %s, TRUE)
            RETURNING id, created_at;
            """,
            (
                aff.cve_id, aff.source, aff.vendor, aff.product,
                _json(aff.versions), aff.cpes, aff.default_status,
                _json(aff.raw_data), aff.source_record_id,
            ),
        )
        row = cur.fetchone()
        aff.id = str(row["id"])
        aff.created_at = row["created_at"]
    return aff


def get_cve_affected(
    conn: psycopg.Connection,
    cve_id: str,
    *,
    current_only: bool = True,
) -> list[CveAffected]:
    clause = " AND is_current = TRUE" if current_only else ""
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM cve_affected WHERE cve_id = %s{clause} ORDER BY created_at;",
            (cve_id,),
        )
        rows = cur.fetchall()
    return [_row_to_affected(r) for r in rows]


def _row_to_affected(row: dict) -> CveAffected:
    return CveAffected(
        id=str(row["id"]),
        cve_id=row["cve_id"],
        source=row["source"],
        vendor=row.get("vendor"),
        product=row.get("product"),
        versions=row.get("versions"),
        cpes=row.get("cpes"),
        default_status=row.get("default_status"),
        raw_data=row.get("raw_data"),
        source_record_id=str(row["source_record_id"]) if row.get("source_record_id") else None,
        is_current=row["is_current"],
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# ADP / SSVC entries
# ---------------------------------------------------------------------------

def upsert_adp_entry(
    conn: psycopg.Connection,
    adp: CveAdpEntry,
) -> CveAdpEntry:
    with conn.cursor() as cur:
        # Retire previous current for same (cve_id, provider_org_id)
        cur.execute(
            """
            UPDATE cve_adp_entries SET is_current = FALSE
            WHERE cve_id = %s AND provider_org_id = %s AND is_current = TRUE;
            """,
            (adp.cve_id, adp.provider_org_id),
        )
        cur.execute(
            """
            INSERT INTO cve_adp_entries
                (cve_id, provider_org_id, provider_short_name, date_updated,
                 title, ssvc_data, raw_data, source_record_id, is_current)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, TRUE)
            RETURNING id, created_at;
            """,
            (
                adp.cve_id, adp.provider_org_id, adp.provider_short_name,
                _ts(adp.date_updated), adp.title, _json(adp.ssvc_data),
                _json(adp.raw_data if adp.raw_data is not None else {}), adp.source_record_id,
            ),
        )
        row = cur.fetchone()
        adp.id = str(row["id"])
        adp.created_at = row["created_at"]
    return adp


def get_adp_entries(
    conn: psycopg.Connection,
    cve_id: str,
    *,
    current_only: bool = True,
) -> list[CveAdpEntry]:
    clause = " AND is_current = TRUE" if current_only else ""
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM cve_adp_entries WHERE cve_id = %s{clause} ORDER BY created_at;",
            (cve_id,),
        )
        rows = cur.fetchall()
    return [_row_to_adp(r) for r in rows]


def _row_to_adp(row: dict) -> CveAdpEntry:
    return CveAdpEntry(
        id=str(row["id"]),
        cve_id=row["cve_id"],
        provider_org_id=row["provider_org_id"],
        provider_short_name=row.get("provider_short_name"),
        date_updated=row.get("date_updated"),
        title=row.get("title"),
        ssvc_data=row.get("ssvc_data"),
        raw_data=row.get("raw_data"),
        source_record_id=str(row["source_record_id"]) if row.get("source_record_id") else None,
        is_current=row["is_current"],
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# KEV entries
# ---------------------------------------------------------------------------

def upsert_kev_entry(
    conn: psycopg.Connection,
    kev: KevEntry,
) -> KevEntry:
    declared_cve = kev.declared_cve_id or kev.cve_id or ""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO kev_entries
                (declared_cve_id, cve_id, vendor_project, product, vulnerability_name,
                 date_added, short_description, required_action, due_date,
                 known_ransomware, notes, source_record_id, is_active, withdrawn_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (declared_cve_id) DO UPDATE SET
                cve_id = COALESCE(EXCLUDED.cve_id, kev_entries.cve_id),
                vendor_project = EXCLUDED.vendor_project,
                product = EXCLUDED.product,
                vulnerability_name = EXCLUDED.vulnerability_name,
                date_added = EXCLUDED.date_added,
                short_description = EXCLUDED.short_description,
                required_action = EXCLUDED.required_action,
                due_date = EXCLUDED.due_date,
                known_ransomware = EXCLUDED.known_ransomware,
                notes = EXCLUDED.notes,
                source_record_id = EXCLUDED.source_record_id,
                is_active = EXCLUDED.is_active,
                withdrawn_at = EXCLUDED.withdrawn_at,
                updated_at = now()
            RETURNING id, created_at, updated_at, is_active, withdrawn_at;
            """,
            (
                declared_cve, kev.cve_id, kev.vendor_project, kev.product,
                kev.vulnerability_name, _d(kev.date_added),
                kev.short_description, kev.required_action,
                _d(kev.due_date), kev.known_ransomware, kev.notes,
                kev.source_record_id,
                kev.is_active,
                kev.withdrawn_at,
            ),
        )
        row = cur.fetchone()
        kev.id = str(row["id"])
        kev.declared_cve_id = declared_cve
        kev.is_active = row.get("is_active", True)
        kev.withdrawn_at = row.get("withdrawn_at")
        kev.created_at = row["created_at"]
        kev.updated_at = row["updated_at"]
    return kev


def get_kev_entry(
    conn: psycopg.Connection,
    cve_id: str,
    *,
    active_only: bool = False,
) -> Optional[KevEntry]:
    sql = "SELECT * FROM kev_entries WHERE (cve_id = %s OR declared_cve_id = %s)"
    if active_only:
        sql += " AND is_active = TRUE"
    sql += " LIMIT 1;"
    with conn.cursor() as cur:
        cur.execute(sql, (cve_id, cve_id))
        row = cur.fetchone()
    if row is None:
        return None
    return _row_to_kev(row)


def _row_to_kev(row: dict) -> KevEntry:
    return KevEntry(
        id=str(row["id"]) if row.get("id") else None,
        cve_id=row.get("cve_id"),
        declared_cve_id=row.get("declared_cve_id", ""),
        vendor_project=row["vendor_project"],
        product=row["product"],
        vulnerability_name=row["vulnerability_name"],
        date_added=row.get("date_added"),
        short_description=row.get("short_description"),
        required_action=row.get("required_action"),
        due_date=row.get("due_date"),
        known_ransomware=row.get("known_ransomware"),
        notes=row.get("notes"),
        source_record_id=str(row["source_record_id"]) if row.get("source_record_id") else None,
        is_active=bool(row.get("is_active", True)),
        withdrawn_at=row.get("withdrawn_at"),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


# ---------------------------------------------------------------------------
# EPSS scores
# ---------------------------------------------------------------------------

def upsert_epss_score(
    conn: psycopg.Connection,
    epss: EpssScore,
) -> EpssScore:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO epss_scores
                (cve_id, score, percentile, model_version, score_date, source_record_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id, score_date) DO UPDATE SET
                score = EXCLUDED.score,
                percentile = EXCLUDED.percentile,
                model_version = EXCLUDED.model_version,
                source_record_id = EXCLUDED.source_record_id
            RETURNING id, created_at;
            """,
            (
                epss.cve_id, str(epss.score), str(epss.percentile),
                epss.model_version, _d(epss.score_date), epss.source_record_id,
            ),
        )
        row = cur.fetchone()
        epss.id = str(row["id"])
        epss.created_at = row["created_at"]
    return epss


def get_epss_scores(
    conn: psycopg.Connection,
    cve_id: str,
    *,
    latest_only: bool = False,
) -> list[EpssScore]:
    """Get EPSS score history for a CVE. If latest_only, return just the most recent."""
    limit = " LIMIT 1" if latest_only else ""
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM epss_scores WHERE cve_id = %s ORDER BY score_date DESC{limit};",
            (cve_id,),
        )
        rows = cur.fetchall()
    return [_row_to_epss(r) for r in rows]


def _row_to_epss(row: dict) -> EpssScore:
    return EpssScore(
        id=str(row["id"]),
        cve_id=row["cve_id"],
        score=Decimal(str(row["score"])),
        percentile=Decimal(str(row["percentile"])),
        model_version=row.get("model_version"),
        score_date=row.get("score_date"),
        source_record_id=str(row["source_record_id"]) if row.get("source_record_id") else None,
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# OSV records
# ---------------------------------------------------------------------------

def upsert_osv_record(
    conn: psycopg.Connection,
    osv: OsvRecord,
) -> OsvRecord:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO osv_records
                (osv_id, summary, details, published, modified, withdrawn,
                 ecosystem, package_name, package_purl, affected_ranges,
                 severity, database_specific, "references", raw_payload,
                 source_record_id, schema_version)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb,
                    %s::jsonb, %s::jsonb, %s::jsonb, %s, %s)
            ON CONFLICT (osv_id) DO UPDATE SET
                summary = EXCLUDED.summary,
                details = EXCLUDED.details,
                published = EXCLUDED.published,
                modified = EXCLUDED.modified,
                withdrawn = EXCLUDED.withdrawn,
                ecosystem = EXCLUDED.ecosystem,
                package_name = EXCLUDED.package_name,
                package_purl = EXCLUDED.package_purl,
                affected_ranges = EXCLUDED.affected_ranges,
                severity = EXCLUDED.severity,
                database_specific = EXCLUDED.database_specific,
                "references" = EXCLUDED."references",
                raw_payload = EXCLUDED.raw_payload,
                source_record_id = EXCLUDED.source_record_id,
                schema_version = EXCLUDED.schema_version,
                updated_at = now()
            RETURNING created_at, updated_at;
            """,
            (
                osv.osv_id, osv.summary, osv.details,
                _ts(osv.published), _ts(osv.modified), _ts(osv.withdrawn),
                osv.ecosystem, osv.package_name, osv.package_purl,
                _json(osv.affected_ranges), _json(osv.severity),
                _json(osv.database_specific), _json(osv.references),
                _json(osv.raw_payload if osv.raw_payload is not None else {}), osv.source_record_id,
                osv.schema_version,
            ),
        )
        row = cur.fetchone()
        osv.created_at = row["created_at"]
        osv.updated_at = row["updated_at"]
    return osv


def get_osv_record(
    conn: psycopg.Connection,
    osv_id: str,
) -> Optional[OsvRecord]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM osv_records WHERE osv_id = %s;", (osv_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return _row_to_osv(row)


def _row_to_osv(row: dict) -> OsvRecord:
    return OsvRecord(
        osv_id=row["osv_id"],
        summary=row.get("summary"),
        details=row.get("details"),
        published=row.get("published"),
        modified=row.get("modified"),
        withdrawn=row.get("withdrawn"),
        ecosystem=row.get("ecosystem"),
        package_name=row.get("package_name"),
        package_purl=row.get("package_purl"),
        affected_ranges=row.get("affected_ranges"),
        severity=row.get("severity"),
        database_specific=row.get("database_specific"),
        references=row.get("references"),
        raw_payload=row.get("raw_payload"),
        source_record_id=str(row["source_record_id"]) if row.get("source_record_id") else None,
        schema_version=row.get("schema_version"),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


# ---------------------------------------------------------------------------
# OSV aliases
# ---------------------------------------------------------------------------

def upsert_osv_alias(
    conn: psycopg.Connection,
    alias: OsvAlias,
) -> OsvAlias:
    declared_cve = alias.declared_linked_cve_id or (alias.linked_cve_id if alias.alias_type == "alias" and validate_cve_id(alias.alias) else (alias.alias if alias.alias_type == "alias" and validate_cve_id(alias.alias) else None))
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO osv_aliases
                (osv_id, alias, alias_type, linked_cve_id, declared_linked_cve_id)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (osv_id, alias, alias_type) DO UPDATE SET
                linked_cve_id = COALESCE(EXCLUDED.linked_cve_id, osv_aliases.linked_cve_id),
                declared_linked_cve_id = COALESCE(EXCLUDED.declared_linked_cve_id, osv_aliases.declared_linked_cve_id)
            RETURNING id, created_at;
            """,
            (alias.osv_id, alias.alias, alias.alias_type, alias.linked_cve_id,
             declared_cve),
        )
        row = cur.fetchone()
        alias.id = str(row["id"])
        alias.declared_linked_cve_id = declared_cve
        alias.created_at = row["created_at"]
    return alias


def get_osv_aliases(
    conn: psycopg.Connection,
    osv_id: str,
) -> list[OsvAlias]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM osv_aliases WHERE osv_id = %s ORDER BY alias;",
            (osv_id,),
        )
        rows = cur.fetchall()
    return [_row_to_osv_alias(r) for r in rows]


def get_osv_records_by_cve(
    conn: psycopg.Connection,
    cve_id: str,
) -> list[OsvRecord]:
    """Find OSV records linked to a CVE through exact declared aliases."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT o.* FROM osv_records o
            JOIN osv_aliases a ON a.osv_id = o.osv_id
            WHERE a.linked_cve_id = %s AND a.alias_type = 'alias'
            ORDER BY o.osv_id;
            """,
            (cve_id,),
        )
        rows = cur.fetchall()
    return [_row_to_osv(r) for r in rows]


def _row_to_osv_alias(row: dict) -> OsvAlias:
    return OsvAlias(
        id=str(row["id"]),
        osv_id=row["osv_id"],
        alias=row["alias"],
        alias_type=row["alias_type"],
        linked_cve_id=row.get("linked_cve_id"),
        declared_linked_cve_id=row.get("declared_linked_cve_id"),
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# Sync snapshots
# ---------------------------------------------------------------------------

def create_sync_snapshot(
    conn: psycopg.Connection,
    snapshot: SyncSnapshot,
) -> SyncSnapshot:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO sync_snapshots
                (source, sync_mode, status, cursor_before, metadata)
            VALUES (%s, %s, %s, %s, %s::jsonb)
            RETURNING id, started_at, created_at;
            """,
            (snapshot.source, snapshot.sync_mode, snapshot.status,
             snapshot.cursor_before, _json(snapshot.metadata)),
        )
        row = cur.fetchone()
        snapshot.id = str(row["id"])
        snapshot.started_at = row["started_at"]
        snapshot.created_at = row["created_at"]
    return snapshot


def complete_sync_snapshot(
    conn: psycopg.Connection,
    snapshot_id: str,
    *,
    status: str,
    records_processed: int = 0,
    records_created: int = 0,
    records_updated: int = 0,
    records_unchanged: int = 0,
    records_failed: int = 0,
    cursor_after: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE sync_snapshots SET
                status = %s,
                completed_at = now(),
                records_processed = %s,
                records_created = %s,
                records_updated = %s,
                records_unchanged = %s,
                records_failed = %s,
                cursor_after = %s,
                error_message = %s
            WHERE id = %s;
            """,
            (
                status, records_processed, records_created,
                records_updated, records_unchanged, records_failed,
                cursor_after, error_message, snapshot_id,
            ),
        )


def get_sync_snapshot(
    conn: psycopg.Connection,
    snapshot_id: str,
) -> Optional[SyncSnapshot]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM sync_snapshots WHERE id = %s;", (snapshot_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return _row_to_snapshot(row)


def _row_to_snapshot(row: dict) -> SyncSnapshot:
    return SyncSnapshot(
        id=str(row["id"]),
        source=row["source"],
        sync_mode=row["sync_mode"],
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        status=row["status"],
        records_processed=row.get("records_processed", 0),
        records_created=row.get("records_created", 0),
        records_updated=row.get("records_updated", 0),
        records_unchanged=row.get("records_unchanged", 0),
        records_failed=row.get("records_failed", 0),
        error_message=row.get("error_message"),
        cursor_before=row.get("cursor_before"),
        cursor_after=row.get("cursor_after"),
        metadata=row.get("metadata"),
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# Sync state
# ---------------------------------------------------------------------------

def get_sync_state(
    conn: psycopg.Connection,
    source: str,
) -> Optional[SyncState]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM sync_state WHERE source = %s;", (source,))
        row = cur.fetchone()
    if row is None:
        return None
    return _row_to_sync_state(row)


def update_sync_state(
    conn: psycopg.Connection,
    source: str,
    *,
    cursor_value: Optional[Union[str, dict, list]] = None,
    last_snapshot_id: Optional[str] = None,
    success: bool = True,
    error: Optional[str] = None,
) -> SyncState:
    """
    Atomically advance sync state after a snapshot completes.
    On success: update cursor, reset failures, mark healthy.
    On failure: increment failures, record error, mark unhealthy.
    Gracefully handles string, dict, or list for cursor_value (SCOPE-2).
    """
    serialized_cursor = cursor_value
    if isinstance(cursor_value, (dict, list)):
        serialized_cursor = json.dumps(cursor_value, sort_keys=True)

    with conn.cursor() as cur:
        if success:
            cur.execute(
                """
                UPDATE sync_state SET
                    cursor_value = COALESCE(%s, cursor_value),
                    last_successful_at = now(),
                    last_attempted_at = now(),
                    last_error = NULL,
                    last_snapshot_id = %s,
                    consecutive_failures = 0,
                    is_healthy = TRUE,
                    updated_at = now()
                WHERE source = %s
                RETURNING *;
                """,
                (serialized_cursor, last_snapshot_id, source),
            )
        else:
            cur.execute(
                """
                UPDATE sync_state SET
                    last_attempted_at = now(),
                    last_error = %s,
                    last_snapshot_id = %s,
                    consecutive_failures = consecutive_failures + 1,
                    is_healthy = FALSE,
                    updated_at = now()
                WHERE source = %s
                RETURNING *;
                """,
                (error, last_snapshot_id, source),
            )
        row = cur.fetchone()
    return _row_to_sync_state(row)


def get_all_sync_states(
    conn: psycopg.Connection,
) -> list[SyncState]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM sync_state ORDER BY source;")
        rows = cur.fetchall()
    return [_row_to_sync_state(r) for r in rows]


def _row_to_sync_state(row: dict) -> SyncState:
    return SyncState(
        source=row["source"],
        cursor_value=row.get("cursor_value"),
        last_successful_at=row.get("last_successful_at"),
        last_attempted_at=row.get("last_attempted_at"),
        last_error=row.get("last_error"),
        last_snapshot_id=str(row["last_snapshot_id"]) if row.get("last_snapshot_id") else None,
        consecutive_failures=row.get("consecutive_failures", 0),
        is_healthy=row.get("is_healthy", True),
        config=row.get("config"),
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


# ---------------------------------------------------------------------------
# CVE references
# ---------------------------------------------------------------------------

def upsert_cve_references(
    conn: psycopg.Connection,
    cve_id: str,
    source: str,
    refs: list[dict],
    source_record_id: Optional[str] = None,
) -> int:
    """Bulk-insert references for a CVE from a given source. Returns count inserted."""
    if not refs:
        return 0
    # Retire old current refs from this source
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE cve_references SET is_current = FALSE
            WHERE cve_id = %s AND source = %s AND is_current = TRUE;
            """,
            (cve_id, source),
        )
        count = 0
        for ref in refs:
            cur.execute(
                """
                INSERT INTO cve_references
                    (cve_id, source, url, name, tags, source_identifier, source_record_id, is_current)
                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE);
                """,
                (
                    cve_id, source, ref.get("url"), ref.get("name"),
                    ref.get("tags"), ref.get("source"), source_record_id,
                ),
            )
            count += 1
    return count


def get_cve_references(
    conn: psycopg.Connection,
    cve_id: str,
    *,
    current_only: bool = True,
) -> list[dict]:
    clause = " AND is_current = TRUE" if current_only else ""
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM cve_references WHERE cve_id = %s{clause} ORDER BY created_at;",
            (cve_id,),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# CWE / weakness mappings
# ---------------------------------------------------------------------------

def upsert_cve_weaknesses(
    conn: psycopg.Connection,
    cve_id: str,
    source: str,
    weaknesses: list[dict],
    source_record_id: Optional[str] = None,
) -> int:
    """Bulk-insert weakness mappings for a CVE. Returns count inserted."""
    if not weaknesses:
        return 0
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE cve_weaknesses SET is_current = FALSE
            WHERE cve_id = %s AND source = %s AND is_current = TRUE;
            """,
            (cve_id, source),
        )
        count = 0
        for w in weaknesses:
            cur.execute(
                """
                INSERT INTO cve_weaknesses
                    (cve_id, source, cwe_id, description, weakness_type, source_record_id, is_current)
                VALUES (%s, %s, %s, %s, %s, %s, TRUE);
                """,
                (
                    cve_id, source, w.get("cwe_id"), w.get("description"),
                    w.get("type"), source_record_id,
                ),
            )
            count += 1
    return count


def get_cve_weaknesses(
    conn: psycopg.Connection,
    cve_id: str,
    *,
    current_only: bool = True,
) -> list[dict]:
    clause = " AND is_current = TRUE" if current_only else ""
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM cve_weaknesses WHERE cve_id = %s{clause} ORDER BY created_at;",
            (cve_id,),
        )
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Composed CVE detail and search queries
# ---------------------------------------------------------------------------

def get_source_records_by_cve(
    conn: psycopg.Connection,
    cve_id: str,
) -> list[SourceRecord]:
    """Get all source records associated with a CVE ID (via cve_id FK or declared_cve_id)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM vuln_source_records
            WHERE cve_id = %s OR declared_cve_id = %s
            ORDER BY created_at DESC;
            """,
            (cve_id, cve_id),
        )
        rows = cur.fetchall()
    return [_row_to_source_record(r) for r in rows]


def get_composed_cve_detail(
    conn: psycopg.Connection,
    cve_id: str,
) -> Optional[dict]:
    """
    Assemble the complete source-aware vulnerability intelligence record
    for a given CVE ID. Preserves exact provenance, multi-assessment CVSS,
    TES-input resolution, applicability, KEV, ADP/SSVC, EPSS, and linked OSV.
    """
    vuln = get_canonical_vulnerability(conn, cve_id)
    if vuln is None:
        return None

    # Source provenance
    source_recs = get_source_records_by_cve(conn, cve_id)
    provenance = [
        {
            "id": r.id,
            "source": r.source,
            "source_id": r.source_id,
            "source_updated_at": _ts(r.source_updated_at),
            "content_hash": r.content_hash,
            "is_current": r.is_current,
            "snapshot_id": r.snapshot_id,
            "created_at": _ts(r.created_at),
        }
        for r in source_recs
    ]

    # Descriptions from upstream providers
    descriptions = []
    for r in source_recs:
        if not r.is_current or not r.raw_payload:
            continue
        if r.source == "cve":
            cna_desc = r.raw_payload.get("containers", {}).get("cna", {}).get("descriptions", [])
            for d in cna_desc:
                if isinstance(d, dict) and d.get("value"):
                    descriptions.append({
                        "source": "cve",
                        "lang": d.get("lang", "en"),
                        "value": d.get("value"),
                    })
        elif r.source == "nvd":
            nvd_data = r.raw_payload.get("cve", r.raw_payload)
            nvd_desc = nvd_data.get("descriptions", [])
            for d in nvd_desc:
                if isinstance(d, dict) and d.get("value"):
                    descriptions.append({
                        "source": "nvd",
                        "lang": d.get("lang", "en"),
                        "value": d.get("value"),
                    })

    # CVSS assessments
    cvss_list = get_cvss_assessments(conn, cve_id, current_only=False)
    assessments = [
        {
            "id": a.id,
            "source": a.source,
            "assessor": a.assessor,
            "assessment_type": a.assessment_type,
            "container_role": a.container_role,
            "provider_org_id": a.provider_org_id,
            "cvss_version": a.cvss_version,
            "vector_string": a.vector_string,
            "base_score": float(a.base_score),
            "base_severity": a.base_severity,
            "exploitability_score": float(a.exploitability_score) if a.exploitability_score is not None else None,
            "impact_score": float(a.impact_score) if a.impact_score is not None else None,
            "scenario": a.scenario,
            "is_current": a.is_current,
            "created_at": _ts(a.created_at),
        }
        for a in cvss_list
    ]

    # Deterministic TES-input resolution
    tes_res = resolve_tes_cvss(conn, cve_id)
    tes_dict = {
        "is_scoreable": tes_res.is_scoreable,
        "resolved_score": float(tes_res.resolved_score) if tes_res.resolved_score is not None else None,
        "resolved_vector": tes_res.resolved_vector,
        "resolved_severity": tes_res.resolved_severity,
        "resolved_assessor": tes_res.resolved_assessor,
        "resolution_tier": tes_res.resolution_tier,
        "unscoreable_reason": tes_res.unscoreable_reason,
    }

    # Affected / applicability
    affected_rows = get_cve_affected(conn, cve_id, current_only=True)
    affected = [
        {
            "id": aff.id,
            "source": aff.source,
            "vendor": aff.vendor,
            "product": aff.product,
            "versions": aff.versions,
            "cpes": aff.cpes,
            "default_status": aff.default_status,
            "is_current": aff.is_current,
        }
        for aff in affected_rows
    ]

    # Weaknesses (CWE)
    weaknesses = get_cve_weaknesses(conn, cve_id, current_only=True)

    # References
    refs = get_cve_references(conn, cve_id, current_only=True)

    # Relationships
    rels = get_cve_relationships(conn, cve_id)
    relationships = [
        {
            "relationship_type": r.relationship_type,
            "related_cve_id": r.related_cve_id,
            "source": r.source,
        }
        for r in rels
    ]

    # ADP / SSVC
    adp_rows = get_adp_entries(conn, cve_id, current_only=True)
    adp_entries = [
        {
            "id": adp.id,
            "provider_org_id": adp.provider_org_id,
            "provider_short_name": adp.provider_short_name,
            "date_updated": _ts(adp.date_updated),
            "title": adp.title,
            "ssvc_data": adp.ssvc_data,
            "is_current": adp.is_current,
        }
        for adp in adp_rows
    ]

    # KEV enrichment
    kev_row = get_kev_entry(conn, cve_id, active_only=True)
    kev_dict = None
    if kev_row and kev_row.is_active:
        kev_dict = {
            "vendor_project": kev_row.vendor_project,
            "product": kev_row.product,
            "vulnerability_name": kev_row.vulnerability_name,
            "date_added": _d(kev_row.date_added),
            "short_description": kev_row.short_description,
            "required_action": kev_row.required_action,
            "due_date": _d(kev_row.due_date),
            "known_ransomware": kev_row.known_ransomware,
            "notes": kev_row.notes,
        }

    # EPSS scores
    epss_history_rows = get_epss_scores(conn, cve_id, latest_only=False)
    epss_current = None
    epss_history = []
    for ep in epss_history_rows:
        ep_dict = {
            "score": float(ep.score),
            "percentile": float(ep.percentile),
            "score_date": _d(ep.score_date),
            "model_version": ep.model_version,
        }
        epss_history.append(ep_dict)
    if epss_history:
        epss_current = epss_history[0]

    # Linked OSV records via exact declared CVE alias
    osv_linked = get_osv_records_by_cve(conn, cve_id)
    osv_records = [
        {
            "osv_id": o.osv_id,
            "ecosystem": o.ecosystem,
            "package_name": o.package_name,
            "package_purl": o.package_purl,
            "summary": o.summary,
            "details": o.details,
            "published": _ts(o.published),
            "modified": _ts(o.modified),
            "withdrawn": _ts(o.withdrawn),
            "severity": o.severity,
            "affected_ranges": o.affected_ranges,
        }
        for o in osv_linked
    ]

    return {
        "cve_id": vuln.cve_id,
        "state": vuln.state,
        "assigner_org_id": vuln.assigner_org_id,
        "assigner_short_name": vuln.assigner_short_name,
        "date_published": _ts(vuln.date_published),
        "date_updated": _ts(vuln.date_updated),
        "date_reserved": _ts(vuln.date_reserved),
        "date_rejected": _ts(vuln.date_rejected),
        "created_at": _ts(vuln.created_at),
        "updated_at": _ts(vuln.updated_at),
        "source_provenance": provenance,
        "descriptions": descriptions,
        "cvss_assessments": assessments,
        "tes_resolution": tes_dict,
        "affected": affected,
        "weaknesses": weaknesses,
        "references": refs,
        "relationships": relationships,
        "adp_entries": adp_entries,
        "kev": kev_dict,
        "epss": epss_current,
        "epss_history": epss_history,
        "osv_records": osv_records,
    }


def search_vulnerabilities(
    conn: psycopg.Connection,
    *,
    q: Optional[str] = None,
    state: Optional[str] = None,
    has_kev: Optional[bool] = None,
    min_tes_cvss: Optional[float] = None,
    max_tes_cvss: Optional[float] = None,
    min_cvss: Optional[float] = None,
    max_cvss: Optional[float] = None,
    min_epss: Optional[float] = None,
    ecosystem: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """
    Search indexed normalized vulnerability fields with deterministic TES filtering.
    Returns {"total": int, "limit": int, "offset": int, "items": list[dict]}.
    """
    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    effective_min_tes = min_tes_cvss if min_tes_cvss is not None else min_cvss
    effective_max_tes = max_tes_cvss if max_tes_cvss is not None else max_cvss

    where_clauses = ["1=1"]
    params: list[Any] = []

    if state:
        where_clauses.append("cv.state = %s")
        params.append(state.upper())

    if has_kev is not None:
        if has_kev:
            where_clauses.append("EXISTS (SELECT 1 FROM kev_entries k WHERE (k.cve_id = cv.cve_id OR k.declared_cve_id = cv.cve_id) AND k.is_active = TRUE)")
        else:
            where_clauses.append("NOT EXISTS (SELECT 1 FROM kev_entries k WHERE (k.cve_id = cv.cve_id OR k.declared_cve_id = cv.cve_id) AND k.is_active = TRUE)")

    if ecosystem:
        where_clauses.append(
            """
            EXISTS (
                SELECT 1 FROM osv_aliases oa
                JOIN osv_records o ON o.osv_id = oa.osv_id
                WHERE oa.linked_cve_id = cv.cve_id AND oa.alias_type = 'alias'
                  AND LOWER(o.ecosystem) = LOWER(%s)
            )
            """
        )
        params.append(ecosystem)

    if effective_min_tes is not None:
        where_clauses.append("tes.resolved_score >= %s")
        params.append(Decimal(str(effective_min_tes)))

    if effective_max_tes is not None:
        where_clauses.append("tes.resolved_score <= %s")
        params.append(Decimal(str(effective_max_tes)))

    if min_epss is not None:
        where_clauses.append(
            """
            EXISTS (
                SELECT 1 FROM epss_scores ep
                WHERE ep.cve_id = cv.cve_id AND ep.score >= %s
            )
            """
        )
        params.append(Decimal(str(min_epss)))

    if q and q.strip():
        q_term = f"%{q.strip()}%"
        where_clauses.append(
            """
            (
                cv.cve_id ILIKE %s
                OR cv.assigner_short_name ILIKE %s
                OR EXISTS (
                    SELECT 1 FROM cve_affected aff
                    WHERE aff.cve_id = cv.cve_id AND (aff.product ILIKE %s OR aff.vendor ILIKE %s)
                )
                OR EXISTS (
                    SELECT 1 FROM cve_weaknesses w
                    WHERE w.cve_id = cv.cve_id AND (w.cwe_id ILIKE %s OR w.description ILIKE %s)
                )
                OR EXISTS (
                    SELECT 1 FROM osv_aliases oa
                    JOIN osv_records o ON o.osv_id = oa.osv_id
                    WHERE oa.linked_cve_id = cv.cve_id AND (o.package_name ILIKE %s OR o.summary ILIKE %s)
                )
            )
            """
        )
        params.extend([q_term, q_term, q_term, q_term, q_term, q_term, q_term, q_term])

    where_sql = " AND ".join(where_clauses)

    tes_lateral = """
        LEFT JOIN LATERAL (
            SELECT
                CASE
                    -- Tier 1: exactly 1 current CNA CVSS 3.1 GENERAL assessment
                    WHEN COUNT(*) FILTER (WHERE ca.container_role = 'cna' OR (ca.container_role IS NULL AND ca.source = 'cve' AND (ca.assessment_type = 'cna' OR ca.assessment_type IS NULL))) = 1 THEN
                        (ARRAY_AGG(ca.base_score) FILTER (WHERE ca.container_role = 'cna' OR (ca.container_role IS NULL AND ca.source = 'cve' AND (ca.assessment_type = 'cna' OR ca.assessment_type IS NULL))))[1]
                    -- Ambiguous CNA (>1 CNA): NULL
                    WHEN COUNT(*) FILTER (WHERE ca.container_role = 'cna' OR (ca.container_role IS NULL AND ca.source = 'cve' AND (ca.assessment_type = 'cna' OR ca.assessment_type IS NULL))) > 1 THEN
                        NULL
                    -- Tier 2: 0 CNA and exactly 1 current NVD CVSS 3.1 GENERAL assessment
                    WHEN COUNT(*) FILTER (WHERE ca.container_role = 'cna' OR (ca.container_role IS NULL AND ca.source = 'cve' AND (ca.assessment_type = 'cna' OR ca.assessment_type IS NULL))) = 0
                         AND COUNT(*) FILTER (WHERE ca.container_role = 'nvd' OR (ca.container_role IS NULL AND ca.source = 'nvd') OR ca.source = 'nvd') = 1 THEN
                        (ARRAY_AGG(ca.base_score) FILTER (WHERE ca.container_role = 'nvd' OR (ca.container_role IS NULL AND ca.source = 'nvd') OR ca.source = 'nvd'))[1]
                    -- Otherwise (0 CNA & >1 NVD, or 0 CNA & 0 NVD, e.g. only ADP): NULL
                    ELSE NULL
                END as resolved_score
            FROM cvss_assessments ca
            WHERE ca.cve_id = cv.cve_id
              AND ca.cvss_version = '3.1'
              AND COALESCE(ca.scenario, 'GENERAL') = 'GENERAL'
              AND ca.is_current = TRUE
        ) tes ON TRUE
    """

    with conn.cursor() as cur:
        # Count total
        cur.execute(
            f"""
            SELECT COUNT(*) as total
            FROM canonical_vulnerabilities cv
            {tes_lateral}
            WHERE {where_sql};
            """,
            params,
        )
        count_row = cur.fetchone()
        total = count_row["total"] if count_row else 0

        # Query page
        cur.execute(
            f"""
            SELECT
                cv.cve_id,
                cv.state,
                cv.assigner_org_id,
                cv.assigner_short_name,
                cv.date_published,
                cv.date_updated,
                cv.date_reserved,
                cv.date_rejected,
                EXISTS (SELECT 1 FROM kev_entries k WHERE (k.cve_id = cv.cve_id OR k.declared_cve_id = cv.cve_id) AND k.is_active = TRUE) as has_kev,
                (
                    SELECT ep.score FROM epss_scores ep
                    WHERE ep.cve_id = cv.cve_id ORDER BY ep.score_date DESC LIMIT 1
                ) as epss_score,
                (
                    SELECT ep.percentile FROM epss_scores ep
                    WHERE ep.cve_id = cv.cve_id ORDER BY ep.score_date DESC LIMIT 1
                ) as epss_percentile,
                tes.resolved_score as sql_tes_score
            FROM canonical_vulnerabilities cv
            {tes_lateral}
            WHERE {where_sql}
            ORDER BY cv.date_published DESC NULLS LAST, cv.cve_id DESC
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()

    items = []
    for r in rows:
        cve_id = r["cve_id"]
        tes_res = resolve_tes_cvss(conn, cve_id)
        items.append({
            "cve_id": cve_id,
            "state": r["state"],
            "assigner_short_name": r.get("assigner_short_name"),
            "date_published": _ts(r.get("date_published")),
            "date_updated": _ts(r.get("date_updated")),
            "has_kev": bool(r.get("has_kev", False)),
            "epss_score": float(r["epss_score"]) if r.get("epss_score") is not None else None,
            "epss_percentile": float(r["epss_percentile"]) if r.get("epss_percentile") is not None else None,
            "tes_score": float(tes_res.resolved_score) if tes_res.resolved_score is not None else None,
            "tes_severity": tes_res.resolved_severity,
            "is_scoreable": tes_res.is_scoreable,
        })

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


# ---------------------------------------------------------------------------
# Backfill unresolved enrichment references (Sprint 01)
# ---------------------------------------------------------------------------

def _backfill_unresolved_references(
    conn: psycopg.Connection,
    cve_id: str,
) -> int:
    """
    After a canonical row is created by the CVE Program adapter, backfill
    the nullable FK columns on enrichment tables where declared_cve_id
    matches but cve_id is still NULL.

    Returns total number of rows backfilled across all tables.
    """
    total = 0
    with conn.cursor() as cur:
        # 1. vuln_source_records
        cur.execute(
            """
            UPDATE vuln_source_records
            SET cve_id = declared_cve_id
            WHERE declared_cve_id = %s AND cve_id IS NULL;
            """,
            (cve_id,),
        )
        total += cur.rowcount

        # 2. kev_entries
        cur.execute(
            """
            UPDATE kev_entries
            SET cve_id = declared_cve_id
            WHERE declared_cve_id = %s AND cve_id IS NULL;
            """,
            (cve_id,),
        )
        total += cur.rowcount

        # 3. osv_aliases
        cur.execute(
            """
            UPDATE osv_aliases
            SET linked_cve_id = declared_linked_cve_id
            WHERE declared_linked_cve_id = %s AND linked_cve_id IS NULL;
            """,
            (cve_id,),
        )
        total += cur.rowcount

    return total


# ---------------------------------------------------------------------------
# Source artifacts — exact byte preservation (Sprint 01)
# ---------------------------------------------------------------------------

def upsert_source_artifact(
    conn: psycopg.Connection,
    artifact: SourceArtifact,
) -> SourceArtifact:
    """Store an exact downloaded artifact with its SHA-256 hash."""
    retrieval = _ts(artifact.retrieval_time) or datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO source_artifacts
                (source_record_id, sha256_hash, artifact_url, media_type,
                 byte_size, artifact_bytes, retrieval_time, importer_version)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at, retrieval_time;
            """,
            (
                artifact.source_record_id,
                artifact.sha256_hash,
                artifact.artifact_url,
                artifact.media_type,
                artifact.byte_size,
                artifact.artifact_bytes,
                retrieval,
                artifact.importer_version,
            ),
        )
        row = cur.fetchone()
        artifact.id = str(row["id"])
        artifact.created_at = row["created_at"]
        artifact.retrieval_time = row["retrieval_time"]
    return artifact


def get_source_artifacts(
    conn: psycopg.Connection,
    source_record_id: str,
) -> list[SourceArtifact]:
    """Get all artifacts for a source record."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM source_artifacts WHERE source_record_id = %s ORDER BY created_at;",
            (source_record_id,),
        )
        rows = cur.fetchall()
    return [_row_to_artifact(r) for r in rows]


def get_source_artifact_by_hash(
    conn: psycopg.Connection,
    sha256_hash: str,
) -> Optional[SourceArtifact]:
    """Get an artifact by its SHA-256 hash."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM source_artifacts WHERE sha256_hash = %s LIMIT 1;",
            (sha256_hash,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return _row_to_artifact(row)


def _row_to_artifact(row: dict) -> SourceArtifact:
    art_bytes = row.get("artifact_bytes")
    if isinstance(art_bytes, memoryview):
        art_bytes = bytes(art_bytes)
    return SourceArtifact(
        id=str(row["id"]),
        source_record_id=str(row["source_record_id"]),
        sha256_hash=row["sha256_hash"],
        artifact_url=row.get("artifact_url"),
        media_type=row.get("media_type"),
        byte_size=row["byte_size"],
        artifact_bytes=art_bytes,
        retrieval_time=row.get("retrieval_time"),
        importer_version=row.get("importer_version"),
        created_at=row.get("created_at"),
    )


# ---------------------------------------------------------------------------
# Unresolved enrichment queries (Sprint 01)
# ---------------------------------------------------------------------------

def get_unresolved_source_records(
    conn: psycopg.Connection,
    source: Optional[str] = None,
) -> list[SourceRecord]:
    """Find source records where declared_cve_id is set but cve_id FK is NULL."""
    where = "declared_cve_id IS NOT NULL AND cve_id IS NULL"
    params: list[Any] = []
    if source:
        where += " AND source = %s"
        params.append(source)
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM vuln_source_records WHERE {where} ORDER BY created_at;",
            params,
        )
        rows = cur.fetchall()
    return [_row_to_source_record(r) for r in rows]


def list_sync_snapshots(
    conn: psycopg.Connection,
    *,
    source: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[SyncSnapshot]:
    """List sync snapshots with optional filtering."""
    where = ["1=1"]
    params: list[Any] = []
    if source:
        where.append("source = %s")
        params.append(source)
    if status:
        where.append("status = %s")
        params.append(status)
    where_sql = " AND ".join(where)

    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT * FROM sync_snapshots
            WHERE {where_sql}
            ORDER BY started_at DESC
            LIMIT %s OFFSET %s;
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()
    return [_row_to_snapshot(r) for r in rows]


# ---------------------------------------------------------------------------
# Full snapshot absence reconciliation & mass-withdrawal guard (Sprint 02)
# ---------------------------------------------------------------------------

def reconcile_full_snapshot_absence(
    conn: psycopg.Connection,
    source: str,
    seen_declared_ids: Union[set[str], list[str]],
    *,
    threshold_pct: float = 0.20,
    ecosystem: Optional[str] = None,
) -> tuple[int, int]:
    """
    Reconcile absent entries for a full snapshot source (e.g. 'kev' or 'osv').
    Marks records that were previously active but absent from seen_declared_ids as withdrawn.
    Enforces the mass-withdrawal safety guard (threshold_pct).

    Returns (active_count_before, deactivated_count).
    Raises MassWithdrawalExceededError if deactivated_count / active_count_before > threshold_pct.
    """
    seen_list = list(seen_declared_ids)
    with conn.cursor() as cur:
        if source == "kev":
            cur.execute("SELECT COUNT(*) AS active_count FROM kev_entries WHERE is_active = TRUE;")
            row = cur.fetchone()
            active_count = row["active_count"] if row else 0
            if active_count == 0:
                return 0, 0

            # Count absent active entries
            if seen_list:
                cur.execute(
                    "SELECT COUNT(*) AS absent_count FROM kev_entries WHERE is_active = TRUE AND declared_cve_id != ALL(%s);",
                    (seen_list,),
                )
            else:
                cur.execute("SELECT COUNT(*) AS absent_count FROM kev_entries WHERE is_active = TRUE;")
            row = cur.fetchone()
            absent_count = row["absent_count"] if row else 0

            if absent_count == 0:
                return active_count, 0

            # Mass withdrawal check
            absent_ratio = absent_count / active_count
            if absent_ratio > threshold_pct:
                raise MassWithdrawalExceededError(
                    f"KEV full snapshot drops {absent_count}/{active_count} records ({absent_ratio:.1%}), "
                    f"exceeding mass-withdrawal threshold ({threshold_pct:.1%})"
                )

            # Deactivate absent entries
            if seen_list:
                cur.execute(
                    """
                    UPDATE kev_entries
                    SET is_active = FALSE, withdrawn_at = now(), updated_at = now()
                    WHERE is_active = TRUE AND declared_cve_id != ALL(%s);
                    """,
                    (seen_list,),
                )
            else:
                cur.execute(
                    """
                    UPDATE kev_entries
                    SET is_active = FALSE, withdrawn_at = now(), updated_at = now()
                    WHERE is_active = TRUE;
                    """
                )
            return active_count, absent_count

        elif source == "osv":
            # For OSV, reconcile within an ecosystem (if specified) or all records
            if ecosystem:
                cur.execute(
                    "SELECT COUNT(*) AS active_count FROM osv_records WHERE withdrawn IS NULL AND LOWER(ecosystem) = LOWER(%s);",
                    (ecosystem,),
                )
            else:
                cur.execute("SELECT COUNT(*) AS active_count FROM osv_records WHERE withdrawn IS NULL;")
            row = cur.fetchone()
            active_count = row["active_count"] if row else 0
            if active_count == 0:
                return 0, 0

            if seen_list:
                if ecosystem:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS absent_count FROM osv_records
                        WHERE withdrawn IS NULL AND LOWER(ecosystem) = LOWER(%s) AND osv_id != ALL(%s);
                        """,
                        (ecosystem, seen_list),
                    )
                else:
                    cur.execute(
                        "SELECT COUNT(*) AS absent_count FROM osv_records WHERE withdrawn IS NULL AND osv_id != ALL(%s);",
                        (seen_list,),
                    )
            else:
                if ecosystem:
                    cur.execute(
                        "SELECT COUNT(*) AS absent_count FROM osv_records WHERE withdrawn IS NULL AND LOWER(ecosystem) = LOWER(%s);",
                        (ecosystem,),
                    )
                else:
                    cur.execute("SELECT COUNT(*) AS absent_count FROM osv_records WHERE withdrawn IS NULL;")
            row = cur.fetchone()
            absent_count = row["absent_count"] if row else 0

            if absent_count == 0:
                return active_count, 0

            absent_ratio = absent_count / active_count
            if absent_ratio > threshold_pct:
                eco_desc = f" for ecosystem {ecosystem}" if ecosystem else ""
                raise MassWithdrawalExceededError(
                    f"OSV full snapshot drops {absent_count}/{active_count} records ({absent_ratio:.1%}){eco_desc}, "
                    f"exceeding mass-withdrawal threshold ({threshold_pct:.1%})"
                )

            if seen_list:
                if ecosystem:
                    cur.execute(
                        """
                        UPDATE osv_records
                        SET withdrawn = now(), updated_at = now()
                        WHERE withdrawn IS NULL AND LOWER(ecosystem) = LOWER(%s) AND osv_id != ALL(%s);
                        """,
                        (ecosystem, seen_list),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE osv_records
                        SET withdrawn = now(), updated_at = now()
                        WHERE withdrawn IS NULL AND osv_id != ALL(%s);
                        """,
                        (seen_list,),
                    )
            else:
                if ecosystem:
                    cur.execute(
                        """
                        UPDATE osv_records
                        SET withdrawn = now(), updated_at = now()
                        WHERE withdrawn IS NULL AND LOWER(ecosystem) = LOWER(%s);
                        """,
                        (ecosystem,),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE osv_records
                        SET withdrawn = now(), updated_at = now()
                        WHERE withdrawn IS NULL;
                        """
                    )
            return active_count, absent_count

        return 0, 0


