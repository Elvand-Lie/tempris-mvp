"""Canonical, tenant-agnostic vulnerability intelligence layer.

This service implements:
1. Deterministic, offline file/snapshot ingestion for CanonicalVulnerability,
   VulnerabilityCvssAssessment, and CisaKevEntry.
2. Exact Finding-to-Canonical link/backfill command.
3. Server-authoritative vulnerability intelligence resolver with deterministic CVSS
   selection policy and legacy read-only fallback.

INVARIANTS:
- No network requests during tests or runtime ingestion.
- No heuristic or keyword-estimated CVSS derivation.
- Multiple CVSS scoring authorities and versions coexist without overwriting.
- Rejected CVEs are preserved with lifecycle status.
- Exact CVE syntax only for linkage; never fuzzy/keyword matching.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from models import CanonicalVulnerability, CisaKevEntry, Finding, VulnerabilityCvssAssessment

logger = logging.getLogger("tempris.cve_intelligence")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
REJECTED_CONSULT_PATTERN = re.compile(
    r"(?:consult\s*ids?|superseded\s*by|replaced\s*by|see)\s*[:\s]\s*(CVE-\d{4}-\d{4,})",
    re.IGNORECASE,
)

CVSS_VERSION_RANK = {
    "4.0": 40,
    "3.1": 31,
    "3.0": 30,
    "2.0": 20,
}


def validate_and_normalize_cve(cve_input: str) -> str:
    """Validate and normalize a CVE string to canonical uppercase 'CVE-YYYY-NNNN'.

    Raises ValueError on empty or malformed strings.
    """
    if not cve_input or not isinstance(cve_input, str):
        raise ValueError("CVE identifier must be a non-empty string")
    cleaned = cve_input.strip().upper()
    if not CVE_PATTERN.match(cleaned):
        raise ValueError(f"Invalid CVE identifier format: '{cve_input}' (expected 'CVE-YYYY-NNNN')")
    return cleaned


def extract_cve_from_finding(finding: Finding | dict) -> str | None:
    """Extract and normalize a valid CVE ID from a Finding instance or dict.

    Returns None if no valid CVE is present.
    """
    raw_cve = None
    if isinstance(finding, dict):
        raw_cve = finding.get("canonical_cve_id") or finding.get("cve_id") or finding.get("cve")
        if not raw_cve:
            ext = str(finding.get("external_id") or "")
            if ext.lower().startswith("cve:"):
                raw_cve = ext[4:]
    else:
        raw_cve = getattr(finding, "canonical_cve_id", None) or getattr(finding, "cve_id", None) or getattr(finding, "cve", None)
        if not raw_cve:
            ext = str(getattr(finding, "external_id", "") or "")
            if ext.lower().startswith("cve:"):
                raw_cve = ext[4:]

    if not raw_cve or not isinstance(raw_cve, str):
        return None
    try:
        return validate_and_normalize_cve(raw_cve)
    except ValueError:
        return None


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None


def _calculate_record_hash(data: dict | Any) -> str:
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ── Snapshot Importers ─────────────────────────────────────────────────────────

def import_cisa_kev_snapshot(
    file_path: str | Path,
    db: Session,
    *,
    snapshot_id: str | None = None,
) -> dict[str, Any]:
    """Deterministically import a local CISA KEV JSON snapshot into the shadow registry.

    Idempotent and transactional.
    Does NOT create CVSS assessments, Finding rows, or AssetExposure links.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"CISA KEV snapshot file not found: {path}")

    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)

    if not isinstance(data, dict) or "vulnerabilities" not in data:
        raise ValueError("Invalid CISA KEV snapshot format: missing top-level 'vulnerabilities' key")

    file_bytes = path.read_bytes()
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()

    catalog_version = str(data.get("catalogVersion") or data.get("dateReleased") or "").strip()
    active_snapshot_id = snapshot_id or catalog_version or f"KEV-FILE-{file_sha256[:16]}"
    vulnerabilities = data.get("vulnerabilities", [])

    canonical_created = 0
    canonical_reused = 0
    kev_created = 0
    kev_updated = 0
    kev_unchanged = 0
    invalid_records = 0
    errors: list[dict[str, str]] = []

    try:
        for entry in vulnerabilities:
            raw_cve = entry.get("cveID") or entry.get("cve_id")
            try:
                cve_id = validate_and_normalize_cve(str(raw_cve or ""))
            except ValueError as ex:
                invalid_records += 1
                errors.append({"raw_record": str(raw_cve), "reason": str(ex)})
                continue

            record_hash = _calculate_record_hash(entry)
            short_desc = entry.get("shortDescription") or entry.get("vulnerabilityName")
            date_added = entry.get("dateAdded")
            due_date = entry.get("dueDate")
            vendor = str(entry.get("vendorProject") or "").strip()
            product = str(entry.get("product") or "").strip()
            vuln_name = str(entry.get("vulnerabilityName") or "").strip()
            action = entry.get("requiredAction")
            ransomware = str(entry.get("knownRansomwareCampaignUse") or "Unknown").strip()
            notes = entry.get("notes")

            # 1. Upsert CanonicalVulnerability
            vuln = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == cve_id).first()
            if vuln is None:
                vuln = CanonicalVulnerability(
                    cve_id=cve_id,
                    status="published",
                    description=short_desc,
                    description_source="CISA-KEV",
                    published_at=_parse_iso_datetime(date_added) if date_added else None,
                )
                db.add(vuln)
                canonical_created += 1
            else:
                canonical_reused += 1
                if not vuln.description and short_desc:
                    vuln.description = short_desc
                    vuln.description_source = "CISA-KEV"

            # 2. Upsert CisaKevEntry
            kev_entry = db.query(CisaKevEntry).filter(CisaKevEntry.cve_id == cve_id).first()
            if kev_entry is None:
                kev_entry = CisaKevEntry(
                    id=f"KEV-{cve_id}",
                    cve_id=cve_id,
                    vendor_project=vendor,
                    product=product,
                    vulnerability_name=vuln_name,
                    date_added=date_added,
                    due_date=due_date,
                    required_action=action,
                    known_ransomware_campaign_use=ransomware,
                    notes=notes,
                    catalog_version=catalog_version,
                    source_snapshot_id=active_snapshot_id,
                    source_record_sha256=record_hash,
                )
                db.add(kev_entry)
                kev_created += 1
            else:
                if kev_entry.source_record_sha256 == record_hash:
                    kev_unchanged += 1
                else:
                    kev_entry.vendor_project = vendor
                    kev_entry.product = product
                    kev_entry.vulnerability_name = vuln_name
                    kev_entry.date_added = date_added
                    kev_entry.due_date = due_date
                    kev_entry.required_action = action
                    kev_entry.known_ransomware_campaign_use = ransomware
                    kev_entry.notes = notes
                    kev_entry.catalog_version = catalog_version
                    kev_entry.source_snapshot_id = active_snapshot_id
                    kev_entry.source_record_sha256 = record_hash
                    kev_updated += 1

        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "source_type": "cisa-kev",
        "source_file": str(path),
        "source_sha256": file_sha256,
        "snapshot_id": active_snapshot_id,
        "records_read": len(vulnerabilities),
        "canonical_created": canonical_created,
        "canonical_reused": canonical_reused,
        "kev_created": kev_created,
        "kev_updated": kev_updated,
        "kev_unchanged": kev_unchanged,
        "invalid_records": invalid_records,
        "errors": errors[:50],
    }


def _extract_explicit_replacement_cve(description: str, comments: str | None = None) -> str | None:
    """Extract explicit superseding CVE if and only if stated in authoritative text."""
    combined = f"{description}\n{comments or ''}"
    match = REJECTED_CONSULT_PATTERN.search(combined)
    if match:
        candidate = match.group(1).upper()
        try:
            return validate_and_normalize_cve(candidate)
        except ValueError:
            return None
    return None


def import_nvd_cve_snapshot(
    file_path: str | Path,
    db: Session,
    *,
    snapshot_id: str | None = None,
) -> dict[str, Any]:
    """Deterministically import an NVD CVE JSON snapshot (API 2.0 format) into the shadow registry.

    Idempotent and transactional.
    Supports CVSS v2.0, v3.0, v3.1, and v4.0 assessments.
    Preserves multiple scoring authorities and rejected CVE status.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"NVD CVE snapshot file not found: {path}")

    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)

    file_bytes = path.read_bytes()
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()
    active_snapshot_id = snapshot_id or f"NVD-FILE-{file_sha256[:16]}"

    items = data.get("vulnerabilities", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    if not items and isinstance(data, dict) and "cve" in data:
        items = [data]

    canonical_created = 0
    canonical_updated = 0
    canonical_reused = 0
    cvss_created = 0
    cvss_updated = 0
    cvss_unchanged = 0
    invalid_records = 0
    errors: list[dict[str, str]] = []

    try:
        for item in items:
            cve_obj = item.get("cve", item) if isinstance(item, dict) else {}
            raw_cve_id = cve_obj.get("id") or cve_obj.get("cveId")
            try:
                cve_id = validate_and_normalize_cve(str(raw_cve_id or ""))
            except ValueError as ex:
                invalid_records += 1
                errors.append({"raw_record": str(raw_cve_id), "reason": str(ex)})
                continue

            vuln_status_raw = str(cve_obj.get("vulnStatus") or "").strip().lower()
            if "reject" in vuln_status_raw:
                status = "rejected"
            elif "reserved" in vuln_status_raw:
                status = "reserved"
            elif vuln_status_raw in {"analyzed", "modified", "published", "received", "undergoing analysis"}:
                status = "published"
            elif vuln_status_raw:
                status = "unknown"
            else:
                status = "published"

            descs = cve_obj.get("descriptions", [])
            desc_text = None
            if isinstance(descs, list):
                for d in descs:
                    if isinstance(d, dict) and d.get("lang") == "en":
                        desc_text = d.get("value")
                        break
                if not desc_text and descs and isinstance(descs[0], dict):
                    desc_text = descs[0].get("value")

            published_at = _parse_iso_datetime(cve_obj.get("published"))
            source_modified_at = _parse_iso_datetime(cve_obj.get("lastModified"))

            replaced_by_cve = None
            if status == "rejected" and desc_text:
                replaced_by_cve = _extract_explicit_replacement_cve(desc_text, cve_obj.get("evaluatorComment"))

            # 1. Upsert CanonicalVulnerability
            vuln = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == cve_id).first()
            if vuln is None:
                vuln = CanonicalVulnerability(
                    cve_id=cve_id,
                    status=status,
                    description=desc_text,
                    description_source="NVD",
                    published_at=published_at,
                    source_modified_at=source_modified_at,
                    replaced_by_cve_id=replaced_by_cve,
                )
                db.add(vuln)
                canonical_created += 1
            else:
                canonical_reused += 1
                updated = False
                if vuln.status != status:
                    vuln.status = status
                    updated = True
                if desc_text and (not vuln.description or vuln.description_source != "NVD"):
                    vuln.description = desc_text
                    vuln.description_source = "NVD"
                    updated = True
                if published_at and not vuln.published_at:
                    vuln.published_at = published_at
                    updated = True
                if source_modified_at:
                    vuln.source_modified_at = source_modified_at
                    updated = True
                if replaced_by_cve and vuln.replaced_by_cve_id != replaced_by_cve:
                    vuln.replaced_by_cve_id = replaced_by_cve
                    updated = True
                if updated:
                    canonical_updated += 1

            # 2. Parse CVSS assessments across all versions (v4.0, v3.1, v3.0, v2.0)
            metrics = cve_obj.get("metrics") or {}
            metric_groups = [
                ("4.0", metrics.get("cvssMetricV40", [])),
                ("3.1", metrics.get("cvssMetricV31", [])),
                ("3.0", metrics.get("cvssMetricV30", [])),
                ("2.0", metrics.get("cvssMetricV2", [])),
            ]

            for default_ver, group in metric_groups:
                if not isinstance(group, list):
                    continue
                for metric in group:
                    if not isinstance(metric, dict):
                        continue
                    cvss_data = metric.get("cvssData") or {}
                    version = str(cvss_data.get("version") or default_ver).strip()
                    vector_string = str(cvss_data.get("vectorString") or "").strip()
                    if not vector_string:
                        continue

                    source = str(metric.get("sourceIdentifier") or metric.get("source") or "NVD").strip()
                    source_role = metric.get("type")  # e.g., "Primary", "Secondary"
                    base_score_raw = cvss_data.get("baseScore")
                    try:
                        base_score = float(base_score_raw)
                    except (TypeError, ValueError):
                        continue

                    base_severity = (
                        cvss_data.get("baseSeverity")
                        or metric.get("baseSeverity")
                    )
                    if base_severity:
                        base_severity = str(base_severity).strip().upper()

                    record_hash = _calculate_record_hash(metric)
                    vector_hash = hashlib.sha256(vector_string.encode("utf-8")).hexdigest()[:16]
                    assessment_id = f"CVSS-{cve_id}-{source[:20]}-{version}-{vector_hash}"

                    existing_assessment = (
                        db.query(VulnerabilityCvssAssessment)
                        .filter(
                            VulnerabilityCvssAssessment.cve_id == cve_id,
                            VulnerabilityCvssAssessment.source == source,
                            VulnerabilityCvssAssessment.cvss_version == version,
                            VulnerabilityCvssAssessment.vector_string == vector_string,
                        )
                        .first()
                    )

                    if existing_assessment is None:
                        new_assessment = VulnerabilityCvssAssessment(
                            id=assessment_id,
                            cve_id=cve_id,
                            source=source,
                            source_role=source_role,
                            cvss_version=version,
                            vector_string=vector_string,
                            base_score=base_score,
                            base_severity=base_severity,
                            source_modified_at=source_modified_at,
                            source_snapshot_id=active_snapshot_id,
                            source_record_sha256=record_hash,
                        )
                        db.add(new_assessment)
                        cvss_created += 1
                    else:
                        if existing_assessment.source_record_sha256 == record_hash:
                            cvss_unchanged += 1
                        else:
                            existing_assessment.source_role = source_role
                            existing_assessment.base_score = base_score
                            existing_assessment.base_severity = base_severity
                            existing_assessment.source_modified_at = source_modified_at
                            existing_assessment.source_snapshot_id = active_snapshot_id
                            existing_assessment.source_record_sha256 = record_hash
                            cvss_updated += 1

        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "source_type": "nvd-json",
        "source_file": str(path),
        "source_sha256": file_sha256,
        "snapshot_id": active_snapshot_id,
        "records_read": len(items),
        "canonical_created": canonical_created,
        "canonical_updated": canonical_updated,
        "canonical_reused": canonical_reused,
        "cvss_created": cvss_created,
        "cvss_updated": cvss_updated,
        "cvss_unchanged": cvss_unchanged,
        "invalid_records": invalid_records,
        "errors": errors[:50],
    }


# ── Exact Finding-to-Canonical Link/Backfill Command ───────────────────────────

def link_findings_to_canonical_cves(
    db: Session,
    *,
    dry_run: bool = False,
    create_missing_canonical: bool = True,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Link existing CVE-bearing Findings to CanonicalVulnerability records.

    Rules:
    - Reads exact CVE identifier from Finding.
    - Normalizes syntactically valid CVEs only (never title, vendor, product, keywords).
    - If CanonicalVulnerability exists, sets Finding.canonical_cve_id.
    - If CanonicalVulnerability does not exist and create_missing_canonical is True,
      creates status='unknown' CanonicalVulnerability and links it.
    - Preserves all Finding IDs, AssetExposure IDs, evidence, and non-CVE findings.
    - Never merges or deletes duplicate Finding rows.
    - Transactional and idempotent.
    """
    query = db.query(Finding)
    if tenant_id:
        query = query.filter(Finding.tenant_id == tenant_id)

    findings = query.all()

    findings_inspected = len(findings)
    valid_cve_identifiers = 0
    canonical_links_created = 0
    links_already_present = 0
    missing_canonical_identities = 0
    canonical_identities_created = 0
    malformed_values = 0
    non_cve_findings_skipped = 0

    try:
        for finding in findings:
            raw_cve = getattr(finding, "cve_id", None) or getattr(finding, "cve", None)
            if not raw_cve or not isinstance(raw_cve, str) or not raw_cve.strip():
                non_cve_findings_skipped += 1
                continue

            cleaned_candidate = raw_cve.strip()
            # Non-CVE markers like SSS-, template:, etc.
            if cleaned_candidate.upper().startswith(("SSS-", "TEMPLATE:", "NON_CVE", "CUSTOM-")):
                non_cve_findings_skipped += 1
                continue

            try:
                cve_id = validate_and_normalize_cve(cleaned_candidate)
                valid_cve_identifiers += 1
            except ValueError:
                malformed_values += 1
                continue

            current_link = getattr(finding, "canonical_cve_id", None)
            if current_link == cve_id:
                links_already_present += 1
                continue

            # Lookup canonical vulnerability
            canonical = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == cve_id).first()
            if canonical is None:
                if create_missing_canonical:
                    canonical = CanonicalVulnerability(
                        cve_id=cve_id,
                        status="unknown",
                        description=getattr(finding, "title", None) or getattr(finding, "short_description", None),
                        description_source="FINDING_LINKAGE",
                    )
                    db.add(canonical)
                    canonical_identities_created += 1
                else:
                    missing_canonical_identities += 1
                    continue

            if not dry_run:
                finding.canonical_cve_id = cve_id
            canonical_links_created += 1

        if dry_run:
            db.rollback()
        else:
            db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "status": "success",
        "dry_run": dry_run,
        "findings_inspected": findings_inspected,
        "valid_cve_identifiers": valid_cve_identifiers,
        "canonical_links_created": canonical_links_created,
        "links_already_present": links_already_present,
        "missing_canonical_identities": missing_canonical_identities,
        "canonical_identities_created": canonical_identities_created,
        "malformed_values": malformed_values,
        "non_cve_findings_skipped": non_cve_findings_skipped,
    }


# ── Canonical Intelligence Resolver & CVSS Selection Policy ───────────────────

@dataclass
class ResolvedVulnerabilityIntelligence:
    """Stable internal representation of resolved vulnerability intelligence."""

    cve_id: str | None
    status: str
    description: str | None
    description_source: str | None
    published_at: datetime | None
    replaced_by_cve_id: str | None
    cvss_score: float | None
    cvss_version: str | None
    cvss_vector: str | None
    cvss_source: str | None
    cvss_source_role: str | None
    cvss_base_severity: str | None
    is_cisa_kev: bool
    is_ransomware: bool
    kev_date_added: str | None
    kev_due_date: str | None
    kev_required_action: str | None
    kev_notes: str | None
    provenance_classification: str  # canonical_authoritative, canonical_secondary, canonical_unassessed, legacy_unprovenanced, non_cve
    has_canonical_data: bool
    used_legacy_fallback: bool

    @property
    def canonical_cve_id(self) -> str | None:
        return self.cve_id

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.published_at:
            data["published_at"] = self.published_at.isoformat()
        return data


def select_preferred_cvss_assessment(
    assessments: list[VulnerabilityCvssAssessment],
) -> VulnerabilityCvssAssessment | None:
    """Deterministic server-side CVSS assessment selection policy.

    Order of preference:
    1. Valid assessments only.
    2. Highest supported CVSS generation: 4.0 > 3.1 > 3.0 > 2.0.
    3. Primary/source-authoritative role preferred over Secondary when comparing
       otherwise equivalent assessments.
    4. Latest source_modified_at.
    5. Stable source/id tie-breaker.
    """
    if not assessments:
        return None

    def _sort_key(assessment: VulnerabilityCvssAssessment) -> tuple:
        ver_rank = CVSS_VERSION_RANK.get(str(assessment.cvss_version or "").strip(), 0)
        role = str(assessment.source_role or "").strip().lower()
        role_rank = 1 if role == "primary" else 0
        mod_time = assessment.source_modified_at.timestamp() if assessment.source_modified_at else 0.0
        src = str(assessment.source or "")
        aid = str(assessment.id or "")
        return (ver_rank, role_rank, mod_time, src, aid)

    return max(assessments, key=_sort_key)


def resolve_vulnerability_intelligence(
    finding_or_cve: Finding | dict | str,
    db: Session,
) -> ResolvedVulnerabilityIntelligence:
    """Authoritative internal resolver for vulnerability intelligence.

    Extracts or resolves canonical intelligence from CanonicalVulnerability,
    VulnerabilityCvssAssessment, and CisaKevEntry with graceful, non-destructive
    legacy compatibility fallback.
    """
    cve_id = None
    finding_dict: dict[str, Any] = {}

    if isinstance(finding_or_cve, str):
        try:
            cve_id = validate_and_normalize_cve(finding_or_cve)
        except ValueError:
            cve_id = None
    elif isinstance(finding_or_cve, dict):
        finding_dict = finding_or_cve
        cve_id = extract_cve_from_finding(finding_dict)
    else:
        # Finding ORM model
        finding_dict = {
            "canonical_cve_id": getattr(finding_or_cve, "canonical_cve_id", None),
            "cve_id": getattr(finding_or_cve, "cve_id", None),
            "cve": getattr(finding_or_cve, "cve", None),
            "cvss": getattr(finding_or_cve, "cvss", None),
            "cisa_kev": getattr(finding_or_cve, "cisa_kev", None),
            "ransomware": getattr(finding_or_cve, "ransomware", None),
            "title": getattr(finding_or_cve, "title", None),
            "short_description": getattr(finding_or_cve, "short_description", None),
            "date_added": getattr(finding_or_cve, "date_added", None),
            "required_action": getattr(finding_or_cve, "required_action", None),
        }
        cve_id = extract_cve_from_finding(finding_dict)

    if not cve_id:
        return ResolvedVulnerabilityIntelligence(
            cve_id=None,
            status="unknown",
            description=finding_dict.get("title") or finding_dict.get("short_description"),
            description_source=None,
            published_at=None,
            replaced_by_cve_id=None,
            cvss_score=float(finding_dict["cvss"]) if finding_dict.get("cvss") is not None else None,
            cvss_version="legacy" if finding_dict.get("cvss") is not None else None,
            cvss_vector=None,
            cvss_source="legacy_finding" if finding_dict.get("cvss") is not None else None,
            cvss_source_role="legacy_fallback" if finding_dict.get("cvss") is not None else None,
            cvss_base_severity=None,
            is_cisa_kev=bool(finding_dict.get("cisa_kev") or finding_dict.get("cisa")),
            is_ransomware=bool(finding_dict.get("ransomware")),
            kev_date_added=finding_dict.get("date_added") or finding_dict.get("dateAdded"),
            kev_due_date=None,
            kev_required_action=finding_dict.get("required_action") or finding_dict.get("requiredAction"),
            kev_notes=None,
            provenance_classification=finding_dict.get("provenance_classification") or "non_cve",
            has_canonical_data=False,
            used_legacy_fallback=bool(finding_dict.get("cvss") is not None),
        )

    # Query canonical models
    canonical = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == cve_id).first()
    assessments = db.query(VulnerabilityCvssAssessment).filter(VulnerabilityCvssAssessment.cve_id == cve_id).all()
    kev_entry = db.query(CisaKevEntry).filter(CisaKevEntry.cve_id == cve_id).first()

    has_canonical = canonical is not None or bool(assessments) or kev_entry is not None

    status = canonical.status if canonical else "unknown"
    desc = canonical.description if canonical else (finding_dict.get("title") or finding_dict.get("short_description"))
    desc_src = canonical.description_source if canonical else None
    pub_at = canonical.published_at if canonical else None
    repl_by = canonical.replaced_by_cve_id if canonical else None

    # Resolve CVSS
    preferred_cvss = select_preferred_cvss_assessment(assessments) if assessments else None

    if preferred_cvss is not None:
        cvss_score = preferred_cvss.base_score
        cvss_version = preferred_cvss.cvss_version
        cvss_vector = preferred_cvss.vector_string
        cvss_source = preferred_cvss.source
        cvss_source_role = preferred_cvss.source_role
        cvss_base_severity = preferred_cvss.base_severity
        role_lower = (preferred_cvss.source_role or "").lower()
        provenance = "canonical_authoritative" if role_lower == "primary" else "canonical_secondary"
        used_fallback = False
    elif finding_dict.get("cvss") is not None:
        # Legacy read-only fallback
        try:
            cvss_score = float(finding_dict["cvss"])
        except (ValueError, TypeError):
            cvss_score = None
        cvss_version = "legacy" if cvss_score is not None else None
        cvss_vector = None
        cvss_source = "legacy_finding" if cvss_score is not None else None
        cvss_source_role = "legacy_fallback" if cvss_score is not None else None
        cvss_base_severity = None
        provenance = "legacy_unprovenanced"
        used_fallback = True
    else:
        cvss_score = None
        cvss_version = None
        cvss_vector = None
        cvss_source = None
        cvss_source_role = None
        cvss_base_severity = None
        provenance = "canonical_unassessed"
        used_fallback = False

    # Resolve KEV
    if kev_entry is not None:
        is_kev = True
        is_ransomware = (kev_entry.known_ransomware_campaign_use or "").strip().lower() == "known"
        kev_date_added = kev_entry.date_added
        kev_due_date = kev_entry.due_date
        kev_action = kev_entry.required_action
        kev_notes = kev_entry.notes
    else:
        is_kev = bool(finding_dict.get("cisa_kev") or finding_dict.get("cisa"))
        is_ransomware = bool(finding_dict.get("ransomware"))
        kev_date_added = finding_dict.get("date_added") or finding_dict.get("dateAdded")
        kev_due_date = None
        kev_action = finding_dict.get("required_action") or finding_dict.get("requiredAction")
        kev_notes = None

    return ResolvedVulnerabilityIntelligence(
        cve_id=cve_id,
        status=status,
        description=desc,
        description_source=desc_src,
        published_at=pub_at,
        replaced_by_cve_id=repl_by,
        cvss_score=cvss_score,
        cvss_version=cvss_version,
        cvss_vector=cvss_vector,
        cvss_source=cvss_source,
        cvss_source_role=cvss_source_role,
        cvss_base_severity=cvss_base_severity,
        is_cisa_kev=is_kev,
        is_ransomware=is_ransomware,
        kev_date_added=kev_date_added,
        kev_due_date=kev_due_date,
        kev_required_action=kev_action,
        kev_notes=kev_notes,
        provenance_classification=provenance,
        has_canonical_data=has_canonical,
        used_legacy_fallback=used_fallback,
    )
