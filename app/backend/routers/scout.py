from fastapi import APIRouter, Query, Depends, HTTPException
from typing import Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from services.kev_loader import get_findings_paginated, get_finding_stats, get_unique_vendors
from services.database import get_db
from models import CanonicalVulnerability, CisaKevEntry, Finding, ScanFinding, ScanJob, VulnerabilityCvssAssessment
from routers.auth import get_auth_context, get_current_user
from services.cve_intelligence import resolve_vulnerability_intelligence, validate_and_normalize_cve
import math

from services.entitlements import require_module
from services.customer_posture import build_customer_posture

router = APIRouter(dependencies=[Depends(require_module("SCOUT"))])


def _strip_internal_fields(f: dict) -> dict:
    public = f.copy()
    public.pop("raw_inputs", None)
    public.pop("sss_data", None)
    if not public.get("decision") and not public.get("edip_decision"):
        public["edip_state"] = "No EDIP decision"
    return public


# ── Canonical Vulnerabilities Reference Intelligence (Global Catalogue) ─────────

@router.get("/vulnerabilities")
def get_canonical_vulnerabilities(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = None,
    kev_only: bool = False,
    ransomware_only: bool = False,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Returns paginated, filterable reference intelligence from the canonical CVE spine.

    INVARIANTS:
    - Queries CanonicalVulnerability / VulnerabilityCvssAssessment / CisaKevEntry only.
    - Zero queries to Finding or ScanFinding customer records.
    - Reference records are never customer exposure.
    """
    query = db.query(CanonicalVulnerability)

    if status:
        query = query.filter(CanonicalVulnerability.status == status.strip().lower())

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            or_(
                CanonicalVulnerability.cve_id.ilike(s),
                CanonicalVulnerability.description.ilike(s),
            )
        )

    if kev_only or ransomware_only or vendor or product:
        kev_subquery = db.query(CisaKevEntry.cve_id)
        if ransomware_only:
            kev_subquery = kev_subquery.filter(func.lower(CisaKevEntry.known_ransomware_campaign_use) == "known")
        if vendor:
            kev_subquery = kev_subquery.filter(CisaKevEntry.vendor_project.ilike(f"%{vendor.strip()}%"))
        if product:
            kev_subquery = kev_subquery.filter(CisaKevEntry.product.ilike(f"%{product.strip()}%"))
        query = query.filter(CanonicalVulnerability.cve_id.in_(kev_subquery))

    total_count = query.count()
    rows = (
        query.order_by(CanonicalVulnerability.cve_id.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    data: list[dict[str, Any]] = []
    for row in rows:
        intel = resolve_vulnerability_intelligence(row.cve_id, db)
        data.append({
            "cve_id": intel.cve_id,
            "status": intel.status,
            "description": intel.description,
            "description_source": intel.description_source,
            "published_at": intel.published_at.isoformat() if intel.published_at else None,
            "replaced_by_cve_id": intel.replaced_by_cve_id,
            "cvss": {
                "score": intel.cvss_score,
                "version": intel.cvss_version,
                "vector": intel.cvss_vector,
                "source": intel.cvss_source,
                "source_role": intel.cvss_source_role,
                "base_severity": intel.cvss_base_severity,
                "provenance": intel.provenance_classification,
            },
            "cisa_kev": {
                "is_kev": intel.is_cisa_kev,
                "is_ransomware": intel.is_ransomware,
                "date_added": intel.kev_date_added,
                "due_date": intel.kev_due_date,
                "required_action": intel.kev_required_action,
                "notes": intel.kev_notes,
            },
            "provenance_classification": intel.provenance_classification,
            "has_canonical_data": intel.has_canonical_data,
        })

    total_pages = math.ceil(total_count / limit) if total_count > 0 else 1

    return {
        "data": data,
        "meta": {
            "total": total_count,
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
        },
    }


@router.get("/vulnerabilities/{cve_id}")
def get_canonical_vulnerability_by_cve(
    cve_id: str,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Returns authoritative canonical vulnerability intelligence for a single CVE."""
    try:
        normalized_cve = validate_and_normalize_cve(cve_id)
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex))

    vuln = db.query(CanonicalVulnerability).filter(CanonicalVulnerability.cve_id == normalized_cve).first()
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerability {normalized_cve} not found in canonical catalogue")

    intel = resolve_vulnerability_intelligence(normalized_cve, db)
    assessments = db.query(VulnerabilityCvssAssessment).filter(VulnerabilityCvssAssessment.cve_id == normalized_cve).all()
    kev_entry = db.query(CisaKevEntry).filter(CisaKevEntry.cve_id == normalized_cve).first()

    return {
        "cve_id": intel.cve_id,
        "status": intel.status,
        "description": intel.description,
        "description_source": intel.description_source,
        "published_at": intel.published_at.isoformat() if intel.published_at else None,
        "replaced_by_cve_id": intel.replaced_by_cve_id,
        "preferred_cvss": {
            "score": intel.cvss_score,
            "version": intel.cvss_version,
            "vector": intel.cvss_vector,
            "source": intel.cvss_source,
            "source_role": intel.cvss_source_role,
            "base_severity": intel.cvss_base_severity,
            "provenance": intel.provenance_classification,
        },
        "all_cvss_assessments": [
            {
                "id": a.id,
                "source": a.source,
                "source_role": a.source_role,
                "cvss_version": a.cvss_version,
                "vector_string": a.vector_string,
                "base_score": a.base_score,
                "base_severity": a.base_severity,
                "source_modified_at": a.source_modified_at.isoformat() if a.source_modified_at else None,
            }
            for a in assessments
        ],
        "cisa_kev": {
            "is_kev": intel.is_cisa_kev,
            "is_ransomware": intel.is_ransomware,
            "vendor_project": kev_entry.vendor_project if kev_entry else None,
            "product": kev_entry.product if kev_entry else None,
            "vulnerability_name": kev_entry.vulnerability_name if kev_entry else None,
            "date_added": intel.kev_date_added,
            "due_date": intel.kev_due_date,
            "required_action": intel.kev_required_action,
            "notes": intel.kev_notes,
            "catalog_version": kev_entry.catalog_version if kev_entry else None,
        } if intel.is_cisa_kev else None,
        "provenance_classification": intel.provenance_classification,
        "has_canonical_data": intel.has_canonical_data,
    }


# ── Tenant Finding Browser (Customer Exposure) ──────────────────────────────────

@router.get("/findings")
def get_scout_findings(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    vendor: Optional[str] = None,
    ransomware_only: bool = False,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Returns paginated, filterable findings for the SCOUT browser."""
    tenant_id = get_auth_context(user).tenant_id
    findings, total_count = get_findings_paginated(
        db, page=page, limit=limit,
        search=search, vendor=vendor,
        ransomware_only=ransomware_only,
        user_tenant_id=tenant_id,
    )
    findings = [_strip_internal_fields(f) for f in findings]
    total_pages = math.ceil(total_count / limit) if total_count > 0 else 1

    return {
        "data": findings,
        "meta": {
            "total": total_count,
            "page": page,
            "limit": limit,
            "total_pages": total_pages
        }
    }


@router.get("/stats")
def get_scout_stats(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Returns aggregate stats for the SCOUT sidebar."""
    tenant_id = get_auth_context(user).tenant_id
    legacy = get_finding_stats(db, tenant_id=tenant_id)
    posture = build_customer_posture(db, tenant_id)
    jobs = db.query(ScanJob).filter(ScanJob.tenant_id == tenant_id)
    observations = db.query(ScanFinding).filter(ScanFinding.tenant_id == tenant_id)

    # Canonical intelligence catalogue totals
    canonical_total = db.query(CanonicalVulnerability).count()
    canonical_kev = db.query(CisaKevEntry).count()

    return {
        **legacy,
        "metric_scope": "separated_reference_catalogue_and_customer_scan_activity",
        "reference_catalogue": {
            "canonical_vulnerabilities": canonical_total,
            "cisa_kev_catalog_entries": canonical_kev,
            "total_records": posture["reference_intelligence_count"],
            "stored_tenant_records": posture["total_stored_finding_count"],
            "label_note": "Reference records are not confirmed customer exposure.",
        },
        "customer_scan_activity": {
            "scan_runs": jobs.count(),
            "completed_runs": jobs.filter(ScanJob.status == "completed").count(),
            "scan_observations": observations.count(),
            "normalized_candidate_findings": observations.filter(ScanFinding.normalized_finding_id.isnot(None)).count(),
            "confirmed_customer_exposures": posture["confirmed_open_exposure_count"],
        },
    }


@router.get("/vendors")
def get_scout_vendors(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Returns a list of unique vendors for the filter dropdown."""
    return get_unique_vendors(db, tenant_id=get_auth_context(user).tenant_id)
