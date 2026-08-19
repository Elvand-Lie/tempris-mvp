"""
KEV Loader — Database-backed vulnerability findings.

Provides query functions for findings stored in the DB, plus a backward-compatible
get_all_findings() wrapper that returns list[dict] for existing consumers.
"""
import logging
from sqlalchemy.orm import Session
from sqlalchemy import case, func, or_

logger = logging.getLogger("tempris.kev_loader")


def _finding_to_dict(f) -> dict:
    """Convert a Finding ORM object to the dict format expected by all consumers."""
    cve_val = getattr(f, "canonical_cve_id", None) or getattr(f, "cve_id", None) or getattr(f, "cve", None)
    return {
        "id": f.id,
        "canonical_cve_id": getattr(f, "canonical_cve_id", None) or cve_val,
        "cve_id": getattr(f, "cve_id", None) or cve_val,
        "finding_type": f.finding_type,
        "sub_class": f.sub_class,
        "cve": cve_val,
        "title": f.title,
        "vendor": f.vendor,
        "product": f.product,
        "cvss": f.cvss,
        "priority": f.priority,
        "status": f.status,
        "cisa": f.cisa_kev,
        "cisa_kev": f.cisa_kev,
        "ransomware": f.ransomware,
        "dateAdded": f.date_added,
        "shortDescription": f.short_description,
        "requiredAction": f.required_action,
        "raw_inputs": f.raw_inputs or {},
        "cve_context": f.cve_context or {},
        "edip_decision": None,
        "edip_rationale": None,
        "asset": f.asset_data,
        "sss_data": f.sss_data,
        "source": f.source,
    }


def get_all_findings(db: Session = None, tenant_id: str = None) -> list[dict]:
    """Backward-compatible wrapper: returns all findings as list of dicts.

    Used by ai_context.py, rag_engine.py, and other consumers that need
    the full dataset. For paginated/filtered access, use get_findings_paginated().
    """
    from services.database import SessionLocal
    from models import Finding

    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True
    try:
        query = db.query(Finding)
        if tenant_id:
            query = query.filter(Finding.tenant_id == tenant_id)
        findings = query.order_by(Finding.priority, Finding.cvss.desc()).all()
        return [_finding_to_dict(f) for f in findings]
    finally:
        if should_close:
            db.close()


def get_findings_paginated(
    db: Session,
    page: int = 1,
    limit: int = 50,
    priority: str = None,
    search: str = None,
    decision_filter: str = None,
    vendor: str = None,
    ransomware_only: bool = False,
    user_tenant_id: str | None = None,
    is_superadmin: bool = False,
) -> tuple[list[dict], int]:
    """DB-level filtered + paginated query. Returns (findings, total_count)."""
    from models import Finding, EdipDecision

    query = db.query(Finding)

    if not user_tenant_id:
        raise ValueError("A verified tenant ID is required for paginated finding access")
    query = query.filter(Finding.tenant_id == user_tenant_id)

    if priority:
        query = query.filter(Finding.priority == priority)
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Finding.cve.ilike(search_pattern),
                Finding.title.ilike(search_pattern),
                Finding.vendor.ilike(search_pattern),
            )
        )
    if vendor:
        query = query.filter(Finding.vendor == vendor)
    if ransomware_only:
        query = query.filter(Finding.ransomware == True)

    # Filter by EDIP decision status
    if decision_filter in ("pending", "decided"):
        decided_ids_list = [
            row[0]
            for row in db.query(EdipDecision.finding_id).filter(
                EdipDecision.tenant_id == user_tenant_id
            ).all()
        ]
                
        if decision_filter == "pending":
            query = query.filter(~Finding.id.in_(decided_ids_list))
        elif decision_filter == "decided":
            query = query.filter(Finding.id.in_(decided_ids_list))

    total = query.count()

    # Order: P0 first, then by CVSS descending
    priority_order = case(
        (Finding.priority == "P0", 0),
        (Finding.priority == "P1", 1),
        (Finding.priority == "P2", 2),
        else_=3
    )
    results = (
        query.order_by(priority_order, Finding.cvss.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )
    return [_finding_to_dict(f) for f in results], total


def get_finding_by_id(db: Session, finding_id: str, tenant_id: str | None = None) -> dict | None:
    """Look up a single finding by ID."""
    from models import Finding
    query = db.query(Finding).filter(Finding.id == finding_id)
    if tenant_id:
        query = query.filter(Finding.tenant_id == tenant_id)
    f = query.first()
    return _finding_to_dict(f) if f else None


def get_finding_stats(db: Session, tenant_id: str = None) -> dict:
    """Aggregate counts via SQL — no iteration needed."""
    from models import Finding
    query = db.query(Finding)
    if tenant_id:
        query = query.filter(Finding.tenant_id == tenant_id)
    
    total = query.count()
    critical = query.filter(Finding.priority == "P0").count()
    high = query.filter(Finding.priority == "P1").count()
    kev = query.filter(Finding.cisa_kev == True).count()
    ransomware = query.filter(Finding.ransomware == True).count()
    return {
        "total_findings": total,
        "critical_count": critical,
        "high_count": high,
        "kev_count": kev,
        "ransomware_linked": ransomware,
    }


def get_unique_vendors(db: Session, tenant_id: str | None = None) -> list[str]:
    """Get distinct vendor names for filter dropdowns."""
    from models import Finding
    query = db.query(Finding.vendor).distinct().filter(Finding.vendor.isnot(None))
    if tenant_id:
        query = query.filter(Finding.tenant_id == tenant_id)
    rows = query.all()
    return sorted([r[0] for r in rows])


def get_top_critical_findings(db: Session, limit: int = 20, tenant_id: str = None) -> list[dict]:
    """Get top N critical findings for TES calculation."""
    from models import Finding
    query = db.query(Finding).filter(Finding.priority == "P0")
    if tenant_id:
        query = query.filter(Finding.tenant_id == tenant_id)
    findings = (
        query.order_by(Finding.cvss.desc())
        .limit(limit)
        .all()
    )
    return [_finding_to_dict(f) for f in findings]


def get_ransomware_findings(db: Session, limit: int = 5, tenant_id: str = None) -> list[dict]:
    """Get ransomware-linked findings for alerts."""
    from models import Finding, CisaKevEntry
    from sqlalchemy import or_, select

    ransomware_cves = select(CisaKevEntry.cve_id).where(
        CisaKevEntry.known_ransomware_campaign_use.in_(["Known", "known"])
    )

    query = db.query(Finding).filter(
        or_(
            Finding.ransomware == True,
            Finding.canonical_cve_id.in_(ransomware_cves),
            Finding.cve.in_(ransomware_cves),
            Finding.cve_id.in_(ransomware_cves),
        )
    )
    if tenant_id:
        query = query.filter(Finding.tenant_id == tenant_id)
    findings = (
        query.order_by(Finding.cvss.desc())
        .limit(limit)
        .all()
    )
    return [_finding_to_dict(f) for f in findings]


# ── Startup seed check ────────────────────────────────────────────────────────

def ensure_findings_seeded():
    """Called on startup; idempotently inserts any missing seeded findings."""
    from services.database import SessionLocal
    from models import Finding

    db = SessionLocal()
    try:
        count = db.query(Finding).count()
        logger.info(f"Findings table has {count} entries; checking for missing seed data.")
    finally:
        db.close()

    from scripts.seed_findings import seed_all
    seed_all()

    db = SessionLocal()
    try:
        count = db.query(Finding).count()
        logger.info(f"Seed check complete. {count} findings in DB.")
    finally:
        db.close()


# ── Legacy compatibility ──────────────────────────────────────────────────────
# These are kept so existing imports don't break during migration.

def load_kev_data():
    """Legacy no-op. Findings are now loaded from the DB via ensure_findings_seeded()."""
    pass
