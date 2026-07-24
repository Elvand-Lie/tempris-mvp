from fastapi import APIRouter, Query, Depends
from typing import Optional
from sqlalchemy.orm import Session
from services.kev_loader import get_findings_paginated, get_finding_stats, get_unique_vendors
from services.database import get_db
from routers.auth import get_auth_context, get_current_user
import math

from services.entitlements import require_module

router = APIRouter(dependencies=[Depends(require_module("SCOUT"))])


def _strip_internal_fields(f: dict) -> dict:
    public = f.copy()
    public.pop("raw_inputs", None)
    public.pop("sss_data", None)
    return public

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
    return get_finding_stats(db, tenant_id=get_auth_context(user).tenant_id)

@router.get("/vendors")
def get_scout_vendors(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Returns a list of unique vendors for the filter dropdown."""
    return get_unique_vendors(db, tenant_id=get_auth_context(user).tenant_id)
