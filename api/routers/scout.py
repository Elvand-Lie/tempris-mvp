from fastapi import APIRouter, Query
from typing import List, Optional
from services.kev_loader import get_all_findings
import math

router = APIRouter()

@router.get("/findings")
def get_scout_findings(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    vendor: Optional[str] = None,
    ransomware_only: bool = False
):
    """Returns paginated, filterable findings for the SCOUT browser."""
    all_findings = get_all_findings()
    
    # Filter
    filtered = all_findings
    if search:
        search_lower = search.lower()
        filtered = [f for f in filtered if search_lower in f["cve"].lower() or search_lower in f["title"].lower() or search_lower in f["id"].lower()]
        
    if vendor:
        filtered = [f for f in filtered if f["vendor"] == vendor]
        
    if ransomware_only:
        filtered = [f for f in filtered if f["ransomware"]]
        
    # Paginate
    total_count = len(filtered)
    total_pages = math.ceil(total_count / limit)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    
    return {
        "data": filtered[start_idx:end_idx],
        "meta": {
            "total": total_count,
            "page": page,
            "limit": limit,
            "total_pages": total_pages
        }
    }

@router.get("/stats")
def get_scout_stats():
    """Returns aggregate stats for the SCOUT sidebar."""
    all_findings = get_all_findings()
    
    total = len(all_findings)
    critical = sum(1 for f in all_findings if f["priority"] == "P0")
    ransomware = sum(1 for f in all_findings if f["ransomware"])
    
    return {
        "total_findings": total,
        "critical_count": critical,
        "ransomware_linked": ransomware
    }

@router.get("/vendors")
def get_scout_vendors():
    """Returns a list of unique vendors for the filter dropdown."""
    all_findings = get_all_findings()
    vendors = set(f["vendor"] for f in all_findings if f["vendor"])
    return sorted(list(vendors))
