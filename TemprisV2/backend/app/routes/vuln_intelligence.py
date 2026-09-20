# backend/app/routes/vuln_intelligence.py
"""
Read-only Internal Vulnerability Intelligence API & Search routes.

Endpoints:
  - GET /api/vuln-intelligence/cve/{cve_id}: exact CVE lookup & composed source-aware detail (Active V2 User)
  - GET /api/vuln-intelligence/cve: search & filtered listing across normalized fields (Active V2 User)
  - GET /api/vuln-intelligence/health: observable health for all sources (Platform Admin)
  - GET /api/vuln-intelligence/health/{source}: health for a specific source (Platform Admin)
  - GET /api/vuln-intelligence/snapshots: sync snapshot history (Platform Admin)
  - POST /api/vuln-intelligence/sync/{source}: trigger manual source sync (Platform Admin)

Security & Non-negotiables:
  - Any authenticated active V2 user may read global public intelligence
  - Operational and sync triggers require platform administrator authority
  - No tenant IDs, asset exposure, Finding state, or Tempris-authored claims
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import AuthContext, get_auth_context, require_platform_admin
from app.db import get_db_connection
from app.vuln_intelligence.models import validate_cve_id
from app.vuln_intelligence.repository import (
    get_composed_cve_detail,
    search_vulnerabilities,
    list_sync_snapshots,
)
from app.vuln_intelligence.sync_engine import (
    get_all_source_health,
    get_source_health,
    sync_source,
)
from app.vuln_intelligence.sync_adapters import ALL_ADAPTERS, get_adapter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/vuln-intelligence", tags=["Vulnerability Intelligence"])


# ---------------------------------------------------------------------------
# Public Intelligence Read & Search (Any Authenticated Active V2 User)
# ---------------------------------------------------------------------------

@router.get("/cve/{cve_id}", summary="Exact CVE lookup with composed source-aware provenance")
def get_cve_detail(
    cve_id: str,
    auth: AuthContext = Depends(get_auth_context),
):
    """
    Retrieve composed vulnerability intelligence for an exact CVE ID.

    Returns:
      - Canonical CVE identity, lifecycle state, assigning CNA metadata
      - Source provenance (all raw revisions, hashes, timestamps, snapshots)
      - Upstream descriptions from CNA and NVD
      - All independent CVSS assessments across versions and providers
      - Deterministic CVSS authority resolution with full provenance (P0-03,
        PRD §3.5 #2) — or the explicit stable unscoreable reason code
      - Affected product configurations, CPEs, and version ranges
      - Weaknesses (CWE) and upstream references
      - Exact relationships and replacements
      - Embedded CISA ADP and SSVC decision trees
      - CISA KEV known-exploitation enrichment (if catalogued)
      - FIRST EPSS current probability/percentile and daily history
      - Linked OSV package records via exact declared CVE aliases
    """
    clean_cve = cve_id.strip().upper()
    if not validate_cve_id(clean_cve):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid CVE ID syntax: {cve_id!r}. Expected format: CVE-YYYY-NNNN+",
        )

    with get_db_connection() as conn:
        detail = get_composed_cve_detail(conn, clean_cve)

    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability {clean_cve} not found in intelligence library.",
        )

    return detail


@router.get("/cve", summary="Search and list vulnerability intelligence")
def search_cves(
    q: Optional[str] = Query(None, description="Search keyword across CVE ID, vendor, product, CWE, OSV package"),
    state: Optional[str] = Query(None, description="Filter by lifecycle state (PUBLISHED, RESERVED, REJECTED)"),
    has_kev: Optional[bool] = Query(None, description="Filter by CISA KEV presence"),
    min_cvss: Optional[float] = Query(None, description="Minimum resolved CVSS authority base score"),
    max_cvss: Optional[float] = Query(None, description="Maximum resolved CVSS authority base score"),
    min_epss: Optional[float] = Query(None, description="Minimum EPSS probability score"),
    ecosystem: Optional[str] = Query(None, description="Filter by OSV ecosystem (e.g. npm, PyPI, Go)"),
    limit: int = Query(50, ge=1, le=100, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    auth: AuthContext = Depends(get_auth_context),
):
    """
    Search indexed normalized vulnerability intelligence.
    Search indexed normalized vulnerability intelligence with CVSS authority
    filtering (P0-03: intrinsic CVSS is never TES).
    """
    with get_db_connection() as conn:
        results = search_vulnerabilities(
            conn,
            q=q,
            state=state,
            has_kev=has_kev,
            min_cvss=min_cvss,
            max_cvss=max_cvss,
            min_epss=min_epss,
            ecosystem=ecosystem,
            limit=limit,
            offset=offset,
        )
    return results


# ---------------------------------------------------------------------------
# Operational & Health Endpoints (Platform Administrator Authority Required)
# ---------------------------------------------------------------------------

@router.get("/health", summary="Observable source health for all intelligence sources")
def get_sources_health(
    auth: AuthContext = Depends(require_platform_admin),
):
    """
    Retrieve observable per-source synchronization health and scheduling state
    for all 5 public intelligence sources (CVE, NVD, KEV, EPSS, OSV).
    """
    with get_db_connection() as conn:
        health_list = get_all_source_health(conn)

    return {
        "sources": [
            {
                "source": h.source,
                "is_healthy": h.is_healthy,
                "last_attempted_at": h.last_attempted_at.isoformat() if h.last_attempted_at else None,
                "last_successful_at": h.last_successful_at.isoformat() if h.last_successful_at else None,
                "last_error": h.last_error,
                "consecutive_failures": h.consecutive_failures,
                "cursor_value": h.cursor_value,
                "active_record_count": h.active_record_count,
                "last_snapshot_id": h.last_snapshot_id,
                "last_good_snapshot_id": h.last_good_snapshot_id,
                "last_sync_duration_ms": h.last_sync_duration_ms,
                "sync_enabled": h.sync_enabled,
                "sync_interval_seconds": h.sync_interval_seconds,
                "next_sync_at": h.next_sync_at.isoformat() if h.next_sync_at else None,
                "data_age_seconds": h.data_age_seconds,
            }
            for h in health_list
        ]
    }


@router.get("/health/{source}", summary="Observable health for a single intelligence source")
def get_single_source_health(
    source: str,
    auth: AuthContext = Depends(require_platform_admin),
):
    """Retrieve health and scheduling state for a single source."""
    clean_src = source.strip().lower()
    if clean_src not in ALL_ADAPTERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown source {source!r}. Available: {list(ALL_ADAPTERS.keys())}",
        )

    with get_db_connection() as conn:
        h = get_source_health(conn, clean_src)

    if h is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No sync state found for source {clean_src}",
        )

    return {
        "source": h.source,
        "is_healthy": h.is_healthy,
        "last_attempted_at": h.last_attempted_at.isoformat() if h.last_attempted_at else None,
        "last_successful_at": h.last_successful_at.isoformat() if h.last_successful_at else None,
        "last_error": h.last_error,
        "consecutive_failures": h.consecutive_failures,
        "cursor_value": h.cursor_value,
        "active_record_count": h.active_record_count,
        "last_snapshot_id": h.last_snapshot_id,
        "last_good_snapshot_id": h.last_good_snapshot_id,
        "last_sync_duration_ms": h.last_sync_duration_ms,
        "sync_enabled": h.sync_enabled,
        "sync_interval_seconds": h.sync_interval_seconds,
        "next_sync_at": h.next_sync_at.isoformat() if h.next_sync_at else None,
        "data_age_seconds": h.data_age_seconds,
    }


@router.get("/snapshots", summary="List synchronization snapshots")
def get_snapshots(
    source: Optional[str] = Query(None, description="Filter by source name"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (running, completed, partial, failed)"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(require_platform_admin),
):
    """List historical synchronization snapshots and their metrics."""
    with get_db_connection() as conn:
        snapshots = list_sync_snapshots(
            conn,
            source=source,
            status=status_filter,
            limit=limit,
            offset=offset,
        )

    return {
        "limit": limit,
        "offset": offset,
        "snapshots": [
            {
                "id": s.id,
                "source": s.source,
                "sync_mode": s.sync_mode,
                "status": s.status,
                "records_processed": s.records_processed,
                "records_created": s.records_created,
                "records_updated": s.records_updated,
                "records_unchanged": s.records_unchanged,
                "records_failed": s.records_failed,
                "cursor_before": s.cursor_before,
                "cursor_after": s.cursor_after,
                "error_message": s.error_message,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in snapshots
        ],
    }


@router.post("/sync/{source}", summary="Trigger manual synchronization for a source")
def trigger_sync(
    source: str,
    batch_size: int = Query(1000, ge=1, le=10000),
    auth: AuthContext = Depends(require_platform_admin),
):
    """
    Manually trigger synchronization for a source.
    Acquires PostgreSQL advisory lock, validates batch, and atomically activates.
    """
    clean_src = source.strip().lower()
    adapter = get_adapter(clean_src)
    if adapter is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown source {source!r}. Available: {list(ALL_ADAPTERS.keys())}",
        )

    with get_db_connection() as conn:
        outcome = sync_source(conn, adapter, batch_size=batch_size)

    return {
        "source": outcome.source,
        "success": outcome.success,
        "snapshot_id": outcome.snapshot_id,
        "sync_mode": outcome.sync_mode,
        "records_processed": outcome.records_processed,
        "records_created": outcome.records_created,
        "records_updated": outcome.records_updated,
        "records_unchanged": outcome.records_unchanged,
        "records_failed": outcome.records_failed,
        "cursor_before": outcome.cursor_before,
        "cursor_after": outcome.cursor_after,
        "error": outcome.error,
        "duration_ms": outcome.duration_ms,
        "skipped_overlap": outcome.skipped_overlap,
    }
