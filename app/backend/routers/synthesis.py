from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from services.kev_loader import get_finding_stats, get_top_critical_findings, get_ransomware_findings, get_all_findings
from services.database import get_db, SessionLocal
from models import TesSnapshot
from routers.auth import get_current_user
from datetime import datetime, timedelta, timezone

from services.entitlements import require_module
from services.workflow_connections import build_exposure_coverage, build_module_health

router = APIRouter(dependencies=[Depends(require_module("SYNTHESIS"))])

def get_dashboard_data(db: Session = None, tenant_id: str = "tempris"):
    """Generate dashboard telemetry from real data scoped to tenant."""
    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True

    try:
        stats = get_finding_stats(db, tenant_id=tenant_id)

        exposure = build_exposure_coverage(db, tenant_id)
        aggregate_tes = exposure["aggregate_tes"]

        # A CISA/KEV alert is customer exposure only after an explicit tenant asset link.
        ransomware_list = get_ransomware_findings(db, limit=5, tenant_id=tenant_id)
        alerts = []
        linked_kev_ids = set(exposure["asset_linked_cisa_kev_ids"])
        for f in ransomware_list:
            if f.get("id") not in linked_kev_ids:
                continue
            alerts.append({
                "id": hash(f["cve"]) % 10000,
                "module": "SPECTRUM",
                "message": f"CISA KEV Alert: {f['cve']} — {f['title']} (Ransomware-linked, CVSS {f['cvss']})",
                "time": f.get("dateAdded", ""),
                "type": "critical"
            })
        from models import Finding, AuditLog
        final_rows = db.query(Finding).filter(Finding.id >= "F-7000", Finding.id < "F-8000", Finding.tenant_id == tenant_id).all()
        nhi_count = 0
        blflaw_count = 0
        for row in final_rows:
            ftype = str((row.sss_data or {}).get("type", ""))
            if ftype.startswith("NHI"):
                nhi_count += 1
            if ftype == "BLFLAW":
                blflaw_count += 1
        auto_edip = db.query(AuditLog).filter(AuditLog.module == "EDIP", AuditLog.action.like("AUTO_%"), AuditLog.tenant_id == tenant_id).all()
        complete_auto = sum(1 for a in auto_edip if all(k in (a.metadata_ or {}) for k in ("agent_identity", "authority_granted", "tool_used", "evidence_generated", "revocation_path", "under_policy_control")))
        final_update = {
            "v54_findings": len(final_rows),
            "nhi_authority_findings": nhi_count,
            "blflaw_findings": blflaw_count,
            "auto_edip_metadata_pct": round((complete_auto / len(auto_edip) * 100), 1) if auto_edip else 100.0,
            "surge_open_submissions": None,
            "surge_scope_status": "unavailable",
        }
        module_health = build_module_health(db, tenant_id)

        return {
            "aggregate_tes": round(aggregate_tes, 1) if aggregate_tes is not None else None,
            "exposure_coverage": exposure,
            "module_health": module_health,
            "alerts": alerts,
            "final_update": final_update,
            "_stats": stats,  # pass through for snapshot
        }
    finally:
        if should_close:
            db.close()

@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), user = Depends(get_current_user)):
    tenant_id = user.get("tenant_id", "tempris")
    data = get_dashboard_data(db, tenant_id=tenant_id)

    # Compute TES trend from DB snapshots
    tes_trend = None
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    old_snapshot = db.query(TesSnapshot).filter(
        TesSnapshot.tenant_id == tenant_id,
        TesSnapshot.snapshot_at >= thirty_days_ago
    ).order_by(TesSnapshot.snapshot_at.asc()).first()

    if old_snapshot and data["aggregate_tes"] is not None:
        delta = data["aggregate_tes"] - old_snapshot.aggregate_tes
        sign = "+" if delta >= 0 else ""
        tes_trend = f"{sign}{delta:.1f}"

    data["tes_trend"] = tes_trend
    # Remove internal stats from response
    data.pop("_stats", None)
    return data

@router.post("/tes-snapshot")
def take_tes_snapshot(db: Session = Depends(get_db), user = Depends(get_current_user)):
    """Manually trigger a TES snapshot (also called on startup)."""
    tenant_id = user.get("tenant_id", "tempris")
    data = get_dashboard_data(db, tenant_id=tenant_id)
    if data["aggregate_tes"] is None:
        raise HTTPException(
            status_code=409,
            detail="TES snapshot requires at least one open finding with a valid tenant asset link and complete TES inputs",
        )
    stats = data.get("_stats", get_finding_stats(db, tenant_id=tenant_id))

    snapshot = TesSnapshot(
        tenant_id=tenant_id,
        aggregate_tes=data["aggregate_tes"],
        finding_count=stats["total_findings"],
        critical_count=stats["critical_count"]
    )
    db.add(snapshot)
    db.commit()
    return {"status": "snapshot_taken", "tes": data["aggregate_tes"], "findings": stats["total_findings"]}



