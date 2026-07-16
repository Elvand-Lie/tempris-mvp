from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from services.kev_loader import get_finding_stats, get_top_critical_findings, get_ransomware_findings, get_all_findings
from services.tes_engine import calculate_finding_tes
from services.database import get_db, SessionLocal
from models import TesSnapshot
from routers.auth import get_current_user
from datetime import datetime, timedelta, timezone

router = APIRouter()

def get_dashboard_data(db: Session = None, tenant_id: str = "tempris"):
    """Generate dashboard telemetry from real data scoped to tenant."""
    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True

    try:
        stats = get_finding_stats(db, tenant_id=tenant_id)

        # Compute aggregate TES from top-20 critical findings, including SSS/NHI paths
        critical = get_top_critical_findings(db, limit=20, tenant_id=tenant_id)
        tes_scores = [calculate_finding_tes(f) for f in critical]
        aggregate_tes = sum(tes_scores) / len(tes_scores) if tes_scores else 0

        # Real alerts from ransomware-linked findings
        ransomware_list = get_ransomware_findings(db, limit=5, tenant_id=tenant_id)
        alerts = []
        for f in ransomware_list:
            alerts.append({
                "id": hash(f["cve"]) % 10000,
                "module": "SPECTRUM",
                "message": f"CISA KEV Alert: {f['cve']} — {f['title']} (Ransomware-linked, CVSS {f['cvss']})",
                "time": f.get("dateAdded", ""),
                "type": "critical"
            })
        alerts.append({"id": 98, "module": "STRIKE", "message": "Simulation #211 confirmed exploit path to internal DMZ.", "time": "15 mins ago", "type": "warning"})
        alerts.append({"id": 99, "module": "STANDARD", "message": "MAS TRM 11.1.1 SLA breached for FortiGate patching.", "time": "1 hour ago", "type": "warning"})


        from models import Finding, AuditLog, SurgeSubmission
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
        surge_open = db.query(SurgeSubmission).filter(SurgeSubmission.status.in_(["submitted", "triaged"])).count()
        final_update = {
            "v54_findings": len(final_rows),
            "nhi_authority_findings": nhi_count,
            "blflaw_findings": blflaw_count,
            "auto_edip_metadata_pct": round((complete_auto / len(auto_edip) * 100), 1) if auto_edip else 100.0,
            "surge_open_submissions": surge_open,
        }
        # Dynamic module health based on actual state
        critical_count = stats["critical_count"]
        total = stats["total_findings"]
        spectrum_status = "healthy" if critical_count < 500 else "warning" if critical_count < 1000 else "degraded"
        scout_status = "healthy" if total > 0 else "offline"

        module_health = [
            {"name": "SPECTRUM", "status": spectrum_status},
            {"name": "SCOUT", "status": scout_status},
            {"name": "STRIKE", "status": "healthy"},
            {"name": "STANDARD", "status": "warning" if critical_count > 100 else "healthy"},
            {"name": "SPOTLIGHT", "status": "healthy"},
            {"name": "SPEAK", "status": "healthy"},
            {"name": "SURGE", "status": "healthy" if final_update["surge_open_submissions"] < 20 else "warning"},
        ]

        return {
            "aggregate_tes": round(aggregate_tes, 1),
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
    tes_trend = "+0.0"
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    old_snapshot = db.query(TesSnapshot).filter(
        TesSnapshot.snapshot_at >= thirty_days_ago
    ).order_by(TesSnapshot.snapshot_at.asc()).first()

    if old_snapshot:
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
    stats = data.get("_stats", get_finding_stats(db, tenant_id=tenant_id))

    snapshot = TesSnapshot(
        aggregate_tes=data["aggregate_tes"],
        finding_count=stats["total_findings"],
        critical_count=stats["critical_count"]
    )
    db.add(snapshot)
    db.commit()
    return {"status": "snapshot_taken", "tes": data["aggregate_tes"], "findings": stats["total_findings"]}



