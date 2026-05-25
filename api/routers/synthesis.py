from fastapi import APIRouter
from services.tes_engine import calculate_tes, TESInputs
from services.kev_loader import get_all_findings
import random

router = APIRouter()

@router.get("/dashboard")
def get_dashboard_data():
    """Returns telemetry data for the main SYNTHESIS dashboard."""
    all_findings = get_all_findings()
    
    if not all_findings:
        return {"aggregate_tes": 0, "tes_trend": "0", "module_health": [], "alerts": []}
        
    # Calculate aggregate TES across top 10 critical findings
    critical_findings = [f for f in all_findings if f["priority"] == "P0"][:10]
    total_tes = 0
    for f in critical_findings:
        inputs = TESInputs(**f["raw_inputs"])
        total_tes += calculate_tes(inputs).total_score
        
    aggregate_tes = total_tes / len(critical_findings) if critical_findings else 0
    
    # Generate some alerts from the latest findings
    recent_findings = all_findings[:5]
    alerts = []
    for idx, f in enumerate(recent_findings):
        alerts.append({
            "id": idx + 1,
            "module": "SCOUT",
            "message": f"New CVE {f['cve']} detected on {f['vendor']} {f['product']}.",
            "time": "Just now",
            "type": "danger" if f["ransomware"] else "warning"
        })
    
    # Keep some mock alerts for STRIKE and STANDARD to show integration
    alerts.append({"id": 98, "module": "STRIKE", "message": "Simulation #211 confirmed exploit path to internal DMZ.", "time": "15 mins ago", "type": "warning"})
    alerts.append({"id": 99, "module": "STANDARD", "message": "MAS TRM 11.1.1 SLA breached for FortiGate patching.", "time": "1 hour ago", "type": "warning"})
    
    return {
        "aggregate_tes": round(aggregate_tes, 1),
        "tes_trend": "+1.2",
        "module_health": [
            {"name": "SPECTRUM", "status": "healthy"},
            {"name": "SCOUT", "status": "healthy"},
            {"name": "STRIKE", "status": "healthy"},
            {"name": "STANDARD", "status": "healthy"},
            {"name": "SPOTLIGHT", "status": "healthy"},
            {"name": "SPEAK", "status": "healthy"},
        ],
        "alerts": alerts
    }
