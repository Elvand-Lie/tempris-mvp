from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from sqlalchemy.orm import Session
from services.database import get_db
from models import StrikeAuthorization, StrikeSimulation
from routers.audit import append_to_audit_log, AuditEntry

router = APIRouter()

# ── Data Models ──────────────────────────────────────────────────────────────

class AuthorizationRequest(BaseModel):
    target_name: str
    target_ip: str
    techniques: List[str]
    rules_of_engagement: str
    authorized_by: str
    scope_notes: Optional[str] = ""

class SimulationRequest(BaseModel):
    authorization_id: str
    adapter: str = "caldera"

# Real MITRE ATT&CK technique subset
MITRE_TECHNIQUES = {
    "Initial Access": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tested": True, "result": "exploitable"},
        {"id": "T1078", "name": "Valid Accounts", "tested": True, "result": "blocked"},
        {"id": "T1133", "name": "External Remote Services", "tested": False, "result": None},
        {"id": "T1566", "name": "Phishing", "tested": False, "result": None},
        {"id": "T1195", "name": "Supply Chain Compromise", "tested": False, "result": None},
        {"id": "T1189", "name": "Drive-by Compromise", "tested": False, "result": None},
    ],
    "Execution": [
        {"id": "T1059", "name": "Command & Scripting Interpreter", "tested": True, "result": "blocked"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tested": False, "result": None},
        {"id": "T1047", "name": "Windows Management Instrumentation", "tested": False, "result": None},
        {"id": "T1053", "name": "Scheduled Task/Job", "tested": False, "result": None},
        {"id": "T1204", "name": "User Execution", "tested": False, "result": None},
        {"id": "T1569", "name": "System Services", "tested": False, "result": None},
    ],
    "Persistence": [
        {"id": "T1098", "name": "Account Manipulation", "tested": False, "result": None},
        {"id": "T1136", "name": "Create Account", "tested": False, "result": None},
        {"id": "T1543", "name": "Create or Modify System Process", "tested": False, "result": None},
        {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tested": False, "result": None},
        {"id": "T1505", "name": "Server Software Component", "tested": False, "result": None},
        {"id": "T1546", "name": "Event Triggered Execution", "tested": False, "result": None},
    ],
    "Privilege Escalation": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tested": True, "result": "exploitable"},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tested": False, "result": None},
        {"id": "T1134", "name": "Access Token Manipulation", "tested": False, "result": None},
        {"id": "T1574", "name": "Hijack Execution Flow", "tested": False, "result": None},
        {"id": "T1055", "name": "Process Injection", "tested": False, "result": None},
        {"id": "T1078b", "name": "Valid Accounts", "tested": False, "result": None},
    ],
    "Defense Evasion": [
        {"id": "T1070", "name": "Indicator Removal", "tested": False, "result": None},
        {"id": "T1036", "name": "Masquerading", "tested": False, "result": None},
        {"id": "T1027", "name": "Obfuscated Files or Information", "tested": False, "result": None},
        {"id": "T1562", "name": "Impair Defenses", "tested": True, "result": "blocked"},
        {"id": "T1112", "name": "Modify Registry", "tested": False, "result": None},
        {"id": "T1218", "name": "System Binary Proxy Execution", "tested": False, "result": None},
    ],
}

def seed_strike_data(db: Session):
    """Seed demo authorization + simulations if DB is empty."""
    if db.query(StrikeAuthorization).count() > 0:
        return
    
    auth = StrikeAuthorization(
        id="AUTH-001", target_name="FortiGate-01", target_ip="10.0.5.1",
        techniques=["T1190", "T1078"], rules_of_engagement="non-destructive",
        authorized_by="sherie@tempris.com", scope_notes="Perimeter firewall assessment",
        status="pending", created_at=datetime.fromisoformat("2026-05-28T10:30:00")
    )
    db.add(auth)
    
    sim1 = StrikeSimulation(
        id="SIM-210", authorization_id="AUTH-001", adapter="caldera", status="completed",
        techniques_tested=["T1190"],
        results=[{"technique": "T1190", "result": "exploitable", "evidence": "RCE confirmed via CVE-2024-53704", "impact_tes": "+0.8"}],
        started_at=datetime.fromisoformat("2026-05-28T11:00:00"),
        completed_at=datetime.fromisoformat("2026-05-28T11:15:00")
    )
    sim2 = StrikeSimulation(
        id="SIM-209", authorization_id="AUTH-001", adapter="caldera", status="completed",
        techniques_tested=["T1059"],
        results=[{"technique": "T1059", "result": "blocked", "evidence": "WAF blocked command injection attempt", "impact_tes": "0"}],
        started_at=datetime.fromisoformat("2026-05-28T09:00:00"),
        completed_at=datetime.fromisoformat("2026-05-28T09:12:00")
    )
    db.add_all([sim1, sim2])
    db.commit()
    print("STRIKE: Seeded demo authorization + 2 simulations.")

# ── API Endpoints ────────────────────────────────────────────────────────────

@router.get("/matrix")
def get_mitre_matrix():
    return MITRE_TECHNIQUES

@router.get("/authorizations")
def get_authorizations(db: Session = Depends(get_db)):
    auths = db.query(StrikeAuthorization).order_by(StrikeAuthorization.created_at.desc()).all()
    return [{
        "id": a.id, "target_name": a.target_name, "target_ip": a.target_ip,
        "techniques": a.techniques, "rules_of_engagement": a.rules_of_engagement,
        "authorized_by": a.authorized_by, "scope_notes": a.scope_notes,
        "status": a.status, "created_at": a.created_at.isoformat() if a.created_at else ""
    } for a in auths]

@router.post("/authorizations")
def create_authorization(req: AuthorizationRequest, db: Session = Depends(get_db)):
    count = db.query(StrikeAuthorization).count()
    auth_id = f"AUTH-{1000 + count}"
    auth = StrikeAuthorization(
        id=auth_id, target_name=req.target_name, target_ip=req.target_ip,
        techniques=req.techniques, rules_of_engagement=req.rules_of_engagement,
        authorized_by=req.authorized_by, scope_notes=req.scope_notes, status="pending"
    )
    db.add(auth)
    db.commit()
    append_to_audit_log(AuditEntry(
        user=req.authorized_by, action="STRIKE_AUTH_CREATED", module="STRIKE",
        detail=f"Authorization {auth_id} created for {req.target_name} ({req.target_ip})"
    ))
    return {"id": auth_id, "status": "pending", "target_name": req.target_name}

@router.post("/authorizations/{auth_id}/sign")
def sign_authorization(auth_id: str, db: Session = Depends(get_db)):
    auth = db.query(StrikeAuthorization).filter(StrikeAuthorization.id == auth_id).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Authorization not found")
    if auth.status != "pending":
        raise HTTPException(status_code=400, detail="Authorization already processed")
    auth.status = "signed"
    auth.signed_at = datetime.utcnow()
    db.commit()
    append_to_audit_log(AuditEntry(
        user=auth.authorized_by, action="STRIKE_AUTH_SIGNED", module="STRIKE",
        detail=f"Authorization {auth_id} signed for {auth.target_name}."
    ))
    return {"status": "signed", "message": f"Authorization {auth_id} signed."}

@router.get("/simulations")
def get_simulations(db: Session = Depends(get_db)):
    sims = db.query(StrikeSimulation).order_by(StrikeSimulation.started_at.desc()).all()
    return [{
        "id": s.id, "authorization_id": s.authorization_id, "adapter": s.adapter,
        "status": s.status, "techniques_tested": s.techniques_tested,
        "results": s.results,
        "started_at": s.started_at.isoformat() if s.started_at else "",
        "completed_at": s.completed_at.isoformat() if s.completed_at else ""
    } for s in sims]

@router.post("/simulations")
def run_simulation(req: SimulationRequest, db: Session = Depends(get_db)):
    auth = db.query(StrikeAuthorization).filter(StrikeAuthorization.id == req.authorization_id).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Authorization not found")
    if auth.status != "signed":
        raise HTTPException(status_code=403, detail="STRIKE cannot run without a signed authorization.")
    
    count = db.query(StrikeSimulation).count()
    sim_id = f"SIM-{211 + count}"
    sim = StrikeSimulation(
        id=sim_id, authorization_id=req.authorization_id, adapter=req.adapter,
        status="completed", techniques_tested=auth.techniques,
        results=[{"technique": t, "result": "tested", "evidence": f"Simulated via {req.adapter}", "impact_tes": "0"} for t in auth.techniques],
        started_at=datetime.utcnow(), completed_at=datetime.utcnow()
    )
    db.add(sim)
    db.commit()
    append_to_audit_log(AuditEntry(
        user=auth.authorized_by, action="STRIKE_SIMULATION_RUN", module="STRIKE",
        detail=f"Simulation {sim_id} executed via {req.adapter} against {auth.target_name}"
    ))
    return {"id": sim_id, "status": "completed", "techniques_tested": auth.techniques, "results": sim.results}
