"""
STRIKE Red Team Simulation Router — Production
Integrates with the adversary_engine for real MITRE ATT&CK technique execution.
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timezone
import asyncio
from sqlalchemy.orm import Session
from services.database import get_db
from models import StrikeAuthorization, StrikeSimulation
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user, require_role
from services.adversary_engine import run_adversary_emulation, TECHNIQUE_HANDLERS
import ipaddress
import socket

from services.entitlements import require_module

router = APIRouter(dependencies=[Depends(require_module("STRIKE"))])

# ── SSRF Protection ──────────────────────────────────────────────────────────

def _is_blocked_target(host: str) -> bool:
    # Strip brackets if IPv6
    clean_host = host.replace("[", "").replace("]", "")
    
    def is_blocked_ip(ip_obj) -> bool:
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
            return True
        if getattr(ip_obj, "ipv4_mapped", None):
            mapped = ip_obj.ipv4_mapped
            if mapped.is_private or mapped.is_loopback or mapped.is_link_local:
                return True
        return False

    try:
        raw_ip = ipaddress.ip_address(clean_host)
        if is_blocked_ip(raw_ip):
            return True
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in resolved:
            ip = ipaddress.ip_address(sockaddr[0])
            if is_blocked_ip(ip):
                return True
    except (socket.gaierror, ValueError):
        return True
    return False

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
    adapter: str = "adversary_engine"

class QuickScanRequest(BaseModel):
    target: str  # Domain or IP
    rules_of_engagement: str = "non-destructive"

# ── MITRE ATT&CK Matrix (updated dynamically based on results) ───────────────

BASE_MITRE_TECHNIQUES = {
    "Reconnaissance": [
        {"id": "T1595", "name": "Active Scanning", "tested": False, "result": None},
    ],
    "Initial Access": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tested": False, "result": None},
        {"id": "T1078", "name": "Valid Accounts", "tested": False, "result": None},
        {"id": "T1133", "name": "External Remote Services", "tested": False, "result": None},
        {"id": "T1566", "name": "Phishing", "tested": False, "result": None},
        {"id": "T1195", "name": "Supply Chain Compromise", "tested": False, "result": None},
        {"id": "T1189", "name": "Drive-by Compromise", "tested": False, "result": None},
    ],
    "Execution": [
        {"id": "T1059", "name": "Command & Scripting Interpreter", "tested": False, "result": None},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tested": False, "result": None},
        {"id": "T1047", "name": "Windows Management Instrumentation", "tested": False, "result": None},
        {"id": "T1053", "name": "Scheduled Task/Job", "tested": False, "result": None},
        {"id": "T1204", "name": "User Execution", "tested": False, "result": None},
        {"id": "T1569", "name": "System Services", "tested": False, "result": None},
    ],
    "Discovery": [
        {"id": "T1046", "name": "Network Service Scanning", "tested": False, "result": None},
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
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tested": False, "result": None},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tested": False, "result": None},
        {"id": "T1134", "name": "Access Token Manipulation", "tested": False, "result": None},
        {"id": "T1574", "name": "Hijack Execution Flow", "tested": False, "result": None},
        {"id": "T1055", "name": "Process Injection", "tested": False, "result": None},
    ],
    "Defense Evasion": [
        {"id": "T1070", "name": "Indicator Removal", "tested": False, "result": None},
        {"id": "T1036", "name": "Masquerading", "tested": False, "result": None},
        {"id": "T1027", "name": "Obfuscated Files or Information", "tested": False, "result": None},
        {"id": "T1562", "name": "Impair Defenses", "tested": False, "result": None},
        {"id": "T1112", "name": "Modify Registry", "tested": False, "result": None},
        {"id": "T1218", "name": "System Binary Proxy Execution", "tested": False, "result": None},
    ],
}

def _build_matrix_with_results(db: Session) -> dict:
    """Build the MITRE matrix overlaid with actual simulation results."""
    import copy
    matrix = copy.deepcopy(BASE_MITRE_TECHNIQUES)

    # Get all completed simulations
    sims = db.query(StrikeSimulation).filter(
        StrikeSimulation.status == "completed"
    ).order_by(StrikeSimulation.completed_at.desc()).all()

    # Build a map of technique_id -> latest result
    technique_results = {}
    for sim in sims:
        if sim.results:
            for r in sim.results:
                tid = r.get("technique_id") or r.get("technique", "")
                if tid and tid not in technique_results:
                    technique_results[tid] = r

    # Overlay results onto matrix
    for tactic, techniques in matrix.items():
        for tech in techniques:
            if tech["id"] in technique_results:
                result_data = technique_results[tech["id"]]
                tech["tested"] = True
                tech["result"] = result_data.get("result", "tested")
                tech["evidence"] = result_data.get("evidence", "")
                tech["confidence"] = result_data.get("confidence", 0.0)
                tech["details"] = result_data.get("details", [])

    return matrix


def seed_strike_data(db: Session):
    """Seed demo authorization if DB is empty."""
    if db.query(StrikeAuthorization).count() > 0:
        return

    auth = StrikeAuthorization(
        id="AUTH-001", target_name="scanme.nmap.org", target_ip="45.33.32.156",
        techniques=["T1190", "T1078", "T1059", "T1068", "T1562"],
        rules_of_engagement="non-destructive",
        authorized_by="sherie@tempris.com",
        scope_notes="Public Nmap test target — authorized for scanning",
        status="signed", created_at=datetime.fromisoformat("2026-05-28T10:30:00")
    )
    db.add(auth)
    db.commit()
    print("STRIKE: Seeded demo authorization for scanme.nmap.org.")


# ── API Endpoints ────────────────────────────────────────────────────────────

@router.get("/matrix")
def get_mitre_matrix(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Return the MITRE ATT&CK matrix overlaid with real simulation results."""
    return _build_matrix_with_results(db)


@router.get("/techniques")
def get_available_techniques(user=Depends(get_current_user)):
    """Return technique IDs that the adversary engine can actually execute."""
    return {
        "available": list(TECHNIQUE_HANDLERS.keys()),
        "descriptions": {
            "T1595": "Active Scanning — DNS + HTTP reconnaissance",
            "T1046": "Network Service Scanning — Nmap port/service discovery",
            "T1190": "Exploit Public-Facing App — Nuclei CVE template scanning",
            "T1078": "Valid Accounts — SSH/FTP default credential testing",
            "T1059": "Command Injection — HTTP parameter injection testing",
            "T1068": "Privilege Escalation — Exposed admin/debug endpoint detection",
            "T1562": "Impair Defenses — Security header & TLS analysis",
        }
    }


@router.get("/authorizations")
def get_authorizations(db: Session = Depends(get_db), user=Depends(get_current_user)):
    auths = db.query(StrikeAuthorization).order_by(StrikeAuthorization.created_at.desc()).all()
    return [{
        "id": a.id, "target_name": a.target_name, "target_ip": a.target_ip,
        "techniques": a.techniques, "rules_of_engagement": a.rules_of_engagement,
        "authorized_by": a.authorized_by, "scope_notes": a.scope_notes,
        "status": a.status, "created_at": a.created_at.isoformat() if a.created_at else ""
    } for a in auths]


@router.post("/authorizations")
def create_authorization(
    req: AuthorizationRequest,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    count = db.query(StrikeAuthorization).count()
    auth_id = f"AUTH-{1000 + count}"
    auth = StrikeAuthorization(
        id=auth_id, target_name=req.target_name, target_ip=req.target_ip,
        techniques=req.techniques, rules_of_engagement=req.rules_of_engagement,
        authorized_by=req.authorized_by, scope_notes=req.scope_notes, status="pending"
    )
    db.add(auth)
    db.commit()
    user_email = user.get("sub", "unknown")
    append_to_audit_log(AuditEntry(
        user=user_email, action="STRIKE_AUTH_CREATED", module="STRIKE",
        detail=f"Authorization {auth_id} created for {req.target_name} ({req.target_ip})"
    ))
    return {"id": auth_id, "status": "pending", "target_name": req.target_name}


@router.post("/authorizations/{auth_id}/sign")
def sign_authorization(
    auth_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin"))
):
    auth = db.query(StrikeAuthorization).filter(StrikeAuthorization.id == auth_id).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Authorization not found")
    if auth.status != "pending":
        raise HTTPException(status_code=400, detail="Authorization already processed")
    user_email = user.get("sub", "unknown")
    auth.status = "signed"
    auth.signed_at = datetime.now(timezone.utc)
    db.commit()
    append_to_audit_log(AuditEntry(
        user=user_email, action="STRIKE_AUTH_SIGNED", module="STRIKE",
        detail=f"Authorization {auth_id} signed for {auth.target_name} by {user_email}."
    ))
    return {"status": "signed", "message": f"Authorization {auth_id} signed."}


@router.get("/simulations")
def get_simulations(db: Session = Depends(get_db), user=Depends(get_current_user)):
    sims = db.query(StrikeSimulation).order_by(StrikeSimulation.started_at.desc()).all()
    return [{
        "id": s.id, "authorization_id": s.authorization_id, "adapter": s.adapter,
        "status": s.status, "techniques_tested": s.techniques_tested,
        "results": s.results,
        "started_at": s.started_at.isoformat() if s.started_at else "",
        "completed_at": s.completed_at.isoformat() if s.completed_at else ""
    } for s in sims]


@router.post("/simulations")
async def run_simulation(
    req: SimulationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin"))
):
    """Execute a real adversary emulation campaign against the authorized target."""
    auth = db.query(StrikeAuthorization).filter(
        StrikeAuthorization.id == req.authorization_id
    ).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Authorization not found")
    if auth.status != "signed":
        raise HTTPException(
            status_code=403,
            detail="STRIKE cannot run without a signed authorization."
        )

    # SSRF protection
    host = auth.target_ip or auth.target_name
    host_clean = host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if _is_blocked_target(host_clean):
        raise HTTPException(
            status_code=403,
            detail="Scanning internal, private, or link-local targets is prohibited."
        )

    user_email = user.get("sub", "unknown")
    count = db.query(StrikeSimulation).count()
    sim_id = f"SIM-{1000 + count}"

    # Create simulation record as "running"
    sim = StrikeSimulation(
        id=sim_id, authorization_id=req.authorization_id,
        adapter="adversary_engine",
        status="running", techniques_tested=auth.techniques,
        results=[], started_at=datetime.now(timezone.utc)
    )
    db.add(sim)
    db.commit()

    # Determine target URL
    target = auth.target_name
    if not target.startswith("http"):
        target = f"http://{target}"

    # Run the real adversary emulation
    try:
        emulation_result = await run_adversary_emulation(
            target=target,
            techniques=auth.techniques,
            rules_of_engagement=auth.rules_of_engagement,
        )

        sim.status = "completed"
        sim.completed_at = datetime.now(timezone.utc)
        sim.results = emulation_result["results"]
        sim.techniques_tested = [r["technique_id"] for r in emulation_result["results"]]
        db.commit()

        # Audit log
        client_ip = request.client.host if request.client else None
        append_to_audit_log(AuditEntry(
            user=user_email, action="STRIKE_SIMULATION_COMPLETED", module="STRIKE",
            detail=(
                f"Simulation {sim_id} completed against {auth.target_name}: "
                f"{emulation_result['exploitable']} exploitable, "
                f"{emulation_result['blocked']} blocked, "
                f"{emulation_result['techniques_tested']} techniques tested "
                f"({emulation_result['duration_ms']}ms)"
            ),
            ip_address=client_ip
        ))

        return {
            "id": sim_id,
            "status": "completed",
            "target": auth.target_name,
            "duration_ms": emulation_result["duration_ms"],
            "techniques_tested": emulation_result["techniques_tested"],
            "exploitable": emulation_result["exploitable"],
            "blocked": emulation_result["blocked"],
            "results": emulation_result["results"],
            "message": (
                f"Adversary emulation completed: {emulation_result['exploitable']} exploitable, "
                f"{emulation_result['blocked']} blocked out of "
                f"{emulation_result['techniques_tested']} techniques."
            )
        }

    except Exception as e:
        sim.status = "failed"
        sim.completed_at = datetime.now(timezone.utc)
        sim.results = [{"error": str(e)}]
        db.commit()
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)[:200]}")


@router.get("/simulations/{sim_id}")
def get_simulation_status(sim_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Poll a specific simulation's status and results."""
    sim = db.query(StrikeSimulation).filter(StrikeSimulation.id == sim_id).first()
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    auth = db.query(StrikeAuthorization).filter(StrikeAuthorization.id == sim.authorization_id).first()
    exploitable = len([r for r in (sim.results or []) if r.get("result") == "exploitable"])
    blocked = len([r for r in (sim.results or []) if r.get("result") == "blocked"])
    return {
        "id": sim.id,
        "status": sim.status,
        "target": auth.target_name if auth else "unknown",
        "results": sim.results or [],
        "exploitable": exploitable,
        "blocked": blocked,
        "duration_ms": int((sim.completed_at - sim.started_at).total_seconds() * 1000) if sim.completed_at and sim.started_at else 0,
        "started_at": sim.started_at.isoformat() if sim.started_at else "",
        "completed_at": sim.completed_at.isoformat() if sim.completed_at else "",
    }


async def _run_scan_background(sim_id: str, target_url: str, techniques: list, roe: str):
    """Run the adversary emulation in the background and update the DB when done."""
    from services.database import SessionLocal
    try:
        result = await run_adversary_emulation(target=target_url, techniques=techniques, rules_of_engagement=roe)
        db = SessionLocal()
        sim = db.query(StrikeSimulation).filter(StrikeSimulation.id == sim_id).first()
        if sim:
            sim.status = "completed"
            sim.completed_at = datetime.now(timezone.utc)
            sim.results = result["results"]
            sim.techniques_tested = [r["technique_id"] for r in result["results"]]
            db.commit()
        db.close()
    except Exception as e:
        db = SessionLocal()
        sim = db.query(StrikeSimulation).filter(StrikeSimulation.id == sim_id).first()
        if sim:
            sim.status = "failed"
            sim.completed_at = datetime.now(timezone.utc)
            sim.results = [{"error": str(e)}]
            db.commit()
        db.close()


@router.post("/quick-scan")
async def quick_scan(
    req: QuickScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_role("Superadmin", "Admin", "Analyst"))
):
    """One-click scan: auto-create auth + launch simulation in background."""
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required.")

    # SSRF protection
    host_clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    if _is_blocked_target(host_clean):
        raise HTTPException(status_code=403, detail="Scanning internal, private, or link-local targets is prohibited.")

    user_email = user.get("sub", "unknown")

    # Auto-create authorization
    auth_count = db.query(StrikeAuthorization).count()
    auth_id = f"AUTH-{1000 + auth_count}"
    auth = StrikeAuthorization(
        id=auth_id, target_name=target, target_ip=host_clean,
        techniques=list(TECHNIQUE_HANDLERS.keys()),
        rules_of_engagement=req.rules_of_engagement,
        authorized_by=user_email,
        scope_notes=f"Quick scan initiated by {user_email}",
        status="signed",
        signed_at=datetime.now(timezone.utc)
    )
    db.add(auth)
    db.commit()

    # Create simulation record
    sim_count = db.query(StrikeSimulation).count()
    sim_id = f"SIM-{1000 + sim_count}"
    sim = StrikeSimulation(
        id=sim_id, authorization_id=auth_id,
        adapter="adversary_engine", status="running",
        techniques_tested=list(TECHNIQUE_HANDLERS.keys()),
        results=[], started_at=datetime.now(timezone.utc)
    )
    db.add(sim)
    db.commit()

    # Build target URL
    target_url = target if target.startswith("http") else f"http://{target}"

    # Launch in background
    asyncio.create_task(_run_scan_background(sim_id, target_url, list(TECHNIQUE_HANDLERS.keys()), req.rules_of_engagement))

    append_to_audit_log(AuditEntry(
        user=user_email, action="STRIKE_QUICK_SCAN", module="STRIKE",
        detail=f"Quick scan {sim_id} launched against {target}"
    ))

    return {"sim_id": sim_id, "status": "running", "target": target, "message": f"Scan launched against {target}. Poll /api/strike/simulations/{sim_id} for results."}

