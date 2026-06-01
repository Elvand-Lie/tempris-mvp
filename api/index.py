from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
import time
import os
import sys
from pathlib import Path

# Add the api directory to the Python path for Vercel Serverless
sys.path.append(os.path.dirname(__file__))

from routers import auth, spectrum, audit, synthesis, scout, scanner, strike, standard
from routers.audit import append_to_audit_log, AuditEntry
from services.kev_loader import load_kev_data, get_all_findings
from services.database import get_db, init_db, SessionLocal
from models import SpotlightReport, ChatSession, ChatMessage, TesSnapshot

app = FastAPI(title="Tempris Wave 1 MVP", version="1.0.0")

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(spectrum.router, prefix="/api/spectrum", tags=["spectrum"])
app.include_router(scout.router, prefix="/api/scout", tags=["scout"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(synthesis.router, prefix="/api/synthesis", tags=["synthesis"])
app.include_router(scanner.router, prefix="/api/scanner", tags=["scanner"])
app.include_router(strike.router, prefix="/api/strike", tags=["strike"])
app.include_router(standard.router, prefix="/api/standard", tags=["standard"])

# ── Startup: Init DB, Preload data, Seed ─────────────────────────────────────

@app.on_event("startup")
def startup():
    # 1. Create all tables
    init_db()
    # 2. Load KEV data into memory
    load_kev_data()
    # 3. Seed audit log + strike data
    db = SessionLocal()
    try:
        from routers.audit import seed_audit_log
        seed_audit_log(db)
        from routers.strike import seed_strike_data
        seed_strike_data(db)
        # 4. Take initial TES snapshot
        from routers.synthesis import get_dashboard_data
        data = get_dashboard_data()
        existing = db.query(TesSnapshot).count()
        if existing == 0:
            all_findings = get_all_findings()
            db.add(TesSnapshot(
                aggregate_tes=data["aggregate_tes"],
                finding_count=len(all_findings),
                critical_count=len([f for f in all_findings if f.get("priority") == "P0"])
            ))
            db.commit()
            print("DB: Initial TES snapshot recorded.")
    finally:
        db.close()

# CORS setup for Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://187.127.114.218", "https://187.127.114.218", "http://187.127.114.218:80"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware (auth=5/min, scanner=10/min, api=100/min)
from middleware.rate_limit import RateLimitMiddleware
app.add_middleware(RateLimitMiddleware)

# ── SPEAK (Chat) ─────────────────────────────────────────────────────────────

class ChatMessageReq(BaseModel):
    message: str
    session_id: int | None = None

class ChatResponse(BaseModel):
    response: str
    sources: list[str] | None = None
    session_id: int | None = None

@app.get("/api/health")
def read_root():
    return {"status": "Tempris API running"}

@app.get("/api/speak/history")
def get_chat_history(session_id: int | None = None, db: Session = Depends(get_db)):
    """Return chat history for a session, or latest session if none specified."""
    if session_id:
        session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
    else:
        session = db.query(ChatSession).order_by(ChatSession.created_at.desc()).first()
    
    if not session:
        return {"session_id": None, "messages": []}
    
    messages = db.query(ChatMessage).filter(
        ChatMessage.session_id == session.id
    ).order_by(ChatMessage.created_at.asc()).all()
    
    return {
        "session_id": session.id,
        "messages": [{"role": m.role, "content": m.content} for m in messages]
    }

@app.post("/api/speak/chat", response_model=ChatResponse)
def speak_chat(chat: ChatMessageReq, db: Session = Depends(get_db)):
    """AI Chatbot Endpoint (SPEAK Module) with chat persistence."""
    # Get or create session
    if chat.session_id:
        session = db.query(ChatSession).filter(ChatSession.id == chat.session_id).first()
    else:
        session = db.query(ChatSession).order_by(ChatSession.created_at.desc()).first()
    
    if not session:
        session = ChatSession(user_email="Current User")
        db.add(session)
        db.commit()
        db.refresh(session)
    
    # Save user message
    db.add(ChatMessage(session_id=session.id, role="user", content=chat.message))
    db.commit()
    
    # Build context
    all_findings = get_all_findings()
    total = len(all_findings)
    ransomware_findings = [f for f in all_findings if f.get("ransomware")]
    critical_findings = [f for f in all_findings if f.get("priority") == "P0"]
    top_finding = ransomware_findings[0] if ransomware_findings else (all_findings[0] if all_findings else None)
    
    stats = {
        "total": total,
        "ransomware": len(ransomware_findings),
        "critical": len(critical_findings),
        "top_cve": top_finding
    }

    from routers.synthesis import get_dashboard_data
    dashboard = get_dashboard_data()
    tes_score = dashboard.get("aggregate_tes", 0)
    alerts_text = "\n".join([f"- {a['module']}: {a['message']}" for a in dashboard.get("alerts", [])])
    
    # Enhanced context-stuffing RAG: keyword match relevant findings
    query_lower = chat.message.lower()
    relevant_findings = []
    for f in all_findings[:500]:
        cve = (f.get("cve") or "").lower()
        vendor = (f.get("vendor") or "").lower()
        title = (f.get("title") or "").lower()
        if any(term in query_lower for term in [cve, vendor] if term and len(term) > 3):
            relevant_findings.append(f)
        elif any(word in title for word in query_lower.split() if len(word) > 4):
            relevant_findings.append(f)
    
    relevant_text = ""
    if relevant_findings:
        relevant_text = "\n\nRelevant findings matching your query:\n"
        for rf in relevant_findings[:5]:
            relevant_text += f"- {rf['cve']}: {rf['title']} (Vendor: {rf['vendor']}, CVSS: {rf['cvss']}, Ransomware: {rf.get('ransomware', False)})\n"

    # Load recent audit logs from DB
    audit_logs = db.query(__import__('models').AuditLog).order_by(
        __import__('models').AuditLog.timestamp.desc()
    ).limit(5).all()
    audit_summary = "\n".join([f"- {log.module}: {log.action} - {log.detail}" for log in audit_logs])

    system_prompt = f"""You are SPEAK, the Tempris AI Security Assistant.
You have access to real-time CISA KEV vulnerability data, your organization's Tempris Exposure Score (TES), and TACF audit logs for compliance tracking.
- Overall TES Score: {tes_score} (Critical if > 8.0)
- Total CVEs monitored: {stats['total']}
- Ransomware-linked: {stats['ransomware']}  
- Critical (P0): {stats['critical']}
- Top threat: {stats['top_cve']['cve'] if stats['top_cve'] else 'N/A'} — {stats['top_cve']['title'] if stats['top_cve'] else 'N/A'}

Recent Alerts:
{alerts_text}

Recent TACF Audit Logs:
{audit_summary}
{relevant_text}
Answer security questions using this data. Be concise, professional, and reference specific CVEs, TES scores, or MAS TRM compliance events when relevant."""

    try:
        from services.llm_client import chat_completion
        response = chat_completion(system_prompt, chat.message)
        # Save AI response
        db.add(ChatMessage(session_id=session.id, role="assistant", content=response))
        db.commit()
        append_to_audit_log(AuditEntry(
            user="Current User", action="SPEAK_AI_CALL", module="SPEAK",
            detail=f"AI query: '{chat.message[:80]}' — responded successfully"
        ))
        return {"response": response, "sources": ["CISA KEV Catalog", "FreeLLMAPI"], "session_id": session.id}
    except Exception as e:
        print(f"FreeLLMAPI Error: {e}")
        query = chat.message.lower()
        if "ransomware exposure" in query or "ransomware" in query:
            rw_count = len(ransomware_findings)
            top_cve = top_finding["cve"] if top_finding else "N/A"
            top_title = top_finding["title"] if top_finding else "N/A"
            top_vendor = top_finding["vendor"] if top_finding else "N/A"
            top_cvss = top_finding["cvss"] if top_finding else 0
            fallback = f"Based on our CISA KEV intelligence feed, your environment has **{rw_count} ransomware-linked vulnerabilities** out of {total} total known exploited CVEs. The most critical is **{top_cve}** ({top_title}) affecting {top_vendor} with a CVSS of **{top_cvss}**. I recommend using the EDIP decision engine in SPECTRUM to triage and assign mitigation ownership for these high-risk findings."
        else:
            fallback = f"I am currently tracking {total} known exploited vulnerabilities from the CISA KEV catalog, with {len(critical_findings)} at critical priority (P0) and {len(ransomware_findings)} linked to active ransomware campaigns. The overall Tempris Exposure Score is {tes_score:.1f}, which places the organization in a Critical risk posture. How can I help you assess your exposure?"
        
        # Save fallback response too
        db.add(ChatMessage(session_id=session.id, role="assistant", content=fallback))
        db.commit()
        return {"response": fallback, "sources": ["CISA KEV Catalog"], "session_id": session.id}

# ── SPOTLIGHT (Reports) ──────────────────────────────────────────────────────

class SpotlightRequest(BaseModel):
    report_type: str = "executive"

@app.post("/api/spotlight/generate")
def generate_spotlight_report(req: SpotlightRequest = SpotlightRequest(), db: Session = Depends(get_db)):
    """Generate AI board narrative and persist to DB."""
    all_findings = get_all_findings()
    total = len(all_findings)
    ransomware = len([f for f in all_findings if f.get("ransomware")])
    critical = len([f for f in all_findings if f.get("priority") == "P0"])

    from routers.synthesis import get_dashboard_data
    dashboard = get_dashboard_data()
    tes_score = dashboard.get("aggregate_tes", 0)
    alerts_text = "\n".join([f"- {a['module']}: {a['message']}" for a in dashboard.get("alerts", [])])
    
    audit_logs = db.query(__import__('models').AuditLog).order_by(
        __import__('models').AuditLog.timestamp.desc()
    ).limit(10).all()
    audit_summary = "\n".join([f"- {log.module}: {log.action} - {log.detail}" for log in audit_logs])

    base_context = f"""Data:
- Tempris Exposure Score (TES): {tes_score}
- {total} total known exploited vulnerabilities (CISA KEV)
- {critical} critical (P0) vulnerabilities
- {ransomware} ransomware-linked vulnerabilities

Recent Alerts:
{alerts_text}

TACF Audit Logs:
{audit_summary}"""

    report_prompts = {
        "executive": f"""You are SPOTLIGHT, the Tempris executive reporting engine.
Generate a board-level executive summary. Focus on business risk, strategic posture, and recommended actions.
Use 3 paragraphs: current posture, top 3 risks, and recommended next steps.
{base_context}""",
        "ciso": f"""You are SPOTLIGHT generating a CISO Technical Summary.
Focus on technical risk details: specific CVEs, exploit chains, attack surface analysis, and prioritized remediation.
{base_context}""",
        "compliance": f"""You are SPOTLIGHT generating a Compliance Audit Report.
Focus on regulatory compliance gaps: MAS TRM, PDPA, IM8A, ISO 27001.
{base_context}""",
        "insurance": f"""You are SPOTLIGHT generating a Cyber Insurance Risk Assessment.
Focus on risk quantification for underwriters: exposure metrics, ransomware probability, remediation timeline.
{base_context}"""
    }

    system_prompt = report_prompts.get(req.report_type, report_prompts["executive"])

    try:
        from services.llm_client import chat_completion
        response = chat_completion(system_prompt, "Generate the latest executive cybersecurity briefing.")
        narrative = response
        model = "FreeLLMAPI Route"
    except Exception as e:
        print(f"FreeLLMAPI Error: {e}")
        top_cve = [f for f in all_findings if f.get("priority") == "P0"]
        top_cve = top_cve[0] if len(top_cve) > 0 else {"cve": "N/A", "title": "N/A", "vendor": "N/A", "product": "N/A", "cvss": 0.0}
        
        narrative = f"""As of today, the organization's Tempris Exposure Score (TES) stands at {tes_score:.1f} (Critical). This score is calculated across {total:,} known exploited vulnerabilities tracked by the US Cybersecurity & Infrastructure Security Agency (CISA). Of these, {ransomware} have confirmed ties to active ransomware campaigns, and {critical} are classified as P0 (critical priority).

The primary driver of elevated risk is {top_cve.get('cve', 'N/A')} — {top_cve.get('title', 'N/A')}, affecting {top_cve.get('vendor', 'N/A')}. This vulnerability carries a CVSS score of {top_cve.get('cvss', 0.0):.1f} and has been linked to known ransomware operations.

Recommended Action: Immediate prioritization of all CISA KEV-listed vulnerabilities with confirmed ransomware ties. The EDIP decision engine within SPECTRUM should be used to triage and assign mitigation ownership."""
        model = "offline"

    # Persist report to DB
    report = SpotlightReport(
        report_type=req.report_type, narrative=narrative,
        tes_score=tes_score, metadata_={"model": model},
        generated_by="Current User"
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    append_to_audit_log(AuditEntry(
        user="Current User", action="SPOTLIGHT_REPORT_GENERATED", module="SPOTLIGHT",
        detail=f"AI {req.report_type} report generated. TES: {tes_score}, Findings: {total}"
    ))

    return {"ai_narrative": narrative, "metadata": {"model": model}, "report_id": report.id}

@app.get("/api/spotlight/history")
def get_spotlight_history(db: Session = Depends(get_db)):
    """Return all previously generated reports from DB."""
    reports = db.query(SpotlightReport).order_by(SpotlightReport.generated_at.desc()).limit(20).all()
    return [{
        "id": r.id,
        "report_type": r.report_type,
        "tes_score": r.tes_score,
        "narrative": r.narrative[:200] + "..." if len(r.narrative) > 200 else r.narrative,
        "full_narrative": r.narrative,
        "generated_at": r.generated_at.isoformat() if r.generated_at else "",
        "generated_by": r.generated_by,
        "metadata": r.metadata_
    } for r in reports]

# --- Serve React SPA (production VPS only) ---
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
# Also check Docker-mounted path
if not FRONTEND_DIR.exists():
    FRONTEND_DIR = Path("/frontend")
if FRONTEND_DIR.exists():
    # Serve static assets (JS, CSS, images)
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR / "assets")), name="static_assets")

    # Serve root as SPA index
    @app.get("/")
    async def serve_root():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    # Catch-all: serve index.html for any non-API route (SPA client-side routing)
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api"):
            raise HTTPException(status_code=404, detail="Not found")
        file_path = FRONTEND_DIR / full_path
        if file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_DIR / "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)
