from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
import time
import os
import sys
import logging
from pathlib import Path

# M-02: Centralized structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("tempris")

# Add the api directory to the Python path for Vercel Serverless
sys.path.append(os.path.dirname(__file__))

from routers import auth, spectrum, audit, synthesis, scout, scanner, strike, standard, assets, grc
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user
from services.kev_loader import load_kev_data, get_all_findings
from services.database import get_db, init_db, SessionLocal
from models import SpotlightReport, ChatSession, ChatMessage, TesSnapshot

app = FastAPI(title="Tempris Wave 1 MVP", version="2.0.0", docs_url=None, redoc_url=None, openapi_url=None)

# ── Register all routers ──────────────────────────────────────────────────────

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(spectrum.router, prefix="/api/spectrum", tags=["spectrum"])
app.include_router(scout.router, prefix="/api/scout", tags=["scout"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(synthesis.router, prefix="/api/synthesis", tags=["synthesis"])
app.include_router(scanner.router, prefix="/api/scanner", tags=["scanner"])
app.include_router(strike.router, prefix="/api/strike", tags=["strike"])
app.include_router(standard.router, prefix="/api/standard", tags=["standard"])
app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(grc.router, prefix="/api/grc", tags=["grc"])

# ── Startup: Init DB, Preload data, Seed ─────────────────────────────────────

@app.on_event("startup")
def startup():
    # 1. Create all tables
    init_db()
    # 2. Seed assets FIRST (before KEV so vendor→asset mapping works)
    db = SessionLocal()
    try:
        from services.asset_seeder import seed_assets
        seed_assets(db)
    finally:
        db.close()
    # 3. Load KEV data into memory (uses asset map for vendor+product matching)
    load_kev_data()
    # 4. Seed audit log + strike data
    db = SessionLocal()
    try:
        from routers.audit import seed_audit_log
        seed_audit_log(db)
        from routers.strike import seed_strike_data
        seed_strike_data(db)
        # 5. Take initial TES snapshot
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
            logger.info("Initial TES snapshot recorded.")
    finally:
        db.close()
    # 6. Sync RAG knowledge base
    db = SessionLocal()
    try:
        from services.rag_engine import sync_knowledge_base
        sync_knowledge_base(db)
    except Exception as e:
        logger.warning(f"RAG knowledge sync failed (non-fatal): {e}")
    finally:
        db.close()

# H-06: CORS — configurable via env, no wildcard in production
allowed_origins = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:5174,http://187.127.114.218,https://187.127.114.218,http://187.127.114.218:80"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# Rate limiting middleware (auth=5/min, scanner=10/min, api=100/min)
from middleware.rate_limit import RateLimitMiddleware
app.add_middleware(RateLimitMiddleware)

# ── Security Headers Middleware (H-09) ────────────────────────────────────────

from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        # H-10: Strip server fingerprint headers to block reconnaissance
        if "server" in response.headers:
            del response.headers["server"]
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        if os.environ.get("ENABLE_HSTS", "false").lower() == "true":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ── SPEAK (Chat) ─────────────────────────────────────────────────────────────

class ChatMessageReq(BaseModel):
    message: str = Field(..., max_length=2000)
    session_id: int | None = None

class ChatResponse(BaseModel):
    response: str
    sources: list[str] | None = None
    session_id: int | None = None

@app.get("/api/health")
def read_root():
    return {"status": "Tempris API running"}

@app.get("/api/speak/history")
def get_chat_history(
    session_id: int | None = None,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Return chat history for a session, or latest session if none specified."""
    user_email = user.get("sub", "Current User")
    
    if session_id:
        session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
        if session and session.user_email != user_email:
            raise HTTPException(status_code=403, detail="Not authorized to access this session")
    else:
        session = db.query(ChatSession).filter(ChatSession.user_email == user_email).order_by(ChatSession.created_at.desc()).first()
    
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
def speak_chat(
    chat: ChatMessageReq,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """AI Chatbot Endpoint (SPEAK Module) with full platform awareness."""
    user_email = user.get("sub", "Current User")
    
    # Get or create session
    if chat.session_id:
        session = db.query(ChatSession).filter(ChatSession.id == chat.session_id).first()
        if session and session.user_email != user_email:
            raise HTTPException(status_code=403, detail="Not authorized to access this session")
    else:
        session = db.query(ChatSession).filter(ChatSession.user_email == user_email).order_by(ChatSession.created_at.desc()).first()
    
    if not session:
        session = ChatSession(user_email=user_email)
        db.add(session)
        db.commit()
        db.refresh(session)
    
    # Save user message
    db.add(ChatMessage(session_id=session.id, role="user", content=chat.message))
    db.commit()
    
    # RAG: Retrieve semantically relevant knowledge chunks
    from services.ai_context import build_full_context, build_speak_system_prompt, retrieve_rag_context
    ctx = build_full_context(db)
    context_text = ctx["full_text"]
    structured = ctx["structured"]
    all_findings = structured.get("all_findings", [])
    
    # Semantic search via vector DB
    rag_text = retrieve_rag_context(chat.message, n_results=5)
    
    # Enhanced RAG: keyword match relevant findings from KEV data
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

    system_prompt = build_speak_system_prompt(context_text, relevant_text, rag_text)

    # Load chat history for context
    db_history = db.query(ChatMessage).filter(
        ChatMessage.session_id == session.id
    ).order_by(ChatMessage.created_at.asc()).all()
    history_messages = [{"role": m.role, "content": m.content} for m in db_history[:-1]]

    try:
        from services.llm_client import chat_completion
        response = chat_completion(system_prompt, chat.message, history=history_messages[-10:])
        db.add(ChatMessage(session_id=session.id, role="assistant", content=response))
        db.commit()
        append_to_audit_log(AuditEntry(
            user=user_email, action="SPEAK_AI_CALL", module="SPEAK",
            detail=f"AI query: '{chat.message[:80]}' — responded successfully"
        ))
        return {"response": response, "sources": ["CISA KEV Catalog", "FreeLLMAPI", "All Modules"], "session_id": session.id}
    except Exception as e:
        logger.warning(f"FreeLLMAPI Error: {e}")
        
        # Data-aware fallback responses using structured context
        tes_score = structured.get("tes_score", 0)
        kev_total = structured.get("kev_total", 0)
        kev_critical = structured.get("kev_critical", 0)
        kev_ransomware = structured.get("kev_ransomware", 0)
        asset_count = structured.get("asset_count", 0)
        strike_exploitable = structured.get("strike_exploitable", 0)
        compliance_gaps = structured.get("compliance_gaps", [])
        
        if "asset" in query_lower or "inventory" in query_lower:
            by_type = structured.get("assets_by_type", {})
            critical_assets = structured.get("critical_assets", [])
            type_text = ", ".join([f"{k}: {v}" for k, v in by_type.items()])
            asset_lines = "\n".join([f"- **{a['id']}**: {a['name']} ({a['type']}) — IP: {a.get('ip', 'N/A')}" for a in critical_assets[:5]])
            fallback = f"Your asset inventory contains **{asset_count} active assets** ({type_text}). Here are the critical-rated assets:\n\n{asset_lines}\n\nUse the Asset Inventory module for full details, or ask me about a specific asset."
        elif "strike" in query_lower or "simulation" in query_lower or "red team" in query_lower:
            sim_id = structured.get("strike_sim_id")
            if sim_id:
                blocked = structured.get("strike_blocked", 0)
                results = structured.get("strike_results", [])
                technique_text = "\n".join([f"- **{r.get('technique_id')}** ({r.get('technique_name')}): {r.get('result')}" for r in results[:5]])
                fallback = f"Latest STRIKE simulation **{sim_id}** against {structured.get('strike_target', 'target')}: **{strike_exploitable} exploitable**, {blocked} blocked.\n\n{technique_text}\n\nRecommendation: Address exploitable techniques immediately via the EDIP decision engine."
            else:
                fallback = "No STRIKE adversary simulations have been run yet. Navigate to the STRIKE module to authorize and execute an adversary emulation campaign."
        elif "compliance" in query_lower or "framework" in query_lower or "regulation" in query_lower or "mas" in query_lower:
            total_controls = structured.get("compliance_total_controls", 0)
            compliant = structured.get("compliance_compliant", 0)
            non_compliant = structured.get("compliance_non_compliant", 0)
            gaps_text = "\n".join([f"- ⚠ {g}" for g in compliance_gaps[:5]])
            fallback = f"Across **8 regulatory frameworks**, you have **{compliant}/{total_controls} controls compliant** with **{non_compliant} non-compliant**.\n\nNon-compliant controls:\n{gaps_text}\n\nRemediation priority: Focus on MAS TRM 11.1.1 (patching) and IM8A AM-3 (patch management) which carry regulatory penalties."
        elif "grc" in query_lower or "iso 42001" in query_lower or "ai governance" in query_lower:
            grc = structured.get("grc_tes", {})
            fallback = f"**ISO/IEC 42001:2023 AI Governance Status**:\n- Composite TES: **{grc.get('score', 'N/A')}** ({grc.get('band', 'N/A')})\n- AGM (AI Governance Modifier): {grc.get('agm', 'N/A')}\n- DRF (Data Readiness Factor): {grc.get('drf', 'N/A')}\n- TEF (Third-party Exposure Factor): {grc.get('tef', 'N/A')}\n\nNavigate to the GRC module for per-control sign-off status and SOP management."
        elif "ransomware" in query_lower:
            top5 = structured.get("kev_top5", [])
            top_text = "\n".join([f"- **{f['cve']}**: {f['title']} (CVSS: {f.get('cvss',0)})" for f in top5[:3]])
            fallback = f"Your environment has **{kev_ransomware} ransomware-linked vulnerabilities** out of {kev_total} total KEV findings. Top threats:\n\n{top_text}\n\nRecommendation: Use SPECTRUM's EDIP engine to triage these findings and assign mitigation ownership."
        elif "edip" in query_lower or "decision" in query_lower:
            edip = structured.get("edip_recent", [])
            if edip:
                edip_text = "\n".join([f"- {d['cve']}: **{d['decision'].upper()}** by {d.get('by', 'auto')}" for d in edip[:5]])
                fallback = f"Recent EDIP exposure decisions:\n\n{edip_text}\n\nUse the SPECTRUM module to make new EDIP decisions for untriaged findings."
            else:
                fallback = "No EDIP decisions have been recorded yet. Navigate to SPECTRUM to begin triaging findings through the Escalate/Defer/Investigate/Patch workflow."
        else:
            fallback = f"I'm tracking **{kev_total:,} known exploited vulnerabilities** ({kev_critical} critical, {kev_ransomware} ransomware-linked). TES is **{tes_score:.1f}** (Critical). You have **{asset_count} managed assets**, **{len(compliance_gaps)} compliance gaps**, and STRIKE found **{strike_exploitable} exploitable techniques**. How can I help you assess your exposure?"
        
        db.add(ChatMessage(session_id=session.id, role="assistant", content=fallback))
        db.commit()
        return {"response": fallback, "sources": ["CISA KEV Catalog", "Platform Data"], "session_id": session.id}

# ── SPOTLIGHT (Reports) ──────────────────────────────────────────────────────

class SpotlightRequest(BaseModel):
    report_type: str = "executive"
    custom_focus: str = ""  # Optional: user-provided focus area for the AI

# Default RAG queries per report type (used when no custom focus is provided)
_SPOTLIGHT_RAG_QUERIES = {
    "executive": "executive cybersecurity risk posture board summary",
    "ciso": "technical vulnerability assessment CISA KEV threat landscape",
    "compliance": "regulatory compliance MAS TRM PDPA ISO 27001 IM8A controls gaps",
    "insurance": "cyber insurance risk quantification ransomware exposure",
}

@app.post("/api/spotlight/generate")
def generate_spotlight_report(
    req: SpotlightRequest = SpotlightRequest(),
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Generate AI board narrative with full platform data, RAG context, and persist to DB."""
    user_email = user.get("sub", "Current User")

    # Build FULL platform context from all modules
    from services.ai_context import build_full_context, build_spotlight_prompt, retrieve_rag_context
    ctx = build_full_context(db)
    context_text = ctx["full_text"]
    structured = ctx["structured"]

    tes_score = structured.get("tes_score", 0)
    kev_total = structured.get("kev_total", 0)
    asset_count = structured.get("asset_count", 0)

    # RAG: Pull semantically relevant knowledge from vector DB
    rag_query = req.custom_focus.strip() if req.custom_focus.strip() else _SPOTLIGHT_RAG_QUERIES.get(req.report_type, "cybersecurity risk assessment")
    rag_text = retrieve_rag_context(rag_query, n_results=8)

    # Build prompt with RAG context and optional custom focus
    system_prompt = build_spotlight_prompt(context_text, req.report_type)
    if rag_text:
        system_prompt += f"\n\n{rag_text}"
    if req.custom_focus.strip():
        system_prompt += f"\n\n═══ USER FOCUS AREA ═══\nThe user has specifically requested: {req.custom_focus.strip()}\nPrioritize this area in your report while still covering all sections."

    try:
        from services.llm_client import chat_completion
        user_msg = f"Generate the latest {req.report_type} cybersecurity briefing."
        if req.custom_focus.strip():
            user_msg += f" Focus on: {req.custom_focus.strip()}"
        response = chat_completion(system_prompt, user_msg, max_tokens=2000)
        
        # Detect mock/fallback response — chat_completion silently returns SPEAK
        # chatbot canned text when LLM fails (it never raises). If we see the
        # SPEAK stub markers, discard and use our rich structured fallback instead.
        mock_markers = ["Navigate to the SPOTLIGHT module", "How can I help you today?", "What would you like to explore?"]
        if any(marker in response for marker in mock_markers):
            raise ValueError("LLM returned SPEAK mock response instead of Spotlight report")
        
        narrative = response
        model = "FreeLLMAPI Route"
    except Exception as e:
        logger.warning(f"Spotlight LLM fallback triggered: {e}")
        
        # Rich offline fallback using structured context
        kev_total = structured.get("kev_total", 0)
        kev_critical = structured.get("kev_critical", 0)
        kev_ransomware = structured.get("kev_ransomware", 0)
        asset_count = structured.get("asset_count", 0)
        top5 = structured.get("kev_top5", [])
        compliance_gaps = structured.get("compliance_gaps", [])
        strike_exploitable = structured.get("strike_exploitable", 0)
        strike_blocked = structured.get("strike_blocked", 0)
        grc = structured.get("grc_tes", {})
        compliance_compliant = structured.get("compliance_compliant", 0)
        compliance_total = structured.get("compliance_total_controls", 0)
        
        top_cve = top5[0] if top5 else {"cve": "N/A", "title": "N/A", "vendor": "N/A", "cvss": 0.0}
        
        # Build compliance gap text
        gaps_text = ""
        for g in compliance_gaps[:5]:
            gaps_text += f"\n• {g}"

        narrative = f"""## Security Posture Overview

As of today, the organization's **Tempris Exposure Score (TES)** stands at **{tes_score:.1f}** ({'Critical' if tes_score >= 7 else 'High' if tes_score >= 5 else 'Medium' if tes_score >= 3 else 'Low'}). This score is computed across **{kev_total:,} known exploited vulnerabilities** tracked by the US Cybersecurity & Infrastructure Security Agency (CISA KEV catalog). Of these, **{kev_ransomware}** have confirmed ties to active ransomware campaigns, and **{kev_critical}** are classified as P0 (critical priority).

The organization manages **{asset_count} active assets** across its infrastructure, including critical network appliances, servers, and applications.

## Key Risk Highlights

The primary driver of elevated risk is **{top_cve.get('cve', 'N/A')}** — {top_cve.get('title', 'N/A')}, affecting {top_cve.get('vendor', 'N/A')} with a CVSS score of **{top_cve.get('cvss', 0.0):.1f}**.

STRIKE adversary simulations identified **{strike_exploitable} exploitable techniques** out of {strike_exploitable + strike_blocked} tested, indicating {'significant' if strike_exploitable > 2 else 'moderate' if strike_exploitable > 0 else 'minimal'} attack surface exposure.

## Regulatory Compliance

Across 8 regulatory frameworks (MAS TRM, PDPA, ISO 27001, IM8A, NIST CSF, SOC 2, PCI DSS, CSA Cyber Trust), **{compliance_compliant}/{compliance_total} controls are compliant**. Notable gaps:{gaps_text if gaps_text else ' None identified.'}

ISO/IEC 42001:2023 AI Governance composite TES: **{grc.get('score', 'N/A')}** ({grc.get('band', 'N/A')}).

## Recommended Actions

1. **Immediate**: Prioritize all CISA KEV vulnerabilities with confirmed ransomware ties using the EDIP decision engine in SPECTRUM.
2. **Short-term**: Address non-compliant MAS TRM and IM8A controls to meet regulatory SLAs.
3. **Medium-term**: Remediate exploitable techniques identified by STRIKE simulations.
4. **Ongoing**: Complete ISO 42001 SOP sign-offs in the GRC module to improve the AI Governance Modifier (AGM)."""
        model = "offline"

    # Persist report to DB
    report = SpotlightReport(
        report_type=req.report_type, narrative=narrative,
        tes_score=tes_score, metadata_={"model": model, "custom_focus": req.custom_focus.strip() or None, "rag_chunks": bool(rag_text)},
        generated_by=user_email
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    append_to_audit_log(AuditEntry(
        user=user_email, action="SPOTLIGHT_REPORT_GENERATED", module="SPOTLIGHT",
        detail=f"AI {req.report_type} report generated. TES: {tes_score}, Findings: {kev_total}, Assets: {asset_count}" + (f" Focus: {req.custom_focus[:50]}" if req.custom_focus.strip() else "")
    ))

    return {"ai_narrative": narrative, "metadata": {"model": model}, "report_id": report.id}

@app.get("/api/spotlight/history")
def get_spotlight_history(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Return previously generated reports from DB.
    
    IDOR fix: Superadmin/Admin see all reports; other roles only see their own.
    """
    user_email = user.get("sub", "")
    user_role = user.get("role", "")
    
    query = db.query(SpotlightReport).order_by(SpotlightReport.generated_at.desc())
    
    # Non-admin users can only see their own reports
    if user_role not in ("Superadmin", "Admin"):
        query = query.filter(SpotlightReport.generated_by == user_email)
    
    reports = query.limit(20).all()
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

# ── RAG Vector Database Endpoints ─────────────────────────────────────────────

@app.get("/api/rag/stats")
def get_rag_stats(user=Depends(get_current_user)):
    """Return vector database statistics."""
    from services.rag_engine import get_stats
    return get_stats()

class RagSearchReq(BaseModel):
    query: str = Field(..., max_length=500)
    n_results: int = Field(default=5, ge=1, le=20)

@app.post("/api/rag/search")
def rag_search(req: RagSearchReq, user=Depends(get_current_user)):
    """Perform a semantic search against the knowledge base."""
    from services.rag_engine import semantic_search
    results = semantic_search(req.query, n_results=req.n_results)
    return {"query": req.query, "results": results, "count": len(results)}

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
        # H-13: Block dotfiles and sensitive paths
        if any(segment.startswith(".") for segment in full_path.split("/")):
            raise HTTPException(status_code=404, detail="Not found")
        file_path = (FRONTEND_DIR / full_path).resolve()
        # H-14: Path traversal protection — resolved path must stay inside FRONTEND_DIR
        if not str(file_path).startswith(str(FRONTEND_DIR.resolve())):
            raise HTTPException(status_code=403, detail="Forbidden")
        if file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_DIR / "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)
