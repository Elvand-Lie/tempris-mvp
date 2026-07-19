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

from routers import auth, spectrum, audit, synthesis, scout, scanner, strike, standard, assets, grc, edip, surge, blflaw, partner, reports, aev, ocq, threats, ciso
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_current_user
from services.kev_loader import ensure_findings_seeded, get_finding_stats
from services.database import get_db, init_db, SessionLocal
from models import SpotlightReport, ChatSession, ChatMessage, TesSnapshot

# Fail-closed check for ENVIRONMENT and AUDIT_HMAC_KEY
env = os.environ.get("ENVIRONMENT", "").strip().lower()
ALLOWED_ENVIRONMENTS = {"demo", "test", "development", "staging", "production"}
if not env:
    import sys
    print("FATAL: ENVIRONMENT configuration variable is missing or empty.", file=sys.stderr)
    sys.exit(1)
if env not in ALLOWED_ENVIRONMENTS:
    import sys
    print(f"FATAL: Unrecognized ENVIRONMENT value: '{env}'", file=sys.stderr)
    sys.exit(1)

if env in ("staging", "production"):
    storage_root = os.environ.get("EVIDENCE_STORAGE_ROOT", "").strip()
    if not storage_root:
        import sys
        print("FATAL: EVIDENCE_STORAGE_ROOT is not set in staging/production. Refusing to start.", file=sys.stderr)
        sys.exit(1)
    if not os.path.isabs(storage_root):
        import sys
        print("FATAL: EVIDENCE_STORAGE_ROOT must be an absolute path in staging/production. Refusing to start.", file=sys.stderr)
        sys.exit(1)

if env in ("staging", "production"):
    key_env = os.environ.get("AUDIT_HMAC_KEY", "")
    if not key_env:
        import sys
        print("FATAL: AUDIT_HMAC_KEY is not set in staging/production. Refusing to start.", file=sys.stderr)
        sys.exit(1)
    if len(key_env) < 32:
        import sys
        print("FATAL: AUDIT_HMAC_KEY must have at least 32 characters in staging/production.", file=sys.stderr)
        sys.exit(1)
    if "test_audit_hmac" in key_env or "tempris_dev_audit_hmac" in key_env:
        import sys
        print("FATAL: Weak placeholder key is refused in staging/production.", file=sys.stderr)
        sys.exit(1)


app = FastAPI(title="Tempris Wave 1 MVP", version="2.0.0", docs_url=None, redoc_url=None, openapi_url=None)

# â”€â”€ Register all routers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
app.include_router(edip.router, prefix="/api/edip", tags=["edip"])
app.include_router(surge.router, prefix="/api/surge", tags=["surge"])
app.include_router(blflaw.router, prefix="/api/blflaw", tags=["blflaw"])
app.include_router(partner.router, prefix="/api/partner", tags=["partner"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(aev.router, prefix="/api/aev", tags=["aev"])
app.include_router(ocq.router, prefix="/api/ocq", tags=["ocq"])
app.include_router(threats.router, prefix="/api/threats", tags=["threats"])
app.include_router(ciso.router, prefix="/api/ciso", tags=["ciso"])

# ─ Startup: Init DB, Seed data ──────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    # 1. Create all tables (including new findings table)
    init_db()
    # 2. Seed assets FIRST (before findings so vendorâ†’asset mapping works)
    db = SessionLocal()
    try:
        from services.asset_seeder import seed_assets
        seed_assets(db)
    finally:
        db.close()
    # 3. Seed findings into DB (auto-seeds from JSON if table is empty)
    ensure_findings_seeded()
    # 3b. Load suspended accounts cache for ToS enforcer
    load_suspended_accounts()
    # 4. Seed audit log + strike data
    db = SessionLocal()
    try:
        from routers.audit import seed_audit_log
        seed_audit_log(db)
        from routers.strike import seed_strike_data
        seed_strike_data(db)
        # 5. Take initial TES snapshot
        try:
            from routers.synthesis import get_dashboard_data
            import inspect
            sig = inspect.signature(get_dashboard_data)
            if len(sig.parameters) > 0:
                data = get_dashboard_data(db)
            else:
                data = get_dashboard_data()
            existing = db.query(TesSnapshot).filter(TesSnapshot.tenant_id == 'tempris').count()
            if existing == 0:
                stats = get_finding_stats(db)
                db.add(TesSnapshot(
                    tenant_id='tempris',
                    aggregate_tes=data["aggregate_tes"],
                    finding_count=stats["total_findings"],
                    critical_count=stats["critical_count"]
                ))
                db.commit()
                logger.info("Initial TES snapshot recorded.")
        except Exception as e:
            logger.warning(f"TES snapshot skipped: {e}")
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

# H-06: CORS â€” configurable via env, no wildcard in production
allowed_origins = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:5174,http://187.127.114.218,https://187.127.114.218,http://187.127.114.218:80"
).split(",")

from middleware.rate_limit import RateLimitMiddleware
from middleware.tos_enforcer import ToSEnforcerMiddleware, load_suspended_accounts

# â”€â”€ Security Headers Middleware (H-09) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        
        # Global Serializer Redaction Boundary (CORE-C03)
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            import json
            from services.redactor import redact_private_fields
            body = []
            async for chunk in response.body_iterator:
                body.append(chunk)
            body_bytes = b"".join(body)
            try:
                data = json.loads(body_bytes.decode("utf-8"))
                cleaned_data = redact_private_fields(data)
                new_body = json.dumps(cleaned_data).encode("utf-8")
                
                # Rebuild response with new body
                from fastapi import Response
                headers = dict(response.headers)
                headers["content-length"] = str(len(new_body))
                response = Response(
                    content=new_body,
                    status_code=response.status_code,
                    headers=headers,
                    media_type="application/json"
                )
            except Exception:
                async def re_iterate():
                    for chunk in body:
                        yield chunk
                response.body_iterator = re_iterate()

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        
        # H-10: Strip server fingerprint headers to block reconnaissance
        if "server" in response.headers:
            del response.headers["server"]
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        if os.environ.get("ENABLE_HSTS", "false").lower() == "true":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class AuditContextASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            from fastapi import Request
            from routers.audit import audit_request_var
            request = Request(scope)
            # Initialize request context
            req_token = audit_request_var.set(request)
            # Ensure authenticated user state is clean
            request.state.authenticated_user = None
            try:
                await self.app(scope, receive, send)
            finally:
                audit_request_var.reset(req_token)
        else:
            await self.app(scope, receive, send)



app.add_middleware(AuditContextASGIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ToSEnforcerMiddleware)


app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# â”€â”€ SPEAK (Chat) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

@app.delete("/api/speak/history")
def clear_chat_history(
    session_id: int | None = None,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Clear the current user's SPEAK chat history."""
    user_email = user.get("sub", "Current User")
    sessions_query = db.query(ChatSession).filter(ChatSession.user_email == user_email)
    if session_id:
        sessions_query = sessions_query.filter(ChatSession.id == session_id)

    session_ids = [s.id for s in sessions_query.all()]
    if not session_ids:
        return {"status": "cleared", "deleted_sessions": 0, "deleted_messages": 0}

    deleted_messages = db.query(ChatMessage).filter(
        ChatMessage.session_id.in_(session_ids)
    ).delete(synchronize_session=False)
    deleted_sessions = db.query(ChatSession).filter(
        ChatSession.id.in_(session_ids)
    ).delete(synchronize_session=False)
    db.commit()

    append_to_audit_log(AuditEntry(
        user=user_email, action="SPEAK_HISTORY_CLEARED", module="SPEAK",
        detail=f"Cleared {deleted_messages} SPEAK message(s) across {deleted_sessions} session(s)."
    ))
    return {"status": "cleared", "deleted_sessions": deleted_sessions, "deleted_messages": deleted_messages}

@app.post("/api/speak/chat", response_model=ChatResponse)
def speak_chat(
    chat: ChatMessageReq,
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """AI Chatbot Endpoint (SPEAK Module) with full platform awareness."""
    user_email = user.get("sub", "Current User")
    
    # 1. Early Guardrail Intercept (SEC-I2)
    from services.llm_client import sanitize_user_input
    sanitized_msg = sanitize_user_input(chat.message)
    if sanitized_msg == "__INJECTION_BLOCKED__":
        append_to_audit_log(AuditEntry(
            user=user_email, action="SPEAK_GUARDRAIL_TRIGGERED", module="SPEAK",
            detail="Prompt injection attempt blocked by SPEAK guardrails."
        ))
        response = "I'm designed to help with security analysis and threat intelligence. I can't modify my behavior or reveal internal configuration. How can I assist you with your security posture?"
        return {"response": response, "sources": ["Guardrail"], "session_id": chat.session_id}

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
    
    tenant_id = user.get("tenant_id", "tempris")
    from services.ai_context import build_service_ai_context, build_speak_system_prompt
    ctx = build_service_ai_context(db, chat.message, n_results=5, tenant_id=tenant_id)
    context_text = ctx["full_text"]
    structured = ctx["structured"]
    rag_text = ctx["rag_text"]
    rag_sources = ctx["rag_sources"]
    
    # Enhanced RAG: DB-level keyword match (replaces in-memory iteration of 500+ findings)
    relevant_text = ""
    query_lower = chat.message.lower()
    try:
        from models import Finding
        from sqlalchemy import or_
        search_terms = [w for w in query_lower.split() if len(w) > 3]
        if search_terms:
            conditions = []
            for term in search_terms[:5]:  # Limit to 5 terms
                pattern = f"%{term}%"
                conditions.append(Finding.cve.ilike(pattern))
                conditions.append(Finding.vendor.ilike(pattern))
                conditions.append(Finding.title.ilike(pattern))
            relevant = db.query(Finding).filter(Finding.tenant_id == tenant_id).filter(or_(*conditions)).limit(10).all()
            if relevant:
                relevant_text = "\n\nRelevant findings matching your query:\n"
                for rf in relevant[:5]:
                    relevant_text += f"- {rf.cve}: {rf.title} (Vendor: {rf.vendor}, CVSS: {rf.cvss}, Ransomware: {rf.ransomware})\n"
    except Exception:
        pass

    system_prompt = build_speak_system_prompt(context_text, relevant_text, rag_text)

    # Load chat history for context (bounded to last 20 for performance)
    db_history = db.query(ChatMessage).filter(
        ChatMessage.session_id == session.id
    ).order_by(ChatMessage.created_at.desc()).limit(20).all()
    db_history.reverse()  # Back to chronological order
    history_messages = [{"role": m.role, "content": m.content} for m in db_history[:-1]]

    try:
        from services.llm_client import chat_completion
        response = chat_completion(system_prompt, chat.message, history=history_messages[-10:], user_email=user_email)
        db.add(ChatMessage(session_id=session.id, role="assistant", content=response))
        db.commit()
        append_to_audit_log(AuditEntry(
            user=user_email, action="SPEAK_AI_CALL", module="SPEAK",
            detail=f"AI query: '{chat.message[:80]}' - responded successfully"
        ))
        return {"response": response, "sources": ["All Modules", "FreeLLMAPI", *rag_sources], "session_id": session.id}
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
            asset_lines = "\n".join([f"- **{a['id']}**: {a['name']} ({a['type']}) - IP: {a.get('ip', 'N/A')}" for a in critical_assets[:5]])
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
        elif "incident" in query_lower or "attacked" in query_lower or "attack" in query_lower or "mas trm" in query_lower:
            report = structured.get("latest_incident_report")
            if report:
                summary = report.get("incident_summary", {})
                threat = report.get("threat_landscape", {})
                scanner = report.get("scanner_findings", [])
                strike = report.get("red_team_assessment") or {}
                hit_lines = "\n".join([f"- {f.get('target')}:{f.get('port')} {f.get('service')} ({f.get('risk')}): {f.get('detail')}" for f in scanner[:5]]) or "- No critical/high scanner findings are attached to the draft."
                strike_line = f"STRIKE simulation {strike.get('simulation_id')} found {strike.get('exploitable')} exploitable technique(s)." if strike else "No STRIKE evidence is attached to the draft."
                fallback = f"Latest MAS TRM incident draft **{report.get('report_id')}** is **{report.get('status')}**.\n\n**What happened:** {summary.get('description')}\n\n**What was hit:** {summary.get('affected_systems')}\n\n**Why it matters:** TES is **{threat.get('tempris_exposure_score')}** ({threat.get('risk_band')}), with **{threat.get('critical_cves_tracked')} critical CVEs** and **{threat.get('ransomware_linked_cves')} ransomware-linked CVEs** tracked.\n\n**Evidence:**\n{hit_lines}\n- {strike_line}\n\n**Report deadline:** {report.get('notification_deadline')}\n\nUse STANDARD for the draft report and Audit Log for the TACF generation record."
            else:
                fallback = "No MAS TRM incident draft has been generated yet. Use STANDARD -> MAS TRM 1-Hour Incident Notice to create the draft report from current TES, SCOUT, STRIKE, and vulnerability data."
        elif "compliance" in query_lower or "framework" in query_lower or "regulation" in query_lower or "mas" in query_lower:
            total_controls = structured.get("compliance_total_controls", 0)
            compliant = structured.get("compliance_compliant", 0)
            non_compliant = structured.get("compliance_non_compliant", 0)
            gaps_text = "\n".join([f"- WARNING: {g}" for g in compliance_gaps[:5]])
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

        from services.edip_engine import _build_context_binding_footer
        fallback += _build_context_binding_footer(
            account_ref=user_email,
            asset_context=structured.get("critical_assets", [])[:3],
            response_seed=fallback,
        )
        
        db.add(ChatMessage(session_id=session.id, role="assistant", content=fallback))
        db.commit()
        return {"response": fallback, "sources": ["Platform Data", *rag_sources], "session_id": session.id}

# â”€â”€ SPOTLIGHT (Reports) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    from services.ai_context import build_service_ai_context, build_spotlight_prompt, sanitize_user_focus
    safe_focus = sanitize_user_focus(req.custom_focus)
    req.custom_focus = safe_focus
    default_rag_query = _SPOTLIGHT_RAG_QUERIES.get(req.report_type, "cybersecurity risk assessment")
    ctx = build_service_ai_context(
        db,
        safe_focus or default_rag_query,
        n_results=8,
        extra_query=default_rag_query,
    )
    context_text = ctx["full_text"]
    structured = ctx["structured"]
    rag_text = ctx["rag_text"]
    rag_sources = ctx["rag_sources"]

    tes_score = structured.get("tes_score", 0)
    kev_total = structured.get("kev_total", 0)
    asset_count = structured.get("asset_count", 0)

    # Build prompt with RAG context and optional custom focus
    system_prompt = build_spotlight_prompt(context_text, req.report_type)
    if rag_text:
        system_prompt += f"\n\n{rag_text}"
    if req.custom_focus.strip():
        system_prompt += f"\n\n=== USER FOCUS AREA ===\nThe user has specifically requested: {req.custom_focus.strip()}\nPrioritize this area in your report while still covering all sections."

    try:
        from services.llm_client import chat_completion
        user_msg = f"Generate the latest {req.report_type} cybersecurity briefing."
        if req.custom_focus.strip():
            user_msg += f" Focus on: {req.custom_focus.strip()}"
        response = chat_completion(system_prompt, user_msg, max_tokens=2000, user_email=user_email)
        
        # Detect mock/fallback response â€” chat_completion silently returns SPEAK
        # chatbot canned text when LLM fails (it never raises). If we see the
        # SPEAK stub markers, discard and use our rich structured fallback instead.
        mock_markers = ["Navigate to the SPOTLIGHT module", "How can I help you today?", "What would you like to explore?"]
        if any(marker in response for marker in mock_markers):
            raise ValueError("LLM returned SPEAK mock response instead of Spotlight report")
        if len(response.strip()) < 800 or response.count("## ") < 2:
            raise ValueError("LLM returned underspecified Spotlight report")
        
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
            gaps_text += f"\n- {g}"

        narrative = f"""## Security Posture Overview

As of today, the organization's **Tempris Exposure Score (TES)** stands at **{tes_score:.1f}** ({'Critical' if tes_score >= 7 else 'High' if tes_score >= 5 else 'Medium' if tes_score >= 3 else 'Low'}). This score is computed across **{kev_total:,} known exploited vulnerabilities** tracked by the US Cybersecurity & Infrastructure Security Agency (CISA KEV catalog). Of these, **{kev_ransomware}** have confirmed ties to active ransomware campaigns, and **{kev_critical}** are classified as P0 (critical priority).

The organization manages **{asset_count} active assets** across its infrastructure, including critical network appliances, servers, and applications.

## Key Risk Highlights

The primary driver of elevated risk is **{top_cve.get('cve', 'N/A')}** - {top_cve.get('title', 'N/A')}, affecting {top_cve.get('vendor', 'N/A')} with a CVSS score of **{top_cve.get('cvss', 0.0):.1f}**.

STRIKE adversary simulations identified **{strike_exploitable} exploitable techniques** out of {strike_exploitable + strike_blocked} tested, indicating {'significant' if strike_exploitable > 2 else 'moderate' if strike_exploitable > 0 else 'minimal'} attack surface exposure.

## Regulatory Compliance

Across 8 regulatory frameworks (MAS TRM, PDPA, ISO 27001, IM8A, NIST CSF, SOC 2, PCI DSS, CSA Cyber Trust), **{compliance_compliant}/{compliance_total} controls are compliant**. Notable gaps:{gaps_text if gaps_text else ' None identified.'}

ISO/IEC 42001:2023 AI Governance composite TES: **{grc.get('score', 'N/A')}** ({grc.get('band', 'N/A')}).

## Recommended Actions

1. **Immediate**: Prioritize all CISA KEV vulnerabilities with confirmed ransomware ties using the EDIP decision engine in SPECTRUM.
2. **Short-term**: Address non-compliant MAS TRM and IM8A controls to meet regulatory SLAs.
3. **Medium-term**: Remediate exploitable techniques identified by STRIKE simulations.
4. **Ongoing**: Complete ISO 42001 SOP sign-offs in the GRC module to improve the AI Governance Modifier (AGM)."""
        if req.custom_focus.strip():
            narrative += f"\n\n## Custom Focus\nThis report prioritized **{req.custom_focus.strip()}** using service-wide Tempris context and available RAG results."
        model = "offline"

    # Persist report to DB
    report = SpotlightReport(
        report_type=req.report_type, narrative=narrative,
        tes_score=tes_score, metadata_={"model": model, "custom_focus": req.custom_focus.strip() or None, "rag_chunks": bool(rag_text), "rag_sources": rag_sources},
        generated_by=user_email
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    append_to_audit_log(AuditEntry(
        user=user_email, action="SPOTLIGHT_REPORT_GENERATED", module="SPOTLIGHT",
        detail=f"AI {req.report_type} report generated. TES: {tes_score}, Findings: {kev_total}, Assets: {asset_count}" + (f" Focus: {req.custom_focus[:50]}" if req.custom_focus.strip() else "")
    ))

    return {"ai_narrative": narrative, "metadata": {"model": model, "rag_sources": rag_sources}, "report_id": report.id}

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

# â”€â”€ RAG Vector Database Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
    # Serve VDP policy page at /security (public, no auth)
    DOCS_DIR = Path(__file__).resolve().parent / "docs"
    if not DOCS_DIR.exists():
        DOCS_DIR = Path("/app/docs")

    @app.get("/security")
    async def serve_vdp():
        vdp_path = DOCS_DIR / "tempris_vdp_policy.html"
        if vdp_path.is_file():
            return FileResponse(str(vdp_path), media_type="text/html")
        raise HTTPException(status_code=404, detail="VDP policy not found")

    # Catch-all: serve index.html for any non-API route (SPA client-side routing)
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api"):
            raise HTTPException(status_code=404, detail="Not found")
        if full_path in (".well-known/security.txt", ".well-known/pgp-key.txt"):
            file_path = (FRONTEND_DIR / full_path).resolve()
            if file_path.is_file() and str(file_path).startswith(str(FRONTEND_DIR.resolve())):
                return FileResponse(str(file_path), media_type="text/plain")
            raise HTTPException(status_code=404, detail="Not found")
        # H-13: Block dotfiles and sensitive paths
        if any(segment.startswith(".") for segment in full_path.split("/")):
            raise HTTPException(status_code=404, detail="Not found")
        file_path = (FRONTEND_DIR / full_path).resolve()
        # H-14: Path traversal protection â€” resolved path must stay inside FRONTEND_DIR
        if not str(file_path).startswith(str(FRONTEND_DIR.resolve())):
            raise HTTPException(status_code=403, detail="Forbidden")
        if file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_DIR / "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)

