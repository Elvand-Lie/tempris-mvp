from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
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

from routers import auth, spectrum, audit, synthesis, scout, scanner, strike, standard, assets, grc, edip, surge, blflaw, partner, reports, aev, ocq, threats, ciso, packages, tenants, workflow, incidents
from routers.audit import append_to_audit_log, AuditEntry
from routers.auth import get_auth_context, get_current_user
from services.kev_loader import ensure_findings_seeded, get_finding_stats
from services.database import get_db, init_db, SessionLocal
from models import SpotlightReport, ChatSession, ChatMessage, PostureSnapshot

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
app.include_router(packages.router, prefix="/api/packages", tags=["packages"])
app.include_router(tenants.router, prefix="/api/tenants", tags=["tenants"])
app.include_router(workflow.router, prefix="/api/workflow", tags=["workflow"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["incidents"])

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
        from services.entitlements import ensure_default_tenant_packages
        from services.tenants import ensure_tenant_registry
        tenant_ids = {record.get("tenant_id") for record in auth.USERS.values()}
        ensure_tenant_registry(db, tenant_ids)
        ensure_default_tenant_packages(
            db,
            tenant_ids,
        )
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
        # 5. Take the first canonical posture snapshot.  Legacy TesSnapshot rows
        # remain readable but are deliberately not mixed with the canonical scope.
        try:
            from services.customer_posture import SCOPE_VERSION, build_customer_posture
            posture = build_customer_posture(db, "tempris")
            existing = db.query(PostureSnapshot).filter(
                PostureSnapshot.tenant_id == "tempris",
                PostureSnapshot.scope_version == SCOPE_VERSION,
            ).count()
            if existing == 0:
                db.add(PostureSnapshot(
                    tenant_id="tempris",
                    scope_version=SCOPE_VERSION,
                    active_asset_count=posture["active_asset_count"],
                    confirmed_open_exposure_count=posture["confirmed_open_exposure_count"],
                    confirmed_critical_count=posture["confirmed_critical_count"],
                    confirmed_high_count=posture["confirmed_high_count"],
                    confirmed_ransomware_linked_count=posture["confirmed_ransomware_linked_count"],
                    needs_classification_count=posture["needs_classification_count"],
                    reference_intelligence_count=posture["reference_intelligence_count"],
                    evidence_backed_link_count=posture["evidence_backed_link_count"],
                    legacy_unverified_link_count=posture["legacy_unverified_link_count"],
                    aggregate_tenant_tes=posture["aggregate_tenant_tes"],
                    scoreable_finding_count=posture["scoreable_finding_count"],
                ))
                db.commit()
                logger.info("Initial canonical posture snapshot recorded.")
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
        canonical_artifact = response.headers.get("X-Tempris-Canonical-Artifact") == "1"
        if "application/json" in content_type and not canonical_artifact:
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

        if "X-Tempris-Canonical-Artifact" in response.headers:
            del response.headers["X-Tempris-Canonical-Artifact"]

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'")
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
        tes_score = structured.get("tes_score")
        tes_display = (
            f"{tes_score:.1f}" if isinstance(tes_score, (int, float)) else "not included (asset-matched scoring coverage is incomplete)"
        )
        kev_total = structured.get("kev_total", 0)
        kev_critical = structured.get("kev_critical", 0)
        kev_ransomware = structured.get("kev_ransomware", 0)
        asset_count = structured.get("asset_count", 0)
        strike_exploitable = structured.get("strike_exploitable_observed", 0)
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
                no_exposure = structured.get("strike_no_exposure_observed", 0)
                verified_blocks = structured.get("strike_defensive_block_verified", 0)
                results = structured.get("strike_results", [])
                technique_text = "\n".join([f"- **{r.get('technique_id')}** ({r.get('technique_name')}): {r.get('result')}" for r in results[:5]])
                fallback = f"Latest STRIKE simulation **{sim_id}** against {structured.get('strike_target', 'target')}: **{strike_exploitable} exploitable observed**, **{no_exposure} no exposure observed**, and **{verified_blocks} defensive blocks verified**. No-exposure observations are not proof that a control blocked an attack.\n\n{technique_text}\n\nRecommendation: Address exploitable observations through the EDIP decision engine."
            else:
                fallback = "No STRIKE adversary simulations have been run yet. Navigate to the STRIKE module to authorize and execute an adversary emulation campaign."
        elif "incident" in query_lower or "attacked" in query_lower or "attack" in query_lower or "mas trm" in query_lower:
            report = structured.get("latest_incident_report")
            if report:
                summary = report.get("incident_summary", {})
                scanner = report.get("scanner_findings", [])
                strike = report.get("red_team_assessment") or {}
                hit_lines = "\n".join([f"- {f.get('target')}:{f.get('port')} {f.get('service')} ({f.get('risk')}): {f.get('detail')}" for f in scanner[:5]]) or "- No critical/high scanner findings are attached to the draft."
                strike_line = f"STRIKE simulation {strike.get('simulation_id')} found {strike.get('exploitable')} exploitable technique(s)." if strike else "No STRIKE evidence is attached to the draft."
                fallback = f"Latest MAS TRM incident draft **{report.get('report_id')}** is **{report.get('status')}**.\n\n**What happened:** {summary.get('description')}\n\n**What was hit:** {summary.get('affected_systems')}\n\nThe draft is based on the recorded Incident, its tenant assets, and related confirmed customer exposures; global catalogue totals are excluded.\n\n**Evidence:**\n{hit_lines}\n- {strike_line}\n\n**Report deadline:** {report.get('notification_deadline')}\n\nUse STANDARD for the draft and Audit Log for the generation record."
            else:
                fallback = "No MAS TRM incident draft has been generated yet. Use STANDARD -> MAS TRM 1-Hour Incident Notice to create the draft report from current TES, SCOUT, STRIKE, and vulnerability data."
        elif "compliance" in query_lower or "framework" in query_lower or "regulation" in query_lower or "mas" in query_lower:
            total_controls = structured.get("compliance_total_controls", 0)
            assessed = structured.get("compliance_assessed_controls", 0)
            compliant = structured.get("compliance_compliant", 0)
            non_compliant = structured.get("compliance_non_compliant", 0)
            gaps_text = "\n".join([f"- WARNING: {g}" for g in compliance_gaps[:5]])
            if assessed:
                fallback = (
                    f"Tempris records **{assessed} control assessment(s)** out of {total_controls} reference controls: "
                    f"**{compliant} compliant** and **{non_compliant} non-compliant**."
                    f"\n\nRecorded non-compliant controls:\n{gaps_text or '- None recorded.'}"
                )
            else:
                fallback = f"No tenant control assessments are recorded. Tempris has {total_controls} reference controls, but they are not evidence of compliance."
        elif "grc" in query_lower or "iso 42001" in query_lower or "ai governance" in query_lower:
            grc = structured.get("grc_ai_system_risk")
            if grc:
                drivers = "; ".join(grc.get("drivers") or []) or "No qualitative drivers recorded"
                fallback = f"**ISO/IEC 42001:2023 AI Governance Status**:\n- AI-system risk score: **{grc.get('score', 'Not recorded')}** ({grc.get('band', 'Not recorded')})\n- Scope: {grc.get('scope', 'AI_SYSTEM')}\n- Qualitative drivers: {drivers}\n\nThis is an AI-system-specific governance risk score, not tenant TES. Navigate to GRC for control sign-off and SOP management."
            else:
                fallback = "No tenant GRC state is recorded, so Tempris does not present a GRC composite TES or governance-factor status."
        elif "ransomware" in query_lower:
            top5 = structured.get("kev_top5", [])
            top_text = "\n".join([f"- **{f['cve']}**: {f['title']} (CVSS: {f.get('cvss',0)})" for f in top5[:3]])
            fallback = f"Your tenant has **{kev_ransomware} confirmed ransomware-linked exposures** out of {kev_total} confirmed exposure finding(s). Recorded critical items:\n\n{top_text or '- None recorded.'}"
        elif "edip" in query_lower or "decision" in query_lower:
            edip = structured.get("edip_recent", [])
            if edip:
                edip_text = "\n".join([f"- {d['cve']}: **{d['decision'].upper()}** by {d.get('by', 'auto')}" for d in edip[:5]])
                fallback = f"Recent EDIP exposure decisions:\n\n{edip_text}\n\nUse the SPECTRUM module to make new EDIP decisions for untriaged findings."
            else:
                fallback = "No EDIP decisions have been recorded yet. Navigate to SPECTRUM to begin triaging findings through the Escalate/Defer/Investigate/Patch workflow."
        else:
            strike_summary = f"STRIKE records {strike_exploitable} exploitable technique(s)" if structured.get("strike_sim_id") else "no STRIKE simulation result is recorded"
            fallback = f"I'm tracking **{kev_total:,} confirmed customer exposures** ({kev_critical} critical, {kev_ransomware} ransomware-linked). Tenant TES is **{tes_display}**. The tenant has **{asset_count} active assets**, **{len(compliance_gaps)} recorded compliance gaps**, and {strike_summary}. How can I help you assess your exposure?"

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
    auth_ctx = get_auth_context(user)
    tenant_id = auth_ctx.tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    user_email = auth_ctx.user_id

    from services.ai_context import build_service_ai_context, build_spotlight_prompt, sanitize_user_focus
    safe_focus = sanitize_user_focus(req.custom_focus)
    req.custom_focus = safe_focus
    default_rag_query = _SPOTLIGHT_RAG_QUERIES.get(req.report_type, "cybersecurity risk assessment")
    ctx = build_service_ai_context(
        db,
        safe_focus or default_rag_query,
        n_results=8,
        extra_query=default_rag_query,
        tenant_id=tenant_id,
    )
    context_text = ctx["full_text"]
    structured = ctx["structured"]
    rag_text = ctx["rag_text"]
    rag_sources = ctx["rag_sources"]

    tes_score = structured.get("tes_score")
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
        strike_exploitable = structured.get("strike_exploitable_observed", 0)
        strike_no_exposure = structured.get("strike_no_exposure_observed", 0)
        strike_verified_blocks = structured.get("strike_defensive_block_verified", 0)
        grc = structured.get("grc_ai_system_risk", {})
        compliance_compliant = structured.get("compliance_compliant", 0)
        
        if top5:
            top_cve = top5[0]
            top_cvss = top_cve.get("cvss")
            cvss_text = f"{top_cvss:.1f}" if isinstance(top_cvss, (int, float)) else "Not recorded"
            top_risk_text = (
                f"The highest recorded asset-linked critical finding is "
                f"**{top_cve.get('cve') or top_cve.get('title') or 'Not recorded'}** "
                f"on asset **{top_cve.get('asset_id') or 'Not recorded'}** "
                f"(vendor: {top_cve.get('vendor') or 'Not recorded'}, CVSS: {cvss_text})."
            )
        else:
            top_risk_text = (
                "No asset-linked critical CVE is recorded, so this report does not claim "
                "a primary vulnerability driver."
            )

        if structured.get("strike_sim_id"):
            strike_text = (
                f"The latest recorded STRIKE simulation contains **{strike_exploitable} exploitable observed**, "
                f"**{strike_no_exposure} no exposure observed**, and **{strike_verified_blocks} defensively blocked with evidence** result(s). "
                "A no-exposure observation is not proof of an active defensive block."
            )
        else:
            strike_text = "No STRIKE simulation result is recorded."

        compliance_assessed = structured.get("compliance_assessed_controls", 0)
        grc_text = (
            f"ISO/IEC 42001:2023 AI-system risk score: **{grc.get('score')}** "
            f"({grc.get('band')}); this is not tenant TES."
            if grc else
            "No tenant GRC state is recorded, so a GRC composite TES is not included."
        )

        
        # Build compliance gap text
        gaps_text = ""
        for g in compliance_gaps[:5]:
            gaps_text += f"\n- {g}"

        compliance_text = (
            f"Of **{compliance_assessed} recorded control assessments**, "
            f"**{compliance_compliant}** are compliant. Recorded gaps:"
            f"{gaps_text if gaps_text else ' None recorded.'}"
        )

        action_items = []
        if kev_total:
            action_items.append(f"Review the {kev_total} confirmed customer exposure finding(s).")
        if compliance_gaps:
            action_items.append("Assign owners and treatment dates to the recorded non-compliant controls.")
        if strike_exploitable:
            action_items.append("Remediate the exploitable techniques recorded by the latest STRIKE simulation.")
        actions_text = "\n".join(
            f"{number}. {action}" for number, action in enumerate(action_items, 1)
        ) or "No prioritized action is generated because no supported action-driving data is recorded."

        narrative = f"""## Security Posture Overview

Aggregate TES is **not included** because validated asset-matched scoring coverage is not recorded for every tenant finding.

Tempris records **{kev_total} confirmed customer exposure finding(s)** for this tenant; **{kev_ransomware}** are ransomware-linked and **{kev_critical}** are critical. The shared CISA catalogue is reference intelligence and is excluded unless an analyst or deterministic scanner created a confirmed, evidence-backed relationship to an active same-tenant asset.

The tenant asset inventory records **{asset_count} active asset(s)**.

## Key Risk Highlights

{top_risk_text}

{strike_text}

## Regulatory Compliance

{compliance_text}

{grc_text}

## Recommended Actions

{actions_text}"""
        if req.custom_focus.strip():
            narrative += f"\n\n## Custom Focus\nThis report prioritized **{req.custom_focus.strip()}** using service-wide Tempris context and available RAG results."
        model = "offline"

    # Persist report to DB
    report = SpotlightReport(
        tenant_id=tenant_id,
        report_type=req.report_type, narrative=narrative,
        tes_score=tes_score, metadata_={"model": model, "custom_focus": req.custom_focus.strip() or None, "rag_chunks": bool(rag_text), "rag_sources": rag_sources},
        generated_by=user_email
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    tes_audit = (
        str(tes_score) if isinstance(tes_score, (int, float)) else "not included"
    )
    append_to_audit_log(AuditEntry(
        user=user_email, action="SPOTLIGHT_REPORT_GENERATED", module="SPOTLIGHT",
        detail=f"AI {req.report_type} report generated. TES: {tes_audit}, Asset-linked KEV findings: {kev_total}, Assets: {asset_count}" + (f" Focus: {req.custom_focus[:50]}" if req.custom_focus.strip() else "")
    ))

    return {"ai_narrative": narrative, "metadata": {"model": model, "rag_sources": rag_sources}, "report_id": report.id}

@app.get("/api/spotlight/history")
def get_spotlight_history(
    db: Session = Depends(get_db),
    user = Depends(get_current_user),
):
    """Return previously generated reports from DB.
    
    Admin roles see tenant reports; other roles see only their own tenant reports.
    """
    auth_ctx = get_auth_context(user)
    if not auth_ctx.tenant_id:
        raise HTTPException(status_code=400, detail="Missing tenant context")
    user_email = auth_ctx.user_id
    user_role = auth_ctx.role
    
    query = db.query(SpotlightReport).filter(
        SpotlightReport.tenant_id == auth_ctx.tenant_id
    ).order_by(SpotlightReport.generated_at.desc())
    
    # Non-admin users can only see their own reports inside their tenant.
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

    # The HTML bootstrap selects a hashed client bundle. Never let an older
    # bootstrap page keep selecting a retired bundle after a deployment.
    SPA_INDEX_HEADERS = {"Cache-Control": "no-store, max-age=0"}

    def serve_spa_index() -> FileResponse:
        return FileResponse(str(FRONTEND_DIR / "index.html"), headers=SPA_INDEX_HEADERS)

    # Serve root as SPA index
    @app.get("/")
    async def serve_root():
        return serve_spa_index()
    # Keep one canonical VDP experience. /security remains as a durable alias.
    VDP_PUBLIC_ORIGIN = os.environ.get("VDP_PUBLIC_ORIGIN", "https://sandbox.tempris.tech").rstrip("/")
    VDP_CONTACT_EMAIL = os.environ.get("VDP_CONTACT_EMAIL", "lohsherie@yahoo.com.sg").strip()
    VDP_SECURITY_TXT_EXPIRES = os.environ.get("VDP_SECURITY_TXT_EXPIRES", "2027-06-30T00:00:00Z").strip()

    @app.get("/security", include_in_schema=False)
    async def redirect_vdp():
        return RedirectResponse(url="/vdp", status_code=308)

    @app.get("/.well-known/security.txt", include_in_schema=False)
    async def serve_security_txt():
        lines = [
            "# Tempris Technology Pte. Ltd. - RFC 9116 security.txt",
            f"Contact: {VDP_PUBLIC_ORIGIN}/vdp#submit",
        ]
        if VDP_CONTACT_EMAIL:
            lines.append(f"Contact: mailto:{VDP_CONTACT_EMAIL}")
        lines.extend([
            f"Acknowledgments: {VDP_PUBLIC_ORIGIN}/vdp#hof",
            f"Policy: {VDP_PUBLIC_ORIGIN}/vdp",
            f"Canonical: {VDP_PUBLIC_ORIGIN}/.well-known/security.txt",
            f"Expires: {VDP_SECURITY_TXT_EXPIRES}",
            "Preferred-Languages: en",
            "",
        ])
        return PlainTextResponse(
            "\n".join(lines),
            media_type="text/plain; charset=utf-8",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    # Catch-all: serve index.html for any non-API route (SPA client-side routing)
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api"):
            raise HTTPException(status_code=404, detail="Not found")
        if full_path == ".well-known/pgp-key.txt":
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
            if file_path == (FRONTEND_DIR / "index.html").resolve():
                return serve_spa_index()
            headers = SPA_INDEX_HEADERS if full_path.startswith("extensions/") else None
            return FileResponse(str(file_path), headers=headers)
        return serve_spa_index()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)
