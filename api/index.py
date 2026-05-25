from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time
import os
import sys

# Add the api directory to the Python path for Vercel Serverless
sys.path.append(os.path.dirname(__file__))

from routers import auth, spectrum, audit, synthesis, scout, scanner
from services.kev_loader import load_kev_data, get_all_findings
app = FastAPI(title="Tempris Wave 1 MVP", version="1.0.0")

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(spectrum.router, prefix="/api/spectrum", tags=["spectrum"])
app.include_router(scout.router, prefix="/api/scout", tags=["scout"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(synthesis.router, prefix="/api/synthesis", tags=["synthesis"])
app.include_router(scanner.router, prefix="/api/scanner", tags=["scanner"])

# Preload KEV data
load_kev_data()

# CORS setup for Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatMessage(BaseModel):
    message: str
    session_id: str | None = None

class ChatResponse(BaseModel):
    response: str
    sources: list[str] | None = None

@app.get("/")
def read_root():
    return {"status": "Tempris API running"}

@app.post("/api/speak/chat", response_model=ChatResponse)
def speak_chat(chat: ChatMessage):
    """
    AI Chatbot Endpoint (SPEAK Module) using FreeLLMAPI
    """
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
    from routers.audit import get_audit_log
    
    dashboard = get_dashboard_data()
    tes_score = dashboard.get("aggregate_tes", 0)
    alerts_text = "\n".join([f"- {a['module']}: {a['message']}" for a in dashboard.get("alerts", [])])
    
    audit_logs = get_audit_log()[:5]
    audit_summary = "\n".join([f"- {log['module']}: {log['action']} - {log['detail']}" for log in audit_logs])

    system_prompt = f"""You are SPEAK, the Tempris AI Security Assistant.
You have access to real-time CISA KEV vulnerability data, your organization's Tempris Exposure Score (TES), and TACF audit logs for compliance tracking.
- Overall TES Score: {tes_score} (Critical if > 8.0)
- Total CVEs monitored: {stats['total']}
- Ransomware-linked: {stats['ransomware']}  
- Critical (P0): {stats['critical']}
- Top threat: {stats['top_cve']['cve'] if stats['top_cve'] else 'N/A'} — {stats['top_cve']['title'] if stats['top_cve'] else 'N/A'}

Recent Alerts:
{alerts_text}

Recent TACF Audit Logs (Use these to assess MAS TRM and compliance state):
{audit_summary}

Answer security questions using this data. Be concise, professional, and reference specific CVEs, TES scores, or MAS TRM compliance events when relevant.
Reference the EDIP decision engine, MAS TRM compliance, and CTEM lifecycle where appropriate."""

    try:
        from services.llm_client import chat_completion
        response = chat_completion(system_prompt, chat.message)
        return {"response": response, "sources": ["CISA KEV Catalog", "FreeLLMAPI"]}
    except Exception as e:
        print(f"FreeLLMAPI Error: {e}")
        # Fallback to mock logic if LLM fails
        query = chat.message.lower()
        if "ransomware exposure" in query or "ransomware" in query:
            rw_count = len(ransomware_findings)
            top_cve = top_finding["cve"] if top_finding else "N/A"
            top_title = top_finding["title"] if top_finding else "N/A"
            top_vendor = top_finding["vendor"] if top_finding else "N/A"
            top_cvss = top_finding["cvss"] if top_finding else 0
            
            return {
                "response": f"[FALLBACK] Based on our CISA KEV intelligence feed, your environment has **{rw_count} ransomware-linked vulnerabilities** out of {total} total known exploited CVEs. The most critical is **{top_cve}** ({top_title}) affecting {top_vendor} with a CVSS of **{top_cvss}**.",
                "sources": ["CISA KEV Catalog v2026.05.22"]
            }
        return {
            "response": f"[FALLBACK] I am operating in offline mode. I am tracking {total} CVEs from the CISA KEV catalog.",
            "sources": ["CISA KEV Catalog"]
        }

@app.post("/api/spotlight/generate")
def generate_spotlight_report():
    """Generate AI board narrative using FreeLLMAPI."""
    all_findings = get_all_findings()
    total = len(all_findings)
    ransomware = len([f for f in all_findings if f.get("ransomware")])
    critical = len([f for f in all_findings if f.get("priority") == "P0"])

    from routers.synthesis import get_dashboard_data
    from routers.audit import get_audit_log
    
    dashboard = get_dashboard_data()
    tes_score = dashboard.get("aggregate_tes", 0)
    alerts_text = "\n".join([f"- {a['module']}: {a['message']}" for a in dashboard.get("alerts", [])])
    
    audit_logs = get_audit_log()[:10]
    audit_summary = "\n".join([f"- {log['module']}: {log['action']} - {log['detail']}" for log in audit_logs])

    system_prompt = f"""You are SPOTLIGHT, the Tempris executive reporting engine.
Generate a concise, board-level executive summary of our current cybersecurity posture based on the following telemetry:
- Tempris Exposure Score (TES): {tes_score}
- {total} total known exploited vulnerabilities (CISA KEV) detected
- {critical} critical (P0) vulnerabilities
- {ransomware} ransomware-linked vulnerabilities

Recent Alerts:
{alerts_text}

Recent TACF Audit Logs (Compliance State):
{audit_summary}

Focus on business risk and compliance (MAS TRM). Provide 3 clear bullet points. Keep the tone professional, authoritative, and direct."""

    try:
        from services.llm_client import chat_completion
        response = chat_completion(system_prompt, "Generate the latest executive cybersecurity briefing.")
        return {"ai_narrative": response, "metadata": {"model": "FreeLLMAPI Route"}}
    except Exception as e:
        print(f"FreeLLMAPI Error: {e}")
        return {"ai_narrative": "AI Service Unavailable. Please check FreeLLMAPI connection.", "metadata": {"model": "offline"}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
