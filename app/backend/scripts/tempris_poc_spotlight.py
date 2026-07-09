"""
Tempris Wave 1 Phase 1 — SPOTLIGHT Board Report Generator
Reads SPECTRUM findings and generates an AI board narrative
using the Claude API (claude-sonnet-4 model).

Usage:
    export ANTHROPIC_API_KEY=your-key-here
    python3 tempris_poc_spotlight.py

Prerequisites:
    pip install anthropic
    - spectrum_findings.json  (from tempris_poc_spectrum_loader.py)
"""

import json, os, datetime

try:
    import anthropic
except ImportError:
    print("Install: pip install anthropic --break-system-packages")
    exit(1)

# ── Load SPECTRUM findings ─────────────────────────────────────
FINDINGS_FILE = "spectrum_findings.json"
if not os.path.exists(FINDINGS_FILE):
    FINDINGS_FILE = "nvd_spectrum_findings.json"

if not os.path.exists(FINDINGS_FILE):
    print(f"No findings file found. Run tempris_poc_spectrum_loader.py first.")
    exit(1)

with open(FINDINGS_FILE) as f:
    data = json.load(f)

findings  = data.get("findings", [])
p0_count  = sum(1 for f in findings if "P0" in f.get("tes_priority",""))
p1_count  = sum(1 for f in findings if "P1" in f.get("tes_priority",""))
top3      = findings[:3]
avg_tes   = round(sum(f["tes_score"] for f in findings) / len(findings), 2) if findings else 0

# ── Configuration ──────────────────────────────────────────────
ORG_NAME = "Tempris Pilot Client"    # change to client name
MAS_TRM_PCT  = 45
NIST_CSF_PCT = 61
PDPA_PCT     = 38

top3_text = "\n".join([
    f"  {i+1}. {f.get('cve_id','N/A')} — {f.get('name','Unknown')} "
    f"(TES {f['tes_score']}, {f['tes_priority']})"
    + (" [ransomware-linked]" if f.get("ransomware_linked") else "")
    + (" [CISA KEV]" if f.get("kev_flagged") else "")
    for i, f in enumerate(top3)
])

# ── Claude API call ────────────────────────────────────────────
client = anthropic.Anthropic()

PROMPT = f"""You are a senior cybersecurity advisor at Tempris, writing a board-level 
executive security brief for {ORG_NAME}. 

Current security data (as of {datetime.date.today().strftime('%d %B %Y')}):
- Average Tempris Exposure Score (TES): {avg_tes}/10
- Critical findings (P0): {p0_count}
- High findings (P1): {p1_count}
- Total findings reviewed: {len(findings)}

Top 3 critical findings:
{top3_text}

Compliance posture:
- MAS TRM (Technology Risk Management): {MAS_TRM_PCT}% compliant
- NIST Cybersecurity Framework 2.0: {NIST_CSF_PCT}% compliant
- PDPA (Personal Data Protection): {PDPA_PCT}% compliant

Write a professional 3-paragraph executive board brief covering:
1. Current security posture — what does a TES of {avg_tes} mean in plain English?
2. The top three risks and their potential business and regulatory impact for a 
   Singapore financial institution (reference MAS TRM where relevant)
3. Three specific recommended actions with clear business rationale

Rules:
- Write for a non-technical board audience — no jargon
- Be specific about MAS TRM obligations and the 60-minute notification requirement
- Be direct and action-oriented
- Maximum 300 words
- Do not use bullet points — use flowing paragraphs only"""

print(f"\nGenerating SPOTLIGHT board narrative for {ORG_NAME}...")
print("(Calling Claude API...)\n")

try:
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=800,
        messages=[{"role": "user", "content": PROMPT}]
    )
    narrative = message.content[0].text

    # ── Build report ───────────────────────────────────────────
    report = {
        "report_id":       f"RPT-{datetime.date.today().strftime('%Y%m%d')}-001",
        "generated_at":    datetime.datetime.utcnow().isoformat() + "Z",
        "organisation":    ORG_NAME,
        "report_type":     "Executive Board Brief",
        "period":          str(datetime.date.today()),
        "tes_average":     avg_tes,
        "findings_summary": {
            "total":   len(findings),
            "p0":      p0_count,
            "p1":      p1_count,
        },
        "compliance": {
            "mas_trm":  MAS_TRM_PCT,
            "nist_csf": NIST_CSF_PCT,
            "pdpa":     PDPA_PCT,
        },
        "top_findings":  top3,
        "ai_narrative":  narrative,
        "model_used":    "claude-sonnet-4-20250514",
        "ai_generated":  True,
        "human_reviewed":False,  # set True after CISO review
    }

    # Save JSON
    OUT = f"spotlight_report_{datetime.date.today().strftime('%Y%m%d')}.json"
    with open(OUT, "w") as f:
        json.dump(report, f, indent=2)

    # Print report
    print("="*65)
    print(f"  SPOTLIGHT — EXECUTIVE BOARD BRIEF")
    print(f"  {ORG_NAME}  ·  {datetime.date.today().strftime('%d %B %Y')}")
    print(f"  TES: {avg_tes}/10  ·  P0: {p0_count}  ·  MAS TRM: {MAS_TRM_PCT}%")
    print("="*65)
    print()
    print(narrative)
    print()
    print("="*65)
    print(f"  Saved → {OUT}")
    print(f"  Tokens used: {message.usage.input_tokens} in / {message.usage.output_tokens} out")
    print(f"  Approx cost: USD ${(message.usage.input_tokens * 3 + message.usage.output_tokens * 15) / 1_000_000:.4f}")
    print("="*65)

except anthropic.AuthenticationError:
    print("Invalid API key. Set: export ANTHROPIC_API_KEY=your-key-here")
except Exception as e:
    print(f"Error: {e}")
