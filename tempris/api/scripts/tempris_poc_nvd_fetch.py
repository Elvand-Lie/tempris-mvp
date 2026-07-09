"""
Tempris Wave 1 Phase 1 — NVD CVE Fetcher
Pulls latest critical CVEs from NIST NVD API v2,
cross-references CISA KEV, and outputs SPECTRUM-ready JSON.

Usage:
    python3 tempris_poc_nvd_fetch.py

Get a free NVD API key (increases rate limit):
    https://nvd.nist.gov/developers/request-an-api-key

Set your key:
    export NVD_API_KEY=your-key-here
    python3 tempris_poc_nvd_fetch.py
"""

import requests, json, time, os, datetime

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL     = "https://raw.githubusercontent.com/BenjiTrapp/cisa-known-vuln-scraper/main/cisa-kev.json"
KEV_FILE    = "cisa_kev_2026_05_22.json"

# ── Load KEV ───────────────────────────────────────────────────
print("Loading CISA KEV...")
if os.path.exists(KEV_FILE):
    with open(KEV_FILE) as f:
        kev_data = json.load(f)
else:
    kev_data = requests.get(KEV_URL, timeout=15).json()
    with open(KEV_FILE, "w") as f:
        json.dump(kev_data, f, indent=2)

kev_cves = {v["cveID"] for v in kev_data["vulnerabilities"]}
ransomware_cves = {
    v["cveID"] for v in kev_data["vulnerabilities"]
    if v.get("knownRansomwareCampaignUse") == "Known"
}
print(f"KEV: {len(kev_cves)} entries, {len(ransomware_cves)} ransomware-linked")

# ── Fetch from NVD ─────────────────────────────────────────────
headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
delay   = 0.6 if NVD_API_KEY else 6.0

params = {
    "cvssV3Severity":  "CRITICAL",
    "resultsPerPage":  50,
    "startIndex":      0,
}

print(f"\nFetching CVEs from NVD API{'(no key — slow mode)' if not NVD_API_KEY else ''}...")
try:
    r = requests.get(NVD_BASE, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    data       = r.json()
    total      = data.get("totalResults", 0)
    nvd_vulns  = data.get("vulnerabilities", [])
    print(f"Retrieved {len(nvd_vulns)} of {total} critical CVEs")
except Exception as e:
    print(f"NVD API error: {e}")
    print("Check your internet connection or try again later.")
    exit(1)

# ── TES scoring ────────────────────────────────────────────────
def calc_tes(cvss, expl, impact, crit, threat):
    return round(
        (cvss/10 * 0.35) + (expl * 0.25) +
        (impact  * 0.20) + (crit * 0.12) + (threat * 0.08),
        2
    )

def tes_priority(tes):
    if tes >= 8.5: return "P0 · Critical"
    if tes >= 7.0: return "P1 · High"
    if tes >= 5.0: return "P2 · Medium"
    return "P3 · Low"

findings = []
for item in nvd_vulns:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # Get CVSS score
    metrics = cve.get("metrics", {})
    cvss_score = 0.0
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]:
        entries = metrics.get(key, [])
        if entries:
            cvss_score = float(
                entries[0].get("cvssData", {}).get("baseScore", 0)
            )
            break

    # Description
    descs = cve.get("descriptions", [])
    desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

    # KEV flags
    kev_flag        = cve_id in kev_cves
    ransomware_flag = cve_id in ransomware_cves

    # CISA KEV fields from NVD (if present)
    kev_due    = cve.get("cisaActionDue", "")
    kev_action = cve.get("cisaRequiredAction", "")

    # TES weights
    if ransomware_flag:   expl = 1.0
    elif kev_flag:        expl = 0.9
    else:                 expl = 0.35

    impact = min(1.0, cvss_score / 10)
    crit   = 0.7
    threat = 0.9 if ransomware_flag else 0.25

    tes = calc_tes(cvss_score, expl, impact, crit, threat)

    findings.append({
        "cve_id":            cve_id,
        "description":       desc[:200],
        "cvss_score":        cvss_score,
        "kev_flagged":       kev_flag,
        "ransomware_linked": ransomware_flag,
        "kev_due_date":      kev_due,
        "kev_required_action": kev_action,
        "tes_score":         tes,
        "tes_priority":      tes_priority(tes),
        "tes_breakdown": {
            "cvss_contrib":   round(cvss_score/10 * 0.35, 3),
            "expl_contrib":   round(expl   * 0.25, 3),
            "impact_contrib": round(impact * 0.20, 3),
            "crit_contrib":   round(crit   * 0.12, 3),
            "threat_contrib": round(threat * 0.08, 3),
        },
        "edip_decision": None,
        "fetched_at":    datetime.datetime.utcnow().isoformat() + "Z",
    })

findings.sort(key=lambda x: x["tes_score"], reverse=True)

# Save
OUT = "nvd_spectrum_findings.json"
with open(OUT, "w") as f:
    json.dump({
        "generated_at":   datetime.datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "kev_version":    kev_data.get("catalogVersion", ""),
        "findings":       findings
    }, f, indent=2)

# Summary
print(f"\n{'='*70}")
print(f"  NVD → SPECTRUM FINDINGS — {len(findings)} critical CVEs scored")
print(f"{'='*70}")
print(f"  {'TES':>5}  {'Priority':<16} {'CVE':<18} {'Flags'}")
print(f"  {'-'*66}")
for fi in findings[:20]:
    flags = ""
    if fi["ransomware_linked"]: flags = "🔴 ransomware"
    elif fi["kev_flagged"]:     flags = "⚠  KEV"
    print(f"  {fi['tes_score']:>5}  {fi['tes_priority']:<16} {fi['cve_id']:<18} {flags}")

p0 = sum(1 for f in findings if "P0" in f["tes_priority"])
p1 = sum(1 for f in findings if "P1" in f["tes_priority"])
print(f"\n  P0 Critical: {p0}  |  P1 High: {p1}")
print(f"  Saved → {OUT}")
print("="*70)
