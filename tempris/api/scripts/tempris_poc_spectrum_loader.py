"""
Tempris Wave 1 Phase 1 — SPECTRUM Findings Loader
Reads Nuclei scan output, cross-references CISA KEV,
runs TES formula, and outputs SPECTRUM-ready JSON.

Usage:
    python3 tempris_poc_spectrum_loader.py

Prerequisites:
    pip install requests
    - scout_findings.jsonl   (from Nuclei scan)
    - cisa_kev_2026_05_22.json (from download)
"""

import json, datetime, os, sys

# ── Load CISA KEV ──────────────────────────────────────────────
KEV_FILE = "cisa_kev_2026_05_22.json"

if not os.path.exists(KEV_FILE):
    print(f"KEV file not found: {KEV_FILE}")
    print("Attempting live download from GitHub mirror...")
    try:
        import requests
        url = "https://raw.githubusercontent.com/BenjiTrapp/cisa-known-vuln-scraper/main/cisa-kev.json"
        r = requests.get(url, timeout=15)
        kev_data = r.json()
        with open(KEV_FILE, "w") as f:
            json.dump(kev_data, f, indent=2)
        print(f"Downloaded {kev_data['count']} KEV entries.")
    except Exception as e:
        print(f"Download failed: {e}")
        print("Place cisa_kev_2026_05_22.json in this folder and retry.")
        sys.exit(1)
else:
    with open(KEV_FILE) as f:
        kev_data = json.load(f)

kev_cves = {v["cveID"] for v in kev_data["vulnerabilities"]}
ransomware_cves = {
    v["cveID"] for v in kev_data["vulnerabilities"]
    if v.get("knownRansomwareCampaignUse") == "Known"
}
print(f"KEV loaded: {len(kev_cves)} entries, {len(ransomware_cves)} ransomware-linked")

# ── Load Nuclei findings ───────────────────────────────────────
NUCLEI_FILE = "scout_findings.jsonl"

if not os.path.exists(NUCLEI_FILE):
    print(f"\nNuclei output file not found: {NUCLEI_FILE}")
    print("Run: nuclei -u http://<TARGET> -severity critical,high,medium -jsonl -o scout_findings.jsonl")
    print("\nGenerating DEMO data instead (5 sample findings)...")

    # Demo findings for testing without a live scan
    demo_lines = [
        '{"template-id":"CVE-2017-5638","info":{"name":"Apache Struts RCE","severity":"critical","classification":{"cve-id":["CVE-2017-5638"],"cvss-score":10.0}},"host":"http://192.168.56.101","matched-at":"http://192.168.56.101/struts"}',
        '{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell RCE","severity":"critical","classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0}},"host":"http://192.168.56.101","matched-at":"http://192.168.56.101/log4j"}',
        '{"template-id":"CVE-2019-0708","info":{"name":"BlueKeep RDP RCE","severity":"critical","classification":{"cve-id":["CVE-2019-0708"],"cvss-score":9.8}},"host":"http://192.168.56.101","matched-at":"http://192.168.56.101:3389"}',
        '{"template-id":"CVE-2024-53704","info":{"name":"SonicWall Auth Bypass","severity":"high","classification":{"cve-id":["CVE-2024-53704"],"cvss-score":8.2}},"host":"http://192.168.56.101","matched-at":"http://192.168.56.101/vpn"}',
        '{"template-id":"apache-tomcat-manager","info":{"name":"Tomcat Manager Default Creds","severity":"medium","classification":{"cvss-score":5.8}},"host":"http://192.168.56.101","matched-at":"http://192.168.56.101:8080/manager"}',
    ]
    with open(NUCLEI_FILE, "w") as f:
        f.write("\n".join(demo_lines))
    print(f"Demo file created: {NUCLEI_FILE}")

# ── TES formula ────────────────────────────────────────────────
def calc_tes(cvss, exploitability, business_impact,
             asset_criticality, threat_activity):
    return round(
        (cvss / 10 * 0.35) +
        (exploitability    * 0.25) +
        (business_impact   * 0.20) +
        (asset_criticality * 0.12) +
        (threat_activity   * 0.08),
        2
    )

def tes_priority(tes):
    if tes >= 8.5:   return "P0 · Critical"
    if tes >= 7.0:   return "P1 · High"
    if tes >= 5.0:   return "P2 · Medium"
    if tes >= 3.0:   return "P3 · Low"
    return "P4 · Info"

# ── Parse findings ─────────────────────────────────────────────
findings = []
severity_to_impact = {
    "critical": 1.0, "high": 0.75,
    "medium": 0.5,   "low": 0.25, "info": 0.1
}

with open(NUCLEI_FILE) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            continue

        info           = hit.get("info", {})
        classification = info.get("classification", {})
        cve_list       = classification.get("cve-id", [])
        cve_id         = cve_list[0] if cve_list else None
        cvss_score     = float(classification.get("cvss-score", 5.0) or 5.0)
        severity       = info.get("severity", "medium").lower()

        kev_flag        = cve_id in kev_cves       if cve_id else False
        ransomware_flag = cve_id in ransomware_cves if cve_id else False

        # Exploitability weight
        if ransomware_flag:   exploitability = 1.0
        elif kev_flag:        exploitability = 0.9
        else:                 exploitability = 0.4

        business_impact   = severity_to_impact.get(severity, 0.5)
        asset_criticality = 0.7   # default — override from asset inventory
        threat_activity   = 0.9 if ransomware_flag else 0.3

        tes = calc_tes(cvss_score, exploitability,
                       business_impact, asset_criticality, threat_activity)

        findings.append({
            "id":                len(findings) + 1,
            "cve_id":            cve_id,
            "name":              info.get("name", "Unknown"),
            "severity_cvss":     severity.upper(),
            "cvss_score":        cvss_score,
            "host":              hit.get("host", ""),
            "matched_at":        hit.get("matched-at", ""),
            "template_id":       hit.get("template-id", ""),
            "kev_flagged":       kev_flag,
            "ransomware_linked": ransomware_flag,
            "tes_score":         tes,
            "tes_priority":      tes_priority(tes),
            "tes_breakdown": {
                "cvss_contrib":   round(cvss_score / 10 * 0.35, 3),
                "expl_contrib":   round(exploitability    * 0.25, 3),
                "impact_contrib": round(business_impact   * 0.20, 3),
                "crit_contrib":   round(asset_criticality * 0.12, 3),
                "threat_contrib": round(threat_activity   * 0.08, 3),
            },
            "edip_decision":     None,   # Mitigate | Accept | Transfer | Ignore
            "edip_notes":        "",
            "scanned_at":        datetime.datetime.utcnow().isoformat() + "Z",
        })

findings.sort(key=lambda x: x["tes_score"], reverse=True)

# ── Save output ────────────────────────────────────────────────
OUT = "spectrum_findings.json"
with open(OUT, "w") as f:
    json.dump({
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "kev_version": kev_data.get("catalogVersion", ""),
        "findings": findings
    }, f, indent=2)

# ── Print summary ──────────────────────────────────────────────
print(f"\n{'='*70}")
print(f"  SPECTRUM TES FINDINGS — {len(findings)} total")
print(f"{'='*70}")
print(f"  {'TES':>5}  {'Priority':<16} {'CVE':<18} {'Name'}")
print(f"  {'-'*66}")
for fi in findings:
    cve  = fi["cve_id"] or "—"
    name = fi["name"][:32]
    flags = ""
    if fi["ransomware_linked"]: flags = " 🔴 ransomware"
    elif fi["kev_flagged"]:     flags = " ⚠  KEV"
    print(f"  {fi['tes_score']:>5}  {fi['tes_priority']:<16} {cve:<18} {name}{flags}")

p0 = sum(1 for f in findings if "P0" in f["tes_priority"])
p1 = sum(1 for f in findings if "P1" in f["tes_priority"])
p2 = sum(1 for f in findings if "P2" in f["tes_priority"])
print(f"\n  P0 Critical : {p0}  |  P1 High : {p1}  |  P2 Medium : {p2}")
print(f"\n  Saved → {OUT}")
print("="*70)
