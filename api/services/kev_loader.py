import json
import os
import random

# In-memory global store for all loaded findings
GLOBAL_FINDINGS = []

def load_kev_data():
    """Loads and parses the CISA KEV catalog into Tempris findings."""
    global GLOBAL_FINDINGS
    
    # Check if already loaded
    if len(GLOBAL_FINDINGS) > 0:
        return
        
    # 1. Load the PoC findings first
    spectrum_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'spectrum_findings.json')
    poc_cves = set()
    if os.path.exists(spectrum_path):
        with open(spectrum_path, 'r', encoding='utf-8') as f:
            poc_data = json.load(f)
            for idx, vuln in enumerate(poc_data.get("findings", [])):
                cve_id = vuln.get('cve_id', 'Unknown')
                if cve_id != 'Unknown':
                    poc_cves.add(cve_id)
                priority_code = "P0" # Force PoC demo vulnerabilities to be Critical
                finding = {
                    "id": f"#{2000 + idx}",
                    "cve": cve_id,
                    "title": vuln.get('name', 'Unknown'),
                    "vendor": "Demo Target",
                    "product": vuln.get('template_id', 'Unknown'),
                    "cvss": vuln.get('cvss_score', 5.0),
                    "priority": priority_code,
                    "status": "unmitigated",
                    "cisa": vuln.get('kev_flagged', False),
                    "ransomware": vuln.get('ransomware_linked', False),
                    "dateAdded": vuln.get('scanned_at', ''),
                    "shortDescription": f"Host: {vuln.get('host', '')}",
                    "requiredAction": "Investigate target asset",
                    "raw_inputs": {
                        "cvss": vuln.get('cvss_score', 5.0),
                        "exploitability": 10.0,
                        "business_impact": 9.5,
                        "asset_criticality": 8.0,
                        "threat_actor_activity": 9.0
                    },
                    "edip_decision": None
                }
                GLOBAL_FINDINGS.append(finding)
        print(f"Loaded {len(poc_cves)} PoC findings.")

    # 2. Load the rest from KEV
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cisa_kev_2026_05_22.json')
    
    if not os.path.exists(data_path):
        print(f"Warning: KEV data file not found at {data_path}")
        return
        
    with open(data_path, 'r', encoding='utf-8') as f:
        kev_data = json.load(f)
        
    vulnerabilities = kev_data.get('vulnerabilities', [])
    vulnerabilities.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
    high_risk_vendors = ['Fortinet', 'Cisco', 'Ivanti', 'Palo Alto Networks', 'Citrix', 'SonicWall']
    
    for idx, vuln in enumerate(vulnerabilities):
        cve = vuln.get('cveID', 'Unknown')
        if cve in poc_cves:
            continue
            
        vendor = vuln.get('vendorProject', 'Unknown')
        product = vuln.get('product', 'Unknown')
        name = vuln.get('vulnerabilityName', 'Unknown')
        ransomware_known = vuln.get('knownRansomwareCampaignUse', 'Unknown') == 'Known'
        base_cvss = 9.8 if ransomware_known else (8.5 if vendor in high_risk_vendors else 7.5)
        jitter = random.uniform(-0.5, 0.5) if not ransomware_known else 0
        cvss = min(10.0, round(base_cvss + jitter, 1))
        priority = 'P0' if (ransomware_known or cvss >= 9.0) else ('P1' if cvss >= 7.0 else 'P2')
        
        finding = {
            "id": f"#{1000 + idx}",
            "cve": cve,
            "title": name,
            "vendor": vendor,
            "product": product,
            "cvss": cvss,
            "priority": priority,
            "status": "unmitigated",
            "cisa": True,
            "ransomware": ransomware_known,
            "dateAdded": vuln.get('dateAdded', ''),
            "shortDescription": vuln.get('shortDescription', ''),
            "requiredAction": vuln.get('requiredAction', ''),
            "raw_inputs": {
                "cvss": cvss,
                "exploitability": 10.0,
                "business_impact": 9.5 if ransomware_known else 7.0,
                "asset_criticality": 8.0 if vendor in high_risk_vendors else 6.0,
                "threat_actor_activity": 9.0 if ransomware_known else 5.0
            },
            "edip_decision": None
        }
        GLOBAL_FINDINGS.append(finding)
        
    print(f"Loaded {len(GLOBAL_FINDINGS)} total vulnerabilities.")

def get_all_findings():
    if not GLOBAL_FINDINGS:
        load_kev_data()
    return GLOBAL_FINDINGS
