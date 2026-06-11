"""
CISA KEV Loader — Production
Loads the Known Exploited Vulnerabilities catalog and maps findings
to internal assets using Vendor + Product matching.
"""
import json
import os

# In-memory global store for all loaded findings
GLOBAL_FINDINGS = []

# ── Vendor/Product → Asset Mapping ───────────────────────────────────────────
# Maps CISA KEV vendor/product strings to internal asset IDs.
# Built dynamically from the assets table at load time.

VENDOR_ASSET_MAP = {}

def _build_vendor_asset_map():
    """Build mapping from vendor/product keywords to asset IDs using DB assets."""
    global VENDOR_ASSET_MAP
    try:
        from services.database import SessionLocal
        from models import Asset
        db = SessionLocal()
        assets = db.query(Asset).filter(Asset.status == "active").all()
        db.close()

        VENDOR_ASSET_MAP = {}
        for asset in assets:
            # Build searchable keyword set from asset name + tags
            keywords = set()
            # Extract keywords from the asset name (lowercased)
            for word in asset.name.lower().split():
                if len(word) > 2:
                    keywords.add(word)
            # Add tags as keywords
            if asset.tags:
                for tag in asset.tags:
                    keywords.add(tag.lower())

            VENDOR_ASSET_MAP[asset.id] = {
                "name": asset.name,
                "criticality": asset.criticality,
                "ip_address": asset.ip_address,
                "keywords": keywords,
            }
        print(f"KEV: Built vendor-to-asset map for {len(VENDOR_ASSET_MAP)} assets.")
    except Exception as e:
        print(f"KEV: Could not build asset map: {e}")


def _match_finding_to_asset(vendor: str, product: str) -> dict | None:
    """Match a CISA KEV finding to an internal asset using vendor+product keywords.
    Returns {"asset_id": str, "asset_name": str} or None.
    """
    if not VENDOR_ASSET_MAP:
        return None

    vendor_lower = vendor.lower().strip()
    product_lower = product.lower().strip()

    best_match = None
    best_score = 0

    for asset_id, asset_info in VENDOR_ASSET_MAP.items():
        score = 0
        keywords = asset_info["keywords"]

        # Check if vendor name matches any keyword
        for word in vendor_lower.split():
            if len(word) > 2 and word in keywords:
                score += 3  # Vendor match is strong signal

        # Check if product name matches any keyword
        for word in product_lower.split():
            if len(word) > 2 and word in keywords:
                score += 2  # Product match

        # Exact vendor match (single word vendors like "cisco", "fortinet")
        if vendor_lower in keywords:
            score += 5

        if score > best_score:
            best_score = score
            best_match = {
                "asset_id": asset_id,
                "asset_name": asset_info["name"],
                "asset_criticality": asset_info["criticality"],
                "asset_ip": asset_info["ip_address"],
                "match_score": score,
            }

    # Only return if we have a meaningful match (score >= 3)
    return best_match if best_score >= 3 else None


def _score_kev_vulnerability(vuln: dict, high_risk_vendors: list[str]) -> tuple[float, str, dict]:
    """Derive a stable severity score from KEV fields when CVSS is not present.

    The CISA KEV catalog does not ship CVSS/severity. The previous fallback put
    every non-critical item at 7.0+, which made Medium/P2 impossible.
    """
    vendor = vuln.get("vendorProject", "Unknown")
    ransomware_known = vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known"
    text = " ".join([
        vuln.get("vulnerabilityName", ""),
        vuln.get("shortDescription", ""),
        vuln.get("requiredAction", ""),
    ]).lower()

    if ransomware_known:
        cvss = 9.8
        business_impact = 9.5
        asset_criticality = 8.0
        threat_actor_activity = 9.0
    elif any(term in text for term in [
        "remote code execution",
        "arbitrary code execution",
        "execute arbitrary code",
        "full system compromise",
        "authentication bypass",
        "unauthenticated",
        "sql injection",
        "command injection",
    ]):
        cvss = 8.8 if vendor in high_risk_vendors else 8.2
        business_impact = 8.0
        asset_criticality = 8.0 if vendor in high_risk_vendors else 6.5
        threat_actor_activity = 6.5
    elif any(term in text for term in [
        "privilege escalation",
        "elevate privileges",
        "path traversal",
        "directory traversal",
        "deserialization",
        "server-side request forgery",
        "ssrf",
        "security feature bypass",
    ]):
        cvss = 7.4 if vendor in high_risk_vendors else 7.0
        business_impact = 7.0
        asset_criticality = 7.0 if vendor in high_risk_vendors else 6.0
        threat_actor_activity = 5.5
    elif any(term in text for term in [
        "denial of service",
        "information disclosure",
        "cross-site scripting",
        "spoofing",
        "out-of-bounds read",
    ]):
        cvss = 6.4
        business_impact = 5.5
        asset_criticality = 6.0
        threat_actor_activity = 5.0
    else:
        cvss = 6.8
        business_impact = 6.0
        asset_criticality = 6.0
        threat_actor_activity = 5.0

    priority = "P0" if cvss >= 9.0 else ("P1" if cvss >= 7.0 else "P2")
    raw_inputs = {
        "cvss": cvss,
        "exploitability": 10.0,
        "business_impact": business_impact,
        "asset_criticality": asset_criticality,
        "threat_actor_activity": threat_actor_activity,
    }
    return cvss, priority, raw_inputs


def load_kev_data():
    """Loads and parses the CISA KEV catalog into Tempris findings."""
    global GLOBAL_FINDINGS

    # Check if already loaded
    if len(GLOBAL_FINDINGS) > 0:
        return

    # Build the asset mapping first
    _build_vendor_asset_map()

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
                    "id": f"F-{2000 + idx}",
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
                    "edip_decision": None,
                    "edip_rationale": None,
                    "asset": None,
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

    mapped_count = 0
    for idx, vuln in enumerate(vulnerabilities):
        cve = vuln.get('cveID', 'Unknown')
        if cve in poc_cves:
            continue

        vendor = vuln.get('vendorProject', 'Unknown')
        product = vuln.get('product', 'Unknown')
        name = vuln.get('vulnerabilityName', 'Unknown')
        ransomware_known = vuln.get('knownRansomwareCampaignUse', 'Unknown') == 'Known'
        cvss, priority, raw_inputs = _score_kev_vulnerability(vuln, high_risk_vendors)

        # Match to internal asset
        asset_match = _match_finding_to_asset(vendor, product)
        if asset_match:
            mapped_count += 1
            # Boost criticality if the matched asset is critical
            if asset_match["asset_criticality"] == "critical":
                cvss = min(10.0, cvss + 0.2)
                raw_inputs["cvss"] = cvss
                raw_inputs["asset_criticality"] = max(raw_inputs["asset_criticality"], 8.0)
                priority = "P0" if cvss >= 9.0 else ("P1" if cvss >= 7.0 else "P2")

        finding = {
            "id": f"F-{1000 + idx}",
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
            "raw_inputs": raw_inputs,
            "edip_decision": None,
            "edip_rationale": None,
            "asset": asset_match,
        }
        GLOBAL_FINDINGS.append(finding)

    print(f"Loaded {len(GLOBAL_FINDINGS)} total vulnerabilities. {mapped_count} mapped to internal assets.")

def get_all_findings():
    if not GLOBAL_FINDINGS:
        load_kev_data()
    return GLOBAL_FINDINGS
