"""
EDIP Decision Engine — Automated Fix / Defer / Accept classification.

L3-01 through L3-10: Deterministic, explainable, business-context-aware.
Implements ISO/IEC 42001:2023 Clause 6.1.2 (AI Risk Assessment) principles
for automated security triage decisions.
"""


def auto_classify(
    cvss: float,
    asset_criticality: str = "medium",
    cisa_kev: bool = False,
    ransomware_linked: bool = False,
    has_compensating_control: bool = False,
    exploit_maturity: str = "unproven",
) -> dict:
    """
    Automated EDIP decision engine.
    
    L3-07: Deterministic — same inputs always produce same output.
    L3-08: Explainable — every decision includes plain-language reasoning.
    
    Returns:
        {
            "decision": "fix" | "defer" | "accept_candidate" | "manual",
            "confidence": float (0.0 to 1.0),
            "explanation": str,
            "auto_classified": True,
            "factors": dict
        }
    """
    factors = {
        "cvss": cvss,
        "asset_criticality": asset_criticality,
        "cisa_kev": cisa_kev,
        "ransomware_linked": ransomware_linked,
        "has_compensating_control": has_compensating_control,
        "exploit_maturity": exploit_maturity,
    }
    
    reasons = []
    
    # ── FIX decisions (immediate remediation required) ───────────────────
    
    # L3-01: Critical path — auto-FIX
    if cvss >= 9.0 and (asset_criticality == "critical" or cisa_kev):
        reasons.append(f"CVSS {cvss} (Critical) on {asset_criticality}-criticality asset")
        if cisa_kev:
            reasons.append("Listed in CISA Known Exploited Vulnerabilities catalog")
        if ransomware_linked:
            reasons.append("Linked to active ransomware campaigns")
        return {
            "decision": "fix",
            "confidence": 0.95,
            "explanation": f"AUTO-FIX: {'. '.join(reasons)}. Immediate remediation required per CTEM policy.",
            "auto_classified": True,
            "factors": factors,
        }
    
    # High CVSS + critical asset + KEV = FIX
    if cvss >= 7.0 and asset_criticality == "critical" and cisa_kev:
        reasons.append(f"CVSS {cvss} (High) on critical asset with active exploitation (CISA KEV)")
        return {
            "decision": "fix",
            "confidence": 0.90,
            "explanation": f"AUTO-FIX: {'. '.join(reasons)}. Business-critical asset at elevated risk.",
            "auto_classified": True,
            "factors": factors,
        }
    
    # Any ransomware-linked on critical/high asset = FIX
    if ransomware_linked and asset_criticality in ("critical", "high"):
        reasons.append(f"Ransomware-linked vulnerability on {asset_criticality}-criticality asset (CVSS {cvss})")
        return {
            "decision": "fix",
            "confidence": 0.88,
            "explanation": f"AUTO-FIX: {'. '.join(reasons)}. Ransomware risk requires immediate action.",
            "auto_classified": True,
            "factors": factors,
        }
    
    # High CVSS + proven exploit on high+ asset = FIX
    if cvss >= 7.0 and exploit_maturity in ("active", "weaponized", "poc") and asset_criticality in ("critical", "high"):
        reasons.append(f"CVSS {cvss} with {exploit_maturity} exploit on {asset_criticality} asset")
        return {
            "decision": "fix",
            "confidence": 0.85,
            "explanation": f"AUTO-FIX: {'. '.join(reasons)}. Active exploitation risk.",
            "auto_classified": True,
            "factors": factors,
        }
    
    # ── ACCEPT CANDIDATE (requires human approval — L3-03) ───────────────
    
    if cvss < 4.0 and not cisa_kev and not ransomware_linked:
        if has_compensating_control:
            reasons.append(f"Low severity (CVSS {cvss}) with documented compensating controls")
            reasons.append("Not in CISA KEV, no ransomware association")
            return {
                "decision": "accept_candidate",
                "confidence": 0.80,
                "explanation": f"ACCEPT CANDIDATE: {'. '.join(reasons)}. Requires human approval before acceptance.",
                "auto_classified": True,
                "factors": factors,
            }
    
    # ── DEFER decisions (scheduled for next review cycle) ────────────────
    
    # L3-02: Low risk path — auto-DEFER
    if cvss < 7.0 and asset_criticality in ("low", "medium") and not cisa_kev and not ransomware_linked:
        reasons.append(f"Moderate severity (CVSS {cvss}) on {asset_criticality}-criticality asset")
        reasons.append("No active exploitation indicators")
        confidence = 0.75 if cvss < 5.0 else 0.65
        return {
            "decision": "defer",
            "confidence": confidence,
            "explanation": f"AUTO-DEFER: {'. '.join(reasons)}. Scheduled for next review cycle.",
            "auto_classified": True,
            "factors": factors,
        }
    
    # ── MANUAL (requires human decision) ─────────────────────────────────
    
    # L3-04: Everything else requires human judgment
    reasons.append(f"CVSS {cvss} on {asset_criticality} asset")
    if cisa_kev:
        reasons.append("CISA KEV listed")
    if ransomware_linked:
        reasons.append("Ransomware linked")
    reasons.append("Mixed risk signals require human triage")
    
    return {
        "decision": "manual",
        "confidence": 0.0,
        "explanation": f"MANUAL REVIEW REQUIRED: {'. '.join(reasons)}.",
        "auto_classified": False,
        "factors": factors,
    }


def bulk_classify(findings: list[dict], asset_map: dict = None) -> list[dict]:
    """
    L3-09: Bulk classification — process 50+ findings efficiently.
    
    Args:
        findings: List of finding dicts with at minimum {cvss, ...}
        asset_map: Optional {asset_id: {criticality, ...}} lookup
    
    Returns:
        List of classification results
    """
    results = []
    for f in findings:
        asset_id = f.get("asset_id", "")
        asset_info = (asset_map or {}).get(asset_id, {})
        
        result = auto_classify(
            cvss=f.get("cvss", 0.0),
            asset_criticality=asset_info.get("criticality", f.get("asset_criticality", "medium")),
            cisa_kev=f.get("cisa_kev", f.get("ransomware", False)),
            ransomware_linked=f.get("ransomware", False),
            has_compensating_control=f.get("has_compensating_control", False),
            exploit_maturity=f.get("exploit_maturity", "unproven"),
        )
        result["finding_id"] = f.get("id", "")
        result["cve"] = f.get("cve", "")
        results.append(result)
    
    return results
