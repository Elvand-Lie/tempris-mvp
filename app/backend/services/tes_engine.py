from pydantic import BaseModel

class TESInputs(BaseModel):
    cvss: float
    exploitability: float  # 0 to 10
    business_impact: float  # 0 to 10
    asset_criticality: float  # 0 to 10
    threat_actor_activity: float  # 0 to 10

class TESBreakdown(BaseModel):
    cvss_component: float
    exploitability_component: float
    business_impact_component: float
    asset_criticality_component: float
    threat_actor_component: float
    total_score: float

def calculate_tes(inputs: TESInputs) -> TESBreakdown:
    """
    Calculates the Tempris Exposure Score based on the formula from the Wave 1 MVP Proposal:
    TES = (CVSS Ã· 10 Ã— 0.35) + (Exploitability Ã— 0.25) + (Business Impact Ã— 0.20) + (Asset Criticality Ã— 0.12) + (Threat Actor Activity Ã— 0.08)
    
    Note: The proposal has CVSS / 10 * 0.35, which yields a max of 0.35 if CVSS is 10.
    Since the other factors are raw scores 0-10, we need to normalize them to max 10 overall.
    Formula interpreted:
    Total = (CVSS * 0.35) + (Exploitability * 0.25) + (Business Impact * 0.20) + (Asset Criticality * 0.12) + (Threat Actor * 0.08)
    """
    
    cvss_comp = inputs.cvss * 0.35
    exp_comp = inputs.exploitability * 0.25
    biz_comp = inputs.business_impact * 0.20
    asset_comp = inputs.asset_criticality * 0.12
    threat_comp = inputs.threat_actor_activity * 0.08
    
    total = cvss_comp + exp_comp + biz_comp + asset_comp + threat_comp
    
    return TESBreakdown(
        cvss_component=round(cvss_comp, 2),
        exploitability_component=round(exp_comp, 2),
        business_impact_component=round(biz_comp, 2),
        asset_criticality_component=round(asset_comp, 2),
        threat_actor_component=round(threat_comp, 2),
        total_score=round(total, 2)
    )


def calculate_sss_tes(scoring: dict) -> float:
    """Calculate non-CVE TES from SSS inputs, capped at 10.0."""
    base = float(scoring.get("base_severity", scoring.get("sss", 0.0)) or 0.0)
    agm = float(scoring.get("AGM", scoring.get("agm", 1.0)) or 1.0)
    drf = float(scoring.get("DRF", scoring.get("drf", 1.0)) or 1.0)
    tef = float(scoring.get("TEF", scoring.get("tef", 1.0)) or 1.0)
    return round(min(base * agm * drf * tef, 10.0), 2)


def severity_from_score(score: float) -> str:
    """Map CVSS/SSS base severity to a public severity band."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def priority_from_tes(score: float) -> str:
    """Map calculated TES to Tempris priority."""
    if score >= 9.0:
        return "P0"
    if score >= 7.0:
        return "P1"
    if score >= 4.0:
        return "P2"
    return "P3"


def decision_from_tes(score: float) -> str:
    if score >= 9.0:
        return "ESCALATE"
    if score >= 7.0:
        return "PATCH"
    if score >= 4.0:
        return "INVESTIGATE"
    return "DEFER"


def public_decision_for_finding(finding: dict, score: float) -> str:
    """Return the public EDIP action without leaking modifier internals."""
    sss = finding.get("sss_data") or {}
    if sss.get("patch_available") is False:
        return "COMPENSATING_CONTROL"
    return decision_from_tes(score)


def calculate_finding_tes(finding: dict) -> float:
    """Calculate public TES for either CVE/CVSS or non-CVE/SSS findings."""
    sss = finding.get("sss_data") or {}
    scoring = sss.get("scoring") or {}
    finding_type = (sss.get("type") or "").upper()
    source = (finding.get("source") or "").lower()
    if source == "sss" or "NON_CVE" in finding_type or scoring.get("base_severity") and not str(finding.get("cve", "")).startswith("CVE-"):
        return calculate_sss_tes(scoring)
    inputs = TESInputs(**finding["raw_inputs"])
    return calculate_tes(inputs).total_score


def public_severity(finding: dict) -> dict:
    """Return the inherent severity band, separate from TES priority."""
    sss = finding.get("sss_data") or {}
    scoring = sss.get("scoring") or {}
    source = (finding.get("source") or "").lower()
    is_sss = source == "sss" or not str(finding.get("cve", "")).startswith("CVE-")
    score = float(scoring.get("base_severity") if is_sss else finding.get("cvss") or 0.0)
    return {
        "score": round(score, 2),
        "label": severity_from_score(score),
        "source": "SSS" if is_sss else "CVSS",
    }

