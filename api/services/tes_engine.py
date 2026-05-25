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
    TES = (CVSS ÷ 10 × 0.35) + (Exploitability × 0.25) + (Business Impact × 0.20) + (Asset Criticality × 0.12) + (Threat Actor Activity × 0.08)
    
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
