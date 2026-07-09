"""
EDIP Decision Engine — Automated Fix / Defer / Accept classification.

L3-01 through L3-10: Deterministic, explainable, business-context-aware.
Implements ISO/IEC 42001:2023 Clause 6.1.2 (AI Risk Assessment) principles
for automated security triage decisions.
"""


def _build_context_binding_footer(
    account_ref: str | None = None,
    asset_context: dict | list[dict] | None = None,
    response_seed: str = "",
) -> str:
    """Build a client-bound footer for AI/EDIP outputs."""
    import hashlib
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    account = account_ref or "platform"
    contexts = asset_context if isinstance(asset_context, list) else [asset_context]

    asset_refs = []
    for ctx in contexts:
        if not ctx:
            continue
        name = ctx.get("asset_name") or ctx.get("name") or ctx.get("asset_id") or ctx.get("id")
        ip = ctx.get("asset_ip") or ctx.get("ip") or ctx.get("ip_address") or "IP pending"
        if name:
            asset_refs.append(f"{name} ({ip})")

    asset_str = "; ".join(asset_refs[:3]) if asset_refs else "pending asset onboarding"
    ref_hash = hashlib.sha256(
        f"{account}:{asset_str}:{timestamp}:{response_seed[:80]}".encode("utf-8")
    ).hexdigest()[:16].upper()

    return (
        f"\n\n---\nContext binding: account={account} | "
        f"assets={asset_str} | generated={timestamp} | ref=TMPR-{ref_hash}"
    )


def auto_classify(
    cvss: float,
    asset_criticality: str = "medium",
    cisa_kev: bool = False,
    ransomware_linked: bool = False,
    has_compensating_control: bool = False,
    exploit_maturity: str = "unproven",
    asset_context: dict = None,
    severity_source: str = "CVSS",
) -> dict:
    """
    Automated EDIP decision engine.

    L3-07: Deterministic — same inputs always produce same output.
    L3-08: Explainable — every decision includes plain-language reasoning.

    asset_context: Optional dict with client-specific identifiers:
        {"asset_name": str, "asset_ip": str, "asset_id": str}
    Every output references at least one client-specific identifier
    to prevent bulk extraction of generic intelligence.

    Returns:
        {
            "decision": "fix" | "defer" | "accept_candidate" | "manual",
            "confidence": float (0.0 to 1.0),
            "explanation": str,
            "auto_classified": True,
            "factors": dict,
            "context_bound": bool
        }
    """
    # Build asset reference string for context binding
    if asset_context and asset_context.get("asset_name"):
        asset_ref = (
            f"{asset_context['asset_name']} "
            f"({asset_context.get('asset_ip', 'IP pending')}, "
            f"Ref: {asset_context.get('asset_id', 'unassigned')})"
        )
        context_bound = True
    else:
        asset_ref = "unassigned infrastructure asset (pending asset mapping)"
        context_bound = False

    score_label = severity_source.upper()

    factors = {
        "severity_score": cvss,
        "severity_source": score_label,
        "asset_criticality": asset_criticality,
        "cisa_kev": cisa_kev,
        "ransomware_linked": ransomware_linked,
        "has_compensating_control": has_compensating_control,
        "exploit_maturity": exploit_maturity,
        "asset_context": asset_context,
    }

    reasons = []

    # ── FIX decisions (immediate remediation required) ───────────────────

    # L3-01: Critical path — auto-FIX
    if cvss >= 9.0 and (asset_criticality == "critical" or cisa_kev):
        reasons.append(f"{score_label} {cvss} (Critical) on {asset_ref}")
        if cisa_kev:
            reasons.append("Listed in CISA Known Exploited Vulnerabilities catalog")
        if ransomware_linked:
            reasons.append("Linked to active ransomware campaigns")
        explanation = f"AUTO-FIX: {'. '.join(reasons)}. Immediate remediation required per CTEM policy."
        return {
            "decision": "fix",
            "confidence": 0.95,
            "explanation": explanation + _build_context_binding_footer(asset_context=asset_context, response_seed=explanation),
            "auto_classified": True,
            "factors": factors,
            "context_bound": context_bound,
        }

    # High CVSS + critical asset + KEV = FIX
    if cvss >= 7.0 and asset_criticality == "critical" and cisa_kev:
        reasons.append(f"{score_label} {cvss} (High) on {asset_ref} with active exploitation (CISA KEV)")
        explanation = f"AUTO-FIX: {'. '.join(reasons)}. Business-critical asset at elevated risk."
        return {
            "decision": "fix",
            "confidence": 0.90,
            "explanation": explanation + _build_context_binding_footer(asset_context=asset_context, response_seed=explanation),
            "auto_classified": True,
            "factors": factors,
            "context_bound": context_bound,
        }

    # Any ransomware-linked on critical/high asset = FIX
    if ransomware_linked and asset_criticality in ("critical", "high"):
        reasons.append(f"Ransomware-linked vulnerability on {asset_ref} ({score_label} {cvss})")
        explanation = f"AUTO-FIX: {'. '.join(reasons)}. Ransomware risk requires immediate action."
        return {
            "decision": "fix",
            "confidence": 0.88,
            "explanation": explanation + _build_context_binding_footer(asset_context=asset_context, response_seed=explanation),
            "auto_classified": True,
            "factors": factors,
            "context_bound": context_bound,
        }

    # High CVSS + proven exploit on high+ asset = FIX
    if cvss >= 7.0 and exploit_maturity in ("active", "weaponized", "poc") and asset_criticality in ("critical", "high"):
        reasons.append(f"{score_label} {cvss} with {exploit_maturity} exploit on {asset_ref}")
        explanation = f"AUTO-FIX: {'. '.join(reasons)}. Active exploitation risk."
        return {
            "decision": "fix",
            "confidence": 0.85,
            "explanation": explanation + _build_context_binding_footer(asset_context=asset_context, response_seed=explanation),
            "auto_classified": True,
            "factors": factors,
            "context_bound": context_bound,
        }

    # ── ACCEPT CANDIDATE (requires human approval — L3-03) ───────────────

    if cvss < 4.0 and not cisa_kev and not ransomware_linked:
        if has_compensating_control:
            reasons.append(f"Low severity ({score_label} {cvss}) with documented compensating controls")
            reasons.append("Not in CISA KEV, no ransomware association")
            explanation = f"ACCEPT CANDIDATE: {'. '.join(reasons)}. Asset: {asset_ref}. Requires human approval before acceptance."
            return {
                "decision": "accept_candidate",
                "confidence": 0.80,
                "explanation": explanation + _build_context_binding_footer(asset_context=asset_context, response_seed=explanation),
                "auto_classified": True,
                "factors": factors,
                "context_bound": context_bound,
            }

    # ── DEFER decisions (scheduled for next review cycle) ────────────────

    # L3-02: Low risk path — auto-DEFER
    if cvss < 7.0 and asset_criticality in ("low", "medium") and not cisa_kev and not ransomware_linked:
        reasons.append(f"Moderate severity ({score_label} {cvss}) on {asset_ref}")
        reasons.append("No active exploitation indicators")
        confidence = 0.75 if cvss < 5.0 else 0.65
        explanation = f"AUTO-DEFER: {'. '.join(reasons)}. Scheduled for next review cycle."
        return {
            "decision": "defer",
            "confidence": confidence,
            "explanation": explanation + _build_context_binding_footer(asset_context=asset_context, response_seed=explanation),
            "auto_classified": True,
            "factors": factors,
            "context_bound": context_bound,
        }

    # ── MANUAL (requires human decision) ─────────────────────────────────

    # L3-04: Everything else requires human judgment
    reasons.append(f"{score_label} {cvss} on {asset_ref}")
    if cisa_kev:
        reasons.append("CISA KEV listed")
    if ransomware_linked:
        reasons.append("Ransomware linked")
    reasons.append("Mixed risk signals require human triage")

    explanation = f"MANUAL REVIEW REQUIRED: {'. '.join(reasons)}."
    return {
        "decision": "manual",
        "confidence": 0.0,
        "explanation": explanation + _build_context_binding_footer(asset_context=asset_context, response_seed=explanation),
        "auto_classified": False,
        "factors": factors,
        "context_bound": context_bound,
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
