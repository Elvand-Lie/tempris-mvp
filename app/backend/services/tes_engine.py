from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

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
    TES = (CVSS ÃƒÂ· 10 Ãƒâ€” 0.35) + (Exploitability Ãƒâ€” 0.25) + (Business Impact Ãƒâ€” 0.20) + (Asset Criticality Ãƒâ€” 0.12) + (Threat Actor Activity Ãƒâ€” 0.08)
    
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


def calculate_sss_tes(scoring: dict, *, live_modifiers: dict | None = None) -> float:
    """Calculate non-CVE TES with a bounded server-side GRC adjustment."""
    base = float(scoring.get("base_severity", scoring.get("sss", 0.0)) or 0.0)
    context = live_modifiers or scoring
    agm = float(context.get("AGM", context.get("agm", 1.0)) or 1.0)
    drf = float(context.get("DRF", context.get("drf", 1.0)) or 1.0)
    tef = float(context.get("TEF", context.get("tef", 1.0)) or 1.0)
    combined_modifier = min(agm * drf * tef, 1.40)
    return round(min(base * combined_modifier, 10.0), 2)


_ASSET_CRITICALITY_VALUES = {"low": 2.0, "medium": 5.0, "high": 8.0, "critical": 10.0}
_OPEN_STATUSES = {"unmitigated", "open", "investigating", "in_progress", "pending"}
_NEUTRAL_UNASSESSED_BUSINESS_IMPACT = 5.0


def _number_0_to_10(value: object) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if 0.0 <= number <= 10.0 else None


def _finding_dict(finding: dict | Any) -> dict:
    if isinstance(finding, dict):
        return finding
    return {
        "id": getattr(finding, "id", None),
        "canonical_cve_id": getattr(finding, "canonical_cve_id", None),
        "cve": getattr(finding, "cve", None),
        "cve_id": getattr(finding, "cve_id", None),
        "title": getattr(finding, "title", None),
        "vendor": getattr(finding, "vendor", None),
        "product": getattr(finding, "product", None),
        "cvss": getattr(finding, "cvss", None),
        "priority": getattr(finding, "priority", None),
        "status": getattr(finding, "status", None),
        "cisa_kev": getattr(finding, "cisa_kev", None),
        "ransomware": getattr(finding, "ransomware", None),
        "cve_context": getattr(finding, "cve_context", None),
        "raw_inputs": getattr(finding, "raw_inputs", None),
        "sss_data": getattr(finding, "sss_data", None),
        "asset_data": getattr(finding, "asset_data", None),
    }


def _is_cve_finding(finding: dict | Any) -> bool:
    f_dict = _finding_dict(finding)
    return str(f_dict.get("cve") or f_dict.get("cve_id") or "").upper().startswith("CVE-")


def _context_score(context: dict, key: str) -> tuple[float | None, dict]:
    value = context.get(key)
    if not isinstance(value, dict):
        return None, {}
    score = _number_0_to_10(value.get("value", value.get("score")))
    if score is None:
        return None, {}
    return score, {
        "source": str(value.get("source") or "recorded_evidence"),
        "reason": str(value.get("reason") or "Recorded trusted evidence"),
        "last_verified_at": value.get("last_verified_at") or value.get("assessed_at"),
    }


def _nuclei_evidence_present(db, tenant_id: str, finding: dict | Any) -> bool:
    """Use only a recorded successful Nuclei match, never port/banner observations."""
    from models import ScanFinding
    from sqlalchemy import func, or_

    f_dict = _finding_dict(finding)
    clauses = [ScanFinding.normalized_finding_id == f_dict.get("id")]
    cve = str(f_dict.get("cve") or f_dict.get("cve_id") or "").upper()
    if cve:
        clauses.append(func.upper(ScanFinding.cve_id) == cve)
    rows = db.query(ScanFinding).filter(
        ScanFinding.tenant_id == tenant_id,
        or_(*clauses),
    ).all()
    return any(
        str((row.evidence_metadata or {}).get("engine") or "").lower() == "nuclei"
        or str(row.template_id or "").strip()
        for row in rows
    )


def get_live_cve_tes_context(finding: dict | Any, *, db, tenant_id: str) -> tuple[TESInputs, dict]:
    """Build CVE TES inputs from current tenant-owned data, never seed inputs."""
    if not _is_cve_finding(finding):
        raise ValueError("CVE TES context requires an exact CVE finding")

    f_dict = _finding_dict(finding)
    from services.cve_intelligence import resolve_vulnerability_intelligence

    intel = resolve_vulnerability_intelligence(finding, db)
    cvss = _number_0_to_10(intel.cvss_score)
    if cvss is None:
        raise ValueError("CVE finding has no valid stored CVSS metadata")

    from services.exposure_links import active_asset_map, confirmed_asset_ids_by_finding

    assets = active_asset_map(db, tenant_id)
    confirmed_ids = confirmed_asset_ids_by_finding(db, tenant_id, assets).get(f_dict.get("id"), set())
    linked_assets = [assets[asset_id] for asset_id in confirmed_ids if asset_id in assets]
    if not linked_assets:
        raise ValueError("CVE finding has no confirmed active customer asset")
    asset_score = max(_ASSET_CRITICALITY_VALUES.get((asset.criticality or "medium").lower(), 5.0) for asset in linked_assets)

    context = dict(f_dict.get("cve_context") or {})
    business_impact, business_source = _context_score(context, "business_impact")
    if business_impact is None:
        business_impact = _NEUTRAL_UNASSESSED_BUSINESS_IMPACT
        business_source = {"source": "unassessed_neutral_default", "reason": "Business impact has not been analyst assessed", "last_verified_at": None}

    exploitability, exploit_source = _context_score(context, "exploitability")
    threat_activity, threat_source = _context_score(context, "threat_actor_activity")
    ransomware = bool(intel.is_ransomware)
    kev = bool(intel.is_cisa_kev)
    last_verified = intel.kev_date_added or f_dict.get("updated_at") or f_dict.get("dateAdded")
    if exploitability is None:
        if ransomware:
            exploitability, exploit_source = 10.0, {"source": "ransomware_linked_intelligence", "reason": "Recorded ransomware-linked exploitation intelligence", "last_verified_at": last_verified}
        elif kev:
            exploitability, exploit_source = 8.0, {"source": "cisa_kev", "reason": "CISA Known Exploited Vulnerabilities membership", "last_verified_at": last_verified}
        elif _nuclei_evidence_present(db, tenant_id, f_dict):
            exploitability, exploit_source = 7.0, {"source": "nuclei_match", "reason": "Recorded successful Nuclei vulnerability evidence", "last_verified_at": None}
        else:
            exploitability, exploit_source = 0.0, {"source": "unknown_no_evidence", "reason": "No recorded exploit evidence", "last_verified_at": None}
    if threat_activity is None:
        if ransomware:
            threat_activity, threat_source = 10.0, {"source": "ransomware_linked_intelligence", "reason": "Recorded ransomware-linked threat activity", "last_verified_at": last_verified}
        elif kev:
            threat_activity, threat_source = 8.0, {"source": "cisa_kev", "reason": "CISA Known Exploited Vulnerabilities membership", "last_verified_at": last_verified}
        else:
            threat_activity, threat_source = 0.0, {"source": "unknown_no_evidence", "reason": "No recorded threat-activity evidence", "last_verified_at": None}

    return TESInputs(
        cvss=cvss,
        exploitability=exploitability,
        business_impact=business_impact,
        asset_criticality=asset_score,
        threat_actor_activity=threat_activity,
    ), {
        "business_impact": {"value": business_impact, "assessed": business_source["source"] != "unassessed_neutral_default", **business_source},
        "exploitability": exploit_source,
        "threat_actor_activity": threat_source,
        "asset_criticality": {"source": "confirmed_active_asset", "asset_count": len(linked_assets)},
        "vulnerability_intelligence": intel.to_dict(),
    }


def public_cve_context(finding: dict, *, db, tenant_id: str) -> dict:
    """Expose only the analyst-facing context state, never weighting internals."""
    _, context = get_live_cve_tes_context(finding, db=db, tenant_id=tenant_id)
    return {"business_impact": context["business_impact"]}


def recalculate_open_cve_findings(db, tenant_id: str, *, actor_id: str | None = None, reason: str) -> list[str]:
    """Persist current CVE scores for open confirmed exposures; leave history closed."""
    from models import Finding
    from services.customer_posture import canonical_exposure_rows, is_open
    from services.operational_events import record_operational_event

    confirmed_ids = {finding.id for finding, _, _ in canonical_exposure_rows(db, tenant_id, open_only=True)}
    changed: list[str] = []
    for finding in db.query(Finding).filter(Finding.tenant_id == tenant_id).all():
        if finding.id not in confirmed_ids or not is_open(finding):
            continue
        serialized = {
            "id": finding.id,
            "canonical_cve_id": getattr(finding, "canonical_cve_id", None),
            "cve": finding.cve,
            "cve_id": finding.cve_id,
            "cvss": finding.cvss,
            "cisa": finding.cisa_kev,
            "cisa_kev": finding.cisa_kev,
            "ransomware": finding.ransomware,
            "cve_context": finding.cve_context or {},
            "updated_at": finding.updated_at,
            "dateAdded": finding.date_added,
        }
        if not _is_cve_finding(serialized):
            continue
        try:
            score = calculate_tes(get_live_cve_tes_context(serialized, db=db, tenant_id=tenant_id)[0]).total_score
        except ValueError:
            continue
        previous = finding.score
        if previous == score:
            continue
        context = dict(finding.cve_context or {})
        history = list(context.get("scoring_history") or [])
        history.append({"at": datetime.now(timezone.utc).isoformat(), "reason": reason, "previous_score": previous})
        context["scoring_history"] = history[-50:]
        finding.cve_context = context
        finding.score = score
        finding.priority = priority_from_tes(score)
        finding.decision = public_decision_for_finding(serialized, score)
        changed.append(finding.id)
        record_operational_event(
            db, tenant_id=tenant_id, event_type="finding.cve_context_recalculated",
            resource_type="finding", resource_id=finding.id, source_module="SPECTRUM",
            actor_id=actor_id, metadata={"reason": reason},
        )
    return changed


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


def public_decision_for_finding(finding: dict | Any, score: float) -> str:
    """Return the public EDIP action without leaking modifier internals."""
    f_dict = _finding_dict(finding)
    sss = f_dict.get("sss_data") or {}
    engine_decision = str(sss.get("engine_decision") or "").upper()
    if engine_decision in {
        "ESCALATE", "PATCH", "INVESTIGATE", "DEFER", "COMPENSATING_CONTROL"
    }:
        return engine_decision
    if sss.get("patch_available") is False:
        return "COMPENSATING_CONTROL"
    return decision_from_tes(score)


def calculate_finding_tes(finding: dict | Any, *, db=None, tenant_id: str | None = None) -> float:
    """Calculate public TES for either CVE/CVSS or non-CVE/SSS findings."""
    f_dict = _finding_dict(finding)
    sss = f_dict.get("sss_data") or {}
    scoring = sss.get("scoring") or {}
    if not _is_cve_finding(finding):
        if db is not None and tenant_id:
            from services.grc_framework import get_live_grc_modifiers
            return calculate_sss_tes(scoring, live_modifiers=get_live_grc_modifiers(db, tenant_id))
        return calculate_sss_tes(scoring)
    if db is None or not tenant_id:
        raise ValueError("CVE TES requires tenant-scoped live context")
    inputs, _ = get_live_cve_tes_context(finding, db=db, tenant_id=tenant_id)
    return calculate_tes(inputs).total_score


def public_severity(finding: dict | Any, *, db=None) -> dict:
    """Return the inherent severity band, separate from TES priority."""
    f_dict = _finding_dict(finding)
    sss = f_dict.get("sss_data") or {}
    scoring = sss.get("scoring") or {}
    is_sss = not _is_cve_finding(finding) and bool(scoring.get("base_severity") or scoring.get("sss") or sss.get("class"))
    cvss_version = None
    cvss_source = None
    cvss_vector = None
    provenance = None
    if is_sss:
        raw_score = scoring.get("base_severity")
        source = "SSS"
    elif db is not None:
        from services.cve_intelligence import resolve_vulnerability_intelligence
        intel = resolve_vulnerability_intelligence(finding, db)
        raw_score = intel.cvss_score
        cvss_version = intel.cvss_version
        cvss_source = intel.cvss_source
        cvss_vector = intel.cvss_vector
        provenance = intel.provenance_classification
        source = "Legacy unprovenanced" if provenance == "legacy_unprovenanced" else ("CVSS" if raw_score is not None else None)
    else:
        raw_score = f_dict.get("cvss")
        provenance = f_dict.get("provenance_classification")
        source = "Legacy unprovenanced" if provenance == "legacy_unprovenanced" else ("CVSS" if raw_score is not None else None)

    if raw_score is None:
        return {
            "score": None,
            "label": "Not available",
            "source": None,
            "version": None,
            "source_authority": None,
            "vector": None,
            "provenance": provenance or "unassessed",
        }

    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        return {
            "score": None,
            "label": "Not available",
            "source": None,
            "version": None,
            "source_authority": None,
            "vector": None,
            "provenance": provenance or "unassessed",
        }

    return {
        "score": round(score, 2),
        "label": severity_from_score(score),
        "source": source,
        "version": cvss_version,
        "source_authority": cvss_source,
        "vector": cvss_vector,
        "provenance": provenance,
    }

