"""Defensive SCOUT connector normalizers required by the v62 debrief."""

import hmac
import os


PHONE_METHOD = "#microsoft.graph.phoneAuthenticationMethod"


def entra_authentication_method_findings(
    users: list[dict],
    *,
    escalation_date: str = "2027-02-01",
) -> list[dict]:
    """Create one identity-posture intake record per user with SMS/voice MFA."""
    findings = []
    for user in users:
        methods = user.get("authenticationMethods") or user.get("methods") or []
        deprecated = []
        for method in methods:
            method_type = method.get("@odata.type") or method.get("type")
            if method_type == PHONE_METHOD or str(method_type).endswith("phoneAuthenticationMethod"):
                deprecated.append(method.get("phoneType") or "phone")
        if not deprecated:
            continue
        principal = user.get("userPrincipalName") or user.get("mail") or user.get("id")
        findings.append({
            "finding_id": f"SSS-ENTRA-{user.get('id')}",
            "class": "IDENTITY_POSTURE",
            "sub_class": "MFA_ENROLMENT",
            "title": f"Legacy SMS/voice MFA enabled for {principal}",
            "description": "Microsoft Graph authenticationMethods reports legacy phone-based MFA factors.",
            "affected_ecosystem": "Microsoft Entra ID",
            "attack_vectors": ["SMS_MFA", "VOICE_MFA"],
            "base_severity": 7.0,
            "patch_available": True,
            "recommended_action": "PATCH",
            "itdr_source": "Microsoft Graph authenticationMethods",
            "escalation_date": escalation_date,
            "escalated_severity": "HIGH",
            "identity_subject": principal,
            "deprecated_methods": sorted(set(deprecated)),
        })
    return findings


def validate_aev_engagement_token(provided: str) -> None:
    """Fail closed unless the connector token is configured and matches."""
    expected = os.environ.get("AEV_VERDICT_ENGAGEMENT_TOKEN", "")
    if not expected:
        raise RuntimeError("AEV verdict connector is not configured")
    if not provided or not hmac.compare_digest(provided, expected):
        raise PermissionError("Invalid AEV engagement token")


def aev_verdict_finding(payload: dict) -> dict:
    """Normalize a third-party AEV verdict without inferring a decision."""
    verdict = str(payload.get("verdict", "")).lower()
    if verdict not in {"allowed", "detected", "prevented"}:
        raise ValueError("verdict must be allowed, detected, or prevented")
    validate_aev_engagement_token(str(payload.get("engagement_token", "")))
    return {
        "finding_id": payload.get("finding_id") or f"SSS-AEV-{payload['path_id']}",
        "class": payload.get("finding_class") or "VALIDATION_EVIDENCE",
        "sub_class": payload.get("sub_class"),
        "title": payload.get("title") or f"AEV validation verdict for {payload['path_id']}",
        "description": payload.get("description") or "Third-party validation evidence received by SCOUT.",
        "affected_ecosystem": payload.get("affected_ecosystem") or "SCOUT AEV",
        "base_severity": float(payload.get("base_severity", 7.0)),
        "patch_available": bool(payload.get("patch_available", True)),
        "recommended_action": payload.get("recommended_action") or "INVESTIGATE",
        "path_id": payload["path_id"],
        "verdict": verdict,
        "evidence_ref": payload["evidence_ref"],
        "revalidate_by": payload["revalidate_by"],
        "validated": True,
    }
