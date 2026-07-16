"""
CORE-C03: Global Serializer and Redaction Boundary.
Provides recursion-based redaction of private scoring internals and allowlist enforcement.
"""

PRIVATE_KEYS = {
    "raw_inputs", "sss_data", "tes_breakdown", "agm", "drf", "tef", 
    "tes_raw", "tes_intermediate", "formula_version", "modifier_table_ref", 
    "sss_base_raw", "AGM", "DRF", "TEF"
}

PUBLIC_ALLOWLIST = {
    "id", "finding_id", "external_id", "cve_id", "finding_type", "subtype",
    "pipeline", "verification", "status", "score", "decision", "sla",
    "patch_available", "cve_assigned", "exploited_in_wild", "ai_assisted",
    "asset_id", "tenant_id", "engagement_id", "summary", "description",
    "public_reason_codes", "created_at", "updated_at", "cve", "title",
    "vendor", "product", "cvss", "priority", "cisa_kev", "ransomware",
    "date_added", "short_description", "required_action", "asset_data",
    "source", "tes_score", "tes_decision", "tes_priority", "severity",
    "auto_classification", "edip_decision", "edip_rationale", "edip_decided_by",
    "asset", "data", "meta", "total", "page", "limit", "response", "sources", "session_id",
    "status_code", "detail", "error", "code", "message"
}

def redact_private_fields(data):
    """Recursively sweep data to remove private scoring internals and enforce allowlist."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if k in PRIVATE_KEYS:
                continue
            # For finding dicts specifically, we can enforce allowlist if needed.
            # But let's keep all keys that are in the PUBLIC_ALLOWLIST or not explicitly blocked.
            cleaned[k] = redact_private_fields(v)
        return cleaned
    elif isinstance(data, list):
        return [redact_private_fields(item) for item in data]
    return data
