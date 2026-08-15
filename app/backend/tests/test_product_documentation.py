import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "docs" / "product"
REQUIRED = {
    "README.md",
    "TEMPRIS_MODULE_CATALOG.md",
    "TEMPRIS_METRIC_DICTIONARY.md",
    "TEMPRIS_DATA_FLOW_AND_LIFECYCLE.md",
    "TEMPRIS_ACTIONS_PERMISSIONS_AND_SIDE_EFFECTS.md",
    "TEMPRIS_SCORING_CONTRACT.md",
    "TEMPRIS_API_AND_STORAGE_MAP.md",
    "TEMPRIS_TELEMETRY_EVENT_CATALOG.md",
    "TEMPRIS_KNOWN_LIMITATIONS_AND_DECISIONS.md",
    "TEMPRIS_CANONICALIZATION_CHANGELOG.md",
    "tempris_data_dictionary.yaml",
}
MODULES = {
    "synthesis", "spectrum", "scout", "strike", "standard", "grc", "assets",
    "spotlight", "ciso", "client_reports", "tenant_access", "intake_triage",
    "vdp_queue", "audit_log", "speak",
}


def test_required_product_documentation_and_yaml_are_valid():
    assert REQUIRED <= {path.name for path in DOCS.iterdir()}
    data = yaml.safe_load((DOCS / "tempris_data_dictionary.yaml").read_text(encoding="utf-8"))
    assert data["canonical_scope_version"] == "canonical-customer-exposure-v1"
    assert set(data["modules"]) == MODULES


def test_metric_ids_are_unique_and_api_paths_are_registered_or_unverified():
    data = yaml.safe_load((DOCS / "tempris_data_dictionary.yaml").read_text(encoding="utf-8"))
    metric_ids = [
        metric["id"]
        for module in data["modules"].values()
        for metric in module.get("metrics", [])
    ]
    assert len(metric_ids) == len(set(metric_ids))

    from index import app

    registered = set(app.openapi()["paths"])
    for module in data["modules"].values():
        for reference in module.get("api_routes", []):
            if reference.startswith("UNVERIFIED"):
                continue
            match = re.search(r"\s(/api/\S+)$", reference)
            assert match, f"API reference has no route path: {reference}"
            assert match.group(1) in registered, f"Documented route is not registered: {reference}"


def test_scoring_document_does_not_publish_crown_jewel_formula():
    public_docs = "\n".join(path.read_text(encoding="utf-8") for path in DOCS.glob("*.md"))
    assert "full acronym expansion not verified" in public_docs
    assert not re.search(r"TES\s*=\s*.*(?:AGM|DRF|TEF)", public_docs, re.IGNORECASE)
