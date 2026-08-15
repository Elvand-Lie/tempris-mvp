"""Minimal Tempris incident intake example using placeholder values only."""

import os
from datetime import datetime, timezone

import requests


BASE_URL = os.environ.get("TEMPRIS_BASE_URL", "https://tempris.example")
TOKEN = os.environ["TEMPRIS_API_TOKEN"]

payload = {
    "external_event_id": "soc-placeholder-0001",
    "source": "customer_soc",
    "discovered_at": datetime.now(timezone.utc).isoformat(),
    "title": "Placeholder security event",
    "summary": "Replace with the observed, non-secret incident summary.",
    "severity": "medium",
    "status": "open",
    "affected_asset_ids": ["ASSET-PLACEHOLDER"],
    "related_finding_ids": [],
    "evidence_references": ["https://evidence.example/incidents/placeholder"],
    "observed_impact": "No impact confirmed at intake time.",
    "response_actions": ["SOC triage started"],
}

response = requests.post(
    f"{BASE_URL}/api/incidents",
    headers={"Authorization": f"Bearer {TOKEN}"},
    json=payload,
    timeout=30,
)
response.raise_for_status()
print(response.json()["incident"]["id"])
