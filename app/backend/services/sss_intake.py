"""
tempris_sss_supply_chain_intake.py
====================================
Tempris Technology Pte. Ltd.
EDIP — Non-CVE SSS Intake Module: Supply Chain Findings

PURPOSE:
    Models supply chain attack findings (no CVE available) as EDIP intake
    entries using the Synthetic Severity Score (SSS) path.
    TES Formula: TES = base_severity × AGM × DRF × TEF (capped at 10.0)

EDIP DECISION THRESHOLDS:
    ESCALATE    >= 9.0
    PATCH        7.0 – 8.9
    INVESTIGATE  4.0 – 6.9
    DEFER        < 4.0

USAGE:
    python tempris_sss_supply_chain_intake.py

OUTPUT:
    - Console summary table
    - JSON file: edip_sss_supply_chain_output.json

DEVELOPER NOTES (for Elvand):
    - Integrate build_sss_finding() into the existing edip_non_cve_extension.py
    - JSON output schema matches the EDIP intake queue expected by the
      React dashboard component (EDIPIntakeQueue.jsx)
    - COMPENSATING_CONTROL action reduces effective TES by 5% per control
      (capped at 20% reduction) — toggle via apply_controls=True

Author  : Tempris Technology Pte. Ltd.
Version : 1.0.0
Date    : 2026-06-25
"""

import json
import math
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

TES_CAP = 10.0
MAX_CONTROL_REDUCTION = 0.20   # max 20% TES reduction from compensating controls
CONTROL_REDUCTION_PER = 0.05   # 5% per compensating control

DECISION_THRESHOLDS = {
    "ESCALATE":    9.0,
    "PATCH":       7.0,
    "INVESTIGATE": 4.0,
    "DEFER":       0.0,
}

# Supply chain attack vector categories (for tagging)
VECTOR_TAGS = {
    "npm":            "PKG_REGISTRY_NPM",
    "pypi":           "PKG_REGISTRY_PYPI",
    "github_actions": "CICD_GITHUB_ACTIONS",
    "vscode":         "IDE_EXTENSION",
    "docker":         "CONTAINER_REGISTRY",
    "github_repo":    "SCM_REPOSITORY",
    "composer":       "PKG_REGISTRY_COMPOSER",
    "crates":         "PKG_REGISTRY_CRATES",
}


# ---------------------------------------------------------------------------
# CORE FUNCTIONS
# ---------------------------------------------------------------------------

def calculate_tes(
    base_severity: float,
    agm: float,
    drf: float,
    tef: float,
    compensating_controls: Optional[list] = None,
    apply_controls: bool = False,
) -> tuple[float, float]:
    """
    Calculate raw and effective TES.

    Args:
        base_severity : Base severity score (0.0 – 10.0). Use CVSS if available,
                        else analyst-assigned SSS base.
        agm           : AI/Automation Growth Modifier (typically 0.8 – 1.5).
                        >1.0 if AI-assisted propagation is confirmed.
        drf           : Detection/Response Friction (0.5 – 1.2).
                        Higher = harder to detect/patch.
        tef           : Threat Environment Factor (0.8 – 1.5).
                        Higher = more exposed environment (CI/CD, cloud, prod).
        compensating_controls : List of active compensating control strings.
        apply_controls        : If True, reduce TES by 5% per control (max 20%).

    Returns:
        (tes_raw, tes_effective) — both capped at TES_CAP.
    """
    tes_raw = min(base_severity * agm * drf * tef, TES_CAP)
    tes_raw = round(tes_raw, 2)

    if apply_controls and compensating_controls:
        reduction = min(
            len(compensating_controls) * CONTROL_REDUCTION_PER,
            MAX_CONTROL_REDUCTION
        )
        tes_effective = round(tes_raw * (1 - reduction), 2)
    else:
        tes_effective = tes_raw

    return tes_raw, tes_effective


def get_decision(tes: float) -> str:
    """Map a TES score to an EDIP decision label."""
    if tes >= DECISION_THRESHOLDS["ESCALATE"]:
        return "ESCALATE"
    elif tes >= DECISION_THRESHOLDS["PATCH"]:
        return "PATCH"
    elif tes >= DECISION_THRESHOLDS["INVESTIGATE"]:
        return "INVESTIGATE"
    else:
        return "DEFER"


def build_sss_finding(
    finding_id: str,
    title: str,
    description: str,
    base_severity: float,
    agm: float,
    drf: float,
    tef: float,
    attack_vectors: list[str],
    affected_ecosystem: str,
    patch_available: bool = False,
    compensating_controls: Optional[list[str]] = None,
    apply_controls: bool = False,
    analyst: str = "system",
    references: Optional[list[str]] = None,
) -> dict:
    """
    Build a fully structured SSS finding for EDIP intake.

    Args:
        finding_id          : Unique ID, format SSS-YYYY-MMDD-NNN
        title               : Short descriptive title
        description         : Full finding description
        base_severity       : Analyst-assigned base score (0.0–10.0)
        agm                 : AI/Automation Growth Modifier
        drf                 : Detection/Response Friction
        tef                 : Threat Environment Factor
        attack_vectors      : List of vector tags (see VECTOR_TAGS keys)
        affected_ecosystem  : e.g. "npm", "GitHub Actions", "PyPI"
        patch_available     : True if a clean version/patch exists
        compensating_controls : Active mitigating controls in place
        apply_controls      : Whether to apply control reduction to TES
        analyst             : Who/what generated this finding
        references          : List of reference URLs

    Returns:
        dict — EDIP intake record (JSON-serialisable)
    """
    if not (0.0 <= base_severity <= 10.0):
        raise ValueError(f"base_severity must be 0.0–10.0, got {base_severity}")

    controls = compensating_controls or []
    refs = references or []
    vector_labels = [VECTOR_TAGS.get(v, v.upper()) for v in attack_vectors]

    tes_raw, tes_effective = calculate_tes(
        base_severity, agm, drf, tef, controls, apply_controls
    )
    decision = get_decision(tes_effective)

    action = "PATCH" if patch_available else "COMPENSATING_CONTROL"

    return {
        "finding_id":          finding_id,
        "type":                "NON_CVE_SSS",
        "source":              "SUPPLY_CHAIN",
        "title":               title,
        "description":         description,
        "affected_ecosystem":  affected_ecosystem,
        "attack_vectors":      vector_labels,
        "patch_available":     patch_available,
        "recommended_action":  action,
        "scoring": {
            "base_severity":   base_severity,
            "AGM":             agm,
            "DRF":             drf,
            "TEF":             tef,
            "TES_raw":         tes_raw,
            "TES_effective":   tes_effective,
            "controls_applied": apply_controls,
        },
        "decision":            decision,
        "compensating_controls": controls,
        "references":          refs,
        "analyst":             analyst,
        "ingested_at":         datetime.now(timezone.utc).isoformat(),
        "mas_trm_mapping":     "MAS TRM §9.1.3 — Third-Party Software Risk",
    }


# ---------------------------------------------------------------------------
# SAMPLE FINDINGS — May 2026 Supply Chain Wave
# ---------------------------------------------------------------------------

def load_sample_findings() -> list[dict]:
    """
    Returns 5 EDIP SSS findings modelling the May 18–19 2026 supply chain wave.
    Pass these to build_sss_finding() or use directly for dashboard testing.
    """
    samples = [
        {
            "finding_id":   "SSS-2026-0518-001",
            "title":        "Shai-Hulud Self-Replicating npm Worm — CI/CD Credential Theft",
            "description":  (
                "Self-replicating npm worm that stole OAuth tokens to propagate "
                "across the npm registry, compromising CI/CD pipelines. No CVE "
                "was assigned during the active exploitation window."
            ),
            "base_severity": 9.1,
            "agm": 1.3,   # AI-assisted self-replication
            "drf": 0.95,  # No patch during active window
            "tef": 1.2,   # CI/CD environment = high blast radius
            "attack_vectors":     ["npm", "github_actions"],
            "affected_ecosystem": "npm / GitHub Actions",
            "patch_available":    False,
            "compensating_controls": [
                "npm ci with committed lockfile enforced",
                "min-release-age=2 configured on npm",
                "Internal registry proxy with quarantine",
            ],
            "apply_controls": True,
            "references": [
                "https://www.stepsecurity.io/blog/5-supply-chain-attacks-in-48-hours",
                "https://boostsecurity.io/blog/supply-chain-hunting-season---may-edition",
            ],
        },
        {
            "finding_id":   "SSS-2026-0518-002",
            "title":        "Poisoned VS Code Extension — 2.2M Install Developer Endpoint Compromise",
            "description":  (
                "Malicious VS Code extension with 2.2 million active installs used "
                "to compromise developer endpoints and exfiltrate GitHub credentials. "
                "Targets developer machines directly, bypassing CI/CD controls."
            ),
            "base_severity": 8.7,
            "agm": 1.1,
            "drf": 1.1,   # Hard to detect — runs silently in IDE
            "tef": 1.0,
            "attack_vectors":     ["vscode"],
            "affected_ecosystem": "VS Code / Developer Endpoint",
            "patch_available":    False,
            "compensating_controls": [
                "Extension allowlist enforced via VS Code policy",
                "Developer endpoint EDR with extension monitoring",
            ],
            "apply_controls": True,
            "references": [
                "https://www.cm-alliance.com/cybersecurity-blog/5-of-the-biggest-supply-chain-attacks-of-2026-so-far",
            ],
        },
        {
            "finding_id":   "SSS-2026-0518-003",
            "title":        "Compromised GitHub Actions — Multiple Workflow Injections",
            "description":  (
                "Multiple GitHub Actions compromised via stolen PATs, injecting "
                "credential-harvesting payloads into CI/CD runner environments. "
                "Targets ephemeral runners not covered by EDR."
            ),
            "base_severity": 8.9,
            "agm": 1.2,
            "drf": 1.15,  # Ephemeral runners leave no persistent logs
            "tef": 1.3,
            "attack_vectors":     ["github_actions", "github_repo"],
            "affected_ecosystem": "GitHub Actions / CI Pipeline",
            "patch_available":    True,
            "compensating_controls": [
                "Pin Actions to full commit SHA (not tags)",
                "Restrict GITHUB_TOKEN permissions to least privilege",
                "StepSecurity Harden-Runner deployed on all runners",
            ],
            "apply_controls": True,
            "references": [
                "https://www.stepsecurity.io/blog/5-supply-chain-attacks-in-48-hours",
                "https://boostsecurity.io/blog/supply-chain-hunting-season---may-edition",
            ],
        },
        {
            "finding_id":   "SSS-2026-0518-004",
            "title":        "Trojanized Microsoft PyPI SDK (durabletask) — 35-Minute Active Window",
            "description":  (
                "Malicious version of Microsoft's durabletask PyPI package active for "
                "35 minutes. No CVE during exploitation window. CI pipelines running "
                "continuous builds were exposed before advisory publication."
            ),
            "base_severity": 8.5,
            "agm": 1.0,
            "drf": 1.2,   # SCA/CVE tools blind during window
            "tef": 1.1,
            "attack_vectors":     ["pypi", "github_actions"],
            "affected_ecosystem": "PyPI / Python CI Pipelines",
            "patch_available":    True,  # clean version published after yanking
            "compensating_controls": [
                "min-release-age gate (pip) configured",
                "Internal PyPI proxy with version quarantine",
            ],
            "apply_controls": True,
            "references": [
                "https://www.stepsecurity.io/blog/5-supply-chain-attacks-in-48-hours",
                "https://www.softscheck.com/en/blog/supply-chain-attacks/",
            ],
        },
        {
            "finding_id":   "SSS-2026-0518-005",
            "title":        "GitHub Internal Repository Exfiltration — ~3,800 Repos",
            "description":  (
                "GitHub disclosed exfiltration of approximately 3,800 internal source "
                "code repositories, culminating the 48-hour supply chain wave. "
                "Demonstrates pipeline compromise leading to platform-level breach."
            ),
            "base_severity": 9.5,
            "agm": 1.1,
            "drf": 0.9,
            "tef": 1.4,   # Platform-level breach = maximum blast radius
            "attack_vectors":     ["github_repo", "github_actions"],
            "affected_ecosystem": "GitHub Platform / SCM",
            "patch_available":    False,
            "compensating_controls": [
                "Repository access audit logs reviewed",
                "Secret scanning enabled on all repos",
                "GITHUB_TOKEN rotation completed",
            ],
            "apply_controls": True,
            "references": [
                "https://www.stepsecurity.io/blog/5-supply-chain-attacks-in-48-hours",
            ],
        },
    ]

    results = []
    for s in samples:
        finding = build_sss_finding(**s, analyst="tempris-system-v1.0")
        results.append(finding)
    return results


# ---------------------------------------------------------------------------
# OUTPUT HELPERS
# ---------------------------------------------------------------------------

DECISION_ICONS = {
    "ESCALATE":    "🔴",
    "PATCH":       "🟠",
    "INVESTIGATE": "🟡",
    "DEFER":       "⚪",
}


def print_summary_table(findings: list[dict]) -> None:
    """Print a formatted console summary of all findings."""
    print("\n" + "=" * 80)
    print("  TEMPRIS EDIP — SSS SUPPLY CHAIN INTAKE SUMMARY")
    print("  Source Event: May 18–19 2026 Supply Chain Wave (48-Hour Attack)")
    print("=" * 80)
    print(f"  {'ID':<24} {'TES':>5}  {'DECISION':<12} {'TITLE'}")
    print("-" * 80)

    for f in findings:
        icon = DECISION_ICONS.get(f["decision"], "")
        tes = f["scoring"]["TES_effective"]
        print(f"  {f['finding_id']:<24} {tes:>5}  {icon} {f['decision']:<10}  {f['title'][:45]}")

    print("=" * 80)
    escalate = sum(1 for f in findings if f["decision"] == "ESCALATE")
    patch    = sum(1 for f in findings if f["decision"] == "PATCH")
    inv      = sum(1 for f in findings if f["decision"] == "INVESTIGATE")
    defer    = sum(1 for f in findings if f["decision"] == "DEFER")
    print(f"  ESCALATE: {escalate}  |  PATCH: {patch}  |  INVESTIGATE: {inv}  |  DEFER: {defer}")
    print(f"  MAS TRM Mapping: {findings[0]['mas_trm_mapping']}")
    print("=" * 80 + "\n")


def export_to_json(findings: list[dict], output_path: str = "edip_sss_supply_chain_output.json") -> None:
    """Export findings list to JSON file for dashboard ingestion."""
    payload = {
        "meta": {
            "source_event":  "May 18–19 2026 Supply Chain Attack Wave",
            "intake_type":   "NON_CVE_SSS",
            "total_findings": len(findings),
            "exported_at":   datetime.now(timezone.utc).isoformat(),
            "schema_version": "1.0.0",
            "generator":     "tempris_sss_supply_chain_intake.py",
        },
        "findings": findings,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"  ✅ JSON exported → {output_path}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n[TEMPRIS EDIP] Loading SSS Supply Chain Findings...")

    findings = load_sample_findings()

    print_summary_table(findings)

    export_to_json(findings, "edip_sss_supply_chain_output.json")

    # Quick decision audit
    print("\n[AUDIT] Per-finding TES breakdown:")
    for f in findings:
        s = f["scoring"]
        print(
            f"  {f['finding_id']} | "
            f"Base={s['base_severity']} × AGM={s['AGM']} × DRF={s['DRF']} × TEF={s['TEF']} "
            f"= TES_raw={s['TES_raw']} → TES_eff={s['TES_effective']} [{f['decision']}]"
            f"{'  (controls applied)' if s['controls_applied'] else ''}"
        )
    print()
