"""Deterministic CVSS v2 to v3.1 intake remapping for legacy CVEs.

The mapping follows the public FIRST metric meanings. It is intentionally a
documented intake normalization, not a claim that every v2 vector can be
losslessly converted to v3.1.
"""

import math
import re


_V2_PATTERN = re.compile(r"(?:CVSS:2\.0/)?(?P<vector>(?:[A-Za-z]+:[A-Za-z]+/?)+)$")


def _roundup(value: float) -> float:
    return math.ceil(value * 10.0 - 1e-10) / 10.0


def parse_v2_vector(vector: str) -> dict[str, str]:
    normalized = vector.strip().upper()
    match = _V2_PATTERN.fullmatch(normalized)
    if not match:
        raise ValueError("Invalid CVSS v2 vector")
    metrics = dict(part.split(":", 1) for part in match.group("vector").rstrip("/").split("/"))
    required = {"AV", "AC", "AU", "C", "I", "A"}
    if not required.issubset(metrics):
        raise ValueError("CVSS v2 vector must include AV, AC, Au, C, I and A")
    return metrics


def calculate_v31_base(metrics: dict[str, str]) -> float:
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
    ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
    scope = metrics["S"]
    pr = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }[scope][metrics["PR"]]
    ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
    impact_values = {"N": 0.0, "L": 0.22, "H": 0.56}
    isc_base = 1 - (
        (1 - impact_values[metrics["C"]])
        * (1 - impact_values[metrics["I"]])
        * (1 - impact_values[metrics["A"]])
    )
    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    base = min(impact + exploitability, 10.0) if scope == "U" else min(1.08 * (impact + exploitability), 10.0)
    return _roundup(base)


def v2_to_v31_remap(vector: str, *, csrf_class: bool = False) -> dict:
    """Map a CVSS v2 base vector into a transparent v3.1 approximation."""
    v2 = parse_v2_vector(vector)
    v31 = {
        "AV": v2["AV"],
        # v2 often encoded user interaction as AC:M. For CSRF, v3.1 carries
        # that condition explicitly in UI:R, so AC remains Low.
        "AC": "L" if v2["AC"] == "L" or (csrf_class and v2["AC"] == "M") else "H",
        "PR": {"N": "N", "S": "L", "M": "H"}[v2["AU"]],
        "UI": "R" if csrf_class else "N",
        "S": "U",
        "C": {"N": "N", "P": "L", "C": "H"}[v2["C"]],
        "I": {"N": "N", "P": "L", "C": "H"}[v2["I"]],
        "A": {"N": "N", "P": "L", "C": "H"}[v2["A"]],
    }
    order = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    remapped_vector = "CVSS:3.1/" + "/".join(f"{key}:{v31[key]}" for key in order)
    return {
        "source_vector": vector,
        "vector": remapped_vector,
        "base_score": calculate_v31_base(v31),
        "ui_mapping": "R" if csrf_class else "N",
        "mapping_version": "v62-first-public-metrics-1",
    }
