"""
EDIP Non-CVE Exposure Extension
================================
Problem this solves:
  EDIP's current decision tree (Escalate >=9.0 / Patch 7-8.9 / Investigate
  4-6.9 / Defer <4) is keyed off CVSS. FortiBleed has no CVE and no CVSS
  score -- it's leaked/reused credentials against an internet-facing mgmt
  interface. As-is, that finding cannot enter the TES pipeline at all.

  EDRChoker is a post-compromise, host-level defense-evasion technique
  (QoS policy abuse). It has no CVE either, and it isn't something an
  external-exposure scanner sees -- it requires an endpoint-side signal.

  The Claude/Codex "prompt kiddie" case isn't a new exposure category --
  it's evidence that the exploit-skill barrier for *existing* exposures
  has collapsed. A CVE that used to sit at "Investigate" because exploitation
  required real expertise no longer gets that discount.

This module:
  1. Lets non-CVE findings (credential exposure, exposed mgmt interface,
     EDR telemetry gap) flow through TES via a Synthetic Severity Score.
  2. Adds an `agentic_exploitability` flag that boosts TEF.
  3. Adds a COMPENSATING_CONTROL action for findings with patch_available=False,
     so "no patch exists" doesn't silently fall through to Defer.
  4. Includes a small, defensive QoS-policy anomaly checker that can feed
     EDR_TELEMETRY_GAP findings into EDIP (Wave 2 / SENTINEL prototype).
"""

from dataclasses import dataclass
from enum import Enum
import subprocess
import json


# ---------------------------------------------------------------------------
# 1. Finding model
# ---------------------------------------------------------------------------

class FindingType(Enum):
    CVE = "cve"
    CREDENTIAL_EXPOSURE = "cred_exposure"          # FortiBleed-class
    EXPOSED_MGMT_INTERFACE = "exposed_mgmt"
    EDR_TELEMETRY_GAP = "edr_telemetry_gap"        # EDRChoker-class
    MISCONFIGURATION = "misconfig"


class DecisionAction(Enum):
    ESCALATE = "Escalate"
    PATCH = "Patch"
    INVESTIGATE = "Investigate"
    DEFER = "Defer"
    COMPENSATING_CONTROL = "Apply Compensating Control"  # no patch exists


@dataclass
class Finding:
    finding_type: FindingType
    asset_id: str
    cvss_score: float | None = None        # required only for FindingType.CVE
    synthetic_severity: float | None = None  # 0-10, required for non-CVE types
    patch_available: bool = True
    agentic_exploitability: bool = False   # exploitable end-to-end by an
                                            # unattended low-skill AI agent
    agm: float = 1.0                       # existing Tempris modifier
    drf: float = 1.0                       # existing Tempris modifier
    tef: float = 1.0                       # existing Tempris modifier

    def base_severity(self) -> float:
        if self.finding_type == FindingType.CVE:
            if self.cvss_score is None:
                raise ValueError(f"{self.asset_id}: CVE finding requires cvss_score")
            return self.cvss_score
        if self.synthetic_severity is None:
            raise ValueError(
                f"{self.asset_id}: non-CVE finding ({self.finding_type.value}) "
                "requires synthetic_severity -- CVSS does not apply here"
            )
        return self.synthetic_severity

    def effective_tef(self) -> float:
        # Calibrate this multiplier against your existing TEF distribution
        # before shipping -- 1.4 is a placeholder, not a validated constant.
        return self.tef * 1.4 if self.agentic_exploitability else self.tef

    def tes(self) -> float:
        return self.base_severity() * self.agm * self.drf * self.effective_tef()

    def decide(self) -> DecisionAction:
        score = self.tes()
        if not self.patch_available and score >= 7.0:
            return DecisionAction.COMPENSATING_CONTROL
        if score >= 9.0:
            return DecisionAction.ESCALATE
        if score >= 7.0:
            return DecisionAction.PATCH
        if score >= 4.0:
            return DecisionAction.INVESTIGATE
        return DecisionAction.DEFER


# ---------------------------------------------------------------------------
# 2. The three incidents run through the extended engine
# ---------------------------------------------------------------------------

def demo() -> list[dict]:
    findings = [
        Finding(
            finding_type=FindingType.CVE,
            asset_id="customer-edge-service-01",
            cvss_score=8.6,
            agentic_exploitability=True,   # low-skill operator + Claude/Codex
            agm=1.2, drf=1.0, tef=1.0,
        ),
        Finding(
            finding_type=FindingType.EDR_TELEMETRY_GAP,
            asset_id="endpoint-finance-22",
            synthetic_severity=7.5,        # QoS-throttle EDR blinding
            patch_available=False,         # living-off-the-land technique, no CVE
            agm=1.0, drf=1.3, tef=1.1,
        ),
        Finding(
            finding_type=FindingType.CREDENTIAL_EXPOSURE,
            asset_id="edge-fortigate-12",
            synthetic_severity=8.0,        # exposed mgmt interface + leaked creds
            patch_available=False,         # FortiBleed: no CVE, no patch
            agm=1.3, drf=1.0, tef=1.0,
        ),
    ]

    results = []
    for f in findings:
        results.append({
            "asset_id": f.asset_id,
            "type": f.finding_type.value,
            "tes": round(f.tes(), 2),
            "action": f.decide().value,
        })
    return results


# ---------------------------------------------------------------------------
# 3. Defensive QoS-policy anomaly check (feeds EDR_TELEMETRY_GAP findings)
#    Read-only: enumerates existing NetQosPolicy objects and flags suspiciously
#    low throttle rates aimed at known EDR process names. Run on the endpoint
#    (or via remote PS session) as a SENTINEL/Wave-2 detection prototype.
# ---------------------------------------------------------------------------

KNOWN_EDR_PROCESS_HINTS = (
    "crowdstrike", "csagent", "sentinelone", "sensor", "defender", "msmpeng",
    "carbonblack", "cbagent", "elastic", "agent.exe", "edragent",
)

SUSPICIOUS_THROTTLE_BPS = 1024  # below this, no real TLS handshake can complete


def check_qos_policy_anomalies() -> list[dict]:
    """Returns a list of suspicious NetQosPolicy entries. Requires PowerShell
    (Windows host). Safe to run repeatedly -- read-only, no policy changes."""
    cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-NetQosPolicy | Select-Object Name, AppPathNameMatchCondition, "
        "ThrottleRateActionBitsPerSecond | ConvertTo-Json -Compress"
    ]
    try:
        raw = subprocess.check_output(cmd, text=True, timeout=15)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        return [{"error": str(e)}]

    policies = json.loads(raw) if raw.strip() else []
    if isinstance(policies, dict):
        policies = [policies]

    flagged = []
    for p in policies:
        app = (p.get("AppPathNameMatchCondition") or "").lower()
        rate = p.get("ThrottleRateActionBitsPerSecond")
        is_edr_named = any(h in app for h in KNOWN_EDR_PROCESS_HINTS)
        is_suspicious_rate = isinstance(rate, (int, float)) and rate < SUSPICIOUS_THROTTLE_BPS
        if is_edr_named or is_suspicious_rate:
            flagged.append({
                "policy_name": p.get("Name"),
                "target_process": p.get("AppPathNameMatchCondition"),
                "throttle_bps": rate,
                "reason": "EDR-named process" if is_edr_named else "extreme throttle rate",
            })
    return flagged


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
