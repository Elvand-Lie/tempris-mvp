# Tempris Scoring Contract

## Public contract

| Term | Meaning | Subject | Authority |
|---|---|---|---|
| CVSS | External 0–10 technical severity for a CVE finding. | Finding | Imported/connector data, then server validation |
| SSS | Internal non-CVE base severity score, 0–10; full acronym expansion not verified. | Finding | Server intake and scoring services |
| Finding TES | Contextual exposure score for one finding. | Finding | Server only |
| Tenant TES | Mean of scoreable open confirmed customer-exposure finding TES values. | Tenant | `customer_posture.build_customer_posture` |
| EDIP | Server-generated ordered decision/action output. | Finding | Server only |
| AI-system risk score | GRC-specific score for an AI system/governance state. It is not finding TES or tenant TES. | AI system | Server only |

## Crown-jewel boundary

The browser receives final rounded scores, bands, direction, non-proprietary qualitative drivers, subject/scope, and timestamp. It does not receive or reconstruct proprietary weights, exact multipliers, factor ranges, thresholds, calibration bands, or the scoring formula. GRC’s public response is produced by `routers/grc.py::_public_ai_system_risk`; frontend rendering is in `extensions/tempris-modules.js`.

The server may retain scoring inputs required to calculate and audit findings. That persistence is not a client presentation contract. Redaction is enforced before CISO, GRC, SPOTLIGHT, and client-facing report output.

## Scope distinctions

- A finding TES may legitimately differ from another finding’s TES.
- Tenant TES changes when the set of open confirmed exposures changes or their server scores change.
- A SPOTLIGHT or client-report TES is historical metadata from report generation time; it is never relabelled as current.
- GRC’s AI-system risk score describes an assessed AI system, not the tenant’s security exposure.
- Unscoreable confirmed findings remain visible but are excluded from the tenant TES denominator and counted in `unscoreable_finding_ids`.

## Explicitly prohibited interpretations

- CVSS is not tenant TES.
- The number of catalogue records is not customer exposure.
- A suggested or legacy asset pointer does not qualify a finding for tenant TES.
- The frontend does not decide an EDIP action.
- A score direction is not a forecast.

## Code evidence

- `services/tes_engine.py::calculate_finding_tes` owns server calculation.
- `services/customer_posture.py::build_customer_posture` selects the canonical population and aggregates available scores.
- `routers/spectrum.py::calculate_tes` returns the public finding score contract.
- `routers/grc.py::_public_ai_system_risk` strips internal factor detail from AI-system risk responses.
- `services/ai_context.py::build_service_ai_context` supplies customer-safe facts to SPEAK/SPOTLIGHT.
