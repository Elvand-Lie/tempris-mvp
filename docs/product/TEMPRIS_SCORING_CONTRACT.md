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

The browser receives final rounded scores, bands, direction, non-proprietary qualitative drivers, subject/scope, and timestamp. It does not receive or reconstruct proprietary weights, exact multipliers, factor ranges, thresholds, calibration bands, or the scoring formula. GRC’s public response is produced by `routers/grc.py::_public_ai_system_risk`; the retained native SPA consumes that public response from the generated bundle under `app/frontend/assets/`.

The server may retain scoring inputs required to calculate and audit findings. That persistence is not a client presentation contract. Redaction is enforced before CISO, GRC, SPOTLIGHT, and client-facing report output.

## Scope distinctions

- A finding TES may legitimately differ from another finding’s TES.
- Tenant TES changes when the set of open confirmed exposures changes or their server scores change.
- A SPOTLIGHT or client-report TES is historical metadata from report generation time; it is never relabelled as current.
- GRC’s AI-system risk score describes an assessed AI system, not the tenant’s security exposure.
- Unscoreable confirmed findings remain visible but are excluded from the tenant TES denominator and counted in `unscoreable_finding_ids`.

## Current CVE context

Current open, confirmed CVE findings are scored only by the server from authoritative current context in `services/tes_engine.py::get_live_cve_tes_context`. The score is recalculated when a confirmed active asset's criticality changes, an authorised analyst records Business Impact in SPECTRUM, or trusted exploit/threat evidence changes. Resolved findings preserve their historical scoring provenance until reopened.

| Input | Current authority | Evidence and interpretation |
|---|---|---|
| CVSS | `Finding.cvss` for the exact stored CVE identifier | Canonical CVE metadata; never inferred from asset matching. |
| Asset criticality | Confirmed active same-tenant `AssetExposure` -> `Asset.criticality` | When one finding has several confirmed active assets, the highest recorded asset criticality is used for current context. Suggested and legacy links do not qualify. |
| Business Impact | `Finding.cve_context.business_impact` | An authorised analyst records a 0-10 assessment and justification from SPECTRUM. If not assessed, the server uses its documented neutral context and labels it unassessed rather than analyst-confirmed. |
| Exploitability | Explicit trusted evidence in the finding context, CISA KEV/ransomware flags, or a successful Nuclei vulnerability observation | Ports, banners, and technology fingerprints are not exploit evidence. |
| Threat Actor Activity | Explicit trusted threat intelligence, including KEV/ransomware flags and retained source/time metadata | No evidence is represented as unknown/no recorded evidence; it is not a claim that attackers are absent. |

The browser receives only the final finding score and the public Business Impact assessment state. It does not receive score weights, factor values, formulas, or raw context.

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

## Canonical GRC context for non-CVE findings

Manual non-CVE intake requires an explicit analyst-assigned SSS base severity. There is no universal manual `SSS = 7` default. Connector-originated findings may use a documented connector-specific server rule.

`services/grc_framework.py::get_live_grc_modifiers` derives the tenant's current governance context from ISO/IEC 42001:2023 `ControlAssessment` records. It is applied server-side to open non-CVE findings; stored per-finding modifiers are historical provenance only and cannot override the current GRC assessment.

| Control | Group | Effect |
|---|---|---|
| A.2.2 AI Policy | AGM | Governance assessment |
| A.3.2 Internal Organisation | AGM | Governance assessment |
| A.5.2 Impact Assessment | AGM | Governance assessment |
| A.6.2.2 AI Lifecycle | AGM | Governance assessment |
| A.9.2 Responsible Use | AGM | Governance assessment |
| A.7.4 Data Quality | DRF | Data-risk assessment |
| A.10.3 Third-Party | TEF | Third-party governance assessment |

Effective completion is server-derived: completed with both required sign-offs is complete, in-review or incomplete sign-off is partial, and pending is incomplete. The resulting governance context is a bounded server-side adjustment to non-CVE TES; exact scoring factors remain server-only and are absent from browser and AI-context contracts.
