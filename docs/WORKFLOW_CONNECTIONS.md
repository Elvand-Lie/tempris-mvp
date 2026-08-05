# Tempris workflow connections

Tempris now connects exposure, asset, EDIP, assurance, and reporting records through a tenant-scoped workflow layer. The layer reports what has actually been recorded and exposes missing coverage instead of filling gaps with assumptions.

## What is connected

| Output | Recorded source | Rule |
| --- | --- | --- |
| Asset-linked TES | SPECTRUM finding + ASSETS link + complete TES inputs | The aggregate includes only open, scorable findings linked to an asset owned by the same tenant. Coverage is shown beside the score. |
| Customer CISA exposure | CISA KEV finding + explicit tenant asset link | An unlinked global/catalog record is not described as customer exposure. |
| Asset owner | `ASSETS.owner` | An owner is shown only after it is recorded on the linked asset. |
| EDIP treatment | `EDIP` decision record | A decision and its rationale are counted separately. Automated classifications remain suggestions, not recorded decisions. |
| Remediation SLA | `SPECTRUM.finding.sla` | A remediation due date exists only when both the finding creation date and an explicit SLA are recorded. |
| KEV deadline | `SSS.kev_due` | Reported as a CISA KEV due date, never as an unexplained generic overdue item. |
| Revalidation deadline | `SSS/EDIP.revalidate_by` | Reported as EDIP revalidation, separately from remediation and KEV deadlines. |
| Business impact and effort | Explicit SSS/workflow fields | These are analyst-supplied facts. Tempris does not calculate or guess them. |
| Compliance gaps | Recorded STANDARD control assessments | Framework defaults and unassessed controls do not become compliance claims. |
| GRC status | Recorded GRC state and sign-offs | No GRC score is emitted when the tenant has no recorded GRC state. |
| Partner delivery | Report configuration and recorded consent | A named alliance partner does not receive a report unless client consent is recorded. |

## Module health semantics

Module health has two independent fields:

- `status`: whether the module's backing repository query succeeded (`operational` or `degraded`).
- `data_status`: whether that tenant currently has records in the repository (`recorded`, `no_data`, or `unavailable`).

This avoids presenting an empty but functioning module as broken, or presenting a configured module as healthy without checking its data dependency.

## API

`GET /api/workflow/overview` returns tenant-scoped exposure coverage, typed deadlines, workflow readiness, recorded assurance state, and module repository health. Viewer and read-only roles can inspect it when SYNTHESIS is entitled.

`PATCH /api/workflow/findings/{finding_id}` allows a Superadmin, Admin, or Analyst to explicitly record any supplied subset of:

- `asset_id`
- `sla_days`
- `required_action`
- `business_impact`
- `effort`
- `revalidate_by`
- `remediation_verification`

The asset must be active and belong to the same tenant. Every update records the actor, timestamp, source (`explicit_analyst_update`), and a tamper-evident audit entry. Omitting a field leaves it unchanged; supplying `null` clears a previously recorded optional value.

## Synthesis and CISO behavior

Synthesis now labels its score as asset-linked coverage, displays the number of linked and scorable findings, shows asset-linked KEV exposure, and separates module availability from tenant data readiness. TES snapshots are rejected when no asset-linked finding has complete scoring inputs.

The CISO response no longer contains a generic top-level `overdue` total. It provides separate remediation SLA, CISA KEV, and EDIP revalidation deadline records with the exact source used for each date.

## Deliberately not implemented

- Automatic vendor/product/version matching. ASSETS does not yet store a normalized software inventory, so automatic matching would create unsupported exposure claims. Findings must be linked explicitly for now.
- Package-derived SLA defaults. No approved priority-to-SLA policy has been supplied. SLA days can be recorded explicitly per finding.
- Insurance tier recommendations. No approved calculation model exists, so the overview returns `not_configured`.
- Automatic EDIP decisions. Engine output can remain a suggestion, but only an explicit recorded analyst decision is used in customer reporting.
- Independent attestation or partner access without recorded approval and consent.
