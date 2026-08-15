# Tempris Telemetry Event Catalog

`OperationalEvent` is a tenant-scoped structured event foundation for later value/throughput reporting. It does not replace the human-readable hash-chained `AuditLog`, and it does not calculate financial ROI.

## Schema

| Field | Meaning |
|---|---|
| `id` | Generated immutable event identifier |
| `tenant_id` | Server-derived tenant scope |
| `event_type` | Stable dotted event name |
| `occurred_at` | Business occurrence timestamp |
| `actor_type`, `actor_id` | User/system/connector identity where applicable |
| `resource_type`, `resource_id` | Object affected |
| `source_module` | Producing Tempris module |
| `metadata` | Small structured non-secret context |
| `correlation_id` | Run/request/report chain identifier |
| `created_at` | Persistence timestamp |

Implementation: `models.py::OperationalEvent` and `services/operational_events.py::record_operational_event`.

## Events

| Event | Producer | Resource | Safe future measures |
|---|---|---|---|
| `scan.started` | SCOUT scanner | scan job | Runs launched, targets/runs by period |
| `scan.completed` | SCOUT scanner | scan job | Completed runs and duration when timestamps exist |
| `scan.failed` | SCOUT scanner | scan job | Failure rate and error category |
| `scan.zero_results` | SCOUT scanner | scan job | Completed zero-observation runs; not “secure” proof |
| `scanfinding.created` | SCOUT normalizer | scan finding | New observations |
| `scanfinding.normalized` | SCOUT normalizer | scan finding | Observations promoted to registry candidates |
| `finding.created` | Intake/connectors/SCOUT/VDP | finding | Intake volume by source |
| `finding.asset_suggested` | workflow/SCOUT | finding | Suggestions awaiting human confirmation |
| `finding.asset_confirmed` | workflow/SCOUT | finding | Confirmed exposure links and provenance |
| `finding.reference_only` | Intake workflow | finding | Analyst reference dispositions |
| `finding.not_applicable` | Intake workflow | finding | False-positive/not-applicable dispositions |
| `finding.resolved` | Finding Registry | finding | Resolution throughput/time when paired with creation |
| `finding.reopened` | Finding Registry | finding | Reopen rate |
| `decision.created` | SPECTRUM/EDIP | decision/finding | Decisions generated |
| `decision.updated` | SPECTRUM/EDIP | decision/finding | Decision changes |
| `decision.overridden` | SPECTRUM/EDIP | decision/finding | Human overrides; not automatically false positives |
| `control.assessed` | STANDARD | control | Assessment throughput |
| `control.evidence_attached` | STANDARD/GRC | control/evidence | Evidence automation/manual volume |
| `gap.opened` | STANDARD | control | Recorded gaps opened |
| `gap.closed` | STANDARD | control | Recorded gaps closed/time-to-close |
| `policy.created` | GRC | policy | Policy creation/version activity |
| `policy.archived` | GRC | policy | Lifecycle changes |
| `policy.superseded` | GRC | policy | New-version creation |
| `policy.deleted` | GRC | policy | Authorized destructive lifecycle action |
| `report.generated` | Client Reports | report | Reports generated |
| `report.version_created` | Client Reports | report | Version activity |
| `report.downloaded` | Client Reports | report | Recorded downloads; not recipient opens unless separately instrumented |
| `report.archived` | Client Reports | report | Archive activity |
| `report.restored` | Client Reports | report | Restore activity |
| `incident.created` | Incident API | incident | Incident intake count by source |
| `incident.updated` | Incident API | incident | Status/detail progression |
| `incident.notification_draft_generated` | STANDARD | incident/report | MAS drafts produced from incidents |

## Measurement readiness

### Directly measured now

- Active/recorded assets and confirmed exposed critical assets.
- Scanner jobs, observations, normalized candidates, zero-result and failed runs.
- Finding creation, classification, confirmation, resolution, and reopen transitions where events are emitted.
- EDIP decision creation/update/override events.
- Control assessment/evidence/gap transitions.
- Policy and report lifecycle activity.
- Incident creation/update/draft generation.

### Derivable now

- Time from finding creation to confirmation/resolution when both timestamps/events are present.
- Confirmed-exposure share of reviewed intake.
- Scan-to-normalized-finding and normalized-to-confirmed-link conversion.
- Assessment coverage movement and gaps closed.
- Report generation/version/archive counts.

### Requires new instrumentation or customer baseline

- Report recipient opens (download is not an open).
- Manual hours saved, analyst hourly cost, manual triage/report duration.
- Expected-loss or insurance ROI baseline.
- Verified defensive-effectiveness improvement across comparable STRIKE runs.

No financial value is inferred from these events. A future ROI model must state analyst cost, baseline effort, reporting effort, expected-cost assumptions, and period explicitly.

## Privacy rule

Never put tokens, secrets, raw credentials, full sensitive message bodies, or unnecessary researcher/customer PII in metadata. Use identifiers and small classifications that can be joined to authorized domain records.
