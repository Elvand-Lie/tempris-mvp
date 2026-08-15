# Tempris CTEM / EDIP Product Documentation

This directory is the canonical, code-aligned description of the current Tempris CTEM/EDIP product. It covers the browser pages, HTTP APIs, persistence objects, state transitions, metrics, permissions, and known limitations in the repository at this revision.

The structured source of truth is [`tempris_data_dictionary.yaml`](tempris_data_dictionary.yaml). The other documents explain that contract for operators, developers, customers, and assurance reviewers.

## Canonical definitions

- **Global/reference intelligence** is catalogue or threat-intelligence material that may be useful for research but is not proof that a customer is affected.
- **Finding Registry** is the tenant-scoped set of submitted, imported, scanned, resolved, reference, not-applicable, and confirmed finding records.
- **Candidate match** is a deterministic or keyword-based suggestion. It is never confirmation.
- **Confirmed customer exposure** is an open finding with a confirmed `AssetExposure` to an active same-tenant asset, excluding reference-only and not-applicable records. The authoritative implementation is `services.customer_posture.canonical_exposure_rows`.
- **Finding TES** is a server-generated contextual exposure score for one finding.
- **Tenant TES** is the mean of available finding TES values for open confirmed customer exposures. It is not a raw catalogue average and is not the GRC AI-system score.
- **Incident** is a tenant-scoped observed event received by the incident compatibility API. An `IncidentReport` is a generated notification draft, not the event itself.
- **Client report** is an immutable current-state snapshot generated at a recorded time. Assessment-period fields are contextual metadata; historical reconstruction is not implemented.

## Documentation map

- [Module catalog](TEMPRIS_MODULE_CATALOG.md): every visible module and utility.
- [Metric dictionary](TEMPRIS_METRIC_DICTIONARY.md): displayed counts, scores, percentages, and statuses.
- [Data flow and lifecycle](TEMPRIS_DATA_FLOW_AND_LIFECYCLE.md): canonical flows and transitions.
- [Actions, permissions, and side effects](TEMPRIS_ACTIONS_PERMISSIONS_AND_SIDE_EFFECTS.md): buttons and mutations.
- [Scoring contract](TEMPRIS_SCORING_CONTRACT.md): public scoring boundary without crown-jewel internals.
- [API and storage map](TEMPRIS_API_AND_STORAGE_MAP.md): route-to-model map.
- [Telemetry event catalog](TEMPRIS_TELEMETRY_EVENT_CATALOG.md): structured operational events.
- [Known limitations and decisions](TEMPRIS_KNOWN_LIMITATIONS_AND_DECISIONS.md): deliberate boundaries and open clarifications.
- [Canonicalization changelog](TEMPRIS_CANONICALIZATION_CHANGELOG.md): changes from legacy semantics.
- [Migration 008 runbook](TEMPRIS_MIGRATION_008_RUNBOOK.md): backup, rehearsal, verification, release, and rollback procedure.
- [Production validation status](TEMPRIS_PRODUCTION_VALIDATION_STATUS.md): latest completed checks and outstanding release gates.

## Evidence convention

Paths are relative to `app/backend` or `app/frontend`. The primary implementation anchors are:

- `services/customer_posture.py::canonical_exposure_rows` and `build_customer_posture`
- `services/exposure_links.py::confirm_finding_assets`
- `services/scan_normalizer.py::normalize_observation`
- `services/reporting_engine.py::generate_poc_report_pipeline`
- `routers/ciso.py::get_ciso_summary`
- `routers/standard.py::list_frameworks` and `generate_mas_trm_incident_report`
- `extensions/tempris-modules.js`

Where the repository does not establish a product fact, the documents use **UNVERIFIED / PRODUCT CLARIFICATION REQUIRED** instead of guessing.

## Scope boundary

This set documents CTEM/EDIP only. TEMI, sales-SCOUT, CHASE, DRAFT, BRIEF, Apollo, HubSpot sales automation, and the separate AI Sales System are excluded.
