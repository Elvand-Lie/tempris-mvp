# Tempris CTEM & EDIP Client Report Service

Cross-module source rules and the explicit workflow API are documented in [Tempris workflow connections](../WORKFLOW_CONNECTIONS.md).

## Purpose

The proof-of-concept now generates a customer-facing, tenant-scoped report package from the findings already held in Tempris. It is intended for the National Day package and early report-as-a-service engagements.

The package uses one server-derived dataset and produces:

- a branded HTML report that can be printed or saved as PDF;
- a JSON artifact for integration and integrity verification; and
- a spreadsheet-safe CSV findings register.

Generation is on demand. Scheduled email delivery remains future work.

## Where to generate a report

An Admin or Superadmin opens **CISO Dashboard ? Client Report Service**, enters the client and engagement details, and selects **Generate report package**.

If no finding IDs are supplied by an API client, the service includes the current tenant's findings. Every source lookup and artifact retrieval is tenant-scoped. Generated reports appear in **Recent Reports**, with Preview, JSON, and CSV actions.

API clients can call:

- `POST /api/reports/poc/generate`
- `GET /api/reports/{report_id}/artifact/html`
- `GET /api/reports/{report_id}/artifact/json`
- `GET /api/reports/{report_id}/artifact/csv`

All routes require authentication and the SPOTLIGHT entitlement. Report generation requires Superadmin, Admin, or Analyst; the CISO user interface remains Admin/Superadmin only.

## Report contract

The approved customer report contains:

- report identity, reporting period, classification, retention statement, and integrity hash;
- client, engagement, environment, and assessment provenance;
- an executive summary using **Fix now**, **Watch**, **Safe to wait**, and **Not assigned**;
- findings ordered from worst to least urgent;
- recorded asset, evidence, remediation, ownership, service-level, due-date, status, rationale, re-evaluation, and public-reference fields;
- scope, out-of-scope boundaries, next actions, limitations, and an interpretation guide.

The server derives the public band, maps a recorded EDIP decision to its action label, and produces counts, ordering, and hashes. It does not infer a decision from severity. A finding without a recorded decision is labelled **Not assigned**.

## Confidential scoring boundary

Customer artifacts deliberately exclude Tempris crown-jewel scoring material, including raw TES values and breakdowns, AGM/DRF/TEF inputs, multipliers, thresholds, caps, calibration tables, formulas, internal weighting, and intermediate calculations.

The report communicates outcomes, evidence, treatments, and decision rationale. It does not disclose how proprietary scoring is calculated.

## Data provenance and omissions

Every report value must have a traceable tenant-scoped source. Missing data is shown as **Not recorded**, counted as **Not assigned**, or omitted. The report service specifically does not create:

- an EDIP decision or action label from severity, priority, band, or score;
- an SLA, due date, re-evaluation date, owner, effort estimate, business impact, remediation guidance, verification result, or rationale when the source record lacks it;
- a client exposure claim from a global CISA KEV catalog entry that is not linked to a tenant asset;
- a whole-tenant aggregate TES when validated asset-matched scoring coverage is incomplete (Synthesis may show a clearly scoped asset-linked/scored aggregate beside its coverage);
- a compliance claim from framework defaults or an unassessed control;
- tenant findings or audit logs in the shared RAG/vector store;
- module-health status without a live telemetry source; or
- independent assurance or partner-sharing authority without explicit recorded approval.

Assessment scope and out-of-scope boundaries are mandatory. This prevents an otherwise polished report from implying coverage that was never recorded.


## Alliance-partner consent gate

Partner distribution defaults to withheld.

- Naming a partner without recorded client consent produces `partner_delivery_status: withheld`.
- A partner is authorised only when both the partner name and explicit client-consent flag are present.
- The proof-of-concept records the decision in the report; it does not send email automatically.

Alliance partners may explain the report, facilitate ownership, and help the client follow the next steps. They must not change Tempris decisions, claim certification, represent the report as MAS approval, or receive it without client consent.

## Interpretation guide

- **Fix now**: ownership and treatment should be prioritised within the stated service level.
- **Watch**: investigate, monitor, or retain a compensating control until the review date.
- **Safe to wait**: deferral is supportable based on current evidence, but the finding must be reassessed when conditions change.
- **Not assigned**: no EDIP decision is recorded; the report does not infer one from severity or score.
- **Evidence tier**: communicates the strength of recorded support; it is not another risk score.
- **Integrity hash**: permits recipients to detect changes to the canonical JSON report data.

Partner enablement should teach the meaning of these fields, how to discuss actions and evidence, and when to return questions to Tempris. It must not include proprietary scoring formulas.

## Integrity and security

The canonical data (excluding its own integrity field) is hashed with SHA-256 and the hash is printed in the HTML report. The complete JSON artifact is separately hashed and recorded in the report registry and audit log.

The HTML response is non-cacheable, cannot be framed, has no script execution, and is rendered with escaped customer/finding text. CSV values that could trigger spreadsheet formulas are prefixed safely. Artifact paths are derived from validated report IDs and are never accepted from the client.

## Regulatory positioning

The MAS TRM gap-check is useful groundwork for technology-risk and vulnerability-management discussions. The report is not:

- approval by the Monetary Authority of Singapore;
- a certification or compliance sign-off;
- legal advice;
- an independent penetration-test opinion; or
- a replacement for assurance activities required by a client's obligations.

Independent assessor or CSRO attestation is shown only when a named person and statement are deliberately supplied. Tempris never auto-claims independent assurance.

## PDF operation

Open **Preview**, use the browser's Print command, select **Save as PDF**, choose A4 paper, enable background graphics, and save the file. HTML remains the single maintained presentation source so PDF and online views do not drift.

Before client delivery, confirm:

- organisation, contact, engagement, environment, and period;
- included findings, asset ownership, service levels, and due dates;
- any assessor or attestation wording;
- scope and limitations;
- partner consent and recipients; and
- the integrity hash against the JSON artifact.

## Current boundary and next phase

The on-demand HTML/PDF, JSON, and CSV package is implemented for the proof-of-concept. Scheduled generation, email delivery, digital signing, configurable client branding, and workflow approvals are intentionally deferred until commercial and operational requirements are confirmed.
