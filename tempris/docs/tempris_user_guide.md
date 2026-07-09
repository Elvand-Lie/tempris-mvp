# Tempris User Guide

Short guide for using the Tempris security and compliance platform.

## 1. Login

Open the Tempris web app and sign in with the account provided by the admin.

After login, use the left-side navigation menu to move between modules.

## 2. Main Modules

### Assets

Use Assets to view and manage systems being tracked by Tempris.

- Review asset names, owners, environments, and risk status.
- Add or update asset records where required.
- Use asset information to support vulnerability and compliance review.

### Scout

Use Scout to review discovered security findings and CVE-related information.

- Search and review findings.
- Check severity, status, and affected assets.
- Send relevant findings into Spectrum for prioritization and decision tracking.

### Spectrum

Use Spectrum to triage vulnerabilities and track EDIP decisions.

EDIP means:

- Expose
- Detect
- Investigate
- Protect

In this module, users can:

- Review vulnerability priority.
- Apply or update EDIP decisions.
- Record business justification.
- Track pending, decided, and remediation-related items.

### Strike

Use Strike for controlled security simulation and validation workflows.

- Review authorized test activity.
- Track simulation results.
- Use the output to support remediation and security hardening.

### Standard

Use Standard for control and evidence management.

- Review security or compliance controls.
- Upload evidence files where needed.
- Download or delete evidence based on role permissions.
- Track whether a control is supported by evidence.

### GRC / TES

Use GRC / TES for ISO 42001-style governance and risk scoring.

Key areas:

- TES Dashboard: shows governance-related risk modifiers.
- GRC SOP Builder: tracks control ownership, notes, and signoffs.
- Gap Analysis: shows completed, in-review, and pending controls.
- Policies and Frameworks: opens the prepared policy documents.

Checkbox signoffs in the SOP Builder feed the AI policy status and gap analysis.

### Spotlight

Use Spotlight to generate executive or compliance summaries.

- Select the report type.
- Generate a short summary for stakeholders.
- Use the output as a starting point for review, not as a final legal or compliance opinion.

### Audit Log

Use Audit Log to review important platform activity.

- Login and security events.
- GRC updates.
- Policy views or edits.
- Evidence and workflow actions.

### SPEAK Assistant

Use the SPEAK assistant for quick security questions inside the platform.

It can help explain findings, risk status, and platform context.

## 3. Data Source

The vulnerability and CVE data used in the demo comes from the official CISA Known Exploited Vulnerabilities catalog.

Tempris then processes that data internally for:

- TES scoring
- EDIP status
- Prioritization
- Dashboard views
- Reports and summaries

The GRC policy documents, SOP entries, and demo evidence workflow are prepared demo/compliance materials. No customer production data is required for the demo.

## 4. Typical Workflow

1. Login to Tempris.
2. Review assets in Assets.
3. Check findings in Scout.
4. Triage important findings in Spectrum.
5. Record EDIP decisions and business justification.
6. Upload supporting evidence in Standard or GRC.
7. Review GRC/TES status and policy documents.
8. Generate a stakeholder summary in Spotlight.
9. Confirm key actions in the Audit Log.

## 5. Notes for Users

- Use the dashboard as a decision-support tool.
- Review AI-generated summaries before sharing externally.
- Keep evidence files relevant and clearly named.
- Do not upload sensitive customer data unless approved.
- Contact the platform admin if access or permissions need to be changed.

