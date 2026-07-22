# Tempris Revision List

## v62 debrief update

- Add deterministic CVSS v2-to-v3.1 normalization for legacy CVE intake, including the CVE-2008-4128 CSRF acceptance path.
- Add SCOUT Entra `authenticationMethods` posture intake for SMS/voice MFA findings and dated escalation outputs.
- Add `AGENTIC_EXPOSURE` and `IDENTITY_POSTURE` subclass contracts, descriptive posture fields, and server-authoritative SSS/TES/EDIP outputs.
- Add authenticated SCOUT AEV verdict intake with validated evidence and server-provided revalidation countdown states.
- Add the July v62 decision records and client rendering for category/subclass tags, VALIDATED state, KEV deadlines, and required controls.
- Before starting an existing deployment, run `scripts/migrations/006_add_sss_sub_class.py` against a verified database backup. Configure `AEV_VERDICT_ENGAGEMENT_TOKEN` before enabling the AEV verdict connector.

## UI/UX

- STRIKE: fix main content overlap/horizontal dragging, shorten "Re-run" target button, add compact result summary, and open MITRE tile evidence in a details drawer.
- STRIKE: split "Exploitable" from lower-risk "Exposure/Observation" so server fingerprint disclosure does not look like a confirmed exploit.
- STANDARD: make the MAS TRM 1-hour incident notice clearly read as a draft notification package, not a submitted regulatory filing.
- STANDARD: add persistent incident-report storage if submission tracking, approval, export history, or MAS submission status is required.
- SPEAK: render assistant replies as Markdown and make reset clear saved server-side chat history.
