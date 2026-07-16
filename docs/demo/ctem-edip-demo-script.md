# Tempris CTEM & EDIP Partner Demonstration Script

This document details the step-by-step walkthrough script for a 10–15 minute recording/demonstration of the Tempris platform capabilities using only fictional client sandbox data. 

> [!WARNING]
> **SAFETY & COMPLIANCE WARNING**
> - **DO NOT** use production client data or connect to production infrastructure during this demonstration.
> - **DO NOT** expose internal scoring formulas, weight tables, raw TES values, or modifier tables (`agm`, `drf`, `tef`, `sss_base_raw`) in UI rendering, exports, or logs. Only display the final scoring decision and public reason codes.
> - All host-level sandbox exercises must run in the disposable, resettable training sandbox environment.

---

## Fictional Scenario Setup

- **Fictional Tenant:** `fictional-partner-corp`
- **Fictional Client:** `fictional-retail-client`
- **Fictional Users:**
  1. `partner-admin@fictional-partner.com` (Role: `Admin` / Partner Admin)
  2. `partner-analyst@fictional-partner.com` (Role: `Analyst` / Partner Analyst)
  3. `admin@tempris.com` (Role: `Superadmin` / Tempris Platform Admin)

### Prerequisites
1. Access to the Tempris Web UI sandbox environment.
2. A client REST client (e.g. Postman or cURL) or the sandbox console.
3. The demo environment initialized with default mock credentials.

---

## Demonstration Sequence

### Step 1: Explain User, Partner-Admin, and Partner-Analyst Roles
- **Narrative:** Briefly explain the segregation of roles. Show that `Partner-Admin` has rights to onboard users, configure workspaces, sign off on controls, and reset sandbox environments. Show that `Partner-Analyst` can view assets and findings, log decisions, and run assessments but cannot perform administrative functions like sandbox resets.
- **Verification:** Attempt to access the sandbox reset endpoint (`POST /api/partner/sandbox-reset`) using the `partner-analyst` token. Show that it returns `403 Forbidden`. Then perform the action using `partner-admin` token to demonstrate authorization controls.

### Step 2: Show Workspace Integration
- **Narrative:** Demonstrate the provisioning of a partner workspace via the `/api/partner/onboard` endpoint. Explain that workspace integration is handled strictly via API keys and secure tenant context at the application layer, without exposing host-level SSH or container configuration.
- **API Action:**
  ```json
  POST /api/partner/onboard
  {
    "license_verified": true,
    "agreements_signed": true,
    "attendees": ["Alice Admin", "Bob Analyst"],
    "provisioning_status": "completed",
    "role_assigned": "partner-admin"
  }
  ```

### Step 3: Create or Import Fictional Assets
- **Narrative:** Add a mock target server to the scope of our assessment.
- **Action:** Post a new asset to `/api/assets` under the `fictional-partner-corp` tenant.
- **Request:**
  ```json
  POST /api/assets
  {
    "id": "ASSET-DEMO-001",
    "name": "E-Commerce Database (Sandbox)",
    "asset_type": "database",
    "ip_address": "192.168.100.5",
    "hostname": "db.sandbox.internal",
    "criticality": "high",
    "environment": "staging"
  }
  ```

### Step 4: Run or Replay a Safe SCOUT Assessment
- **Narrative:** Replay a vulnerability assessment sweep on the newly added asset.
- **Action:** Call the SCOUT simulation endpoint to ingest scan findings.
- **Outcome:** The system detects standard CVEs (e.g., a vulnerability in the database engine) and maps it to the asset.

### Step 5: Show Escalation into SPECTRUM and Final Public Decision
- **Narrative:** View the finding in the SPECTRUM risk module. Explain how the threat is analyzed server-side.
- **Key Visual Check:** The UI displays the vulnerability with its public CVSS score and priority rank.
- **Verify Security Invariant:** Verify that internal formulas (e.g. `TEF` or `AGM`) are completely absent from the page source and response JSON. Only the final priority (`P1`/`P2`), status (`unmitigated`), and public reason codes are visible.

### Step 6: Show EDIP Intake, Decision, and Compensating Controls
- **Narrative:** The partner analyst inputs a security decision for the database vulnerability (e.g., applying a compensating control rather than patching immediately).
- **Action:** Create an EDIP Decision record.
- **Request:**
  ```json
  POST /api/edip/decisions
  {
    "finding_id": "F-DEMO-001",
    "decision": "risk_accepted",
    "rationale": "Compensating database firewall rules are active on the subnet."
  }
  ```
- **Outcome:** The finding status changes to `TRIAGED` or `MITIGATION_PLANNED`. The compensated controls are shown as active.

### Step 7: Configure a STANDARD Framework and Generate a Gap Report
- **Narrative:** Show mapping of findings and controls against standard compliance frameworks (e.g., ISO 27001 or SOC 2).
- **Action:** Update control status in GRC, showing how the compliance framework gap report reflects the triaged vulnerabilities and active compensating controls.

### Step 8: Show Audit Evidence and Actor Attribution
- **Narrative:** Access the audit trail to view logs of the onboarding, decision, and report actions.
- **Key Check:** Show that the logs contain server-derived IP addresses and the authenticated identity from the JWT (rather than any client-supplied header identity). The hash checks confirm integrity.

### Step 9: Generate Combined Client Report Package
- **Narrative:** Export the consolidated compliance and security posture report.
- **Action:** Call the reporting endpoint to produce a combined package manifest referencing the SPECTRUM risk report, STANDARD gap report, and audit logs.
- **Request:**
  ```json
  POST /api/reports/generate
  {
    "report_type": "combined",
    "source_finding_ids": ["F-DEMO-001"],
    "source_evidence_ids": [],
    "framework_configuration": {
      "engagement_id": "ENG-DEMO-2026",
      "framework_id": "ISO-27001"
    }
  }
  ```
- **Outcome:** A package manifest is returned listing the location and hashes of each constituent sub-report.

### Step 10: Reset the Fictional Training Sandbox
- **Narrative:** Clean the environment back to a clean state for the next run.
- **Action:** Call `/api/partner/sandbox-reset` with administrative credentials.
- **Outcome:** Fictional database assets and findings are restored to baseline mock values.

---

## Troubleshooting & Verification Notes
- **401 Unauthorized:** Ensure the `Authorization: Bearer <token>` header contains a fresh, unexpired JWT.
- **Database Connection Issues:** Verify `tempris.db` is writable by the backend process.
- **Reset Fails:** The sandbox reset endpoint is restricted to `Superadmin` and `Admin` roles. Confirm the caller's role mapping.
