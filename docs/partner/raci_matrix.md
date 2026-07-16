# Partner RACI and Escalation Matrix

This document defines the clear operational boundaries, responsibilities, and escalation protocols between Clients, Partners, and the Tempris CSRO team.

## Responsibility Assignment (RACI)

| Activity | Client Tenant | Partner Analyst | Partner Admin | Tempris Admin (CSRO) |
| :--- | :---: | :---: | :---: | :---: |
| **Initial Tenant Provisioning** | I | I | C | A, R |
| **Threat Pack / Feed Ingestion** | I | I | C | A, R |
| **Finding Triage & Validation** | C | R | A, C | I |
| **Remediation & Control Assignment** | A, R | C | C | I |
| **SLA Breach Monitoring & Alerts** | I | R | A, C | I |
| **Sandbox Environment Reset** | I | C | A, R | I |
| **Legal/DPA Sign-offs** | A, R | I | C | C |
| **AI Prompt Injection Guardrails** | I | I | I | A, R |

*Legend: **R** (Responsible), **A** (Accountable), **C** (Consulted), **I** (Informed)*

---

## Technical Access Controls (No Production SSH)

To comply with the Tempris security architecture:
1. **Partner Admin & Analyst Accounts** are strictly mapped to their respective `tenant_id` at the database level.
2. **Production SSH access** is exclusively restricted to the internal Tempris Platform Infrastructure Team (CSRO).
3. **Partners** have zero access to production command shell keys, Docker socket endpoints, or raw database connection strings.
4. **Resettable Training Sandbox:** A secure API sandbox is provided where Partner Admins can run reset commands (`POST /api/partner/sandbox-reset`) to refresh mock datasets for training.

---

## Escalation Path & Contacts

### Level 1: Operational Inquiries (SLA: 4 Hours)
For questions regarding specific finding details, remediation suggestions, or general platform usage:
- **Contact:** Partner Operations Helpdesk (`partner-ops@tempris.com`)

### Level 2: Critical SLA Breach & Security Incidents (SLA: 1 Hour)
For critical-rated findings breaching target resolution times, or suspected tenant isolation issues:
- **Contact:** Tempris Security Operations Center (`soc@tempris.com`)

### Level 3: Platform Outages & Infrastructure (SLA: 30 Minutes)
For total platform unavailability, database connectivity failures, or SSO lockout:
- **Contact:** Tempris Infrastructure Team (`ops@tempris.com`)
