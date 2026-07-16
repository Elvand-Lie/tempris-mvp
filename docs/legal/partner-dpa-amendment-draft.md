# [DRAFT - FOR LEGAL REVIEW]
# DATA PROCESSING AGREEMENT (DPA) AMENDMENT
## Tenancy Isolation & Cybersecurity Compliance Addendum

**Document Version:** 1.2-DRAFT  
**Status:** Under Legal Review  
**Applicability:** Standard Addendum for External Security Partners (Third-Party Providers)  

---

This DPA Amendment ("Amendment") modifies the principal Data Processing Agreement between **Tempris Custodian (CSRO)** and the undersigned **Security Partner** ("Partner").

### 1. Scope of Processing & Access Restriction
- **No Production SSH:** The Partner explicitly acknowledges and agrees that no direct production infrastructure credentials, including Host SSH keys, database connection strings, Docker daemon socket permissions, or cloud console credentials, shall be shared or provisioned to Partner personnel.
- **API-Only Scoping:** All operations, assessments, and queries performed by Partner analysts must run through the tenant-scoped REST API endpoints (`/api/`).
- **Partner Roles:** The Partner will assign personnel strictly into `partner-admin` (tenant configuration and sandbox management) or `partner-analyst` (triage and evidence collection) roles.

### 2. Multi-Tenant Logical Separation
- **Logical Row Isolation:** The platform must logically separate and isolate all database rows across assets, findings, evidence files, reports, scan results, and audit trails.
- **Tenant Context Enforcement:** The FastAPI services layer must enforce checks of the caller's JWT `tenant_id` claim against the resource owner's `tenant_id` for every query.
- **Secure File Ingestion:** Evidence files uploaded by the Partner must be sanitized, saved under UUID-hashed filenames, and restricted behind the `scoped_evidence_query` verification logic.

### 3. Verification & Compliance Monitoring
- **Structured-Probe Alerts:** The platform's rate limiting middleware actively monitors and blocks structured probing sequences designed to map private scoring algorithms.
- **Audit Chain Integrity:** All actions executed by Partner roles are logged in an append-only audit log signed with cryptographic HMAC-SHA256 hash chains.
- **Sandbox Training Environments:** A resettable mock client database is provided to the Partner for training and certification purposes. Resets are requested via `/api/partner/sandbox-reset`.

### 4. SLA & Breach Notification
- **Data Leak SLA:** The Custodian must notify the Partner of any suspected or confirmed cross-tenant data leaks, unauthorized access attempts, or prompt injection anomalies within **two (2) hours** of initial detection.
- **Playbook Execution:** In the event of a secret key leak in the codebase, the Partner must adhere to the standard SLA response guidelines (2 hours for critical, 6 hours for high secrets) defined in the *Secrets Rotation Playbook*.
