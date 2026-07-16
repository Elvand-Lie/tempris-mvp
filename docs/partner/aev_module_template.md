# Autonomous Evidence Verification (AEV) Module Definition Template

This template defines the functional and security boundaries required for any AEV module prior to implementation.

## Module Identification
- **Module Code Name:** (e.g. ATLAS, APOLLO, HELIOS, ORION, TARA)
- **Primary Owner / Custodian:** 
- **Assigned Vulnerability Subtypes:** 

## Business Boundaries
- **Business Purpose:** 
- **Target Audience / Intended Users:** 
- **Allowed Actions:** 
- **Prohibited / Destructive Actions:** 

## Technical Integration Details
- **Inputs Required:** (Specify JSON schema)
- **Target Endpoint/Host Parameters:** 
- **External Scanning Tool Integrations:** (e.g. nmap, nuclei, owasp-zap)

## Safety & Compliance Boundaries
- **Two-Man Authorization Required?** (Yes / No)
- **Execution Environments Allowed:** (e.g. sandbox, staging, production)
- **Required User Role for Run Initiation:** (Superadmin / Admin / Analyst)
- **Execution Expiry/Time Limit:** 

## Verification & Output Manifests
- **Evidence Schema Generated:** (Log path, screenshots, raw output hashes)
- **Verification Criteria:** 
- **Audit Logging Actions & Triggers:** 
