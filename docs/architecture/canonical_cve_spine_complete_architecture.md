# Tempris Architecture: Canonical CVE Spine & Decoupled Exposure Engine

## 1. System Overview

The Tempris Canonical CVE Spine establishes a single, global, tenant-agnostic vulnerability intelligence layer while strictly decoupling global vulnerability records from customer exposure states, compliance tracking, and dynamic risk scoring.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                   GLOBAL CANONICAL INTELLIGENCE SPATIAL LAYER                    │
│                                                                                  │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                      CanonicalVulnerability                              │   │
│   │   cve_id (PK, e.g. 'CVE-2024-38077')                                     │   │
│   │   status ('published', 'rejected', 'reserved', 'unknown')                │   │
│   │   replaced_by_cve_id (FK to CanonicalVulnerability.cve_id)               │   │
│   └───────────────┬──────────────────────────────────────────┬───────────────┘   │
│                   │ 1:N                                      │ 1:1               │
│                   ▼                                          ▼                   │
│   ┌────────────────────────────────┐       ┌─────────────────────────────────┐   │
│   │  VulnerabilityCvssAssessment   │       │         CisaKevEntry            │   │
│   │  (Provenance-Preserving CVSS)  │       │     (Exploitation Enrichment)   │   │
│   │  - Multi-version (2.0/3.x/4.0) │       │  - date_added, due_date         │   │
│   │  - Multi-authority (NVD/CNA)   │       │  - required_action, notes       │   │
│   │  - Exact vector string & score │       │  - known_ransomware_campaign_use│   │
│   │  - Source record SHA-256 hash  │       │  - Source record SHA-256 hash   │   │
│   └────────────────────────────────┘       └─────────────────────────────────┘   │
└───────────────────────────────────────────┬──────────────────────────────────────┘
                                            │ Exact Syntax FK (findings.canonical_cve_id)
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      TENANT-SCOPED SECURITY FINDING LAYER                        │
│                                                                                  │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                              Finding                                     │   │
│   │   id (PK, e.g. 'F-2024-38077-DEF'), tenant_id ('tenant-acme')            │   │
│   │   canonical_cve_id (FK to CanonicalVulnerability.cve_id)                 │   │
│   │   finding_type ('vulnerability', 'sss_supply_chain', etc.)               │   │
│   │   status ('open', 'investigating', 'mitigated', 'resolved')              │   │
│   │   score (Frozen for closed history, live context for open)               │   │
│   │   cve_context (Auditable business impact & scoring history)              │   │
│   │   sss_data (GRC supply chain & non-CVE scoring metadata)                 │   │
│   └───────────────────────────────────────┬──────────────────────────────────┘   │
└───────────────────────────────────────────┼──────────────────────────────────────┘
                                            │ 1:N Confirmed Relationships
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      CUSTOMER POSTURE & EXPOSURE BOUNDARY                        │
│                                                                                  │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                           AssetExposure                                  │   │
│   │   finding_id (FK to Finding.id), asset_id (FK to Asset.id)               │   │
│   │   status ('confirmed', 'accepted', 'mitigated', 'archived')              │   │
│   │   evidence_metadata (Verified scanner run hash / manual audit evidence) │   │
│   └──────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                      │
│                                           ▼ Confirmed Active Asset Only          │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                            Asset                                         │   │
│   │   id ('ASSET-001'), tenant_id, criticality ('critical', 'high', etc.)   │   │
│   │   status ('active', 'decommissioned')                                    │   │
│   └──────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Invariant Rules & Design Decisions

### Invariant 1: Customer Exposure Decoupling
* **Global CVE notices or KEV catalog rows are never customer exposures by themselves.**
* An exposure exists solely when an explicit `AssetExposure` with `status='confirmed'` links an active customer `Asset` to a `Finding`.
* Global reference CVEs, regulatory tracking notices, and un-linked findings are excluded from tenant risk dashboards, TES aggregation, and compliance violation queries.

### Invariant 2: Authoritative Server-Side CVSS Selection Policy
When resolving CVSS for a canonical vulnerability, the engine executes a deterministic priority resolution algorithm:
1. **Validity:** Filter to valid numeric base scores ($0.0 \le \text{score} \le 10.0$).
2. **Version Precedence:** Prefer modern CVSS versions: `4.0` > `3.1` > `3.0` > `2.0`.
3. **Authority Role:** Prefer authoritative primary assessments (`Primary` > `Secondary`).
4. **Recency:** Select the assessment with the newest `source_modified_at` timestamp.
5. **Deterministic Tie-Breaker:** Lexicographical sorting on `id`.

If a canonical vulnerability exists without any CVSS assessments, or if a legacy finding is not yet linked, the resolver safely falls back to finding-level CVSS as `legacy_unprovenanced` without mutating or polluting canonical tables.

### Invariant 3: Dynamic Live Context TES Engine
Live TES for open confirmed CVE findings dynamically draws from:
- **CVSS Component (35%):** Authoritative score from Canonical Intelligence Resolver.
- **Exploitability Component (25%):** Live CISA KEV membership (8.0), ransomware campaign flag (10.0), or recorded verified Nuclei scanner match (7.0).
- **Business Impact Component (20%):** Analyst-recorded context score; defaults to neutral 5.0 when unassessed.
- **Asset Criticality Component (12%):** Maximum criticality across confirmed active linked assets (`critical` = 10.0, `high` = 8.0, `medium` = 5.0, `low` = 2.0).
- **Threat Actor Activity Component (8%):** Threat intelligence feeds / CISA KEV threat context.

### Invariant 4: Historical Integrity & Score Immutability
* Findings with status `mitigated`, `resolved`, or `closed` preserve frozen historical scores.
* Recalculations and snapshot ingestion update only active, open, confirmed findings.

### Invariant 5: Non-CVE SSS Isolation
* Supply chain, pipeline, and architecture findings have `canonical_cve_id = NULL`.
* SSS findings evaluate severity through server-side SSS/GRC algorithms with bounded modifiers (`AGM * DRF * TEF`, capped at 1.40x).

---

## 3. Subsystem Integration & Contracts

### A. SPECTRUM CTEM Platform
* Serves findings enriched with canonical CVE metadata, provenance labels (`canonical_authoritative`, `canonical_secondary`, `legacy_unprovenanced`), and live TES breakdowns.
* Historical audit logs record every context recalculation with before/after scores.

### B. SCOUT Discovery Engine
* Serves global vulnerability catalogue intelligence from `canonical_vulnerabilities` and `cisa_kev_entries`.
* Normalizes incoming scanner observations (Nuclei, Nmap) against the canonical CVE registry without creating dummy tenant findings.

### C. STANDARD GRC & Compliance Framework
* Audits ISO/IEC 27001, ISO/IEC 42001, MAS-TRM, and SOC 2 controls against evidence-backed `AssetExposure` rows.
* Global reference CVEs remain regulatory advisories without triggering false-positive customer compliance violations.

### D. Downstream Contracts (CISO, SYNTHESIS, STRIKE, Reporting Engine)
* **CISO Executive Dashboard:** Reads aggregate TES derived exclusively from confirmed active asset exposures.
* **SYNTHESIS Aggregator:** Groups findings by root cause without cross-tenant leakage.
* **STRIKE Simulation Engine:** Authorizes breach simulation paths only on confirmed reachable exposures.
* **Reporting Engine:** Generates PDF and JSON debriefs preserving provenance classification.
