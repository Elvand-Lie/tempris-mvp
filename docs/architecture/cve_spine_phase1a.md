# Tempris Architecture: Canonical Vulnerability Intelligence Spine (Phase 1A)

## 1. Core Semantic Distinctions

Tempris enforces strict boundaries between global vulnerability intelligence, tenant findings, and confirmed customer exposures:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. CanonicalVulnerability (Global Identity & Lifecycle)                      │
│    - Unique key: cve_id (e.g., CVE-2012-1710)                               │
│    - Status: published, rejected, reserved, unknown                         │
│    - Pure identity: no tenant_id, no asset_id, no exposure state, no TES    │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       │ 1:N
         ┌─────────────┴─────────────────────────────┐
         ▼                                           ▼
┌───────────────────────────────────┐ ┌───────────────────────────────────────┐
│ 2. VulnerabilityCvssAssessment    │ │ 3. CisaKevEntry                       │
│    (Authoritative CVSS Vectors)   │ │    (Exploitation Enrichment)          │
│    - Multi-version (v2, v3, v4)   │ │    - Vendor, product, vuln name       │
│    - Multi-source (NVD, CNA, etc.)│ │    - Date added, due date, action     │
│    - Exact vector string & score  │ │    - Exact ransomware campaign flag   │
│    - Full source provenance hash  │ │    - Source snapshot ID and hash      │
└───────────────────────────────────┘ └───────────────────────────────────────┘

─────────────────────── TENANT & EXPOSURE BOUNDARY ───────────────────────────

┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. Finding (Tenant-Scoped Observation or Finding Record)                    │
│    - Tenant-scoped repository (CVE and non-CVE SSS findings)                │
│    - Triage decisions, business impact, SLA, and workflow state             │
└──────────────────────┬──────────────────────────────────────────────────────┘
                       │ 1:N
                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. AssetExposure (Canonical Customer Exposure Boundary)                     │
│    - Confirmed relationship between a Finding and an active tenant Asset    │
│    - Status: confirmed, accepted, removed                                  │
│    - Evidence: explicit analyst note or verified scanner execution hash     │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Canonical Vulnerability:** Global identifier and lifecycle status (e.g. `CVE-2012-1710`). Tenant-agnostic.
2. **CVSS Assessment:** An evaluation of severity provided by an authoritative body (NVD, CNA, vendor). Multiple versions and authorities coexist.
3. **CISA KEV Entry:** Source-specific exploitation metadata from CISA. Does **not** provide or alter CVSS.
4. **Finding:** A tenant-owned finding or observation in EDIP/CTEM triage.
5. **AssetExposure:** An evidence-backed link between a finding and an active customer asset. **A global CVE never constitutes customer exposure by itself.**

---

## 2. Phase 1A Operating Boundaries

Phase 1A establishes an **additive shadow registry**:
* All existing tables (`findings`, `asset_exposures`, `assets`, `audit_logs`, `control_statuses`, `incident_reports`) remain 100% authoritative and unchanged.
* Zero runtime readers (APIs, SPECTRUM CTEM, SCOUT discovery, STANDARD compliance, TES engine, reporting pipelines) query the shadow registry in this phase.
* Offline snapshot ingestion is executed via explicit CLI tools only. Network fetching is prohibited.

---

## 3. Provenance & Scoring Invariants

1. **No-Heuristic-CVSS Invariant:**
   * CISA KEV ingestion never derives, estimates, or invents CVSS scores.
   * Keyword-matching heuristics (e.g. assigning 10.0 for "remote code execution") are prohibited in the canonical layer.
2. **Multi-Authority Coexistence:**
   * NVD primary assessments do not overwrite CNA secondary assessments.
   * CVSS v2.0, v3.0, v3.1, and v4.0 metrics coexist as separate assessment rows.
3. **Deterministic Idempotency:**
   * Ingesting the same snapshot file multiple times results in zero duplicate rows and zero data drift.
4. **Transaction Safety:**
   * Ingestion operates in atomic transactions; failures trigger a complete rollback.

---

## 4. Lifecycle & Supersession Handling

* **Rejected CVEs:** Retained in `canonical_vulnerabilities` with `status='rejected'`. Historical records are never deleted.
* **Explicit Replacement:** The `replaced_by_cve_id` foreign key is populated **only** when authoritative source metadata explicitly specifies a replacement (e.g., via `ConsultIDs: CVE-YYYY-NNNN`). Inferred replacements by title, vendor, or keywords are prohibited.

---

## 5. Offline Snapshot Importers

1. **CISA KEV Snapshot:**
   ```bash
   python app/backend/scripts/import_cve_intelligence.py --source cisa-kev --file app/backend/data/cisa_kev_2026_05_22.json --db-path ./tempris.db
   ```
2. **NVD API 2.0 JSON Snapshot:**
   ```bash
   python app/backend/scripts/import_cve_intelligence.py --source nvd-json --file ./nvd_snapshot.json --db-path ./tempris.db
   ```

---

## 6. Explicitly Deferred Work (Phase 1B & Phase 2)

The following activities are intentionally out of scope for Phase 1A:
* Adding `findings.canonical_cve_id` foreign key column.
* Backfilling or linking existing `Finding` records to `canonical_vulnerabilities`.
* Updating `services/tes_engine.py` to read canonical CVSS for live scoring.
* Updating `services/scan_normalizer.py` to resolve Nuclei findings against canonical intelligence.
* Updating `routers/scout.py` to serve global catalogue queries from `canonical_vulnerabilities`.
* Fixing the native SPA frontend compliance violation query.
* Archiving legacy unlinked KEV rows from `findings`.
* EPSS (Exploit Prediction Scoring System) integration.
* Live network synchronization / API clients.

---

## 7. Rollback Procedure

Because Phase 1A is completely decoupled from active runtime paths:
* Reverting code changes restores pre-phase state.
* Dropping the three additive tables (`canonical_vulnerabilities`, `vulnerability_cvss_assessments`, `cisa_kev_entries`) completely cleans the database without touching tenant data, findings, exposures, or historical reports.
