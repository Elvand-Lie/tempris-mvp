# Tempris Data Flow and Lifecycle

## Canonical finding lifecycle

```mermaid
flowchart LR
  A[Manual intake / Graph / AEV / legacy import] --> B[Finding Registry]
  B --> C{Disposition}
  C -->|suggestion only| D[Exposure Review Queue]
  C -->|reference| E[Reference intelligence]
  C -->|not applicable| F[Not applicable history]
  D -->|analyst + evidence| G[Confirmed AssetExposure]
  G --> H[SPECTRUM / server EDIP]
  H --> I[Canonical posture]
  I --> J[CISO / SYNTHESIS]
  I --> K[SPOTLIGHT / Client Reports]
  H -->|resolve| L[Resolved history]
  L -->|reopen| H
```

```text
Manual forms / Graph / AEV / legacy import
                    |
                    v
              Finding Registry
                    |
          +---------+----------+
          |                    |
          v                    v
  Exposure Review       Reference / N/A
          |
          | Assign Assets + evidence
          v
 confirmed AssetExposure (same tenant, active asset)
          |
          v
 SPECTRUM / server EDIP --> canonical posture --> CISO / SYNTHESIS
                                             `-> SPOTLIGHT / Client Reports
```

`services.customer_posture.canonical_exposure_rows` is the authoritative inclusion rule. `Finding.asset_id`, keyword suggestions, and imported vendor/product matches do not cross the confirmation boundary.

## SCOUT scan flow

```mermaid
flowchart TD
  A[Authorized target] --> B[ScanJob]
  B --> C[Nmap/TCP observations]
  B --> D[Nuclei matches]
  C --> E[ScanFinding only]
  D --> F{Qualifying security template?}
  F -->|No / informational| E
  F -->|CVE| G[Reuse/create canonical CVE Finding]
  F -->|non-CVE vulnerability| H[Reuse/create non-CVE Finding]
  G --> I{Exactly one active same-tenant asset?}
  H --> I
  I -->|Yes| J[Evidence-backed AssetExposure]
  I -->|No or ambiguous| K[Exposure Review Queue]
  J --> L[SPECTRUM / CISO]
```

```text
Scan target -> ScanJob -> ScanFinding observation
                         |-- Nmap/TCP/technology -> observation only
                         `-- qualifying Nuclei match
                               |-- CVE -> canonical CVE Finding
                               `-- non-CVE -> canonical non-CVE Finding
                                      |
                            exact one asset? -- no/ambiguous --> review
                                      |
                                     yes
                                      v
                         evidence-backed AssetExposure
```

Idempotency uses tenant, normalized target, engine, template/CVE, port, and service to stabilize scan observations; findings use tenant plus CVE or template identity. Repeated runs update last-seen/evidence/history rather than multiplying records.

## Global intelligence flow

```mermaid
flowchart LR
  A[CISA/reference import] --> B[Reference catalogue]
  B --> C[Candidate asset match]
  C -->|suggestion only| D[Analyst review]
  D -->|evidence confirms| E[Confirmed customer exposure]
  D -->|not relevant| F[Reference or not applicable]
```

```text
CISA/reference import -> reference catalogue -> candidate match
                                                   |
                                                   v
                                            analyst confirmation
                                                   |
                                                   v
                                         customer exposure
```

A catalogue row never becomes a customer fact because its vendor name resembles an asset. The explicit relationship and evidence are the boundary.

## Incident flow

```mermaid
flowchart LR
  A[SIEM / EDR / SOC / customer script / manual client] -->|authenticated POST| B[Incident]
  B --> C[Affected same-tenant assets]
  B --> D[Related same-tenant findings]
  D --> E[Intersect canonical confirmed exposure]
  C --> F[STANDARD]
  E --> F
  F --> G[MAS notification draft]
```

```text
SIEM/EDR/manual webhook -> Incident -> assets + related confirmed findings
                                      |
                                      v
                                  STANDARD
                                      |
                                      v
                            MAS notification draft
```

The compatibility API is `/api/incidents`. Idempotency is `(tenant_id, source, external_event_id)`. STANDARD refuses to manufacture an incident draft from global catalogue totals.

## Reporting flow

```mermaid
flowchart LR
  A[Canonical posture service] --> B[Current posture snapshot]
  B --> C[CISO / SYNTHESIS]
  B --> D[SPOTLIGHT narrative]
  B --> E[Client report HTML/JSON/CSV]
  E --> F[Immutable hash + report registry]
```

```text
canonical current posture -> CISO / SYNTHESIS
                          |-> SPOTLIGHT narrative history
                          `-> Client Report artifact + hash + version
```

Client Report assessment dates describe business context. They do not filter or reconstruct prior finding state. The artifact states “Current-state snapshot” and records generation time.

## TES flow

```mermaid
flowchart LR
  A[CVE finding] -->|CVSS base| C[Server contextual processing]
  B[Non-CVE finding] -->|SSS base| C
  C --> D[Finding TES]
  D --> E{Open confirmed exposure?}
  E -->|Yes, scoreable| F[Tenant TES aggregation]
  E -->|No| G[Visible history; excluded from tenant TES]
```

```text
CVE -> CVSS base -----\
                       server contextual processing -> Finding TES
non-CVE -> SSS base --/                              |
                                                      v
                                open confirmed population aggregation
                                                      |
                                                      v
                                                  Tenant TES
```

No browser component contains the contextual scoring internals.

## Exposure state transitions

| From | Action | To | Canonical posture effect |
|---|---|---|---|
| New/manual/connector | Create | Unmapped intake | None |
| Unmapped | Suggest asset | Suggested | None |
| Unmapped/suggested | Assign active same-tenant asset with evidence | Confirmed | Included if open and not reference/N/A |
| Any unconfirmed | Keep as Reference | Reference | Excluded |
| Any unconfirmed | Mark Not Applicable | Not applicable | Excluded |
| Confirmed open | Resolve | Resolved history | Removed from open posture |
| Resolved with confirmed link | Reopen | Confirmed open | Restored to open posture |
| Confirmed | Clear assignment | Unmapped/legacy history | Removed from canonical posture |

Each consequential transition writes audit evidence, a structured operational event where supported, and the existing finding/watch refresh event.
