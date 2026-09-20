# Tempris STRIKE Architecture Review

Prepared for standalone reading and sharing with GPT Web. This document contains the architecture recommendation, current-code evidence, deployment model, result semantics, scope, POCs, and primary sources. Local file links identify inspected code; GPT Web cannot open them without a separate upload. This review is not a full PRD.

## Quick reading guide

The original STRIKE concept is feasible. Keep CALDERA for ATT&CK emulation and Metasploit for supported vulnerability validation. Tempris governs authorization and evidence; its Collector forwards bounded jobs to a separate Linux runtime. The main deployment addition is that runtime VM and, for endpoint emulation, approved CALDERA agents. Reuse upstream content rather than writing thousands of exploits. First prove one CALDERA ability and one Metasploit check.

# Verdict

YES WITH CONDITIONS. The original CALDERA + Metasploit + BAS intent is implementable through a separate customer-side STRIKE Runtime. This is an architecture recommendation, not implementation approval or operational acceptance. No application code, deployment, engine installation, or scan was changed/executed for this review.

Reviewed 2026-09-06 against current C:\Tempris\TemprisV2 working contents, HEAD ad3624db816185c398613f0b120f6c06abaded1a. Existing uncommitted Collector/SCOUT changes were present and preserved. Earlier agent PASS reports were not treated as current implementation evidence.

# Current evidence and integration seams

- [Collector protocol](C:/Tempris/TemprisV2/collector/src/protocol.rs): typed SCOUT_JOB and result frames exist; no STRIKE protocol or cancellation frame exists.
- [Collector registry](C:/Tempris/TemprisV2/backend/app/collector_registry.py:600): authenticated-session dispatch checks tenant and lifecycle, tracks in-memory futures, and times out. Reuse transport, but long-running STRIKE needs durable operation identity and reconnect reconciliation instead of relying on a future surviving.
- [SCOUT authorization](C:/Tempris/TemprisV2/backend/app/scout.py:425): exact target/tenant/active Asset/approved unexpired authorization/Collector assignment checks exist. Scan approval has no authority for endpoint agents, exploit actions, credentials, callbacks, or multi-asset emulation.
- [SCOUT normalization](C:/Tempris/TemprisV2/backend/app/scout.py:274): strict CVE-template qualification; normalizer requires a PUBLISHED canonical record. Preserve unchanged.
- [Exposure query](C:/Tempris/TemprisV2/backend/app/exposure/service.py:303): same-tenant open Finding + confirmed exposure + active Asset. STRIKE references these identities; it does not redefine them.
- [Audit writer](C:/Tempris/TemprisV2/backend/app/audit.py:23): existing tenant audit writer can record STRIKE actions; raw engine output belongs in bounded evidence storage, not audit details.
- [Managed toolchain](C:/Tempris/TemprisV2/collector/src/toolchain/manifest.rs): allowed components are nuclei and nuclei_templates. Do not add offensive engines to this updater simply for convenience.
- [Collector storage](C:/Tempris/TemprisV2/collector/src/storage.rs:175): non-Windows credential protection is a test stub. Current Collector cannot be assumed production-ready on Linux.
- [V2 main](C:/Tempris/TemprisV2/backend/app/main.py): no STRIKE or SPECTRUM router registered. Parent [legacy STRIKE](C:/Tempris/app/backend/routers/strike.py) uses custom adversary_engine handlers and free-form legacy targets; it is not a ready CALDERA/Metasploit adapter or safe V2 schema transplant.

# Recommended topology

Dashboard -> Backend -> existing outbound authenticated Collector WSS -> authenticated STRIKE Runtime API -> CALDERA / Metasploit. Evidence returns through the same control path.

Keep the Windows Collector. Run Runtime, CALDERA server, and Metasploit Framework/RPC in one isolated customer Linux VM initially. A VM on the same physical Windows security host is sufficient; a separate customer Linux host also works. Collector initiates a certificate-authenticated connection to an operator-paired fixed runtime endpoint. Across a VM boundary this is not literal loopback: restrict the interface to the paired Collector. Engine management APIs remain private to the runtime VM. No inbound listener is added to Collector.

CALDERA endpoint agents run on explicitly approved test endpoints and contact the customer CALDERA server. An agent only on the security host cannot simulate endpoint execution on arbitrary other Assets. Agent-to-server contact and any allowed engine callback paths require separate topology/engagement approval.

Backend caches a pinned ATT&CK STIX dataset. Runtime has approved, versioned CALDERA profiles/abilities and Metasploit modules. Native engine data is supporting execution state; Tempris retains authoritative tenant job/result/evidence history.

# Ownership and bounded commands

CALDERA provides server, agents, abilities, adversary profiles, operations, planners, and ATT&CK-labelled content. Tempris selects approved compatible content and supplies validated facts. Existing content removes the need to implement every technique but does not guarantee complete ATT&CK coverage or prerequisites.

Metasploit provides module metadata, checks where implemented, and separately approved exploit validation. Exact CVE references identify candidate modules, not guaranteed compatibility. Tempris must evaluate actual platform/architecture/service/version/options/credentials/session prerequisites and preserve unknowns. A check is module-specific and can be intrusive.

BAS playbooks should be thin Tempris orchestration records referencing curated CALDERA profiles plus expected evidence/control outcomes and cleanup. Use CALDERA's existing Atomic plugin if Atomic Red Team content is needed. No third offensive engine or hand-written per-CVE exploit library.

Collector adds readiness, sealed start/status/cancel/result messages, authenticated runtime pairing, expiry and replay checks, bounded forwarding, durable correlation/acknowledgment, and reconnection reconciliation. Execution remains asynchronous so SCOUT heartbeat/probing is not blocked. Runtime independently enforces signed/time-limited engagement permissions, approved catalog versions, parameter schemas, destination/agent scope, limits, cancellation, and cleanup. No raw RPC, console, command, arbitrary module options, or arbitrary runtime URL passes through Collector.

CALDERA and Metasploit are powerful execution engines. Moving them to another process does not by itself make them bounded. Runtime policy, pinned content, isolation and network restrictions are necessary; SCOUT DNS pinning alone cannot constrain every downstream ability or callback. One runtime/engine tenancy per customer initially; CALDERA groups and Metasploit workspaces are not Tempris tenant-security boundaries.

# Minimum backend and UI

New tenant domains: approved engagement with immutable ROE versions and explicit Asset/agent scope; STRIKE job with engine operation ID and lifecycle; per-step validation results with native outcome; evidence references/hashes; approved content compatibility catalog and ATT&CK mappings. Use existing Asset, Finding, Exposure, SCOUT observation IDs with same-tenant checks. SPECTRUM linkage is an optional future reference, not a new SPECTRUM implementation. Persist ordered evidence-backed step relationships for confirmed paths; no graph engine for the POCs. Isolated successful checks do not prove a traversed multi-hop path.

Authorization UI approves scope, methods, credentials, time window, cleanup, and stop conditions. Simulation Console selects compatible approved profiles/checks and shows readiness/status/cancel. ATT&CK Matrix shows tested, observed, prevented, unsupported and untested techniques by engagement. Results show evidence and source links. Red Team Report is a reproducible export of engagement scope, outcomes, evidence, limitations and cleanup, without new scoring logic.

# Result semantics

Keep execution status separate from validation outcome, and retain native engine codes.

| Outcome | Required meaning |
| --- | --- |
| EXPLOITABLE | Reviewed validation predicate has direct evidence of the specified vulnerability being exercised on the exact Asset. A CVE association, banner, successful generic technique or process exit is insufficient. |
| PREVENTED | Evidence links the attempted authorized action to an actual defensive control intervention. Failure, timeout or silence alone is insufficient. |
| INCONCLUSIVE | Attempt ran but evidence cannot establish the claim; preserve why. |
| NOT_EXECUTED | No attempt occurred, e.g. approval or prerequisite missing or cancellation before dispatch. |
| UNSUPPORTED | No approved compatible module/check/ability exists for this request. |
| ERROR | Adapter/engine/transport/parser failed; target outcome remains unknown. |
| OBSERVED | The requested non-exploit technique executed with its expected evidence; necessary for CALDERA discovery/control tests. |

Keep Metasploit Safe as a native negative result; never translate it to PREVENTED. Appears/Detected do not establish exploitation. Do not create/resolve Exposure rows merely from generic emulation outcomes. The first POCs attach results to existing references only.

# Blast radius

| Component | Required change | Size | Risk |
| --- | --- | --- | --- |
| Frontend | Five STRIKE areas over shared design/auth | Medium | Medium |
| Backend | Engagement, jobs, adapters, normalized results | Large | High |
| Collector | Narrow runtime bridge, status/cancel/recovery | Small-medium | High trust impact |
| STRIKE Runtime | Isolated policy enforcement and two engine adapters | Large | High |
| Database | Additive STRIKE tables and tenant-consistent references | Medium | Medium |
| Deployment | Linux VM, pairing, agents, credentials, network/cleanup | Medium-large | High |
| SCOUT | Read existing observations only | None initially | Low |
| SPECTRUM | Future optional references | None initially | Low |
| Audit | New events using existing writer | Small | Medium |
| Reporting | Export STRIKE evidence/history | Small-medium | Medium |

# Smallest proofs

POC A: one authorized test Asset with one manually approved CALDERA agent; one existing non-destructive discovery ability; Collector -> Runtime -> CALDERA -> endpoint -> correlated evidence back to a simple STRIKE result. Validate wrong-tenant/expired permission rejection and cancel/disconnect reconciliation. Success is OBSERVED, not EXPLOITABLE. This proves the architecture, not prevention detection; PREVENTED needs correlated control telemetry or reviewed evidence.

POC B: one existing SCOUT-linked CVE on an authorized isolated lab Asset, one compatible reviewed Metasploit module with check support, exact scope through the same Collector/Runtime path, preserved native check evidence, linked STRIKE result. Verify unsupported/checkless cases truthfully. No automatic transition to exploit. A separately approved controlled exploit proof is a later gate if the product claims confirmed exploitation. Neither POC uses backend-local execution as fallback.

# Major blockers and proposed freeze

Blockers: inability to run Linux CALDERA infrastructure; prohibited endpoint agents; absent platform executors/credentials/privileges; restricted agent/engine callback routes; uncontrolled planners/third-party module destinations; insufficient evidence for prevention or exploitation; cancellation that cannot confirm stop or cleanup; vulnerable/unpinned engine versions; component-specific license/distribution requirements. Runtime expiry must stop scheduling during disconnection; offline endpoint processes may not be instantly stoppable and must be reported unresolved. No guarantee of complete cleanup or rollback of executed actions.

Propose freezing: original engines retained; Windows Collector as narrow gateway; Linux Runtime per tenant; independent STRIKE engagement approval; curated versioned upstream content; no raw execution interface; durable evidence and truthful outcome semantics; existing SCOUT/Exposure/VI untouched; pass POCs A/B before full PRD. User acceptance of this recommendation is not assumed.

# Primary external sources checked

- [CALDERA requirements and deployment security](https://github.com/apache/caldera): Linux/macOS server requirements, REST framework, plugins, private deployment recommendation. Current mitre/caldera URL redirects here; pin the selected release and plugins.
- [CALDERA terminology](https://caldera.readthedocs.io/en/latest/Learning-the-terminology.html): agent, ability, adversary, planner, operation, fact and output model.
- [CALDERA plugin library](https://caldera.readthedocs.io/en/latest/Plugin-library.html): Atomic plugin reuses Atomic Red Team tests.
- [CALDERA operation results](https://caldera.readthedocs.io/en/stable/Operation-Results.html): operation/event-log evidence exports.
- [Metasploit RPC module API](https://docs.metasploit.com/api/Msf/RPC/RPC_Module.html): metadata, options, module search, check, results, compatibility interfaces.
- [Metasploit RPC guide](https://docs.metasploit.com/docs/using-metasploit/advanced/RPC/how-to-use-metasploit-messagepack-rpc.html): asynchronous job/result/session handling.
- [Metasploit check semantics](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-write-a-check-method.html): Safe, Detected, Appears, Vulnerable, Unknown, Unsupported distinctions and intrusive checks.
- [Metasploit installers](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html): Windows/Linux/macOS packaging; Linux choice is deployment simplification, not a claim Metasploit requires Linux.
- [ATT&CK data](https://attack.mitre.org/resources/attack-data-and-tools/): STIX data and TAXII access.
- License evidence: [CALDERA Apache-2.0](https://github.com/apache/caldera/blob/master/LICENSE), [Metasploit BSD-3-Clause and third-party exceptions](https://github.com/rapid7/metasploit-framework/blob/master/LICENSE), [Atomic Red Team MIT](https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt). Review notices/dependencies for the exact packaged versions; these licenses are not blanket permission for every bundled payload/plugin.

