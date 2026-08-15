# Tempris Actions, Permissions, and Side Effects

Roles are enforced server-side. “Audit” means an `AuditLog` record; “event” means an `OperationalEvent`. Failed validation rolls back the transaction and returns a 4xx response; external/scanner failure records a failed run where possible.

| Action / page | Required role | Endpoint / function | Database and downstream effects | Reversible? |
|---|---|---|---|---|
| Submit Business Logic Finding — Intake | Authenticated permitted intake user | `POST /api/edip/intake/blflaw`; `edip.intake_blflaw` | Creates tenant `Finding`, event `finding.created`, audit; appears in registry/review and refreshes watchers. No posture impact until confirmed. | Resolve, classify, or reopen; record retained. |
| Submit Identity/Agentic Finding — Intake | Authenticated permitted intake user | `POST /api/edip/intake/sss` | Creates tenant `Finding` with server-validated SSS posture data; event/audit/watch. | Resolve/classify/reopen; record retained. |
| Assign Assets — Intake | Analyst/Admin/Superadmin | `POST/PUT /api/workflow/findings/{id}/assets`; `set_finding_assets` | Same-tenant validation; creates/updates confirmed `AssetExposure`, evidence/provenance, history, `finding.asset_confirmed`, audit, SSE. Canonical posture and reports change immediately. | Manage assets/Clear all; removal is recorded. |
| Keep as Reference — Intake | Analyst/Admin/Superadmin | `PUT /api/workflow/findings/{id}/exposure-classification` | Sets reference classification with rationale, event/audit/SSE; excludes posture. | Return to review. |
| Mark Not Applicable — Intake | Analyst/Admin/Superadmin | Same classification endpoint | Sets not-applicable with rationale, event/audit/SSE; excludes posture. | Return to review/reopen classification. |
| Resolve — Finding Registry | Superadmin | `POST /api/workflow/findings/{id}/resolve` or SSS resolve route | Status history preserved; `finding.resolved`, audit/SSE; leaves open posture. | Reopen. |
| Reopen — Finding Registry | Superadmin | `POST /api/workflow/findings/{id}/reopen` | Restores open/unmitigated status, preserves decisions/history; `finding.reopened`, audit/SSE; confirmed exposure re-enters posture. | Resolve again. |
| Mark Patch Available/Unavailable — Intake | Analyst/Admin/Superadmin | `PUT /api/edip/intake/sss/{id}` | Changes patch flag and update timestamp; audit/SSE. It does not itself resolve a finding or calculate an EDIP decision in the browser. | Toggle again. |
| Run SCOUT Scan — SCOUT | Authorized scanner role + explicit target authorization | `POST /api/scanner/scan` | Creates `ScanJob`; observations become idempotent `ScanFinding`; qualifying Nuclei results may normalize to Finding/AssetExposure; scan events. | Findings can be reclassified/resolved; run history retained. |
| Generate EDIP Decision — SPECTRUM | Permitted EDIP role | `POST /api/spectrum/findings/{id}/edip` | Adds/updates ordered server decision history, events `decision.created/updated`, audit/watch. | Override/add later decision; history preserved. |
| Override EDIP Decision — SPECTRUM | Authorized decision role | Same decision route with override contract | Adds override rather than erasing prior decision; `decision.overridden`, audit/watch. | Supersede with another authorized decision; history retained. |
| Create STRIKE authorization — STRIKE | Admin/Superadmin | `POST /api/strike/authorizations` | Creates tenant `StrikeAuthorization` with scope/rules. | Can remain unsigned/expire; no cross-tenant reuse. |
| Sign authorization — STRIKE | Admin/Superadmin | `POST /api/strike/authorizations/{id}/sign` | Records authorization signature/status. | Not silently reversible; create a new authorization when scope changes. |
| Generate STRIKE Simulation — STRIKE | Admin/Superadmin with signed same-tenant authorization | `POST /api/strike/simulations` | Creates `StrikeSimulation` and explicit outcome evidence. No-exposure is not converted to blocked. | Historical; run a new simulation. |
| Update STANDARD Control — STANDARD | Manager/Admin/Superadmin | `PUT /api/standard/frameworks/{framework}/controls/{control}` | Upserts `ControlStatus`; events `control.assessed`, `gap.opened/closed`; audit. Recalculates coverage/compliance. | Update assessment again; history/audit remains. |
| Attach Evidence — STANDARD | Manager/Admin/Superadmin | `POST .../evidence` | Creates `ControlEvidence`, event `control.evidence_attached`, audit. | Delete only with authorized endpoint; audit remains. |
| Create custom policy — GRC | Manager/Admin/Superadmin | `POST /api/grc/policies` | Creates versioned tenant `GrcPolicyDocument`, `policy.created`, audit. | Archive/supersede; unreferenced Superadmin delete. |
| Archive/Restore policy — GRC | Manager/Admin/Superadmin | `PATCH /api/grc/policies/{id}/archive` | Sets/clears archive metadata, event/audit; content/history retained. | Yes, restore. |
| Supersede policy — GRC | Manager/Admin/Superadmin | `POST /api/grc/policies/{id}/supersede` | Creates new version and links both versions; `policy.superseded`, audit. | Old version remains historical; new version can be superseded. |
| Delete policy — GRC | Superadmin | `DELETE /api/grc/policies/{id}` | Bundled rejected. Unreferenced custom policy hard-deleted. Referenced custom policy is archived to protect references. `policy.deleted`/archive audit. | Hard delete no; archive can restore. |
| Generate SPOTLIGHT Brief — SPOTLIGHT | Authenticated entitled user | `POST /api/spotlight/generate` | Stores `SpotlightReport` with generation timestamp and safe context metadata; audit. | Generate a new report; old report is historical. |
| Generate Client Report — Reports | Authorized report role | `POST /api/reports/poc/generate` | Builds current canonical snapshot artifacts, stores `GeneratedReport`, hash, sources, `report.generated`. | Immutable; regenerate/version or archive. |
| Download report — Reports | Same-tenant authorized user | `GET /api/reports/{id}/artifact/{format}` | Reads artifact; `report.downloaded` event where supported. No content mutation. | Not applicable. |
| Edit as new report — Reports | Authorized report role | Browser pre-fills a new request | Does not edit artifact; next generate creates a new immutable report. | Abandon draft before generating. |
| Regenerate report — Reports | Authorized report role | `POST /api/reports/{id}/regenerate` | Creates a new report/version and artifact/hash; preserves original; `report.version_created`. | Archive/delete new version subject to policy. |
| Archive/Restore report — Reports | Admin/Superadmin | `PATCH /api/reports/{id}/archive` | Updates lifecycle metadata; artifact and hash retained; event/audit. | Yes. |
| Delete report — Reports | Admin/Superadmin with confirmation | `DELETE /api/reports/{id}` | Deletes eligible registry/artifact according to route safeguards; audit/event. | No; use archive when retention matters. |
| Assign Package — Tenant Admin | Superadmin | `PUT /api/tenants/{id}/entitlements` or `/api/packages/current` | Updates package/config version and effective access; audit; backend enforcement changes. | Assign previous package. |
| Apply Module Override — Tenant Admin | Superadmin | Same entitlement route | Persists explicit module override and increments configuration version. | Remove/reset override. |
| Create Incident — integration/manual client | Admin/Analyst/Superadmin | `POST /api/incidents`; `incidents.create_incident` | Validates same-tenant asset/finding IDs, creates idempotent `Incident`, `incident.created`, audit. | Update status/details; record retained. |
| Update Incident — integration/manual client | Admin/Analyst/Superadmin | `PATCH /api/incidents/{id}` | Updates validated fields, `incident.updated`, audit. | Update again; history in audit/event. |
| Generate MAS Incident Draft — STANDARD | Authorized STANDARD role | `POST /api/standard/mas-trm/incident-report` | Requires real `Incident`; creates `IncidentReport` from incident assets, related canonical exposures, observed impact/actions/evidence; event/audit. | Generate a revised draft; existing draft remains. |
| Accept VDP submission — VDP Queue | Restricted triage staff | `POST /api/surge/submissions/{id}/triage` with accepted | Marks disposition and creates SPECTRUM finding; audit. | Subsequent finding lifecycle; submission history retained. |
| Reject VDP submission — VDP Queue | Restricted triage staff | Same endpoint with rejected | Stores rejected disposition/audit; no finding created. | Re-triage only if route state permits. |
| Mark VDP duplicate — VDP Queue | Restricted triage staff | Same endpoint with duplicate | Stores duplicate disposition/audit; no duplicate finding. | Re-triage if permitted. |
| Remove selected VDP submissions — VDP Queue | Superadmin/authorized deletion role | `DELETE /api/surge/submissions/{id}` | Deletes only eligible queue records after confirmation; audit. | No. |
| Verify Audit Log — Audit | Authorized assurance/admin role | `GET /api/audit/verify` | Recomputes tenant hash chain; no mutation. | Not applicable. |
| Ask SPEAK — SPEAK | Authenticated user | SPEAK endpoint in `index.py` | Stores tenant/user chat session and message; reads safe context. No control/finding mutation. | Conversation history policy applies; no security state to reverse. |

## Failure behavior

- Authentication/authorization failure returns 401/403 without mutation.
- Cross-tenant references return 404 or 422 without revealing the other tenant’s record.
- Optimistic entitlement version conflict returns 409 and preserves both the administrator’s local selections and the stored policy.
- Invalid scanner target/authorization fails before network execution.
- Report registry rows can outlive a missing file; UI displays artifact availability rather than fabricating content.
- Failed STRIKE/scanner execution uses `ERROR`/failed job state, never `BLOCKED`.
