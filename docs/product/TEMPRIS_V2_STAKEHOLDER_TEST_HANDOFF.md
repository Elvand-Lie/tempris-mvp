# Tempris V2 — Stakeholder Testing Handoff

*Prepared 2026-09-25. Every step below was executed against the live production console the same day.*

## 1. Access

- **Console URL:** https://sandbox.tempris.tech/v2-assets/
- **Accounts:** one **Admin** demo account and one **Analyst** demo account in a dedicated demo tenant ("PRD Acceptance 20260922 Ch2-7"). Nothing you do there can touch real customer data.
- **Credentials:** supplied separately in a private message — intentionally NOT stored in this document.
- Note: the site root (https://sandbox.tempris.tech/) shows the older V1 system. Use the `/v2-assets/` address.

**What is already in the demo tenant:** 3 assets (including `demo-tour-webapp`), 5 intake records, 2 confirmed exposures, 3 regulatory incidents, 1 compliance assessment draft (CT-INC-1) waiting for its two signatures, and 1 open remediation decision in EDIP.

## 2. What to test — the guided tour

Sign in with the **Admin demo** account, then follow in order. Each step says exactly what to click and what you should see.

### Step 1 — Sign in
1. Open the URL above.
2. Enter the **Admin demo email** and **password** (from the private message), click **Sign In**.
3. You land on **Assets Console**. The left sidebar shows the whole platform: Operations (Assets, Collectors, SCOUT, Intake & Triage, STRIKE), Analysis (SPECTRUM, SYNTHESIS), Governance (EDIP, STANDARD), Executive & Reporting (SPOTLIGHT, SPEAK Reports), Administration (Organization).

### Step 2 — Assets Console (register what you protect)
*Capability: an inventory of everything you want to protect, with business criticality that later feeds scoring.*
1. Note the summary cards on top: **TOTAL ASSETS**, **REACHABLE BY SCOUT**, **AUTHORIZED TO SCAN**, **PENDING AUTHORIZATION**, **NO SCANNER AVAILABLE**.
2. Click **+ Add Asset** (top right).
3. Fill in exactly:
   - **Asset Name**: `stakeholder-demo-asset`
   - **Asset Type**: `Web Application`
   - **Target Type**: `Domain`
   - **Network Scope**: `Internet / Tempris Cloud route`
   - **Target Value**: `demo.example.com`
   - **Environment**: `Production`, **Criticality**: `High`
4. Click **Create Asset**. The new row appears in the **Active Assets** table.
5. On any asset row, click the **⋮** button — the menu shows the full lifecycle: **View Details, Edit Asset, Recheck Reachability, Request Scan Auth, Approve Scan Auth, Revoke Scan Auth, Decommission Asset**.
6. Click **👁️ View Details** on your new asset. In the **Asset Details** window, find **ASSET ID** — select and copy that long ID (letters-dashes); you will paste it in Step 4. Close the window.

### Step 3 — Intake & Triage (report a security issue)
*Capability: any report — manual, connector, bug-bounty, threat feed — enters as ONE record and is triaged to exactly one outcome: a confirmed exposure, a rejection, or a request for more info.*
1. Click **Intake & Triage** in the sidebar.
2. The **Raw intake queue** lists existing records with their states (Submitted / Under review / Confirmed / Rejected / Duplicate). Try the **Filter by lifecycle state** dropdown to see each.
3. Scroll to **SUBMIT AN INTAKE RECORD** and fill in:
   - **Source**: `Manual report`
   - **Title**: `stakeholder-demo: suspicious admin function`
   - **Severity (proposed)**: `high`
   - **Source payload (mandatory JSON object)**: `{"summary":"demo submission","how_found":"manual review"}`
4. Click **Submit intake record**. Your record appears at the top of the queue as **Submitted**.
5. Click your record's row to open it. Click **Start review** — the state changes to **Under Review**.
6. In **CLASSIFY**, choose **Taxonomy class** `BLFLAW`, then the subtype that appears (e.g. `IDOR`), and type a **Rationale** (required, one sentence). Click **Save classification**. *This step is mandatory — the system refuses to confirm an unclassified record.*
7. Scroll to **CONFIRM — THE SINGLE HANDOFF INTO THE EXPOSURE DOMAIN**:
   - **Anchor asset id**: paste the **ASSET ID** you copied in Step 2.
   - **Evidence (mandatory JSON object)**: `{"source":"stakeholder demo","how":"manual verification"}`
8. Click **Confirm exposure**. You should see: **"Confirmed. Finding and exposure created — the record handed off to SPECTRUM."**

### Step 4 — SPECTRUM (see the exposure and how its score is built)
*Capability: every confirmed exposure with a TES score that is recomputed live on every view — with a full, honest breakdown.*
1. Click **SPECTRUM** in the sidebar. The **Current exposure queue** now shows 3 confirmed exposures; yours is at the top.
2. Click your exposure's row. The detail view shows:
   - **FINDING ROLL-UP (SIX-FIELD SUMMARY)** — max FINAL, max PROVISIONAL, and UNSCOREABLE counts.
   - **CURRENT TES — RECOMPUTED AT READ (NEVER STORED HERE)** — your exposure is **UNSCOREABLE** with the exact reason listed (*no authoritative intrinsic severity — no CVSS / no validated severity rubric*). This is the honesty rule: missing facts are never guessed as zero.
   - **TES decomposition by axis** — the five factors (Intrinsic, Exploit Reality, Criticality, Reachability, Business Impact) with each one's value, weight and state. Note **CRITICALITY** is already **Known** (it came from the asset you registered).
3. Try the analyst tools further down: **ANALYST WORKFLOW** (assign the exposure, move its state), **BUSINESS IMPACT (PER EXPOSURE)** (enter `6.5`, click **Record Business Impact**), **ANALYST-REVIEWED EVIDENCE** (record reachability / exploitation evidence).
4. Scroll to **HANDOFFS** and click **Create EDIP decision (Needs Decision)** — this pushes the exposure into the remediation workflow you'll see next.

### Step 5 — EDIP (decide what to do about it)
*Capability: remediation and risk decisions with owners, deadlines, verification and closure — every decision sealed in immutable history.*
1. Click **EDIP** in the sidebar. **Open decisions** now includes your new `remediate / needs decision` entry.
2. Click its **Open** button. The decision panel shows the full lifecycle buttons: **Plan, Start, Declare mitigated, Attach verification, Verified close, Defer, Propose accepted risk, Reopen** — and **Admin: decide & apply**, the two-person control (an analyst proposes, an admin applies).

### Step 6 — STANDARD (compliance workbench)
*Capability: prove control compliance with evidence and two signatures, track obligations and regulatory incidents.*
1. Click **STANDARD**. The top cards show **FRAMEWORKS 8**, **CONTROLS ASSESSED 1/30**, **OBLIGATIONS OPEN**, **INCIDENTS 3**.
2. Click the **SOP Builder** tab (first tab). Pick a framework in the **Framework** dropdown (CSA Cyber Trust, IM8A, ISO 27001, MAS TRM, NIST CSF, PCI DSS, PDPA, SOC 2).
3. In the controls table, click **Open workbench** on **CT-INC-1 Incident Management** — a compliant **draft** assessment is already prepared there for you.
4. In the workbench panel:
   - Click **Sign (end user)** — one signature applied.
   - Sign in as the **Analyst demo** account (another browser window or after signing out) and click **Sign (PIC)** — the second signature. The control becomes **COMPLIANT** once both are in. *Two different people are required — that is the control working, not a bug.*
   - Click **Load evidence**: attach any small file (**File**, **Media type** e.g. `application/pdf`, **Title**, **Attach evidence**). Attached evidence can be **Preview**ed and **Download**ed.
5. Click the **Gap Analysis** tab: summary cards (COMPLETED (SIGNED) / IN REVIEW (DRAFT) / PENDING) and the full per-control gap table — watch CT-INC-1 move as you sign.
6. Click the **Regulatory Incidents** tab. On an incident row click **Draft MAS notice** — a MAS TRM 12.1.5 one-hour-notification draft is generated from the recorded incident only ("nothing is stored or submitted" is written on the panel itself).
7. Skim the other tabs: **Policies & Frameworks**, **Policy Registry** (create/activate/archive policies), **Exceptions** (request/approve with mandatory expiry), **Obligations**, **Rules**.

### Step 7 — SPOTLIGHT, SPEAK, SYNTHESIS (executive views)
1. **SPOTLIGHT** — the executive dashboard: severe exposures (UNSCOREABLE items are listed, never hidden), workflow posture, regulatory pressure, and the **Capture snapshot** button that freezes an executive snapshot for trending.
2. **SPEAK Reports** — sealed, versioned deliverables. Existing reports can be exported as **HTML / JSON / CSV**; register a new draft with **Register draft**. There is also a fail-closed AI section.
3. **SYNTHESIS** — read-only correlations across modules ("Serious & unremediated", "Risks vs obligations", "Coverage gaps") — every row keeps its source links.

### Step 8 — SCOUT & STRIKE (view only in this demo)
1. **SCOUT** — shows scanner readiness (Central VPS and per-Collector) and the **asset-only launch** rule: scans are derived from an authorized asset, never a free-text target. Scanner engines are currently **UNAVAILABLE/OFFLINE** in this environment — view only.
2. **STRIKE** — the toolbox catalogue (curl, nmap, nuclei, ffuf, dig) with their fixed limits. Every run is **scope-checked**: a target with no pre-authorized testing scope is refused with `run_target_out_of_scope` — by design. **Do not attempt runs against any real system.**

### Step 9 — Role check (optional)
Sign out and sign in as the **Analyst demo** account: the menu is smaller (no Organization administration), showing role-based access. Use this account for the second STANDARD signature in Step 6.

## 3. Known limitations / remaining work

**Expected during this review (not broken):**
- **STRIKE needs pre-authorized scope** for any target — there is no screen for that yet (admin API only). This is the authorization ledger by design.
- **SCOUT scanner engines are unavailable** in this environment — the console and readiness views work; actual scans are not part of this demo.
- **UNSCOREABLE exposures** in SPECTRUM are honest states (missing intrinsic severity/context), not errors. Scores finalize only when facts are known.
- CVE intelligence feed is ~95% populated in the background; not needed for this walkthrough.

**Deferred / by design:** STANDARD advisories derive from compliance data only; MAS TRM drafts are generated on demand and not stored; demo data is intentionally small.

**Minor polish:** "Draft MAS notice" also appears on resolved incidents (harmless); some lists show page counts rather than totals; 5 failed sign-ins in one minute locks login briefly.

## 4. Current testing status

| Module | Status | Notes |
|---|---|---|
| Assets | Ready | Full lifecycle incl. scan-auth menu; verified live |
| Collectors | Ready | Registry/status views |
| SCOUT | View-ready | Scanners offline in this env; authorized-scan model visible |
| Intake | Ready | Submit → review → classify → confirm verified live end-to-end |
| STRIKE | Partial | Catalogue + composer visible; runs blocked without scope (by design, no scope UI yet) |
| SPECTRUM | Ready | Queue, TES decomposition, analyst tools, handoffs verified live |
| SYNTHESIS | Ready | Correlation views verified live |
| EDIP | Ready | Decision created from SPECTRUM live; full action set visible |
| STANDARD | Ready | SOP Builder dual sign-off + evidence, gap analysis, MAS draft verified live |
| SPOTLIGHT | Ready | Crash found during this review was fixed and re-verified live (2026-09-25) |
| SPEAK | Ready | Reports register/export verified live |
| Organization | Ready | Admin area (not part of the demo flow) |

## 5. Important testing notes

- Everything you do is inside the sandboxed demo tenant — create, classify, confirm, sign freely.
- **Never point STRIKE or SCOUT at systems you do not own.** Unauthorized targets are refused by design; do not ask to authorize real third-party targets.
- TES shows **PROVISIONAL** (not FINAL) while any factor is missing, and missing factors are never zero — seeing "UNSCOREABLE / PROVISIONAL" with reasons listed is the product working correctly.
- The demo passwords are for this review only — do not forward or store them in shared documents.
