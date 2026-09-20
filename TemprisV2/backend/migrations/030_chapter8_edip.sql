-- Migration 030: Chapter 8 — EDIP (Remediation & Risk Decisions) (PRD-000 v1.11 Ch.8).
--
-- EDIP turns an exposure that requires action into an explicit remediation/
-- risk decision with ownership, deadlines, evidence, verification, and closure
-- — CONSUMING TES, never rewriting or multiplying it (Ch.8 outcome).
--
-- Authority boundaries made structural here:
--   * NO score column exists in any table below. The score a decision consumed
--     is an immutable SNAPSHOT (consumed_snapshot, §3.3.6 history-only writer,
--     PATCH-13: one coherent as_of source view per consuming revision) — never
--     a display source, never recomputed in place.
--   * NO exposure-status column is writable here. Verified closure emits the
--     transition intent THROUGH the Ch.3 exposure service inside one
--     version-checked transaction (PATCH-09 compare-and-set on both states);
--     the Ch.3 service remains the only writer of asset_exposures.status
--     (D-5/D-16; the V1 status-overwrite defect stays retired).
--   * The Ch.7 handoff (spectrum_edip_handoffs) gains the CONSUMED vocabulary
--     EDIP writes when it creates the correlated decision (PATCH-09 handoff
--     retry correlation). Ch.7's original NEEDS_DECISION rows stay valid.
--
-- Decision lifecycle (Ch.8 rule 2): Needs Decision → Planned → In Progress →
-- Mitigated → Verification → Closed, with the branch dispositions
-- Accepted Risk / Deferred (ACTIVE dispositions carrying a mandatory
-- review_due_at — the exposure stays confirmed and visible) and the
-- system-initiated Superseded. Closed and Superseded are the only terminals.
-- VERIFIED precedes Closed (the blflaw lesson): closure requires verification
-- evidence bound to the decision revision AND the current exposure row version.
--
-- History is a sequence of decision REVISIONS (Q7: many decisions over time,
-- one CURRENT decision per exposure): every score-consuming branch action
-- (accept-risk, defer) inserts a NEW revision row sealing its OWN immutable
-- snapshot and replaces the prior row (replaced_at/replaced_by_id). The
-- current decision per exposure is the row with replaced_at IS NULL (partial
-- unique index below). Superseded/Closed rows are terminal-but-current.
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Module catalogue: EDIP
-- ---------------------------------------------------------------------------

INSERT INTO modules (id, name, description, status, created_at)
VALUES (
    'EDIP',
    'EDIP — Remediation & Risk Decisions',
    'Remediation/risk decisions over confirmed exposures: decision lifecycle with verification-before-closure, accepted-risk dual control, review-dated branch dispositions, sealed score snapshots. Consumes TES; never writes scores or exposure status.',
    'active',
    now()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO package_modules (package_id, module_id)
VALUES ('CORE_ASSETS', 'EDIP')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Ch.7 handoff correlation: EDIP extends the handoff vocabulary
--    (Ch.7 migration 026 deliberately kept it single-valued for EDIP to
--    extend forward-only). consumed_* columns record the PATCH-09
--    decision correlation.
-- ---------------------------------------------------------------------------

ALTER TABLE spectrum_edip_handoffs DROP CONSTRAINT IF EXISTS spectrum_edip_handoffs_state_check;
ALTER TABLE spectrum_edip_handoffs ADD CONSTRAINT spectrum_edip_handoffs_state_check
    CHECK (state IN ('NEEDS_DECISION', 'CONSUMED'));

ALTER TABLE spectrum_edip_handoffs
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS consumed_by TEXT,
    ADD COLUMN IF NOT EXISTS edip_decision_id UUID;

-- ---------------------------------------------------------------------------
-- 3. Decisions (the revision chain)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS edip_decisions (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id         UUID NOT NULL,
    -- revision chain: decision_group_id = the ROOT revision's id (self value
    -- for roots; service-enforced — a composite self-FK cannot express it);
    -- supersedes_id names the immediately prior revision.
    decision_group_id   UUID NOT NULL,
    revision            INT NOT NULL DEFAULT 1,
    supersedes_id       UUID REFERENCES edip_decisions(id),
    -- recurrence linkage (rule 9 / D-16): a NEW decision on a NEW episode may
    -- reference the prior episode's decision for history; never reopened.
    previous_decision_id UUID REFERENCES edip_decisions(id),
    -- the Ch.7 handoff this decision consumed, when created from one
    handoff_id          UUID REFERENCES spectrum_edip_handoffs(id),
    -- unified decision vocabulary (rule 5). ESCALATE/PATCH/... band labels are
    -- display-only consumer policy and deliberately absent; COMPENSATING_
    -- CONTROL demotes to a mitigation_type VALUE, not a state.
    decision_type       TEXT NOT NULL CHECK (decision_type IN
                            ('remediate', 'mitigate', 'accept-risk', 'defer')),
    -- lifecycle (rule 2). accepted_risk/deferred are ACTIVE dispositions;
    -- closed/superseded are the ONLY terminals.
    state               TEXT NOT NULL DEFAULT 'needs_decision' CHECK (state IN (
                            'needs_decision', 'planned', 'in_progress',
                            'mitigated', 'verification',
                            'accepted_risk', 'deferred',
                            'closed', 'superseded')),
    superseded_reason   TEXT,
    -- ownership + deadlines (rule 6); overdue derived at read (no scheduler)
    owner               TEXT NOT NULL,
    rationale           TEXT,
    plan                TEXT,
    due_at              TIMESTAMPTZ,
    -- mandatory review/expiry date on the branch dispositions (rule 2/8)
    review_due_at       TIMESTAMPTZ,
    -- mitigation-type taxonomy is an open Ch.8 decision — free-text value at
    -- v1 (COMPENSATING_CONTROL is one legal value), constrained forward-only
    mitigation_type     TEXT,
    -- the sealed score snapshot this decision consumed (§3.3.6 history-only;
    -- PATCH-13: one coherent as_of source view per consuming revision —
    -- value/state/formula_version/decomposition/source_view/as_of)
    consumed_snapshot   JSONB NOT NULL CHECK (jsonb_typeof(consumed_snapshot) = 'object'),
    snapshot_as_of      TIMESTAMPTZ NOT NULL,
    created_by          TEXT NOT NULL,
    created_role        TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at           TIMESTAMPTZ,
    -- revision replacement: a score-consuming branch action inserts a NEW
    -- revision and stamps the prior row (history retained, never mutated).
    -- replaced_by_id is the mirror of the new row's supersedes_id and is
    -- service-stamped WITHOUT an FK: the one-current-per-exposure partial
    -- unique index forces the prior row to be stamped BEFORE the new row
    -- inserts, while an FK would require the opposite order. Lineage
    -- integrity is carried by supersedes_id (below), which does FK the
    -- existing predecessor at insert time.
    replaced_at         TIMESTAMPTZ,
    replaced_by_id      UUID,
    CONSTRAINT uq_edip_decisions_tenant_id UNIQUE (tenant_id, id),
    -- mandatory review date on the active branch dispositions
    CONSTRAINT ck_edip_review_due_required CHECK (
        state NOT IN ('accepted_risk', 'deferred') OR review_due_at IS NOT NULL
    ),
    -- terminal discipline
    CONSTRAINT ck_edip_closed_shape CHECK (
        (state = 'closed') OR (closed_at IS NULL)
    ),
    CONSTRAINT ck_edip_superseded_shape CHECK (
        (state = 'superseded') OR (superseded_reason IS NULL)
    ),
    CONSTRAINT fk_edip_decision_exposure FOREIGN KEY (tenant_id, exposure_id)
        REFERENCES asset_exposures(tenant_id, id) ON DELETE RESTRICT
);

-- ONE CURRENT decision per exposure (Q7): at most one row per exposure with
-- replaced_at IS NULL (terminal rows stay current; replaced revisions are
-- history). Partial unique — table constraints cannot carry WHERE.
CREATE UNIQUE INDEX IF NOT EXISTS uq_edip_current_per_exposure
    ON edip_decisions (tenant_id, exposure_id)
    WHERE replaced_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_edip_decisions_exposure
    ON edip_decisions (tenant_id, exposure_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_edip_decisions_state
    ON edip_decisions (tenant_id, state) WHERE replaced_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_edip_decisions_owner
    ON edip_decisions (tenant_id, owner) WHERE replaced_at IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'spectrum_edip_handoffs'::regclass
          AND conname = 'uq_spectrum_edip_handoffs_tenant_id'
    ) THEN
        ALTER TABLE spectrum_edip_handoffs
            ADD CONSTRAINT uq_spectrum_edip_handoffs_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Verifications — Ch.8's OWN evidence class (rule 7, Flow D)
--    Remediation proof lives HERE, referencing a SCOUT job, a STRIKE
--    artifact, or an analyst attestation. Only a qualifying STRIKE
--    controlled-validation may ADDITIONALLY become a Ch.3 evidence record
--    (§3.3.3 governs it there) — that promotion is Ch.4/Ch.3 surface, never
--    this table. PATCH-09: each verification binds the decision revision and
--    the CURRENT exposure row version — newer contradictory evidence
--    (any exposure-row movement) invalidates it for closure.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS edip_verifications (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    decision_id           UUID NOT NULL,
    evidence_kind         TEXT NOT NULL CHECK (evidence_kind IN
                              ('analyst_attestation', 'scout_job', 'strike_artifact')),
    evidence_ref          JSONB NOT NULL CHECK (jsonb_typeof(evidence_ref) = 'object'),
    verdict               TEXT NOT NULL CHECK (verdict IN ('pass', 'fail')),
    note                  TEXT,
    verified_by           TEXT NOT NULL,
    verified_role         TEXT,
    verified_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- PATCH-09 binding: the exact decision revision + the exposure row
    -- version (xmin token) observed at verification time. Closure re-checks
    -- BOTH; a moved exposure row invalidates the verification.
    decision_revision_id  UUID NOT NULL,
    exposure_version      TEXT NOT NULL,
    CONSTRAINT uq_edip_verifications_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_edip_verif_decision FOREIGN KEY (tenant_id, decision_id)
        REFERENCES edip_decisions(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_edip_verifications_decision
    ON edip_verifications (tenant_id, decision_id, verified_at DESC);

-- ---------------------------------------------------------------------------
-- 5. Accepted-risk dual-control binding (rule 8 — decided YES)
--    The Ch.5 primitive stores only the payload HASH; this row is the
--    consumer-side binding carrying the exact proposed disposition data
--    (the P0-08 override-binding pattern, migration 022 precedent), written
--    in the SAME transaction as the primitive's propose. The apply handler
--    re-derives the canonical payload from these columns, so the applied
--    disposition is exactly what was approved.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS edip_accepted_risk_bindings (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    decision_id      UUID NOT NULL,
    approval_id      UUID NOT NULL REFERENCES chapter5_approvals(id),
    rationale        TEXT NOT NULL CHECK (length(btrim(rationale)) > 0),
    review_due_at    TIMESTAMPTZ NOT NULL,
    mitigation_type  TEXT,
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_edip_ar_binding_approval UNIQUE (approval_id),
    CONSTRAINT fk_edip_ar_decision FOREIGN KEY (tenant_id, decision_id)
        REFERENCES edip_decisions(tenant_id, id) ON DELETE RESTRICT
);

-- Multiple proposals may bind one decision over its life (a review-expired
-- acceptance is re-proposed on the same current revision); only the approval
-- identity is unique (one binding per approval, single-use by the primitive).
CREATE INDEX IF NOT EXISTS idx_edip_ar_binding_decision
    ON edip_accepted_risk_bindings (tenant_id, decision_id, created_at DESC);
