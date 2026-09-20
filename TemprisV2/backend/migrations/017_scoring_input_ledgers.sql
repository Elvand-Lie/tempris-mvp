-- Migration 017: Scoring Input Ledgers (P0-02, PRD-000 v1.11 §§3.3.2–3.3.4)
--
-- Persists the mutable contextual TES inputs as provenance-bearing records
-- bound to ONE exposure episode:
--   * exposure_reachability_evidence     — exact-exposure reachability (§3.3.2)
--   * exposure_business_impact           — per-exposure BI, versioned/current (§3.3.2)
--   * exposure_exploitation_evidence     — ER top-rung evidence (§3.3.3)
--   * exposure_non_exploitation_attestations — reserved 180d non-CVE attestation (§3.6.4),
--     approval-gated and INELIGIBLE until P0-08 applies a valid Chapter 5 approval
--
-- Every record carries server-assigned provenance (producer, actor, occurrence
-- time, source-object identity). Rows are append-only: correction uses a
-- revocation record (revocation_of_id) with audit history; nothing is updated
-- in place and nothing is deleted on TTL expiry (expiry affects eligibility
-- only). Existing asset_exposures.evidence JSON is historical context — it is
-- NOT reinterpreted as trusted scoring evidence (§3.6.5: V2 has no score-bearing
-- storage to migrate).
--
-- Forward-only; runs in one transaction (see migrations/runner.py).

-- ---------------------------------------------------------------------------
-- 1. Composite-FK target: unique (tenant_id, id) on asset_exposures
--    (same pattern as 013's uq_assets_tenant_id / uq_findings_tenant_id)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'asset_exposures'::regclass
          AND conname = 'uq_asset_exposures_tenant_id'
    ) THEN
        ALTER TABLE asset_exposures
            ADD CONSTRAINT uq_asset_exposures_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Reachability evidence (append-only; §3.3.2: external=10 / internal=8,
--    absent = unknown — never host-level fields)
--    Producer-agnostic (§3.3.2: "Evidence is producer-agnostic"): ANY
--    server-authenticated producer may establish reachability with evidence
--    and provenance. producer is server-owned, non-empty, and never
--    client-supplied; no closed producer allowlist exists on this ledger.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exposure_reachability_evidence (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id         UUID NOT NULL,
    -- semantic fields are NULL on revocation rows (revocation_of_id set);
    -- the CHECKs tolerate NULL so only real evidence rows carry vantage/evidence
    vantage             TEXT CHECK (vantage IN ('external', 'internal')),
    evidence            JSONB CHECK (evidence <> '{}'::jsonb AND jsonb_typeof(evidence) = 'object'),
    producer            TEXT CHECK (length(btrim(producer)) > 0),
    -- NOT NULL is enforced per-row-shape by ck_reachability_row_shape:
    -- evidence rows require it, revocation rows leave it NULL. No DEFAULT:
    -- an insert that omits observed_at is a malformed evidence row.
    observed_at         TIMESTAMPTZ,
    recorded_by         TEXT NOT NULL,
    source_object_type  TEXT NOT NULL,
    source_object_id    TEXT NOT NULL,
    -- append-only correction shape: a revocation row points at the record it
    -- revokes; the original row is never mutated
    revocation_of_id    UUID REFERENCES exposure_reachability_evidence(id) ON DELETE RESTRICT,
    revocation_reason   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Row-shape invariant: a row is EXACTLY an original evidence row or
    -- EXACTLY a revocation row (SQL CHECKs accept NULL, so the two shapes
    -- are spelled out explicitly; source identity and recorded_by stay
    -- required for both).
    CONSTRAINT ck_reachability_row_shape CHECK (
        (
            revocation_of_id IS NULL
            AND vantage IS NOT NULL
            AND evidence IS NOT NULL
            AND producer IS NOT NULL AND length(btrim(producer)) > 0
            AND observed_at IS NOT NULL
            AND revocation_reason IS NULL
        )
        OR
        (
            revocation_of_id IS NOT NULL
            AND vantage IS NULL
            AND evidence IS NULL
            AND producer IS NULL
            AND observed_at IS NULL
            AND revocation_reason IS NOT NULL AND length(btrim(revocation_reason)) > 0
        )
    ),
    -- Retained episode history (§3.3.2/§3.3.3): ledger rows never disappear
    -- with their exposure — deleting the exposure is refused while history exists.
    CONSTRAINT fk_reachability_exposure
        FOREIGN KEY (tenant_id, exposure_id) REFERENCES asset_exposures(tenant_id, id) ON DELETE RESTRICT
);
-- Source identity applies to EVIDENCE rows only: revocation rows carry the
-- original's id inside source_object_id and deduplicate via the
-- one-revocation-per-original invariant below — keeping the indexes
-- non-overlapping means the ON CONFLICT arbiter in revoke_evidence is the
-- ONLY unique constraint a revocation insert can hit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_reachability_source_identity
    ON exposure_reachability_evidence (tenant_id, source_object_type, source_object_id)
    WHERE revocation_of_id IS NULL;
-- Append-only correction invariant: AT MOST ONE revocation row per original
-- record (database-enforced — an alternate source id cannot create a second
-- revocation of the same original).
CREATE UNIQUE INDEX IF NOT EXISTS uq_reachability_one_revocation
    ON exposure_reachability_evidence (tenant_id, revocation_of_id)
    WHERE revocation_of_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_reachability_exposure
    ON exposure_reachability_evidence (tenant_id, exposure_id, observed_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- 3. Business Impact (versioned/current; §3.3.2: per-exposure 0–10,
--    actor + timestamp + optional reason; update affects only this exposure;
--    no assessment = unknown, never a default)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exposure_business_impact (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id UUID NOT NULL,
    -- NUMERIC(6,4) preserves up to four decimal places exactly (a documented
    -- finite TES-input precision, inclusive of the 10 bound); no silent
    -- rounding of submitted values at the application boundary.
    value       NUMERIC(6,4) NOT NULL CHECK (value >= 0 AND value <= 10),
    reason      TEXT,
    assessed_by TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_bi_exposure
        FOREIGN KEY (tenant_id, exposure_id) REFERENCES asset_exposures(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_bi_exposure_current
    ON exposure_business_impact (tenant_id, exposure_id, created_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- 4. Exploitation evidence (append-only; §3.3.3): kind is a locked write-time
--    classification (observed_exploitation → 365d / controlled_validation →
--    180d), producer allowlist closed to STRIKE control plane and analyst
--    review. Failed/prevented/cancelled/unconfirmed/artifact-only attempts
--    never reach this table (server-side rejection). TTL expiry never deletes.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exposure_exploitation_evidence (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id         UUID NOT NULL,
    -- semantic fields are NULL on revocation rows (revocation_of_id set)
    evidence_kind       TEXT CHECK (evidence_kind IN ('observed_exploitation', 'controlled_validation')),
    -- Exploitation-evidence producers ARE closed (§3.3.3): only the STRIKE
    -- control plane and analyst-reviewed evidence reach the top rung today.
    producer            TEXT CHECK (producer IN ('strike', 'analyst_review')),
    evidence            JSONB CHECK (evidence <> '{}'::jsonb AND jsonb_typeof(evidence) = 'object'),
    -- NOT NULL is enforced per-row-shape by ck_exploitation_row_shape:
    -- evidence rows require it, revocation rows leave it NULL. No DEFAULT:
    -- an insert that omits observed_at is a malformed evidence row.
    observed_at         TIMESTAMPTZ,
    recorded_by         TEXT NOT NULL,
    reviewed_by         TEXT,
    source_object_type  TEXT NOT NULL,
    source_object_id    TEXT NOT NULL,
    revocation_of_id    UUID REFERENCES exposure_exploitation_evidence(id) ON DELETE RESTRICT,
    revocation_reason   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Row-shape invariant: EXACTLY an original evidence row or EXACTLY a
    -- revocation row. Analyst-review evidence rows require reviewed_by (the
    -- authenticated reviewer of record); STRIKE rows may leave it null.
    CONSTRAINT ck_exploitation_row_shape CHECK (
        (
            revocation_of_id IS NULL
            AND evidence_kind IS NOT NULL
            AND evidence IS NOT NULL
            AND producer IS NOT NULL AND length(btrim(producer)) > 0
            AND observed_at IS NOT NULL
            AND revocation_reason IS NULL
            AND (producer <> 'analyst_review' OR reviewed_by IS NOT NULL)
        )
        OR
        (
            revocation_of_id IS NOT NULL
            AND evidence_kind IS NULL
            AND evidence IS NULL
            AND producer IS NULL
            AND reviewed_by IS NULL
            AND observed_at IS NULL
            AND revocation_reason IS NOT NULL AND length(btrim(revocation_reason)) > 0
        )
    ),
    -- Retained episode history: deleting the exposure is refused while
    -- evidence history exists (append-only audit provenance).
    CONSTRAINT fk_exploitation_exposure
        FOREIGN KEY (tenant_id, exposure_id) REFERENCES asset_exposures(tenant_id, id) ON DELETE RESTRICT
);
-- Source identity applies to EVIDENCE rows only: revocation rows carry the
-- original's id inside source_object_id and deduplicate via the
-- one-revocation-per-original invariant below — keeping the indexes
-- non-overlapping means the ON CONFLICT arbiter in revoke_evidence is the
-- ONLY unique constraint a revocation insert can hit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_exploitation_source_identity
    ON exposure_exploitation_evidence (tenant_id, source_object_type, source_object_id)
    WHERE revocation_of_id IS NULL;
-- Append-only correction invariant: AT MOST ONE revocation row per original
-- record (database-enforced — an alternate source id cannot create a second
-- revocation of the same original).
CREATE UNIQUE INDEX IF NOT EXISTS uq_exploitation_one_revocation
    ON exposure_exploitation_evidence (tenant_id, revocation_of_id)
    WHERE revocation_of_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploitation_exposure
    ON exposure_exploitation_evidence (tenant_id, exposure_id, observed_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- 5. Non-exploitation attestation (§3.6.4): reserved storage shape for the
--    180-day analyst "no known exploitation" floor. Approval columns are
--    reserved for the Chapter 5 dual-control primitive (P0-08): nothing in
--    this ticket can set them, so no attestation is scoring-eligible yet.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exposure_non_exploitation_attestations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    exposure_id     UUID NOT NULL,
    attested_by     TEXT NOT NULL,
    attested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    evidence_ref    TEXT NOT NULL,
    -- Chapter 5 dual-control approval — reserved, set only by P0-08
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_attestation_exposure
        FOREIGN KEY (tenant_id, exposure_id) REFERENCES asset_exposures(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_attestation_exposure
    ON exposure_non_exploitation_attestations (tenant_id, exposure_id, attested_at DESC, id DESC);
