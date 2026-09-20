-- Migration 022: Approval-Backed Non-CVE TES (P0-08, PRD-000 v1.11
-- §3.6.3–§3.6.6 esp. #3/#5/#6, §3.3.2–§3.3.5, Appendix C Q11/Q12/Q17,
-- Appendix D PATCH-13).
--
-- Storage additions ONLY — the approval mechanism is migration 021's
-- chapter5_approvals (Chapter 5 primitive). Chapter 3 adds NO second
-- approval store, table, or workflow:
--
--   * non_cve_sss_derivations gains the OVERRIDE provenance columns: an
--     approved SSS override is published as a NEW derivation row of path
--     'override' (version rows immutable, is_current chain DB-enforced by
--     migration 019 — the pre-override derived value stays visible in
--     history), referencing the immutable approval id + exact subject
--     revision it was applied from.
--   * exposure_non_exploitation_attestations gains the approval provenance
--     columns (approved_by/approved_at already exist from 017): the apply
--     handler stamps the approving actor + the immutable approval id.
--   * manual SSS proposals keep their existing columns; the applied approval
--     reference lives in the derivation it publishes (no proposal mutation —
--     019 keeps proposals immutable).
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Override provenance on non_cve_sss_derivations (path 'override').
--    The four-value path CHECK and the path-conditioned version-shape CHECK
--    (manual/override ⇒ NULL version) live in migration 019, edited in place
--    while unshipped — nothing to release here.
-- ---------------------------------------------------------------------------

ALTER TABLE non_cve_sss_derivations
    ADD COLUMN IF NOT EXISTS approval_id UUID,
    ADD COLUMN IF NOT EXISTS pre_override_derivation_id UUID;

-- The approval reference is the IMMUTABLE Chapter 5 primitive row (021) in
-- the same tenant; the pre-override binding points at an exact derivation of
-- the SAME tenant AND finding (composite identity, migration 019).
ALTER TABLE non_cve_sss_derivations
    DROP CONSTRAINT IF EXISTS fk_non_cve_sss_derivations_approval;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'non_cve_sss_derivations'::regclass
          AND conname = 'fk_non_cve_sss_derivations_approval'
    ) THEN
        ALTER TABLE non_cve_sss_derivations
            ADD CONSTRAINT fk_non_cve_sss_derivations_approval
            FOREIGN KEY (approval_id, tenant_id)
            REFERENCES chapter5_approvals (id, tenant_id) ON DELETE RESTRICT;
    END IF;
END $$;

ALTER TABLE non_cve_sss_derivations
    DROP CONSTRAINT IF EXISTS fk_non_cve_sss_derivations_pre_override;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'non_cve_sss_derivations'::regclass
          AND conname = 'fk_non_cve_sss_derivations_pre_override'
    ) THEN
        ALTER TABLE non_cve_sss_derivations
            ADD CONSTRAINT fk_non_cve_sss_derivations_pre_override
            FOREIGN KEY (pre_override_derivation_id, tenant_id, finding_id)
            REFERENCES non_cve_sss_derivations (id, tenant_id, finding_id)
            ON DELETE RESTRICT;
    END IF;
END $$;

-- row shape: an override row references BOTH its approval and the derivation
-- it overrode; a derived row references neither.
ALTER TABLE non_cve_sss_derivations
    DROP CONSTRAINT IF EXISTS ck_non_cve_sss_derivations_override_shape;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'non_cve_sss_derivations'::regclass
          AND conname = 'ck_non_cve_sss_derivations_override_shape'
    ) THEN
        ALTER TABLE non_cve_sss_derivations
            ADD CONSTRAINT ck_non_cve_sss_derivations_override_shape CHECK (
                (path = 'override') =
                (approval_id IS NOT NULL AND pre_override_derivation_id IS NOT NULL)
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Approval provenance on the negative-ER attestation ledger (017 columns
--    approved_by/approved_at; P0-08 stamps them exactly once and adds the
--    immutable approval reference)
-- ---------------------------------------------------------------------------

ALTER TABLE exposure_non_exploitation_attestations
    ADD COLUMN IF NOT EXISTS approval_id UUID;

ALTER TABLE exposure_non_exploitation_attestations
    DROP CONSTRAINT IF EXISTS fk_attestation_approval;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'exposure_non_exploitation_attestations'::regclass
          AND conname = 'fk_attestation_approval'
    ) THEN
        ALTER TABLE exposure_non_exploitation_attestations
            ADD CONSTRAINT fk_attestation_approval
            FOREIGN KEY (approval_id, tenant_id)
            REFERENCES chapter5_approvals (id, tenant_id) ON DELETE RESTRICT;
    END IF;
END $$;

-- approval provenance is all-or-none and written at most once: once stamped,
-- the columns are pinned (the immutability trigger below rejects any change)
ALTER TABLE exposure_non_exploitation_attestations
    DROP CONSTRAINT IF EXISTS ck_attestation_approval_shape;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'exposure_non_exploitation_attestations'::regclass
          AND conname = 'ck_attestation_approval_shape'
    ) THEN
        ALTER TABLE exposure_non_exploitation_attestations
            ADD CONSTRAINT ck_attestation_approval_shape CHECK (
                (approval_id IS NULL) = (approved_by IS NULL)
                AND (approval_id IS NULL) = (approved_at IS NULL)
            );
    END IF;
END $$;

-- One approval may attest exactly one attestation row (single-use by rule,
-- visible at the storage layer).
CREATE UNIQUE INDEX IF NOT EXISTS uq_attestation_approval
    ON exposure_non_exploitation_attestations (approval_id)
    WHERE approval_id IS NOT NULL;

-- Ledger rows are append-only correction-safe: the ONLY permitted mutation
-- stamps the approval provenance NULL → set, once. Every other UPDATE and
-- every DELETE rejects.
CREATE OR REPLACE FUNCTION attestation_approval_stamp() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'exposure_non_exploitation_attestations are append-only (DELETE forbidden)';
    END IF;
    IF OLD.approval_id IS NULL
       AND NEW.approval_id IS NOT NULL
       AND NEW.approved_by IS NOT NULL
       AND NEW.approved_at IS NOT NULL
       AND NEW.tenant_id      IS NOT DISTINCT FROM OLD.tenant_id
       AND NEW.exposure_id    IS NOT DISTINCT FROM OLD.exposure_id
       AND NEW.attested_by    IS NOT DISTINCT FROM OLD.attested_by
       AND NEW.attested_at    IS NOT DISTINCT FROM OLD.attested_at
       AND NEW.evidence_ref   IS NOT DISTINCT FROM OLD.evidence_ref
       AND NEW.created_at     IS NOT DISTINCT FROM OLD.created_at
    THEN
        RETURN NEW;  -- the one permitted stamp: P0-08 apply, once
    END IF;
    IF OLD.approval_id IS NOT NULL THEN
        RAISE EXCEPTION
            'attestation approval provenance is already stamped (record %)', OLD.id;
    END IF;
    RAISE EXCEPTION
        'exposure_non_exploitation_attestations rows are immutable (only the P0-08 approval stamp is permitted)';
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_attestation_approval_stamp ON exposure_non_exploitation_attestations;
CREATE TRIGGER trg_attestation_approval_stamp
    BEFORE UPDATE OR DELETE ON exposure_non_exploitation_attestations
    FOR EACH ROW EXECUTE FUNCTION attestation_approval_stamp();

-- ---------------------------------------------------------------------------
-- 2b. Classification/derivation path vocabulary: the approval-applied manual
--     path and the analyst-override path (P0-08) extend the 019 CHECKs.
-- ---------------------------------------------------------------------------

ALTER TABLE non_cve_classifications
    DROP CONSTRAINT IF EXISTS non_cve_classifications_path_check;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'non_cve_classifications'::regclass
          AND conname = 'ck_non_cve_classifications_path'
    ) THEN
        ALTER TABLE non_cve_classifications
            ADD CONSTRAINT ck_non_cve_classifications_path
            CHECK (path IN ('vrt', 'rubric', 'manual', 'override'));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Override-payload bindings (consumer SUBJECT data, NOT approval state):
--    the Chapter 5 primitive stores only the payload HASH; the override's
--    value/reason/evidence live HERE so the apply-time re-derivation can
--    rebuild the exact canonical payload and detect post-approval alteration.
--    All approval LIFECYCLE state remains exclusively in chapter5_approvals
--    (021) — this is not a second approval store.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS non_cve_sss_override_proposals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    finding_id      UUID NOT NULL,
    approval_id     UUID NOT NULL,
    value           NUMERIC(6, 4) NOT NULL CHECK (value >= 0 AND value <= 10),
    reason          TEXT NOT NULL CHECK (length(reason) > 0),
    evidence        JSONB NOT NULL CHECK (evidence <> '{}'::jsonb),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_override_binding_finding
        FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT fk_override_binding_approval
        FOREIGN KEY (approval_id, tenant_id)
        REFERENCES chapter5_approvals (id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT uq_override_binding_approval UNIQUE (tenant_id, approval_id)
);

CREATE INDEX IF NOT EXISTS idx_override_binding_finding
    ON non_cve_sss_override_proposals (tenant_id, finding_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 4. Derivation immutability trigger extension (migration 019 defined the
--    TRUE→FALSE-only transition; the trigger function is replaced wholesale
--    with the same contract PLUS the override columns in the unchanged set)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION non_cve_sss_derivations_immutable() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'non_cve_sss_derivations history is immutable (DELETE forbidden)';
    END IF;
    -- the ONLY permitted transition: is_current TRUE → FALSE
    IF OLD.is_current = TRUE AND NEW.is_current = FALSE THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.finding_id IS DISTINCT FROM OLD.finding_id
           OR NEW.finding_revision_xmin IS DISTINCT FROM OLD.finding_revision_xmin
           OR NEW.classification_id IS DISTINCT FROM OLD.classification_id
           OR NEW.taxonomy_class IS DISTINCT FROM OLD.taxonomy_class
           OR NEW.taxonomy_subclass IS DISTINCT FROM OLD.taxonomy_subclass
           OR NEW.taxonomy_subtype IS DISTINCT FROM OLD.taxonomy_subtype
           OR NEW.path IS DISTINCT FROM OLD.path
           OR NEW.version_id_ref IS DISTINCT FROM OLD.version_id_ref
           OR NEW.inputs IS DISTINCT FROM OLD.inputs
           OR NEW.value IS DISTINCT FROM OLD.value
           OR NEW.evidence IS DISTINCT FROM OLD.evidence
           OR NEW.approval_id IS DISTINCT FROM OLD.approval_id
           OR NEW.pre_override_derivation_id IS DISTINCT FROM OLD.pre_override_derivation_id
           OR NEW.created_by IS DISTINCT FROM OLD.created_by
           OR NEW.created_role IS DISTINCT FROM OLD.created_role
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'superseding a current derivation may not change any other column';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.is_current = FALSE AND NEW.is_current = TRUE THEN
        RAISE EXCEPTION 'a superseded derivation can never be reactivated';
    END IF;
    RAISE EXCEPTION 'non_cve_sss_derivations rows are immutable (only is_current TRUE→FALSE is permitted)';
END $$ LANGUAGE plpgsql;
