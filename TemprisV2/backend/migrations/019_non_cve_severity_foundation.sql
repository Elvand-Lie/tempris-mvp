-- Migration 019: Non-CVE Severity Foundation (P0-06, PRD-000 v1.11 §3.6.1–§3.6.6;
-- §3.4 non-CVE/SSS rows; Appendix C Q11–Q12) — bounded correction round.
--
-- Forward-only. The whole file runs inside one transaction (migrations/runner.py);
-- any failure aborts atomically.
--
-- Establishes:
--   * sss_derivation_versions — immutable rubric/VRT version metadata (forward-only
--     trigger unchanged: test_only can never be promoted; approved requires
--     explicit operator approval metadata).
--   * non_cve_classifications — immutable classification history over the CLOSED
--     SSS taxonomy spine (class/subclass/subtype combinations enforced by CHECKs;
--     no defaults, no invented vocabularies).
--   * non_cve_sss_derivations — immutable SSS derivation history. DB-enforced
--     immutability: DELETE rejected; the ONLY permitted update is the one
--     semantic transition is_current TRUE→FALSE with every other column
--     unchanged; FALSE→TRUE reactivation rejected; any other UPDATE rejected.
--     Provenance is composite-FK bound: a derivation's classification must
--     belong to the SAME tenant and finding.
--   * non_cve_sss_proposals — manual SSS proposals, pending forever (CHECK).
--     UPDATE and DELETE rejected. The displayed derived comparison binds to an
--     EXACT derivation id (composite FK: same tenant and finding); when no
--     current derivation exists the binding is NULL.
--
-- Tenant security is DB-enforced: every record carries a composite foreign key
-- (tenant_id, finding_id) → findings (tenant_id, id) (uq_findings_tenant_id,
-- migration 013). The CVE-rejection trigger performs a TENANT-SCOPED lookup.
-- Taxonomy spine (§3.6.2/§3.6.5, inherited from V1 sss_contract.py) as a
-- PRESENCE/ABSENCE matrix:
--   classes: BLFLAW, SUPPLY_CHAIN, IDENTITY_POSTURE, AGENTIC_EXPOSURE,
--            VALIDATION_EVIDENCE, NHI
--   IDENTITY_POSTURE subclasses: AUTH_FLOW_ABUSE, MFA_ENROLMENT, SESSION_TOKEN,
--            MACHINE_KEY, CONDITIONAL_ACCESS
--   AGENTIC_EXPOSURE subclasses: ADVERSARY_AI, AUTONOMOUS_PRINCIPAL,
--            INJECTION_PATH, MEMORY_RAG, TOOL_MCP, TRAINING_SUPPLY
--   BLFLAW subtypes: IDOR, BFLAW-BAC, BFLAW-HPE, BFLAW-BFB, BFLAW-MSC
--   Subclass is required from the closed list for IDENTITY_POSTURE and
--   AGENTIC_EXPOSURE and NULL for every other class; subtype is required
--   from the closed list for BLFLAW and NULL for every other class.
--   Absence — not an invented token — is the representation for a dimension
--   without an approved vocabulary.

-- ---------------------------------------------------------------------------
-- 1. Immutable rubric/VRT version metadata (generic-evaluator substrate)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sss_derivation_versions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_id   TEXT NOT NULL UNIQUE,
    kind         TEXT NOT NULL CHECK (kind IN ('vrt_release', 'rubric')),
    -- rubric content: closed-enum fact schema + ordered rules; VRT rows: NULL
    -- (the P1–P5 → SSS mapping is the PRD-locked Tempris policy in code).
    content      JSONB,
    status       TEXT NOT NULL DEFAULT 'test_only' CHECK (status IN ('test_only', 'approved', 'retired')),
    test_only    BOOLEAN NOT NULL DEFAULT FALSE,
    -- 'approved' rows must carry explicit operator approval (never app-written).
    approved_by  TEXT,
    approved_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status <> 'approved' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)),
    CHECK (kind <> 'rubric' OR content IS NOT NULL),
    CHECK (test_only = (status = 'test_only'))
);

CREATE OR REPLACE FUNCTION sss_derivation_version_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.version_id IS DISTINCT FROM OLD.version_id
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.content IS DISTINCT FROM OLD.content
       OR NEW.test_only IS DISTINCT FROM OLD.test_only
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.approved_at IS DISTINCT FROM OLD.approved_at THEN
        RAISE EXCEPTION 'sss_derivation_versions rows are immutable (forward-only): %', OLD.version_id;
    END IF;
    IF OLD.status = 'test_only' AND NEW.status <> 'test_only' THEN
        RAISE EXCEPTION 'test-only sss derivation content can never be promoted to production authority: %', OLD.version_id;
    END IF;
    IF OLD.status = 'approved' AND NEW.status NOT IN ('approved', 'retired') THEN
        RAISE EXCEPTION 'approved sss derivation versions may only advance forward to retired: %', OLD.version_id;
    END IF;
    IF OLD.status = 'retired' AND NEW.status <> 'retired' THEN
        RAISE EXCEPTION 'retired sss derivation versions are immutable: %', OLD.version_id;
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sss_derivation_version_immutable ON sss_derivation_versions;
CREATE TRIGGER trg_sss_derivation_version_immutable
    BEFORE UPDATE ON sss_derivation_versions
    FOR EACH ROW EXECUTE FUNCTION sss_derivation_version_immutable();

-- ---------------------------------------------------------------------------
-- 2. Shared guards: closed taxonomy spine + tenant-scoped CVE rejection
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION sss_validate_taxonomy_spine(
    p_class TEXT, p_subclass TEXT, p_subtype TEXT
) RETURNS boolean AS $$
BEGIN
    -- class: required, closed six (verbatim uppercase; no defaults)
    IF p_class IS NULL OR length(btrim(p_class)) = 0 THEN
        RAISE EXCEPTION 'taxonomy_class is required (no defaults)';
    END IF;
    IF p_class <> btrim(p_class) OR upper(p_class) <> p_class THEN
        RAISE EXCEPTION 'taxonomy_class % must be a verbatim spine token (uppercase, unpadded)', p_class;
    END IF;
    IF p_class NOT IN ('BLFLAW', 'SUPPLY_CHAIN', 'IDENTITY_POSTURE', 'AGENTIC_EXPOSURE',
                       'VALIDATION_EVIDENCE', 'NHI') THEN
        RAISE EXCEPTION 'unknown taxonomy class %', p_class;
    END IF;
    -- subclass: required-closed for IDENTITY_POSTURE / AGENTIC_EXPOSURE,
    -- absent (NULL) for every other class
    IF p_class IN ('IDENTITY_POSTURE', 'AGENTIC_EXPOSURE') THEN
        IF p_subclass IS NULL OR length(btrim(p_subclass)) = 0 THEN
            RAISE EXCEPTION 'taxonomy_subclass is required for % (no defaults)', p_class;
        END IF;
        IF p_subclass <> btrim(p_subclass) OR upper(p_subclass) <> p_subclass THEN
            RAISE EXCEPTION 'taxonomy_subclass % must be a verbatim spine token (uppercase, unpadded)', p_subclass;
        END IF;
        IF p_class = 'IDENTITY_POSTURE' AND p_subclass NOT IN
           ('AUTH_FLOW_ABUSE', 'MFA_ENROLMENT', 'SESSION_TOKEN', 'MACHINE_KEY', 'CONDITIONAL_ACCESS') THEN
            RAISE EXCEPTION 'invalid IDENTITY_POSTURE subclass %', p_subclass;
        END IF;
        IF p_class = 'AGENTIC_EXPOSURE' AND p_subclass NOT IN
           ('ADVERSARY_AI', 'AUTONOMOUS_PRINCIPAL', 'INJECTION_PATH', 'MEMORY_RAG',
            'TOOL_MCP', 'TRAINING_SUPPLY') THEN
            RAISE EXCEPTION 'invalid AGENTIC_EXPOSURE subclass %', p_subclass;
        END IF;
    ELSE
        IF p_subclass IS NOT NULL THEN
            RAISE EXCEPTION 'taxonomy_subclass % is not applicable to % — absence (NULL) is the representation', p_subclass, p_class;
        END IF;
    END IF;
    -- subtype: required-closed for BLFLAW, absent (NULL) for every other class
    IF p_class = 'BLFLAW' THEN
        IF p_subtype IS NULL OR length(btrim(p_subtype)) = 0 THEN
            RAISE EXCEPTION 'taxonomy_subtype is required for BLFLAW (no defaults)';
        END IF;
        IF p_subtype <> btrim(p_subtype) OR upper(p_subtype) <> p_subtype THEN
            RAISE EXCEPTION 'taxonomy_subtype % must be a verbatim spine token (uppercase, unpadded)', p_subtype;
        END IF;
        IF p_subtype NOT IN ('IDOR', 'BFLAW-BAC', 'BFLAW-HPE', 'BFLAW-BFB', 'BFLAW-MSC') THEN
            RAISE EXCEPTION 'invalid BLFLAW subtype %', p_subtype;
        END IF;
    ELSE
        IF p_subtype IS NOT NULL THEN
            RAISE EXCEPTION 'taxonomy_subtype % is not applicable to % — absence (NULL) is the representation', p_subtype, p_class;
        END IF;
    END IF;
    RETURN TRUE;
END $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION sss_reject_cve_finding() RETURNS trigger AS $$
DECLARE
    cve TEXT;
BEGIN
    -- TENANT-SCOPED lookup: the CVE gate never reads another tenant's row.
    SELECT canonical_cve_id INTO cve
    FROM findings
    WHERE id = NEW.finding_id AND tenant_id = NEW.tenant_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'finding % not found in tenant %', NEW.finding_id, NEW.tenant_id;
    END IF;
    IF cve IS NOT NULL THEN
        RAISE EXCEPTION 'non-CVE severity records are forbidden on CVE findings (finding % has canonical_cve_id %)', NEW.finding_id, cve;
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- 3. Immutable non-CVE classification history (closed taxonomy spine)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS non_cve_classifications (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    finding_id            UUID NOT NULL,
    -- the exact finding revision the classification was published against
    finding_revision_xmin TEXT NOT NULL,
    taxonomy_class        TEXT NOT NULL,
    -- presence/absence matrix: NULL = dimension without an approved
    -- vocabulary (the CHECK enforces requiredness per class)
    taxonomy_subclass     TEXT,
    taxonomy_subtype      TEXT,
    path                  TEXT NOT NULL CHECK (path IN ('vrt', 'rubric')),
    vrt_id                TEXT,
    vrt_priority          TEXT,
    -- VRT/rubric version when applicable (pinned VRT release / rubric version)
    version_id_ref        UUID REFERENCES sss_derivation_versions (id),
    inputs                JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence              JSONB NOT NULL CHECK (evidence <> '{}'::jsonb),
    -- server-owned evidence-ladder state (client-supplied values are rejected)
    validation_state      TEXT NOT NULL DEFAULT 'single_source'
                          CHECK (validation_state IN ('confirmed', 'single_source', 'disputed')),
    created_by            TEXT NOT NULL,
    created_role          TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_non_cve_classifications_finding
        FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id) ON DELETE RESTRICT,
    -- composite identity consumed by the derivation provenance FK below
    CONSTRAINT uq_non_cve_classifications_identity UNIQUE (id, tenant_id, finding_id),
    -- closed taxonomy spine (no defaults; approved combinations only)
    CONSTRAINT ck_non_cve_classifications_taxonomy
        CHECK (sss_validate_taxonomy_spine(taxonomy_class, taxonomy_subclass, taxonomy_subtype))
);

DROP TRIGGER IF EXISTS trg_non_cve_classifications_reject_cve ON non_cve_classifications;
CREATE TRIGGER trg_non_cve_classifications_reject_cve
    BEFORE INSERT ON non_cve_classifications
    FOR EACH ROW EXECUTE FUNCTION sss_reject_cve_finding();

CREATE OR REPLACE FUNCTION non_cve_classifications_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'non_cve_classifications history is immutable (UPDATE % forbidden)', TG_OP;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_non_cve_classifications_immutable ON non_cve_classifications;
CREATE TRIGGER trg_non_cve_classifications_immutable
    BEFORE UPDATE OR DELETE ON non_cve_classifications
    FOR EACH ROW EXECUTE FUNCTION non_cve_classifications_immutable();

CREATE INDEX IF NOT EXISTS idx_non_cve_classifications_finding
    ON non_cve_classifications (tenant_id, finding_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 4. Immutable SSS derivation history (one current per tenant+finding)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS non_cve_sss_derivations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    finding_id            UUID NOT NULL,
    finding_revision_xmin TEXT NOT NULL,
    classification_id     UUID NOT NULL,
    -- self-contained audit snapshot of the classification identity
    taxonomy_class        TEXT NOT NULL,
    -- presence/absence matrix: NULL = dimension without an approved
    -- vocabulary (the CHECK enforces requiredness per class)
    taxonomy_subclass     TEXT,
    taxonomy_subtype      TEXT,
    -- §3.6.6 #2 escape hatch: the approval-applied paths (manual/override)
    -- publish WITHOUT an approved version row — the version provenance shape
    -- is path-conditioned exactly like non_cve_classifications above
    path                  TEXT NOT NULL CHECK (path IN ('vrt', 'rubric', 'manual', 'override')),
    -- content paths (vrt/rubric) pin their approved version row; approval
    -- paths (manual/override) carry the approval id instead and leave this
    -- NULL (aligned with non_cve_classifications.version_id_ref)
    version_id_ref        UUID REFERENCES sss_derivation_versions (id),
    -- the exact structured inputs the value was derived from (reproducible)
    inputs                JSONB NOT NULL,
    value                 NUMERIC(6, 4) NOT NULL CHECK (value >= 0 AND value <= 10),
    evidence              JSONB NOT NULL CHECK (evidence <> '{}'::jsonb),
    is_current            BOOLEAN NOT NULL DEFAULT TRUE,
    created_by            TEXT NOT NULL,
    created_role          TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_non_cve_sss_derivations_finding
        FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id) ON DELETE RESTRICT,
    -- PROVENANCE: the classification must belong to the SAME tenant AND finding
    CONSTRAINT fk_non_cve_sss_derivations_classification
        FOREIGN KEY (classification_id, tenant_id, finding_id)
        REFERENCES non_cve_classifications (id, tenant_id, finding_id) ON DELETE RESTRICT,
    -- composite identity consumed by the proposal derived-comparison FK below
    CONSTRAINT uq_non_cve_sss_derivations_identity UNIQUE (id, tenant_id, finding_id),
    -- derivation taxonomy must mirror the bound classification's spine triple
    CONSTRAINT ck_non_cve_sss_derivations_taxonomy
        CHECK (sss_validate_taxonomy_spine(taxonomy_class, taxonomy_subclass, taxonomy_subtype)),
    -- path-conditioned version provenance shape (§3.6.6 #2): content paths
    -- REQUIRE a version row; approval paths REQUIRE its absence — the
    -- approval id, not borrowed version content, is the provenance
    CONSTRAINT ck_non_cve_sss_derivations_version_shape
        CHECK (
            (path IN ('vrt', 'rubric') AND version_id_ref IS NOT NULL)
            OR (path IN ('manual', 'override') AND version_id_ref IS NULL)
        )
);

DROP TRIGGER IF EXISTS trg_non_cve_sss_derivations_reject_cve ON non_cve_sss_derivations;
CREATE TRIGGER trg_non_cve_sss_derivations_reject_cve
    BEFORE INSERT ON non_cve_sss_derivations
    FOR EACH ROW EXECUTE FUNCTION sss_reject_cve_finding();

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

DROP TRIGGER IF EXISTS trg_non_cve_sss_derivations_immutable ON non_cve_sss_derivations;
CREATE TRIGGER trg_non_cve_sss_derivations_immutable
    BEFORE UPDATE OR DELETE ON non_cve_sss_derivations
    FOR EACH ROW EXECUTE FUNCTION non_cve_sss_derivations_immutable();

-- One current derivation per (tenant, finding); history stays.
CREATE UNIQUE INDEX IF NOT EXISTS uq_non_cve_sss_current
    ON non_cve_sss_derivations (tenant_id, finding_id) WHERE is_current;

CREATE INDEX IF NOT EXISTS idx_non_cve_sss_derivations_finding
    ON non_cve_sss_derivations (tenant_id, finding_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 5. Manual SSS proposals (pending forever in this build; never score)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS non_cve_sss_proposals (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL,
    finding_id            UUID NOT NULL,
    finding_revision_xmin TEXT NOT NULL,
    -- optional taxonomy (the manual/unstructured path may omit it); when
    -- supplied it must validate against the closed spine; all-or-none.
    taxonomy_class        TEXT,
    taxonomy_subclass     TEXT,
    taxonomy_subtype      TEXT,
    path                  TEXT NOT NULL DEFAULT 'manual' CHECK (path = 'manual'),
    proposed_value        NUMERIC(6, 4) NOT NULL CHECK (proposed_value >= 0 AND proposed_value <= 10),
    reason                TEXT NOT NULL CHECK (length(reason) > 0),
    evidence              JSONB NOT NULL CHECK (evidence <> '{}'::jsonb),
    status                TEXT NOT NULL DEFAULT 'pending' CHECK (status = 'pending'),
    -- the derived comparison binds to an EXACT derivation of the SAME tenant
    -- and finding; the displayed value/path/version are read through this
    -- binding, never denormalized. NULL when no current derivation exists.
    derived_derivation_id UUID,
    proposed_by           TEXT NOT NULL,
    proposed_role         TEXT NOT NULL,
    proposed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_non_cve_sss_proposals_finding
        FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_non_cve_sss_proposals_derived
        FOREIGN KEY (derived_derivation_id, tenant_id, finding_id)
        REFERENCES non_cve_sss_derivations (id, tenant_id, finding_id) ON DELETE RESTRICT,
    -- all-or-none row shape: taxonomy absent entirely, or class + exactly
    -- the spine-required fields present (the spine CHECK enforces which
    -- dimensions carry a token per class; the rest must be NULL)
    CONSTRAINT ck_non_cve_sss_proposals_taxonomy_shape CHECK (
        (taxonomy_class IS NULL AND taxonomy_subclass IS NULL AND taxonomy_subtype IS NULL)
        OR (taxonomy_class IS NOT NULL)
    ),
    CONSTRAINT ck_non_cve_sss_proposals_taxonomy
        CHECK (taxonomy_class IS NULL
               OR sss_validate_taxonomy_spine(taxonomy_class, taxonomy_subclass, taxonomy_subtype))
);

DROP TRIGGER IF EXISTS trg_non_cve_sss_proposals_reject_cve ON non_cve_sss_proposals;
CREATE TRIGGER trg_non_cve_sss_proposals_reject_cve
    BEFORE INSERT ON non_cve_sss_proposals
    FOR EACH ROW EXECUTE FUNCTION sss_reject_cve_finding();

CREATE OR REPLACE FUNCTION non_cve_sss_proposals_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'non_cve_sss_proposals are immutable (UPDATE % forbidden)', TG_OP;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_non_cve_sss_proposals_immutable ON non_cve_sss_proposals;
CREATE TRIGGER trg_non_cve_sss_proposals_immutable
    BEFORE UPDATE OR DELETE ON non_cve_sss_proposals
    FOR EACH ROW EXECUTE FUNCTION non_cve_sss_proposals_immutable();

CREATE INDEX IF NOT EXISTS idx_non_cve_sss_proposals_finding
    ON non_cve_sss_proposals (tenant_id, finding_id, proposed_at DESC);
