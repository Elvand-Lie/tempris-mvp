-- Migration 035: Chapter 11 — SPEAK / Reports (Deliverables) (PRD-000 v1.11 Ch.11).
--
-- One authoritative report model over SEALED SNAPSHOTS:
--
--   * A report is a reader, never a writer: generation never mutates scoring
--     or workflow state. No table below references scoring/workflow tables
--     for writes and no code path may.
--   * Immutability where fidelity matters (PATCH-13): every report row is
--     content-hash-sealed, carries template identity + version + generator
--     actor, and stores the SEALED score values it rendered (a report is a
--     §3.3.6 snapshot writer — values are read from the report, never
--     recomputed at view time). The sealed columns are DB-enforced
--     immutable; only the lifecycle columns (status, approved_*, archived_*)
--     may ever change after generation.
--   * Regeneration creates a NEW version row (parent_report_id chain) —
--     history is never rewritten.
--   * Approved/archived reports are NON-DELETABLE (archive only): V1's hard
--     delete of approved reports is retired. Only never-approved drafts may
--     be deleted (together with their artifacts).
--   * report_artifacts hold the published bytes (html/json/csv) sealed with
--     their own sha256; they are byte-immutable, size-bounded, and
--     tenant-scoped. PDF remains OPEN (V1 explicitly blocked it; no engine
--     decision yet).
--
-- The SPEAK chat/AI surface owns NO tables in this migration: with no LLM
-- provider configured the surface fails closed ("unavailable") and persists
-- nothing — the mock-LLM fallback that invented seed numbers is retired.
-- Chat/session tables arrive with the LLM provider decision (OPEN).
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Module catalogue: SPEAK
-- ---------------------------------------------------------------------------

INSERT INTO modules (id, name, description, status, created_at)
VALUES (
    'SPEAK',
    'SPEAK — Reports & Deliverables',
    'Sealed, versioned, template-identified report deliverables rendered from authoritative upstream state (never a second truth), plus the system''s only AI surface — which fails closed without a model and never invents content.',
    'active',
    now()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO package_modules (package_id, module_id)
VALUES ('CORE_ASSETS', 'SPEAK')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. reports — sealed snapshot rows with a version chain
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS reports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    -- v1 vocabulary is exactly the deliverable types renderable from the
    -- integrated Ch.1-10 baseline; the CHECK extends forward-only as the
    -- upstream domains land (STRIKE packs need Ch.4, remediation/compliance
    -- packs need Ch.8/9 — they fail closed until then)
    report_type       TEXT NOT NULL
                      CHECK (report_type IN ('executive_summary', 'exposure_register')),
    title             TEXT NOT NULL CHECK (length(btrim(title)) > 0),
    -- draft → approved → archived; DELETE only ever permitted for drafts
    status            TEXT NOT NULL DEFAULT 'draft'
                      CHECK (status IN ('draft', 'approved', 'archived')),
    version           INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    parent_report_id  UUID,
    -- template identity + version (the built-in template registry in
    -- app/speak/render.py is the v1 source; template management UI is OPEN)
    template_id       TEXT NOT NULL,
    template_version  INTEGER NOT NULL,
    -- the coherent source-view instant the report sealed (PATCH-13: one
    -- as_of). NULL while the report is an unsealed draft — the seal-shape
    -- CHECK below forces it to exist exactly when the payload does.
    as_of             TIMESTAMPTZ,
    -- the rendered values + source identities (the §3.3.6 snapshot this
    -- report writes). Viewers render FROM THIS, never by recomputation.
    sealed_payload    JSONB,
    -- sha256 over the canonical JSON of sealed_payload
    content_hash      TEXT,
    scope             JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- provenance: who generated / approved / archived, when
    generated_by      TEXT,
    generated_at      TIMESTAMPTZ,
    approved_by       TEXT,
    approved_at       TIMESTAMPTZ,
    archived_by       TEXT,
    archived_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- (tenant_id, id) uniqueness: the parent composite FK binds a parent to
    -- the SAME tenant (the platform's composite-identity convention)
    CONSTRAINT uq_reports_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_reports_parent FOREIGN KEY (tenant_id, parent_report_id)
        REFERENCES reports(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT ck_reports_seal_shape CHECK (
        (sealed_payload IS NULL AND content_hash IS NULL AND as_of IS NULL
         AND generated_by IS NULL AND generated_at IS NULL)
        OR (sealed_payload IS NOT NULL AND content_hash IS NOT NULL
            AND as_of IS NOT NULL
            AND generated_by IS NOT NULL AND generated_at IS NOT NULL)
    ),
    CONSTRAINT ck_reports_hash_shape
        CHECK (content_hash IS NULL OR content_hash ~* '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_reports_tenant_status
    ON reports (tenant_id, status, created_at DESC);

-- Sealed immutability: once generated, the payload/hash/template/as_of/
-- lineage identity can never change — only the lifecycle columns move.
-- (The NULL → sealed transition itself IS the generation step and is the
-- one permitted change of those columns; the ck_reports_seal_shape CHECK
-- forces it to happen atomically with the hash and the generator stamp.)
CREATE OR REPLACE FUNCTION reports_guard_seal()
RETURNS trigger AS $$
BEGIN
    IF OLD.sealed_payload IS NOT NULL THEN
        IF NEW.sealed_payload IS DISTINCT FROM OLD.sealed_payload
           OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
           OR NEW.template_id IS DISTINCT FROM OLD.template_id
           OR NEW.template_version IS DISTINCT FROM OLD.template_version
           OR NEW.as_of IS DISTINCT FROM OLD.as_of
           OR NEW.scope IS DISTINCT FROM OLD.scope
           OR NEW.report_type IS DISTINCT FROM OLD.report_type
           OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.version IS DISTINCT FROM OLD.version
           OR NEW.parent_report_id IS DISTINCT FROM OLD.parent_report_id
           OR NEW.generated_by IS DISTINCT FROM OLD.generated_by
           OR NEW.generated_at IS DISTINCT FROM OLD.generated_at THEN
            RAISE EXCEPTION 'reports are sealed: the payload/hash/template/as_of/lineage identity is immutable (report %)', OLD.id;
        END IF;
    END IF;
    -- provenance stamps never move backwards
    IF OLD.approved_at IS NOT NULL
       AND (NEW.approved_by IS DISTINCT FROM OLD.approved_by
            OR NEW.approved_at IS DISTINCT FROM OLD.approved_at) THEN
        RAISE EXCEPTION 'report % approval provenance is immutable', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_reports_guard_seal ON reports;
CREATE TRIGGER trg_reports_guard_seal
    BEFORE UPDATE ON reports
    FOR EACH ROW EXECUTE FUNCTION reports_guard_seal();

-- Approved/archived deliverables are non-deletable (archive only); the
-- service 409s the same rule, the database enforces it.
CREATE OR REPLACE FUNCTION reports_guard_delete()
RETURNS trigger AS $$
BEGIN
    IF OLD.status <> 'draft' THEN
        RAISE EXCEPTION 'report % is % and cannot be deleted (archive only)', OLD.id, OLD.status;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_reports_guard_delete ON reports;
CREATE TRIGGER trg_reports_guard_delete
    BEFORE DELETE ON reports
    FOR EACH ROW EXECUTE FUNCTION reports_guard_delete();

-- ---------------------------------------------------------------------------
-- 3. report_artifacts — sealed published bytes (html/json/csv)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS report_artifacts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    report_id      UUID NOT NULL,
    artifact_kind  TEXT NOT NULL CHECK (artifact_kind IN ('html', 'json', 'csv')),
    content        BYTEA NOT NULL,
    size_bytes     INTEGER NOT NULL CHECK (size_bytes = octet_length(content)),
    -- sha256 over the exact bytes — verified on every download; mismatch
    -- refuses + alarms (PRD fail-closed)
    content_hash   TEXT NOT NULL
                   CHECK (content_hash ~* '^[0-9a-f]{64}$'),
    created_by     TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_report_artifacts_report FOREIGN KEY (tenant_id, report_id)
        REFERENCES reports(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT uq_report_artifact_per_kind UNIQUE (tenant_id, report_id, artifact_kind),
    -- bounded artifacts (PRD: exports must be bounded)
    CONSTRAINT ck_report_artifact_size CHECK (octet_length(content) <= 4194304)
);

CREATE INDEX IF NOT EXISTS idx_report_artifacts_report
    ON report_artifacts (tenant_id, report_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'report_artifacts'::regclass
          AND conname = 'uq_report_artifacts_tenant_id'
    ) THEN
        ALTER TABLE report_artifacts
            ADD CONSTRAINT uq_report_artifacts_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- Byte immutability: a published artifact never changes. (Removal happens
-- only through the report-cascade, which itself only ever fires for drafts.)
CREATE OR REPLACE FUNCTION report_artifacts_forbid_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'report_artifacts are immutable: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_report_artifacts_no_update ON report_artifacts;
CREATE TRIGGER trg_report_artifacts_no_update
    BEFORE UPDATE ON report_artifacts
    FOR EACH ROW EXECUTE FUNCTION report_artifacts_forbid_mutation();
