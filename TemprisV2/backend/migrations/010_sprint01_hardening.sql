-- Migration 010: Sprint 01 Hardening
-- Canonical authority enforcement, unresolved enrichment references (dual-column),
-- immutable artifact preservation, and atomicity support.
--
-- Idempotent: uses IF NOT EXISTS / ADD COLUMN IF NOT EXISTS throughout.

-- ---------------------------------------------------------------------------
-- 1. Dual-column: vuln_source_records.declared_cve_id (always-set, no FK)
-- ---------------------------------------------------------------------------
ALTER TABLE vuln_source_records
    ADD COLUMN IF NOT EXISTS declared_cve_id TEXT;

-- ---------------------------------------------------------------------------
-- 2. Dual-column: kev_entries restructure
--    - Add UUID id column as new PK (cve_id was PK before)
--    - Add declared_cve_id TEXT NOT NULL
--    - Make cve_id nullable (FK remains but nullable)
-- ---------------------------------------------------------------------------

-- Add id column if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'kev_entries' AND column_name = 'id'
    ) THEN
        ALTER TABLE kev_entries ADD COLUMN id UUID DEFAULT gen_random_uuid();
        -- Populate existing rows
        UPDATE kev_entries SET id = gen_random_uuid() WHERE id IS NULL;
        ALTER TABLE kev_entries ALTER COLUMN id SET NOT NULL;
    END IF;
END $$;

-- Add declared_cve_id column
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'kev_entries' AND column_name = 'declared_cve_id'
    ) THEN
        ALTER TABLE kev_entries ADD COLUMN declared_cve_id TEXT;
        -- Backfill from existing cve_id
        UPDATE kev_entries SET declared_cve_id = cve_id WHERE declared_cve_id IS NULL;
        ALTER TABLE kev_entries ALTER COLUMN declared_cve_id SET NOT NULL;
    END IF;
END $$;

-- Drop old PK on cve_id and create new PK on id
DO $$
BEGIN
    -- Drop existing PK constraint if it references cve_id
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
        WHERE tc.table_name = 'kev_entries'
          AND tc.constraint_type = 'PRIMARY KEY'
          AND kcu.column_name = 'cve_id'
    ) THEN
        -- Get the constraint name dynamically
        EXECUTE (
            SELECT format('ALTER TABLE kev_entries DROP CONSTRAINT %I', tc.constraint_name)
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
            WHERE tc.table_name = 'kev_entries'
              AND tc.constraint_type = 'PRIMARY KEY'
              AND kcu.column_name = 'cve_id'
            LIMIT 1
        );
        ALTER TABLE kev_entries ADD PRIMARY KEY (id);
    END IF;
END $$;

-- Make cve_id nullable (it was NOT NULL as PK before)
ALTER TABLE kev_entries ALTER COLUMN cve_id DROP NOT NULL;

-- Drop old FK on cve_id if it exists, re-add as nullable FK
-- The FK may have been implicitly part of the PK constraint
DO $$
BEGIN
    -- Drop existing FK on kev_entries.cve_id if any
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
        WHERE tc.table_name = 'kev_entries'
          AND tc.constraint_type = 'FOREIGN KEY'
          AND kcu.column_name = 'cve_id'
    ) THEN
        EXECUTE (
            SELECT format('ALTER TABLE kev_entries DROP CONSTRAINT %I', tc.constraint_name)
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
                ON tc.constraint_name = kcu.constraint_name
            WHERE tc.table_name = 'kev_entries'
              AND tc.constraint_type = 'FOREIGN KEY'
              AND kcu.column_name = 'cve_id'
            LIMIT 1
        );
    END IF;
END $$;

-- Re-add FK as nullable reference
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
        WHERE tc.table_name = 'kev_entries'
          AND tc.constraint_type = 'FOREIGN KEY'
          AND kcu.column_name = 'cve_id'
    ) THEN
        ALTER TABLE kev_entries
            ADD CONSTRAINT fk_kev_entries_cve_id
            FOREIGN KEY (cve_id) REFERENCES canonical_vulnerabilities(cve_id);
    END IF;
END $$;

-- Add unique constraint on declared_cve_id for upsert semantics
CREATE UNIQUE INDEX IF NOT EXISTS uix_kev_entries_declared_cve_id
    ON kev_entries (declared_cve_id);

-- ---------------------------------------------------------------------------
-- 3. Dual-column: osv_aliases.declared_linked_cve_id
-- ---------------------------------------------------------------------------
ALTER TABLE osv_aliases
    ADD COLUMN IF NOT EXISTS declared_linked_cve_id TEXT;

-- ---------------------------------------------------------------------------
-- 4. Source artifacts table (inline BYTEA for exact byte preservation)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source_artifacts (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_record_id  UUID NOT NULL REFERENCES vuln_source_records(id),
    sha256_hash       TEXT NOT NULL,
    artifact_url      TEXT,
    media_type        TEXT,
    byte_size         INTEGER NOT NULL,
    artifact_bytes    BYTEA NOT NULL,
    retrieval_time    TIMESTAMPTZ NOT NULL DEFAULT now(),
    importer_version  TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_source_artifacts_source_record_id
    ON source_artifacts (source_record_id);

CREATE INDEX IF NOT EXISTS idx_source_artifacts_sha256_hash
    ON source_artifacts (sha256_hash);
