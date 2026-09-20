-- Migration 025: Chapter 6 — Intake & Triage / Exposure Review (PRD-000 v1.11 Ch.6).
--
-- One intake lifecycle for everything that is not SCOUT: manual reports,
-- connector observations, STRIKE discoveries, VDP submissions, and threat-pack
-- imports enter as intake RECORDS — never findings (connectors are transport,
-- never authority; STRIKE discoveries enter here per Flow C). Confirmation is
-- the ONLY handoff into Ch.3/Ch.7 (finding + evidence-backed exposure via the
-- shared Ch.3 confirmation command).
--
-- Source-event replay identity (PATCH-07): every intake source persists
-- (tenant, source registration, source event id, payload digest). An identical
-- replay returns the original outcome; a conflicting payload under the same
-- event id is rejected. The partial unique index below makes the tuple unique
-- per tenant where an event id exists.
--
-- Duplicate handling stores a REFERENCE (duplicate_of_exposure_id) — no
-- duplicate finding is created merely to have something to link (Ch.6 target
-- architecture item 5).
--
-- Connector registrations carry destination routing + payload semantics ONLY —
-- connector credentials/principals/secrets are Chapter 5-owned (Q19 split);
-- there is deliberately no credential column here.
--
-- Conservative v1: no SLA/escalation policy engine (Ch.6 open decision #1),
-- no non-CVE fact-signature dedup scheme beyond the v1 finding identity
-- (open decision #2), no public VDP submission surface (open decision #3).
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Intake records
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intake_records (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    -- closed source vocabulary (Ch.6 inputs): everything that is not SCOUT
    source                TEXT NOT NULL CHECK (source IN (
                              'MANUAL', 'CONNECTOR', 'STRIKE_DISCOVERY',
                              'VDP', 'THREAT_PACK')),
    -- lifecycle (Ch.6 target architecture item 1):
    --   submitted → under_review → confirmed | rejected | duplicate | needs_info
    -- needs_info holds with a named deficiency and may return to review;
    -- confirmed / rejected / duplicate are terminal.
    state                 TEXT NOT NULL DEFAULT 'submitted'
                          CHECK (state IN ('submitted', 'under_review', 'confirmed',
                                           'rejected', 'duplicate', 'needs_info')),
    -- source payload snapshot (provenance; sanitized copies never re-derive identity)
    payload               JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    -- sha256 hex over the canonical JSON of `payload` — the replay comparator
    payload_digest        TEXT NOT NULL CHECK (length(payload_digest) = 64),
    -- PATCH-07 source-event identity (both NULL for eventless sources)
    source_registration_id TEXT,
    source_event_id       TEXT,
    -- proposed finding shape (closed at the API boundary; the finding itself
    -- is created only by the confirmation handoff)
    title                 TEXT NOT NULL CHECK (length(btrim(title)) > 0),
    description           TEXT,
    severity              TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    canonical_cve_id      TEXT REFERENCES canonical_vulnerabilities(cve_id) ON DELETE SET NULL,
    -- classification spine (closed six-class SSS taxonomy per §3.6.5, shared
    -- presence/absence validator enforced in the service; NULL until
    -- classified — confirmation requires a classification)
    taxonomy_class        TEXT,
    taxonomy_subclass     TEXT,
    taxonomy_subtype      TEXT,
    -- anchor (resolved at REVIEW time, never at submission)
    asset_id              UUID,
    anchor_state          TEXT NOT NULL DEFAULT 'unresolved'
                          CHECK (anchor_state IN ('unresolved', 'resolved')),
    -- confirmation outcome references (the single handoff into Ch.3/Ch.7)
    finding_id            UUID,
    exposure_id           UUID,
    -- exact-duplicate reference — never a duplicate finding (item 5)
    duplicate_of_exposure_id UUID,
    -- actor trail (provenance; server-owned)
    requested_by          TEXT NOT NULL,
    reviewed_by           TEXT,
    reviewed_at           TIMESTAMPTZ,
    -- named deficiency (needs_info) / reasons (terminal states)
    deficiency            TEXT,
    rejection_reason      TEXT,
    duplicate_reason      TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- terminal-shape guards
    CONSTRAINT ck_intake_confirmed_shape CHECK (
        (state <> 'confirmed')
        OR (finding_id IS NOT NULL AND exposure_id IS NOT NULL
            AND anchor_state = 'resolved' AND reviewed_by IS NOT NULL)
    ),
    CONSTRAINT ck_intake_rejected_shape CHECK (
        (state <> 'rejected')
        OR (rejection_reason IS NOT NULL AND reviewed_by IS NOT NULL)
    ),
    CONSTRAINT ck_intake_duplicate_shape CHECK (
        (state <> 'duplicate')
        OR (duplicate_of_exposure_id IS NOT NULL
            AND duplicate_reason IS NOT NULL AND reviewed_by IS NOT NULL)
    ),
    CONSTRAINT ck_intake_needs_info_shape CHECK (
        (state <> 'needs_info')
        OR (deficiency IS NOT NULL)
    ),
    -- an event id REQUIRES its registration half; a registration alone is
    -- fine (eventless connector submissions)
    CONSTRAINT ck_intake_event_identity_pair CHECK (
        source_event_id IS NULL OR source_registration_id IS NOT NULL
    ),
    -- composite tenant integrity on every cross-object reference
    CONSTRAINT fk_intake_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id),
    CONSTRAINT fk_intake_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings(tenant_id, id),
    CONSTRAINT fk_intake_exposure FOREIGN KEY (tenant_id, exposure_id)
        REFERENCES asset_exposures(tenant_id, id),
    CONSTRAINT fk_intake_duplicate_exposure FOREIGN KEY (tenant_id, duplicate_of_exposure_id)
        REFERENCES asset_exposures(tenant_id, id)
);

-- PATCH-07 replay identity: one event id resolves to one outcome per
-- (tenant, registration). Replay/conflict arbitration lives in the service
-- under the per-identity advisory lock; the index is the storage backstop.
CREATE UNIQUE INDEX IF NOT EXISTS uq_intake_event_identity
    ON intake_records (tenant_id, source_registration_id, source_event_id)
    WHERE source_event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_intake_records_queue
    ON intake_records (tenant_id, state, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_intake_records_source
    ON intake_records (tenant_id, source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intake_records_finding
    ON intake_records (tenant_id, finding_id) WHERE finding_id IS NOT NULL;

-- Composite-FK target for the events table below (same pattern as 013's
-- uq_assets_tenant_id / uq_findings_tenant_id)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'intake_records'::regclass
          AND conname = 'uq_intake_records_tenant_id'
    ) THEN
        ALTER TABLE intake_records ADD CONSTRAINT uq_intake_records_tenant_id UNIQUE (tenant_id, id);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Intake record events (append-only actor trail on the record)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intake_record_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    record_id   UUID NOT NULL,
    event       TEXT NOT NULL CHECK (length(btrim(event)) > 0),
    actor       TEXT NOT NULL,
    actor_role  TEXT,
    note        TEXT,
    detail      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_intake_events_record
        FOREIGN KEY (tenant_id, record_id) REFERENCES intake_records(tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_intake_events_record
    ON intake_record_events (tenant_id, record_id, created_at ASC, id ASC);


-- ---------------------------------------------------------------------------
-- 3. Connector registrations (destination routing + payload semantics ONLY;
--    credentials/principals are Ch.5-owned — Q19 split; no secret column)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intake_connector_registrations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name              TEXT NOT NULL CHECK (length(btrim(name)) > 0),
    adapter           TEXT NOT NULL CHECK (length(btrim(adapter)) > 0),
    status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    -- Ch.6-owned destination routing config (where observations land) —
    -- transport auth is NOT configured here
    destination_routing JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(destination_routing) = 'object'),
    -- human-readable payload-semantics contract note for the adapter
    payload_semantics TEXT,
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_intake_connector_registrations UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_intake_connector_registrations_tenant
    ON intake_connector_registrations (tenant_id, status);
