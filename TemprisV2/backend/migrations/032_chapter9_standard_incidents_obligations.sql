-- Migration 032: Chapter 9 — STANDARD / GRC, part 2: obligations & regulatory
-- incidents (PRD-000 v1.11 Ch.9; the MAS pattern generalized; Flows E).
--
--   customer detector / SIEM / SOC / manual
--   → POST /api/standard/incidents (validated, timestamped, deduped candidate)
--   → rule evaluation (explicit rule objects: condition → obligation template)
--   → obligation created: due_at = trigger(event time) + clock (MAS 12.1.5: 1h)
--   → draft notice prepared
--   → HUMAN submits via the official channel (OUTSIDE Tempris — nothing here
--     submits to a regulator; no submission API exists or is claimed)
--   → Tempris records the immutable submission proof
--   → follow-up obligations per rule
--
-- PATCH-11 (evaluation durability): an incident edit durably records a NEW
-- immutable input revision and re-pends ALL expected rules — completed
-- negative evaluations included; a resolved incident reopens to acknowledged
-- in the same transaction with audit. Every attempt reads one immutable
-- incident-input revision pinned to one rule version; results and their
-- uniquely keyed obligation outputs commit only while that revision is
-- current (the same concurrency boundary as incident edits and resolution).
-- Stale attempts remain history. Required unfinished evaluations or
-- obligations — including evaluations not bound to the current revision —
-- block resolution.
--
-- PATCH-12 (clock contract): each evaluation pins its TRIGGER timestamp (the
-- incident's event time — receipt/retry time never starts or restarts the
-- clock); due_at persists at creation and retries never restart it;
-- corrections go through an audited revision using the corrected trigger
-- facts, preserving prior values and submission history. The proof reference
-- and actual completion time bind separately from the recording time;
-- overdue and completed-late derive separately, and lateness survives
-- closure.
--
-- Rule evaluation failure fails VISIBLY on the incident (never on an
-- obligation — none can exist yet): the incident_rule_evaluations row enters
-- evaluation_error / manual_review_required and the incident stays
-- unresolved. The row IS the persisted operator-visible alarm (external
-- notification waits for the shared notification service, Ch.9 open #5).
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Incidents + immutable input revisions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_incidents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    -- dedup identity (V1 pattern): repeated posts of the same
    -- (source, external_event_id) return the original incident
    source              TEXT NOT NULL CHECK (length(btrim(source)) > 0),
    external_event_id   TEXT,
    title               TEXT NOT NULL CHECK (length(btrim(title)) > 0),
    description         TEXT,
    state               TEXT NOT NULL DEFAULT 'open'
                        CHECK (state IN ('open', 'acknowledged', 'resolved')),
    -- the clock anchor (PATCH-12): the incident's event/discovery time —
    -- the trigger every obligation clock pins; receipt time never starts it
    event_time          TIMESTAMPTZ NOT NULL,
    current_revision    INT NOT NULL DEFAULT 1,
    created_by          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,
    CONSTRAINT uq_standard_incidents_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT ck_standard_incident_resolved_shape CHECK (
        (state = 'resolved') OR (resolved_at IS NULL)
    )
);

-- PATCH-07-style replay identity: an identical replay returns the original
-- incident (one row per (tenant, source, external_event_id) where an event
-- id exists) — no duplicate obligations from repeated posts.
CREATE UNIQUE INDEX IF NOT EXISTS uq_standard_incidents_event_identity
    ON standard_incidents (tenant_id, source, external_event_id)
    WHERE external_event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_standard_incidents_state
    ON standard_incidents (tenant_id, state);

CREATE TABLE IF NOT EXISTS standard_incident_revisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    incident_id     UUID NOT NULL,
    revision_no     INT NOT NULL,
    -- the IMMUTABLE rule-input revision (PATCH-11): event_time, kind, and
    -- every fact rules may condition on; rules read THIS, never the incident
    inputs          JSONB NOT NULL CHECK (jsonb_typeof(inputs) = 'object'),
    correction_note TEXT,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_standard_incident_revisions UNIQUE (tenant_id, incident_id, revision_no),
    CONSTRAINT fk_standard_incident_rev FOREIGN KEY (tenant_id, incident_id)
        REFERENCES standard_incidents(tenant_id, id) ON DELETE RESTRICT
);

-- ---------------------------------------------------------------------------
-- 2. Rules — platform-curated rule objects (rule changes are admin+)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_rules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_key            TEXT NOT NULL UNIQUE,
    rule_version        INT NOT NULL DEFAULT 1,
    framework_code      TEXT REFERENCES standard_frameworks(framework_code) ON DELETE RESTRICT,
    control_code        TEXT,
    title               TEXT NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    -- condition: closed equality shape — every key/value must match the
    -- incident-input revision (v1: flat JSON object equality on the named
    -- keys; an unreadable condition fails VISIBLY, never silently matches)
    condition           JSONB NOT NULL CHECK (jsonb_typeof(condition) = 'object'),
    -- obligation template: kind, title, and the policy clock in seconds
    -- (MAS TRM 12.1.5: 3600)
    obligation_template JSONB NOT NULL CHECK (jsonb_typeof(obligation_template) = 'object'),
    clock_seconds       INT NOT NULL CHECK (clock_seconds > 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_standard_rules_key_version UNIQUE (rule_key, rule_version),
    CONSTRAINT ck_standard_rules_template_clock CHECK (
        (obligation_template->>'clock_seconds') IS NULL
        OR (obligation_template->>'clock_seconds')::int = clock_seconds
    )
);

-- The MAS 12.1.5 pattern, generalized (Ch.9 target architecture 2). The rule
-- catalog is platform-curated; MAS rule-set scope beyond this seed is open
-- Ch.9 decision #3 (regulatory input needed).
INSERT INTO standard_rules (
    rule_key, rule_version, framework_code, control_code, title,
    is_active, condition, obligation_template, clock_seconds
) VALUES (
    'mas_trm_12_1_5_incident_notification', 1, 'mas_trm_2024', 'MAS-TRM-12.1.5',
    'MAS TRM 12.1.5 — 1-Hour Incident Notification',
    TRUE,
    '{"incident_kind": "cyber_security_incident"}'::jsonb,
    jsonb_build_object(
        'kind', 'regulator_notification',
        'title', 'MAS TRM 12.1.5 notification (1 hour)',
        'channel_hint', 'MAS official channel (human submission — Tempris records proof only)',
        'clock_seconds', 3600
    ),
    3600
)
ON CONFLICT (rule_key, rule_version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3. Incident rule evaluations — PATCH-11's durable pending-work ledger
--    ONE CURRENT row per (incident, rule), pinned to one incident-input
--    revision + one rule version; prior attempts/revision bindings retained.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_incident_rule_evaluations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    incident_id         UUID NOT NULL,
    rule_id             UUID NOT NULL REFERENCES standard_rules(id) ON DELETE RESTRICT,
    rule_key            TEXT NOT NULL,
    rule_version        INT NOT NULL,
    incident_revision_no INT NOT NULL,
    state               TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending', 'evaluated',
                                         'evaluation_error', 'manual_review_required')),
    attempt             INT NOT NULL DEFAULT 1,
    result              TEXT,
    error_detail        TEXT,
    obligation_id       UUID,
    evaluated_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_current          BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT uq_standard_evaluations_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_standard_evaluation_incident FOREIGN KEY (tenant_id, incident_id)
        REFERENCES standard_incidents(tenant_id, id) ON DELETE RESTRICT
);

-- one CURRENT evaluation per (incident, rule) (partial unique — index)
CREATE UNIQUE INDEX IF NOT EXISTS uq_standard_evaluation_current
    ON standard_incident_rule_evaluations (tenant_id, incident_id, rule_id)
    WHERE is_current;

CREATE INDEX IF NOT EXISTS idx_standard_evaluations_unfinished
    ON standard_incident_rule_evaluations (tenant_id, incident_id, state)
    WHERE is_current AND state IN ('pending', 'evaluation_error', 'manual_review_required');

-- ---------------------------------------------------------------------------
-- 4. Obligations — deadline state with the PATCH-12 clock contract
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_obligations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    incident_id         UUID,
    source_rule_id      UUID REFERENCES standard_rules(id),
    source_rule_version INT,
    -- STABLE identity across incident revisions (PATCH-11): reevaluation
    -- reuses this row, never duplicates it
    obligation_key      TEXT NOT NULL,
    kind                TEXT NOT NULL,
    title               TEXT NOT NULL,
    draft_notice        JSONB,
    -- the pinned trigger (the incident's event time) and the persisted
    -- deadline: created once, never restarted by retries (PATCH-12)
    trigger_at          TIMESTAMPTZ NOT NULL,
    due_at              TIMESTAMPTZ NOT NULL,
    clock_seconds       INT NOT NULL,
    state               TEXT NOT NULL DEFAULT 'open'
                        CHECK (state IN ('open', 'in_progress', 'fulfilled', 'closed')),
    -- audited revision counter for corrections (PATCH-12)
    revision            INT NOT NULL DEFAULT 1,
    correction_note     TEXT,
    -- completion binds to the obligation separately from any recording time;
    -- completed-late derives as fulfilled_at > due_at and SURVIVES closure
    fulfilled_at        TIMESTAMPTZ,
    fulfilled_by        TEXT,
    closed_at           TIMESTAMPTZ,
    -- breach recorded when first OBSERVED (read-time derivation writes it
    -- once); overdue itself stays derived — no scheduler exists
    breached_at         TIMESTAMPTZ,
    created_by          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_standard_obligations_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_standard_obligation_key UNIQUE (tenant_id, obligation_key),
    CONSTRAINT fk_standard_obligation_incident FOREIGN KEY (tenant_id, incident_id)
        REFERENCES standard_incidents(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT ck_standard_obligation_closed_shape CHECK (
        (state = 'closed') OR (closed_at IS NULL)
    ),
    CONSTRAINT ck_standard_obligation_fulfilled_shape CHECK (
        (state IN ('fulfilled', 'closed')) OR (fulfilled_at IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_standard_obligations_state
    ON standard_obligations (tenant_id, state);
CREATE INDEX IF NOT EXISTS idx_standard_obligations_due
    ON standard_obligations (tenant_id, due_at);

-- ---------------------------------------------------------------------------
-- 5. Submission records — immutable on write; proof binds to the obligation
--    (who/when/channel/reference/proof); one submission per obligation
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_submission_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    obligation_id   UUID NOT NULL,
    submitted_by    TEXT NOT NULL,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    channel         TEXT NOT NULL CHECK (length(btrim(channel)) > 0),
    reference       TEXT,
    proof           TEXT NOT NULL CHECK (length(btrim(proof)) > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_standard_submissions_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_standard_submission_per_obligation UNIQUE (tenant_id, obligation_id),
    CONSTRAINT fk_standard_submission_obligation FOREIGN KEY (tenant_id, obligation_id)
        REFERENCES standard_obligations(tenant_id, id) ON DELETE RESTRICT
);

-- Submission records are IMMUTABLE on write (owned-state table, Ch.9) —
-- enforced at the DB layer, not by service discipline.
CREATE OR REPLACE FUNCTION standard_submission_records_immutable()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'standard_submission_records is immutable on write';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_standard_submission_immutable ON standard_submission_records;
CREATE TRIGGER trg_standard_submission_immutable
    BEFORE UPDATE OR DELETE ON standard_submission_records
    FOR EACH ROW EXECUTE FUNCTION standard_submission_records_immutable();
