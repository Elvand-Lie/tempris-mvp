-- Migration 021: Chapter 5 Dual-Control Approval Primitive (PRD-000 v1.11,
-- Chapter 5 Target architecture item 1; consumed by P0-08 per §3.6.6 #6).
--
-- ONE generic, Chapter-5-owned approval object. Chapter 3 (P0-08) registers
-- subject types as consumers of this primitive and never creates a second
-- approval store, table, or workflow.
--
-- Subject model: (tenant_id, subject_type, subject_id) — the subject id is
-- opaque to the primitive (TEXT; consumers own their subject identity) and
-- is validated/interpreted ONLY inside consumer-registered handlers.
--
-- Lifecycle (pinned by trigger to exactly these edges):
--   pending → approved | rejected | cancelled | expired
--   approved → applied  (TERMINAL; records applied_at)
--
-- Enforcement:
--   * HARD dual control: approver ≠ proposer, enforced in the trigger;
--   * approver authority (admin/superadmin membership CURRENT at decision)
--     is enforced by the decide service inside the same transaction;
--   * payload hash + subject-version snapshot are IMMUTABLE after proposal
--     (any update touching them rejects); decided/applied metadata is
--     written exactly once (a second decision or second apply rejects);
--   * single use by rule: one approval authorizes one mutation exactly
--     once — the applied→applied second apply is a VISIBLE conflict
--     refusal (approval_already_applied), never silent absorption;
--   * DELETE forbidden on every row; audit rows append-only (INSERT only).
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. The approval object
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS chapter5_approvals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    -- composite-FK target for consumers stamping approval provenance (022):
    -- (tenant_id, id) is UNIQUE so an approval can be referenced from any
    -- tenant-scoped consumer table
    subject_type        TEXT NOT NULL CHECK (length(btrim(subject_type)) > 0),
    -- opaque to the primitive: the consumer's subject identity exactly as
    -- proposed (consumers own interpretation and validation)
    subject_id          TEXT NOT NULL,
    -- the exact subject state the proposal was made against (opaque version
    -- token owned by the consumer; the primitive only requires non-empty)
    subject_version     TEXT NOT NULL,
    -- IMMUTABLE payload binding: the hash of the proposed mutation payload
    -- (canonical JSON, service-computed) — the payload itself is NOT stored
    -- here; consumers keep it on their own subject rows/tables and the
    -- apply handler re-derives it for verification.
    payload_hash        TEXT NOT NULL,
    proposer_id         TEXT NOT NULL,
    proposer_role       TEXT NOT NULL,
    proposed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    state               TEXT NOT NULL DEFAULT 'pending'
                        CHECK (state IN ('pending', 'approved', 'rejected',
                                         'cancelled', 'expired', 'applied')),
    approver_id         TEXT,
    approver_role       TEXT,
    decided_at          TIMESTAMPTZ,
    applied_by          TEXT,
    applied_at          TIMESTAMPTZ,
    CONSTRAINT ck_chapter5_approvals_pending_shape CHECK (
        (state <> 'pending')
        OR (approver_id IS NULL AND approver_role IS NULL AND decided_at IS NULL
            AND applied_by IS NULL AND applied_at IS NULL)
    ),
    CONSTRAINT ck_chapter5_approvals_decided_shape CHECK (
        (state NOT IN ('approved', 'rejected', 'cancelled', 'expired', 'applied'))
        OR (approver_id IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT ck_chapter5_approvals_applied_shape CHECK (
        (state <> 'applied')
        OR (applied_by IS NOT NULL AND applied_at IS NOT NULL)
    )
);

-- At most one non-terminal approval per (tenant, subject_type, subject_id):
-- a new proposal for the same subject must first resolve the standing one
-- (decide/expire). Applied/rejected/cancelled/expired history stays.
CREATE UNIQUE INDEX IF NOT EXISTS uq_chapter5_approvals_open_per_subject
    ON chapter5_approvals (tenant_id, subject_type, subject_id)
    WHERE state IN ('pending', 'approved');

CREATE INDEX IF NOT EXISTS idx_chapter5_approvals_subject
    ON chapter5_approvals (tenant_id, subject_type, subject_id, proposed_at DESC);

-- Composite-FK target (consumers bind approval provenance + tenant atomically)
CREATE UNIQUE INDEX IF NOT EXISTS uq_chapter5_approvals_tenant_id
    ON chapter5_approvals (tenant_id, id);

-- ---------------------------------------------------------------------------
-- 2. Transition pinning + dual control (BEFORE UPDATE; DELETE forbidden)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION chapter5_approval_lifecycle() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'chapter5_approvals are append-history (DELETE forbidden for % approval)', OLD.state;
    END IF;

    -- Immutable proposal binding: payload hash and subject-version snapshot
    -- can never change after proposal.
    IF NEW.payload_hash    IS NOT DISTINCT FROM OLD.payload_hash
       AND NEW.subject_version IS NOT DISTINCT FROM OLD.subject_version
       AND NEW.subject_id     IS NOT DISTINCT FROM OLD.subject_id
       AND NEW.subject_type   IS NOT DISTINCT FROM OLD.subject_type
       AND NEW.tenant_id      IS NOT DISTINCT FROM OLD.tenant_id
       AND NEW.proposer_id    IS NOT DISTINCT FROM OLD.proposer_id
       AND NEW.proposer_role  IS NOT DISTINCT FROM OLD.proposer_role
       AND NEW.proposed_at    IS NOT DISTINCT FROM OLD.proposed_at
    THEN
        NULL; -- proposal metadata unchanged; the transition may proceed
    ELSE
        RAISE EXCEPTION
            'chapter5_approvals proposal binding is immutable (payload hash, subject version, proposer)';
    END IF;

    -- decided metadata: written exactly once, never altered afterwards
    IF NEW.decided_at    IS NOT DISTINCT FROM OLD.decided_at
       AND NEW.approver_id  IS NOT DISTINCT FROM OLD.approver_id
       AND NEW.approver_role IS NOT DISTINCT FROM OLD.approver_role
    THEN
        NULL;
    ELSE
        IF OLD.decided_at IS NOT NULL THEN
            RAISE EXCEPTION 'chapter5_approvals decision metadata is already written (approval %)', OLD.id;
        END IF;
    END IF;

    -- applied metadata: written exactly once, never altered afterwards
    IF NEW.applied_at IS DISTINCT FROM OLD.applied_at
       OR NEW.applied_by IS DISTINCT FROM OLD.applied_by THEN
        IF OLD.applied_at IS NOT NULL THEN
            RAISE EXCEPTION 'chapter5_approvals apply metadata is already written (approval %)', OLD.id;
        END IF;
    END IF;

    -- ---- legal edges -------------------------------------------------------
    IF OLD.state = 'pending' AND NEW.state IN ('approved', 'rejected', 'cancelled', 'expired') THEN
        -- HARD dual control at the DB layer: the approver can never be the
        -- proposer, regardless of consumer discipline.
        IF NEW.approver_id = OLD.proposer_id THEN
            RAISE EXCEPTION
                'chapter5 dual control violated: approver % equals proposer % (approval %)',
                NEW.approver_id, OLD.proposer_id, OLD.id;
        END IF;
        -- rejected/cancelled/expired carry no apply metadata
        IF NEW.state IN ('rejected', 'cancelled', 'expired')
           AND (NEW.applied_by IS NOT NULL OR NEW.applied_at IS NOT NULL) THEN
            RAISE EXCEPTION 'only an approved approval can transition to applied';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'approved' AND NEW.state = 'applied' THEN
        IF NEW.applied_by IS NULL OR NEW.applied_at IS NULL THEN
            RAISE EXCEPTION 'applying requires applied_by and applied_at';
        END IF;
        RETURN NEW;
    END IF;

    -- second apply / any other mutation: a VISIBLE conflict refusal
    IF OLD.state = 'applied' AND NEW.state = 'applied' THEN
        RAISE EXCEPTION
            'approval % was already applied (single-use by rule; second apply refused)', OLD.id;
    END IF;

    RAISE EXCEPTION
        'chapter5_approvals illegal state transition % -> % (approval %)', OLD.state, NEW.state, OLD.id;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_chapter5_approval_lifecycle ON chapter5_approvals;
CREATE TRIGGER trg_chapter5_approval_lifecycle
    BEFORE UPDATE OR DELETE ON chapter5_approvals
    FOR EACH ROW EXECUTE FUNCTION chapter5_approval_lifecycle();

-- ---------------------------------------------------------------------------
-- 3. Append-only audit trail for approval transitions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS chapter5_approval_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    approval_id     UUID NOT NULL REFERENCES chapter5_approvals(id) ON DELETE RESTRICT,
    action          TEXT NOT NULL CHECK (action IN ('proposed', 'approved', 'rejected',
                                                    'cancelled', 'expired', 'applied')),
    actor_id        TEXT NOT NULL,
    actor_role      TEXT NOT NULL,
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION chapter5_approval_audit_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'chapter5_approval_audit is append-only (UPDATE forbidden)';
    END IF;
    RAISE EXCEPTION 'chapter5_approval_audit is append-only (DELETE forbidden)';
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_chapter5_approval_audit_append_only ON chapter5_approval_audit;
CREATE TRIGGER trg_chapter5_approval_audit_append_only
    BEFORE UPDATE OR DELETE ON chapter5_approval_audit
    FOR EACH ROW EXECUTE FUNCTION chapter5_approval_audit_append_only();

CREATE INDEX IF NOT EXISTS idx_chapter5_approval_audit_approval
    ON chapter5_approval_audit (tenant_id, approval_id, occurred_at);
