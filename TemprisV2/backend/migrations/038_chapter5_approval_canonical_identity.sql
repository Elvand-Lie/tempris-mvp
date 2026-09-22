-- Migration 038: Chapter 5 dual control on CANONICAL user identity.
--
-- Replaces ONLY the chapter5_approval_lifecycle() trigger function of
-- migration 021 (which migration 021 is already applied in production and is
-- never edited). Everything else in 021 stands: table shape, lifecycle
-- edges, immutability, apply-once, audit append-only.
--
-- Defect (proven live): the 021 trigger compared NEW.approver_id =
-- OLD.proposer_id as RAW STRINGS. Login mints sub = user UUID while legacy/
-- test tokens carry email subjects, so the same human could approve their
-- own proposal by presenting the other token shape (email-sub approver vs
-- UUID-sub proposer, or the reverse).
--
-- Fix: both actor ids are resolved to users.id exactly the way login
-- resolves a token subject (user UUID or email) and dual control compares
-- those canonical UUIDs. Raw equality is still refused first, so actor ids
-- that resolve to no user row (service-actor strings) keep the historical
-- protection. Two different humans — under any mix of token shapes — still
-- pass.

CREATE OR REPLACE FUNCTION chapter5_approval_lifecycle() RETURNS trigger AS $$
DECLARE
    v_approver_user_id UUID;
    v_proposer_user_id UUID;
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
        -- proposer, regardless of consumer discipline. Raw equality first
        -- (actor ids that are not user identities), then the canonical
        -- identity compare.
        IF NEW.approver_id = OLD.proposer_id THEN
            RAISE EXCEPTION
                'chapter5 dual control violated: approver % equals proposer % (approval %)',
                NEW.approver_id, OLD.proposer_id, OLD.id;
        END IF;
        SELECT u.id INTO v_approver_user_id
        FROM users u
        WHERE u.id::text = NEW.approver_id
           OR LOWER(u.email) = LOWER(NEW.approver_id)
        ORDER BY (u.id::text = NEW.approver_id) DESC, u.id
        LIMIT 1;
        SELECT u.id INTO v_proposer_user_id
        FROM users u
        WHERE u.id::text = OLD.proposer_id
           OR LOWER(u.email) = LOWER(OLD.proposer_id)
        ORDER BY (u.id::text = OLD.proposer_id) DESC, u.id
        LIMIT 1;
        IF v_approver_user_id IS NOT NULL AND v_proposer_user_id IS NOT NULL
           AND v_approver_user_id = v_proposer_user_id THEN
            RAISE EXCEPTION
                'chapter5 dual control violated (canonical identity): approver % and proposer % are user % (approval %)',
                NEW.approver_id, OLD.proposer_id, v_proposer_user_id, OLD.id;
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
