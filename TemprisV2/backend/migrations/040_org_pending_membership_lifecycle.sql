-- ORG-01: invitation/activation lifecycle for tenant memberships.
--
-- Defect removed by this migration: a tenant invitation created a globally
-- `pending` user together with an `active` tenant membership, so an unusable
-- account was represented as an active, usable membership (and the console /
-- API could not tell "invited, not yet activated" apart from "active member"
-- or "intentionally disabled member").
--
-- Membership status semantics after this migration:
--   * 'pending'  -> the invitation exists, but the account has never been
--                   activated. It grants nothing: authorization requires
--                   users.status='active' AND membership.status='active'
--                   (app/auth.py), and account activation is a Platform
--                   Administrator action only (PRD Ch.5 platform boundary).
--   * 'active'   -> the membership is in force. Usability additionally
--                   requires an active account.
--   * 'disabled' -> the membership is intentionally disabled. Historical
--                   disabled rows may coexist; the single-active-membership
--                   partial unique index (004:48) is unchanged.
--
-- Forward-only; the whole file runs inside one transaction (migrations/runner.py).

-- ---------------------------------------------------------------------------
-- 1. Admit the new 'pending' membership state by replacing migration 004's
--    inline (auto-named) status CHECK with an explicitly named one.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    legacy_check_name text;
BEGIN
    SELECT c.conname INTO legacy_check_name
    FROM pg_constraint c
    WHERE c.conrelid = 'tenant_memberships'::regclass
      AND c.contype = 'c'
      AND pg_get_constraintdef(c.oid) ILIKE '%disabled%'
      AND c.conname <> 'ck_tenant_memberships_status';

    IF legacy_check_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE tenant_memberships DROP CONSTRAINT %I', legacy_check_name);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'tenant_memberships'::regclass
          AND conname = 'ck_tenant_memberships_status'
    ) THEN
        ALTER TABLE tenant_memberships
            ADD CONSTRAINT ck_tenant_memberships_status
            CHECK (status IN ('pending', 'active', 'disabled'));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Legacy backfill: an account that has never been activated must not hold an
--    active membership. Such rows are pending invitations, not active access.
--    (Removing a row from the 004 single-active partial index is always safe.)
-- ---------------------------------------------------------------------------
UPDATE tenant_memberships m
SET status = 'pending',
    updated_at = now()
FROM users u
WHERE u.id = m.user_id
  AND u.status = 'pending'
  AND m.status = 'active';

-- ---------------------------------------------------------------------------
-- 3. At most one pending invitation per user: Platform activation then has
--    exactly one membership to activate, and activating it can never collide
--    with a second outstanding invitation.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS uq_memberships_user_pending
    ON tenant_memberships (user_id) WHERE status = 'pending';