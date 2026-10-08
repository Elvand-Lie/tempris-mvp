-- 043_asset_identity_state.sql
-- Fail-closed guard for unagented assets (PRD V3 Ch2 open decision #7):
-- when a scan's stable identity evidence (non-randomized MAC) conflicts with
-- the asset's prior stored evidence, the asset's target identity is marked
-- unresolved and further scans are blocked until an operator revalidates.
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS identity_state TEXT NOT NULL DEFAULT 'ok'
    CHECK (identity_state IN ('ok', 'unresolved'));
