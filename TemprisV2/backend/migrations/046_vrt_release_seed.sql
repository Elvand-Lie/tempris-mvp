-- Migration 046: Production VRT release seed (P0-06 §3.6.6 #1 path 1).
--
-- Forward-only. The whole file runs inside one transaction (migrations/runner.py);
-- any failure aborts atomically.
--
-- Seeds the ONE approved, non-test-only sss_derivation_versions row that opens
-- the P0-06 production gate (app/exposure/sss.py::_load_version) for VRT-backed
-- SSS derivation. The pinned release identifier must match
-- app.exposure.sss.PINNED_VRT_RELEASE ('bugcrowd-vrt-1.19.1' — official
-- Bugcrowd vulnerability-rating-taxonomy release v1.19.1, vendored in-repo at
-- app/exposure/data/vrt_bugcrowd_v1_19_1.json). Content stays NULL: per
-- migration 019 the 'vrt_release' kind admits no stored content — the P1–P5 →
-- SSS mapping is the PRD-locked Tempris policy in code, and the taxonomy
-- itself is the vendored release content in code, version-matched to this row.
--
-- approved_by is the bootstrap/system actor by design: this row is
-- operator-authorized bootstrap seeding via migration, not a dual-control
-- approval action.
--
-- Idempotent: ON CONFLICT (version_id) DO NOTHING — the row is immutable
-- (migration 019 forward-only trigger), so a re-run never mutates it.

INSERT INTO sss_derivation_versions (version_id, kind, content, status, test_only, approved_by, approved_at)
VALUES ('bugcrowd-vrt-1.19.1', 'vrt_release', NULL, 'approved', FALSE, 'system:bootstrap', now())
ON CONFLICT (version_id) DO NOTHING;
