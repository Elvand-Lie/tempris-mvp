-- Migration 031: Chapter 9 — STANDARD / GRC, part 1: the governance
-- substrate (PRD-000 v1.11 Ch.9).
--
-- Frameworks/controls are REFERENCE CATALOGS (platform-curated, the 8
-- STANDARD frameworks carry over); control assessments carry the per-tenant
-- assessed status (draft → signed via end_user/PIC dual sign-off →
-- archived); policies carry registry + archive/supersede versioning; control
-- evidence is a typed inline store (V2 has no object store; inline BYTEA is
-- the migration-010 precedent) that may map EDIP remediation evidence BY
-- REFERENCE — mapped, never re-scored.
--
-- THE BOUNDARY IS STRUCTURAL (frozen decision 1): no table below carries any
-- score-bearing column, and no code in this module writes findings,
-- asset_exposures, or any scoring state. V1's GRC modifier chain
-- (AGM/DRF/TEF into SSS) is retired, not ported (§3.6.5, D-3). This is
-- compliance STATE, never scoring input.
--
-- Framework/control default_status from V1 is deliberately NOT carried: an
-- absent assessment cannot truthfully imply compliance — everything is
-- not_assessed until a SIGNED assessment says otherwise.
--
-- grc_exceptions land here with v1 authority = admin+ approval (the
-- dual-control candidate remains an OPEN Ch.9 decision #6); expiry is the
-- same effective-on-read rule EDIP uses — no scheduler exists.
--
-- Forward-only; the whole file runs inside one transaction (runner.py).

-- ---------------------------------------------------------------------------
-- 1. Module catalogue: STANDARD
-- ---------------------------------------------------------------------------

INSERT INTO modules (id, name, description, status, created_at)
VALUES (
    'STANDARD',
    'STANDARD — Governance, Risk & Compliance',
    'Governance substrate and obligations: framework catalogs, control assessments (dual sign-off), policy versioning, control evidence, exceptions, regulatory incidents with rule-evaluated obligations. Never touches technical exposure scoring.',
    'active',
    now()
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO package_modules (package_id, module_id)
VALUES ('CORE_ASSETS', 'STANDARD')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Framework + control reference catalogs (platform-curated; no tenant_id)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_frameworks (
    framework_code  TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS standard_controls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_code  TEXT NOT NULL REFERENCES standard_frameworks(framework_code) ON DELETE RESTRICT,
    control_code    TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_standard_controls_code UNIQUE (framework_code, control_code)
);

-- The 8 V1 STANDARD frameworks carry over as catalogs (Ch.9 verified reality,
-- V1:routers/standard.py:117-188). Control lists are the V1 catalog contents.
INSERT INTO standard_frameworks (framework_code, name, description) VALUES
    ('mas_trm_2024',  'MAS TRM 2024',      'Monetary Authority of Singapore Technology Risk Management Guidelines 2024'),
    ('pdpa',          'PDPA Singapore',    'Personal Data Protection Act (Singapore)'),
    ('iso_27001',     'ISO 27001:2022',    'ISO/IEC 27001:2022 information security management'),
    ('im8a',          'IM8A',              'Instruction Manual 8A (Singapore public agencies IT security)'),
    ('nist_csf',      'NIST CSF 2.0',      'NIST Cybersecurity Framework 2.0'),
    ('soc2',          'SOC 2 Type II',     'AICPA SOC 2 Type II trust services criteria'),
    ('pci_dss',       'PCI DSS v4.0',      'PCI DSS v4.0 payment card industry standard'),
    ('csa_cybertrust','CSA Cyber Trust',   'CSA Cyber Trust mark (Singapore)')
ON CONFLICT (framework_code) DO NOTHING;

INSERT INTO standard_controls (framework_code, control_code, title, description) VALUES
    ('mas_trm_2024', 'MAS-TRM-5.1.1',   'IT Security Policies', 'The FI should establish IT security policies approved by the board.'),
    ('mas_trm_2024', 'MAS-TRM-7.4.1',   'Privileged Access Management', 'Privileged system accounts should be subject to enhanced controls.'),
    ('mas_trm_2024', 'MAS-TRM-9.1.1',   'Security Monitoring', 'The FI should implement security monitoring and logging.'),
    ('mas_trm_2024', 'MAS-TRM-11.1.1',  'Timely Patching of Critical Network Devices', 'Security patches must be applied within the timeframe specified.'),
    ('mas_trm_2024', 'MAS-TRM-11.2.3',  'Vulnerability Scanning', 'Regular vulnerability scanning must be conducted.'),
    ('mas_trm_2024', 'MAS-TRM-12.1.1',  'Incident Response Plan', 'The FI should establish incident management and response procedures.'),
    ('mas_trm_2024', 'MAS-TRM-12.1.5',  '1-Hour Incident Notification', 'Notify MAS within 1 hour of discovering a relevant incident.'),
    ('pdpa',         'PDPA-26',         'Protection Obligation', 'Reasonable security arrangements to protect personal data.'),
    ('pdpa',         'PDPA-24',         'Retention Limitation', 'Cease retaining personal data when no longer necessary.'),
    ('pdpa',         'PDPA-26D',        'Data Breach Notification', 'Notify PDPC within 3 calendar days of assessing a notifiable breach.'),
    ('iso_27001',    'ISO-A.5.1',       'Policies for Information Security', 'Information security policy and topic-specific policies.'),
    ('iso_27001',    'ISO-A.8.8',       'Management of Technical Vulnerabilities', 'Information about technical vulnerabilities shall be obtained.'),
    ('iso_27001',    'ISO-A.8.15',      'Logging', 'Logs that record activities, exceptions, faults shall be produced and stored.'),
    ('iso_27001',    'ISO-A.5.24',      'Incident Management Planning', 'Plan and prepare for managing information security incidents.'),
    ('im8a',         'IM8A-SM-1',       'Security Management', 'Chief Information Security Officer shall be appointed.'),
    ('im8a',         'IM8A-AM-3',       'Patch Management', 'Critical patches must be applied within 2 weeks of release.'),
    ('im8a',         'IM8A-IR-1',       'Incident Reporting', 'Security incidents to be reported within 24 hours.'),
    ('nist_csf',     'NIST-ID.AM-1',    'Asset Inventory', 'Inventories of hardware and software are maintained.'),
    ('nist_csf',     'NIST-PR.PS-1',    'Patch Management', 'Patches are applied in a timely manner.'),
    ('nist_csf',     'NIST-DE.CM-8',    'Vulnerability Scanning', 'Vulnerability scans are performed.'),
    ('nist_csf',     'NIST-RS.AN-5',    'Incident Analysis', 'Incidents are categorized consistent with response plans.'),
    ('soc2',         'SOC2-CC6.1',      'Logical and Physical Access Controls', 'Logical access security over protected information assets.'),
    ('soc2',         'SOC2-CC7.1',      'System Monitoring', 'Detection of configuration changes, vulnerabilities, and incidents.'),
    ('soc2',         'SOC2-CC7.2',      'Incident Response', 'The entity monitors system components for anomalies.'),
    ('pci_dss',      'PCI-6.3.3',       'Vulnerability Patch Management', 'Critical patches installed within one month of release.'),
    ('pci_dss',      'PCI-11.3.1',      'Internal Vulnerability Scans', 'Internal scans performed at least quarterly.'),
    ('pci_dss',      'PCI-12.10.1',     'Incident Response Plan', 'An incident response plan exists and is ready for activation.'),
    ('csa_cybertrust','CT-GOV-1',       'Cyber Governance', 'Organisation has established cyber security governance.'),
    ('csa_cybertrust','CT-PRO-3',       'Vulnerability Management', 'Processes to identify and remediate vulnerabilities.'),
    ('csa_cybertrust','CT-INC-1',       'Incident Management', 'Processes for detecting and responding to incidents.')
ON CONFLICT (framework_code, control_code) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3. Control assessments — the per-tenant assessed status
--    draft → signed (dual sign-off: end_user + PIC, distinct actors) → archived
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_control_assessments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    control_id          UUID NOT NULL REFERENCES standard_controls(id) ON DELETE RESTRICT,
    state               TEXT NOT NULL DEFAULT 'draft'
                        CHECK (state IN ('draft', 'signed', 'archived')),
    -- the assessed status — compliance state only, NEVER a scoring input
    status              TEXT NOT NULL
                        CHECK (status IN ('compliant', 'partial', 'non_compliant')),
    notes               TEXT,
    end_user_signoff_by TEXT,
    end_user_signoff_at TIMESTAMPTZ,
    pic_signoff_by      TEXT,
    pic_signoff_at      TIMESTAMPTZ,
    signed_at           TIMESTAMPTZ,
    archived_at         TIMESTAMPTZ,
    created_by          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_standard_assessments_tenant_id UNIQUE (tenant_id, id),
    -- dual sign-off shape: a SIGNED assessment carries BOTH sign-offs held
    -- by two DIFFERENT actors (the V1 end_user/PIC pattern, made an
    -- invariant). Archived rows may be archived drafts — partial sign-offs
    -- are retained as history without implying completion.
    CONSTRAINT ck_standard_assessment_signed_shape CHECK (
        state <> 'signed'
        OR (end_user_signoff_by IS NOT NULL AND pic_signoff_by IS NOT NULL
            AND end_user_signoff_at IS NOT NULL AND pic_signoff_at IS NOT NULL
            AND signed_at IS NOT NULL
            AND end_user_signoff_by <> pic_signoff_by)
    ),
    CONSTRAINT ck_standard_assessment_archived_shape CHECK (
        (state = 'archived') OR (archived_at IS NULL)
    )
);

-- one LIVE assessment per control (history via archived rows)
CREATE UNIQUE INDEX IF NOT EXISTS uq_standard_assessment_live_per_control
    ON standard_control_assessments (tenant_id, control_id)
    WHERE state <> 'archived';

CREATE INDEX IF NOT EXISTS idx_standard_assessments_state
    ON standard_control_assessments (tenant_id, state);

-- ---------------------------------------------------------------------------
-- 4. Policies — registry + archive/supersede versioning (V1 pattern)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    policy_group_id UUID NOT NULL,
    version         INT NOT NULL DEFAULT 1,
    title           TEXT NOT NULL CHECK (length(btrim(title)) > 0),
    body            TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'draft'
                    CHECK (state IN ('draft', 'active', 'superseded', 'archived')),
    supersedes_id   UUID REFERENCES standard_policies(id),
    superseded_at   TIMESTAMPTZ,
    archived_at     TIMESTAMPTZ,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_standard_policies_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT ck_standard_policy_superseded_shape CHECK (
        (state = 'superseded') OR (superseded_at IS NULL)
    ),
    CONSTRAINT ck_standard_policy_archived_shape CHECK (
        (state = 'archived') OR (archived_at IS NULL)
    )
);

-- one ACTIVE policy per versioning family (partial unique — index, not a
-- table constraint)
CREATE UNIQUE INDEX IF NOT EXISTS uq_standard_policy_active_per_group
    ON standard_policies (tenant_id, policy_group_id)
    WHERE state = 'active';

CREATE INDEX IF NOT EXISTS idx_standard_policies_group
    ON standard_policies (tenant_id, policy_group_id, version DESC);

-- ---------------------------------------------------------------------------
-- 5. Control evidence — typed inline store; EDIP remediation evidence maps
--    BY REFERENCE (edip_verification_id), never re-scored (frozen decision 6)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS standard_control_evidence (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    control_id            UUID NOT NULL REFERENCES standard_controls(id) ON DELETE RESTRICT,
    assessment_id         UUID REFERENCES standard_control_assessments(id),
    -- EDIP mapping by reference (open Ch.9 decision #4 resolved to the
    -- minimal reference shape now that Ch.8 is settled): same-tenant,
    -- existence-checked in the service; never a score, never re-derived.
    edip_verification_id  UUID,
    title                 TEXT NOT NULL CHECK (length(btrim(title)) > 0),
    media_type            TEXT NOT NULL CHECK (media_type IN (
                              'application/pdf', 'text/plain', 'text/csv',
                              'application/json', 'image/png')),
    content               BYTEA NOT NULL,
    size_bytes            INT NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 8 * 1024 * 1024),
    sha256                TEXT NOT NULL CHECK (length(sha256) = 64),
    uploaded_by           TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_standard_evidence_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_standard_evidence_assessment FOREIGN KEY (tenant_id, assessment_id)
        REFERENCES standard_control_assessments(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_standard_evidence_control
    ON standard_control_evidence (tenant_id, control_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 6. Exceptions — requested → approved (admin+ at v1; dual-control candidate
--    remains OPEN, Ch.9 decision #6) → expired/rejected; mandatory expiry,
--    effective-on-read like every derived deadline (no scheduler exists)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS grc_exceptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    control_id      UUID REFERENCES standard_controls(id) ON DELETE RESTRICT,
    title           TEXT NOT NULL CHECK (length(btrim(title)) > 0),
    rationale       TEXT NOT NULL CHECK (length(btrim(rationale)) > 0),
    state           TEXT NOT NULL DEFAULT 'requested'
                    CHECK (state IN ('requested', 'approved', 'rejected', 'expired')),
    expires_at      TIMESTAMPTZ NOT NULL,
    requested_by    TEXT NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    rejected_by     TEXT,
    rejected_at     TIMESTAMPTZ,
    CONSTRAINT uq_grc_exceptions_tenant_id UNIQUE (tenant_id, id),
    -- an expired exception keeps its approval provenance (audit trail);
    -- only non-approved states require the absence of an approval stamp
    CONSTRAINT ck_grc_exception_approved_shape CHECK (
        (state IN ('approved', 'expired'))
        OR (approved_by IS NULL AND approved_at IS NULL)
    ),
    CONSTRAINT ck_grc_exception_rejected_shape CHECK (
        (state = 'rejected') OR (rejected_by IS NULL AND rejected_at IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_grc_exceptions_state
    ON grc_exceptions (tenant_id, state);
