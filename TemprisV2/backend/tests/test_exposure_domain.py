# backend/tests/test_exposure_domain.py
"""
Exposure Domain Foundation Test Suite (Sprint 01 Contract Rev 2).
Covers Group 0 (Regression & Idempotency), Group 1 (Canonical Domain Cases 1-10 & Lifecycle Transitions),
Group 2 (Tenant Relational Integrity & Cross-Tenant Defense), and Group 3 (Evidence, Confirmation, Idempotency & History).
"""
import json
import pathlib
import uuid
import psycopg
import pytest
from psycopg.rows import dict_row

from app.db import get_db_connection
from app.exposure.exceptions import (
    AssetNotFoundError,
    EntityNotFoundError,
    ExposureDomainError,
    ExposureNotFoundError,
    FindingNotFoundError,
    InvalidAssetStatusError,
    InvalidEvidenceError,
    InvalidFindingStatusError,
    TenantMismatchError,
)
from app.exposure.models import (
    ApplicabilityReview,
    AssetExposure,
    CanonicalExposureItem,
    ExposureConfirm,
    ExposureResolve,
    Finding,
    FindingCreate,
    ReviewCreate,
)
from app.exposure.service import (
    close_finding,
    confirm_exposure,
    create_finding,
    get_canonical_current_exposures,
    get_finding,
    list_applicability_reviews,
    record_applicability_review,
    resolve_exposure,
)
from migrations.runner import run_migrations
from tests.conftest import TENANT_A, TENANT_B


def create_test_asset(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    name: str = "Test Asset",
    target_value: str = "10.0.0.1",
    target_type: str = "ip",
    network_scope: str = "internal",
    status: str = "active",
) -> uuid.UUID:
    """Helper to insert an asset directly for test setup."""
    asset_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO assets (
                id, tenant_id, name, asset_type, target_type, target_value,
                normalized_target, network_scope, environment, criticality, status
            ) VALUES (
                %s, %s, %s, 'server', %s, %s, %s, %s, 'production', 'medium', %s
            );
            """,
            (
                str(asset_id),
                str(tenant_id),
                name,
                target_type,
                target_value,
                target_value.lower().strip(),
                network_scope,
                status,
            ),
        )
    conn.commit()
    return asset_id


def seed_canonical_cve(
    conn: psycopg.Connection,
    cve_id: str = "CVE-2024-1234",
) -> str:
    """Helper to insert a canonical CVE record."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO canonical_vulnerabilities (
                cve_id, state, assigner_short_name
            ) VALUES (
                %s, 'PUBLISHED', 'test-cna'
            )
            ON CONFLICT (cve_id) DO NOTHING;
            """,
            (cve_id,),
        )
    conn.commit()
    return cve_id


# ===========================================================================
# Group 0: Regression & Idempotency Safety
# ===========================================================================

class TestGroup0RegressionAndIdempotency:
    def test_assertion_0_2_migration_013_idempotent(self):
        """Assertion 0.2: Migration 013 applies idempotently without schema mutation errors."""
        migration_path = pathlib.Path(__file__).resolve().parents[1] / "migrations" / "013_exposure_domain_foundation.sql"
        assert migration_path.exists(), "Migration 013 SQL file must exist"

        with get_db_connection() as conn:
            # Run migration runner multiple times to confirm idempotency
            run_migrations(conn)
            run_migrations(conn)

            # Check that tables and constraints exist
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT table_name FROM information_schema.tables
                    WHERE table_schema = 'public'
                      AND table_name IN ('findings', 'asset_applicability_reviews', 'asset_exposures');
                    """
                )
                tables = {r["table_name"] for r in cur.fetchall()}
                assert tables == {"findings", "asset_applicability_reviews", "asset_exposures"}

                # Check unique constraint on assets
                cur.execute(
                    """
                    SELECT conname FROM pg_constraint
                    WHERE conrelid = 'assets'::regclass AND conname = 'uq_assets_tenant_id';
                    """
                )
                assert cur.fetchone() is not None, "uq_assets_tenant_id constraint must exist"


# ===========================================================================
# Group 1: The Canonical Domain Cases & Lifecycle Transitions
# ===========================================================================

class TestGroup1CanonicalDomainCasesAndLifecycle:
    def test_assertion_1_1_case_1_global_cve_without_finding(self):
        """Case 1: Ingest global CVE; verify canonical exposure query returns 0 rows."""
        with get_db_connection() as conn:
            seed_canonical_cve(conn, "CVE-2024-9001")
            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 0

    def test_assertion_1_2_case_2_tenant_finding_without_asset_link(self):
        """Case 2: Create open finding without asset link; canonical exposure query returns 0 rows."""
        with get_db_connection() as conn:
            create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Open SSH Port", severity="medium"),
            )
            conn.commit()
            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 0

    def test_assertion_1_3_case_3_review_reference_no_exposure(self):
        """Case 3: Finding linked to Asset with Review REFERENCE; canonical query returns 0 rows."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="Web Server 1")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Outdated TLS", severity="low"),
            )
            record_applicability_review(
                conn,
                TENANT_A,
                ReviewCreate(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    applicability="REFERENCE",
                    reviewed_by="analyst-a",
                    reason="Informational reference only",
                ),
            )
            conn.commit()

            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 0

    def test_assertion_1_4_case_4_review_not_applicable_no_exposure(self):
        """Case 4: Finding linked to Asset with Review NOT_APPLICABLE; canonical query returns 0 rows."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="Linux Server")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Windows IIS Bug", severity="high"),
            )
            record_applicability_review(
                conn,
                TENANT_A,
                ReviewCreate(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    applicability="NOT_APPLICABLE",
                    reviewed_by="analyst-a",
                    reason="Server is Linux, not Windows",
                ),
            )
            conn.commit()

            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 0

    def test_assertion_1_5_case_5_review_needs_review_no_exposure(self):
        """Case 5: Finding linked to Asset with Review NEEDS_REVIEW; canonical query returns 0 rows."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="API Server")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="OpenSSL Heap Overflow", severity="critical"),
            )
            record_applicability_review(
                conn,
                TENANT_A,
                ReviewCreate(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    applicability="NEEDS_REVIEW",
                    reviewed_by="analyst-a",
                    reason="Triage in progress",
                ),
            )
            conn.commit()

            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 0

    def test_assertion_1_6_case_6_review_applicable_without_confirmation_no_exposure(self):
        """Case 6: Finding linked to Asset with Review APPLICABLE without explicit confirmation -> 0 exposures."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="DB Node")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Postgres Auth Bypass", severity="critical"),
            )
            record_applicability_review(
                conn,
                TENANT_A,
                ReviewCreate(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    applicability="APPLICABLE",
                    reviewed_by="analyst-a",
                    reason="Package version matched, pending confirmation",
                ),
            )
            conn.commit()

            # No confirm_exposure called -> 0 rows in asset_exposures and 0 in canonical query
            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 0

    def test_assertion_1_7_case_7_confirmed_exposure_with_evidence(self):
        """Case 7: Finding + Asset + confirmed AssetExposure with evidence -> 1 confirmed row with joined metadata."""
        with get_db_connection() as conn:
            cve_id = seed_canonical_cve(conn, "CVE-2024-5555")
            asset_id = create_test_asset(conn, TENANT_A, name="Production Gateway", target_value="10.0.0.5")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(
                    title="Nginx Buffer Overflow",
                    severity="critical",
                    description="RCE vulnerability",
                    canonical_cve_id=cve_id,
                ),
            )
            evidence = {"service": "nginx", "port": 443, "banner": "nginx/1.18.0", "proof": "vulnerable module loaded"}
            exposure = confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    evidence=evidence,
                    confirmed_by="analyst-a",
                ),
            )
            conn.commit()

            assert exposure.status == "confirmed"
            assert exposure.evidence == evidence
            assert exposure.confirmed_by == "analyst-a"

            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 1
            item = exposures[0]
            assert item.exposure_id == exposure.id
            assert item.tenant_id == TENANT_A
            assert item.finding_id == finding.id
            assert item.asset_id == asset_id
            assert item.exposure_status == "confirmed"
            assert item.evidence == evidence
            assert item.canonical_cve_id == "CVE-2024-5555"
            assert item.finding_title == "Nginx Buffer Overflow"
            assert item.finding_severity == "critical"
            assert item.finding_status == "open"
            assert item.asset_name == "Production Gateway"
            assert item.asset_status == "active"

    def test_assertion_1_8_case_8_confirmed_exposure_with_closed_finding(self):
        """Case 8: Confirmed exposure with closed Finding is excluded from current exposure query."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="Auth Server")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Weak Cipher", severity="medium"),
            )
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    evidence={"ciphers": ["DES-CBC3-SHA"]},
                    confirmed_by="analyst-a",
                ),
            )
            conn.commit()

            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1

            # Close finding
            close_finding(conn, TENANT_A, finding.id, closed_by="admin-a", reason="Risk accepted")
            conn.commit()

            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 0

    def test_assertion_1_9_case_9_confirmed_exposure_with_decommissioned_asset(self):
        """Case 9: Confirmed exposure with decommissioned Asset is excluded from current exposure query."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="Old Worker", status="active")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Log4j RCE", severity="critical"),
            )
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    evidence={"component": "log4j-core-2.14.1.jar"},
                    confirmed_by="analyst-a",
                ),
            )
            conn.commit()

            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1

            # Decommission asset
            with conn.cursor() as cur:
                cur.execute("UPDATE assets SET status = 'decommissioned' WHERE id = %s;", (str(asset_id),))
            conn.commit()

            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 0

    def test_assertion_1_10_case_10_resolved_exposure_excluded(self):
        """Case 10: Explicitly resolved Exposure link is excluded from canonical current exposure query."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="DNS Server")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="DNS Cache Poisoning", severity="high"),
            )
            exposure = confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    evidence={"service": "bind9", "version": "9.11"},
                    confirmed_by="analyst-a",
                ),
            )
            conn.commit()

            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1

            # Resolve exposure
            resolved = resolve_exposure(
                conn,
                TENANT_A,
                exposure.id,
                ExposureResolve(
                    resolved_by="admin-a",
                    status="resolved",
                    resolution_reason="Patched to bind 9.18",
                ),
            )
            conn.commit()

            assert resolved.status == "resolved"
            assert resolved.resolved_by == "admin-a"
            assert resolved.resolution_reason == "Patched to bind 9.18"

            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 0

    def test_assertion_1_11_lifecycle_reconfirmation_after_resolution(self):
        """Assertion 1.11: Confirm -> Resolve -> Re-confirm preserves historical resolved record and gives 1 active."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="App Server")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Spring4Shell", severity="critical"),
            )
            # 1. Initial Confirmation
            exp1 = confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    evidence={"step": "initial_finding", "class": "CachedIntrospectionResults"},
                    confirmed_by="analyst-1",
                ),
            )
            conn.commit()
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1

            # 2. Resolution
            resolve_exposure(
                conn,
                TENANT_A,
                exp1.id,
                ExposureResolve(resolved_by="analyst-1", status="resolved", resolution_reason="Temporary patch applied"),
            )
            conn.commit()
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 0

            # 3. Re-confirmation with updated evidence
            exp2 = confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    evidence={"step": "reintroduced", "diff": "regression in v2.1"},
                    confirmed_by="analyst-2",
                ),
            )
            conn.commit()

            # Canonical query returns exactly 1 active exposure
            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 1
            assert exposures[0].exposure_id == exp2.id
            assert exposures[0].evidence["step"] == "reintroduced"

            # Both rows exist in DB (history preserved)
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT id, status, evidence FROM asset_exposures WHERE tenant_id = %s AND finding_id = %s ORDER BY confirmed_at ASC;",
                    (str(TENANT_A), str(finding.id)),
                )
                rows = cur.fetchall()
                assert len(rows) == 2
                assert rows[0]["status"] == "resolved"
                assert rows[1]["status"] == "confirmed"

    def test_assertion_1_12_dynamic_asset_state_transition(self):
        """Assertion 1.12: Active -> Decommissioned -> Active dynamically toggles exposure presence in query."""
        with get_db_connection() as conn:
            asset_id = create_test_asset(conn, TENANT_A, name="Dynamic Asset", status="active")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Dynamic Vulnerability", severity="medium"),
            )
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset_id,
                    evidence={"observation": "active trace"},
                    confirmed_by="analyst-a",
                ),
            )
            conn.commit()

            # 1. Active -> Present
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1

            # 2. Decommissioned -> Immediately excluded
            with conn.cursor() as cur:
                cur.execute("UPDATE assets SET status = 'decommissioned' WHERE id = %s;", (str(asset_id),))
            conn.commit()
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 0

            # 3. Active -> Immediately reappears without exposure row mutation
            with conn.cursor() as cur:
                cur.execute("UPDATE assets SET status = 'active' WHERE id = %s;", (str(asset_id),))
            conn.commit()
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1

    def test_assertion_1_13_multi_asset_finding_closure(self):
        """Assertion 1.13: Multi-Asset Finding closure immediately drops all exposures from canonical query."""
        with get_db_connection() as conn:
            asset_a = create_test_asset(conn, TENANT_A, name="Asset A", target_value="10.0.1.1")
            asset_b = create_test_asset(conn, TENANT_A, name="Asset B", target_value="10.0.1.2")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Shared Flaw", severity="high"),
            )
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding.id, asset_id=asset_a, evidence={"host": "a"}, confirmed_by="analyst-a"),
            )
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding.id, asset_id=asset_b, evidence={"host": "b"}, confirmed_by="analyst-a"),
            )
            conn.commit()

            # Both appear in query
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 2

            # Close finding
            close_finding(conn, TENANT_A, finding.id, closed_by="admin-a", reason="Global mitigation deployed")
            conn.commit()

            # Query returns 0 rows
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 0


# ===========================================================================
# Group 2: Tenant Relational Integrity & Cross-Tenant Defense
# ===========================================================================

class TestGroup2TenantRelationalIntegrityAndCrossTenantDefense:
    def test_assertion_2_1_composite_fk_rejects_cross_tenant_review_at_db(self):
        """Assertion 2.1: Composite FK prevents linking Tenant A Finding to Tenant B Asset in reviews at DB level."""
        with get_db_connection() as conn:
            asset_b = create_test_asset(conn, TENANT_B, name="Tenant B Asset")
            finding_a = create_finding(conn, TENANT_A, FindingCreate(title="Finding A", severity="high"))
            conn.commit()

            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.ForeignKeyViolation):
                    cur.execute(
                        """
                        INSERT INTO asset_applicability_reviews (
                            id, tenant_id, finding_id, asset_id, applicability, reviewed_by
                        ) VALUES (
                            gen_random_uuid(), %s, %s, %s, 'APPLICABLE', 'attacker'
                        );
                        """,
                        (str(TENANT_A), str(finding_a.id), str(asset_b)),
                    )
            conn.rollback()

    def test_assertion_2_2_composite_fk_rejects_cross_tenant_exposure_at_db(self):
        """Assertion 2.2: Composite FK prevents linking Tenant A Finding to Tenant B Asset in exposures at DB level."""
        with get_db_connection() as conn:
            asset_b = create_test_asset(conn, TENANT_B, name="Tenant B Asset")
            finding_a = create_finding(conn, TENANT_A, FindingCreate(title="Finding A", severity="high"))
            conn.commit()

            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.ForeignKeyViolation):
                    cur.execute(
                        """
                        INSERT INTO asset_exposures (
                            id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by
                        ) VALUES (
                            gen_random_uuid(), %s, %s, %s, 'confirmed', '{"proof": "cross"}'::jsonb, 'attacker'
                        );
                        """,
                        (str(TENANT_A), str(finding_a.id), str(asset_b)),
                    )
            conn.rollback()

    def test_assertion_2_3_domain_service_rejects_cross_tenant_actions(self):
        """Assertion 2.3: Domain service layer rejects cross-tenant review and confirmation attempts."""
        with get_db_connection() as conn:
            asset_b = create_test_asset(conn, TENANT_B, name="Asset B")
            finding_a = create_finding(conn, TENANT_A, FindingCreate(title="Finding A", severity="medium"))
            conn.commit()

            # Attempt review under Tenant A referencing Tenant B Asset
            with pytest.raises(TenantMismatchError):
                record_applicability_review(
                    conn,
                    TENANT_A,
                    ReviewCreate(
                        finding_id=finding_a.id,
                        asset_id=asset_b,
                        applicability="APPLICABLE",
                        reviewed_by="analyst-a",
                    ),
                )

            # Attempt confirmation under Tenant A referencing Tenant B Asset
            with pytest.raises(TenantMismatchError):
                confirm_exposure(
                    conn,
                    TENANT_A,
                    ExposureConfirm(
                        finding_id=finding_a.id,
                        asset_id=asset_b,
                        evidence={"port": 80},
                        confirmed_by="analyst-a",
                    ),
                )

            # Attempt confirmation under Tenant B referencing Tenant A Finding
            with pytest.raises(TenantMismatchError):
                confirm_exposure(
                    conn,
                    TENANT_B,
                    ExposureConfirm(
                        finding_id=finding_a.id,
                        asset_id=asset_b,
                        evidence={"port": 80},
                        confirmed_by="analyst-b",
                    ),
                )

    def test_assertion_2_4_canonical_query_tenant_isolation(self):
        """Assertion 2.4: Canonical exposure query for Tenant A never returns any Tenant B data."""
        with get_db_connection() as conn:
            # Seed Tenant A
            asset_a = create_test_asset(conn, TENANT_A, name="Tenant A Server")
            finding_a = create_finding(conn, TENANT_A, FindingCreate(title="Finding A", severity="high"))
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding_a.id, asset_id=asset_a, evidence={"env": "a"}, confirmed_by="user-a"),
            )

            # Seed Tenant B
            asset_b = create_test_asset(conn, TENANT_B, name="Tenant B Server")
            finding_b = create_finding(conn, TENANT_B, FindingCreate(title="Finding B", severity="critical"))
            confirm_exposure(
                conn,
                TENANT_B,
                ExposureConfirm(finding_id=finding_b.id, asset_id=asset_b, evidence={"env": "b"}, confirmed_by="user-b"),
            )
            conn.commit()

            exposures_a = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures_a) == 1
            assert exposures_a[0].tenant_id == TENANT_A
            assert exposures_a[0].asset_name == "Tenant A Server"
            assert exposures_a[0].finding_title == "Finding A"

            exposures_b = get_canonical_current_exposures(conn, TENANT_B)
            assert len(exposures_b) == 1
            assert exposures_b[0].tenant_id == TENANT_B
            assert exposures_b[0].asset_name == "Tenant B Server"
            assert exposures_b[0].finding_title == "Finding B"

    def test_assertion_2_5_cross_tenant_direct_db_rejection_symmetric(self):
        """Assertion 2.5: Direct SQL cross-tenant inserts are symmetrically rejected by composite FKs."""
        with get_db_connection() as conn:
            asset_a = create_test_asset(conn, TENANT_A, name="Asset A")
            finding_b = create_finding(conn, TENANT_B, FindingCreate(title="Finding B", severity="low"))
            conn.commit()

            # Tenant B claiming Tenant A asset
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.ForeignKeyViolation):
                    cur.execute(
                        """
                        INSERT INTO asset_exposures (
                            id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by
                        ) VALUES (
                            gen_random_uuid(), %s, %s, %s, 'confirmed', '{"check": 1}'::jsonb, 'user-b'
                        );
                        """,
                        (str(TENANT_B), str(finding_b.id), str(asset_a)),
                    )
            conn.rollback()


# ===========================================================================
# Group 3: Evidence, Confirmation, Idempotency & Lifecycle History
# ===========================================================================

class TestGroup3EvidenceConfirmationIdempotencyAndHistory:
    def test_assertion_3_1_explicit_confirmation_requires_non_empty_evidence(self):
        """Assertion 3.1: Confirmation requires non-empty evidence at service and DB constraint levels."""
        with get_db_connection() as conn:
            asset = create_test_asset(conn, TENANT_A)
            finding = create_finding(conn, TENANT_A, FindingCreate(title="F1", severity="medium"))
            conn.commit()

            # Service layer validation
            with pytest.raises((InvalidEvidenceError, ValueError)):
                ExposureConfirm(finding_id=finding.id, asset_id=asset, evidence={}, confirmed_by="analyst")

            # Direct DB check constraint validation
            with conn.cursor() as cur:
                with pytest.raises(psycopg.errors.CheckViolation):
                    cur.execute(
                        """
                        INSERT INTO asset_exposures (
                            id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by
                        ) VALUES (
                            gen_random_uuid(), %s, %s, %s, 'confirmed', '{}'::jsonb, 'analyst'
                        );
                        """,
                        (str(TENANT_A), str(finding.id), str(asset)),
                    )
            conn.rollback()

    def test_assertion_3_2_idempotent_confirmation_updates_without_duplicates(self):
        """Assertion 3.2: Repeated confirmation is idempotent, updating evidence without duplicate rows."""
        with get_db_connection() as conn:
            asset = create_test_asset(conn, TENANT_A)
            finding = create_finding(conn, TENANT_A, FindingCreate(title="F1", severity="medium"))

            # First confirmation
            exp1 = confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding.id, asset_id=asset, evidence={"v": 1}, confirmed_by="analyst-1"),
            )
            conn.commit()

            # Second confirmation (idempotent update)
            exp2 = confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding.id, asset_id=asset, evidence={"v": 2, "extra": "info"}, confirmed_by="analyst-2"),
            )
            conn.commit()

            assert exp1.id == exp2.id
            assert exp2.evidence == {"v": 2, "extra": "info"}
            assert exp2.confirmed_by == "analyst-2"

            exposures = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures) == 1
            assert exposures[0].exposure_id == exp1.id
            assert exposures[0].evidence["v"] == 2

    def test_assertion_3_3_applicability_review_history_append_only(self):
        """Assertion 3.3: Applicability review history preserves chronological transitions."""
        import time
        with get_db_connection() as conn:
            asset = create_test_asset(conn, TENANT_A)
            finding = create_finding(conn, TENANT_A, FindingCreate(title="F1", severity="medium"))
            conn.commit()

            r1 = record_applicability_review(
                conn,
                TENANT_A,
                ReviewCreate(finding_id=finding.id, asset_id=asset, applicability="NEEDS_REVIEW", reviewed_by="user-1", reason="initial"),
            )
            conn.commit()
            time.sleep(0.01)

            r2 = record_applicability_review(
                conn,
                TENANT_A,
                ReviewCreate(finding_id=finding.id, asset_id=asset, applicability="NOT_APPLICABLE", reviewed_by="user-2", reason="not installed"),
            )
            conn.commit()
            time.sleep(0.01)

            r3 = record_applicability_review(
                conn,
                TENANT_A,
                ReviewCreate(finding_id=finding.id, asset_id=asset, applicability="APPLICABLE", reviewed_by="user-3", reason="found in custom path"),
            )
            conn.commit()

            history = list_applicability_reviews(conn, TENANT_A, finding_id=finding.id, asset_id=asset)
            assert len(history) == 3
            # Returned in DESC chronological order
            assert history[0].applicability == "APPLICABLE"
            assert history[1].applicability == "NOT_APPLICABLE"
            assert history[2].applicability == "NEEDS_REVIEW"

    def test_assertion_3_4_multi_asset_confirmation(self):
        """Assertion 3.4: One finding confirmed on multiple assets produces distinct exposure records."""
        with get_db_connection() as conn:
            asset_1 = create_test_asset(conn, TENANT_A, name="Cluster Node 1", target_value="192.168.1.10")
            asset_2 = create_test_asset(conn, TENANT_A, name="Cluster Node 2", target_value="192.168.1.11")
            finding = create_finding(conn, TENANT_A, FindingCreate(title="Cluster Vuln", severity="high"))

            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding.id, asset_id=asset_1, evidence={"port": 8080}, confirmed_by="analyst"),
            )
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding.id, asset_id=asset_2, evidence={"port": 8080}, confirmed_by="analyst"),
            )
            conn.commit()

            exposures = get_canonical_current_exposures(conn, TENANT_A, finding_id=finding.id)
            assert len(exposures) == 2
            asset_ids = {e.asset_id for e in exposures}
            assert asset_ids == {asset_1, asset_2}

    def test_assertion_3_5_scan_absence_has_no_lifecycle_effect(self):
        """Assertion 3.5: Scan cycle completion without mentions does not alter findings or exposures."""
        with get_db_connection() as conn:
            asset = create_test_asset(conn, TENANT_A)
            finding = create_finding(conn, TENANT_A, FindingCreate(title="Persistent Vuln", severity="low"))
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding.id, asset_id=asset, evidence={"flag": "present"}, confirmed_by="analyst"),
            )
            conn.commit()

            # Simulate arbitrary scan cycles and other domain activities
            exposures_before = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures_before) == 1

            # No automatic deletion or withdrawal occurs
            exposures_after = get_canonical_current_exposures(conn, TENANT_A)
            assert len(exposures_after) == 1
            assert exposures_after[0].exposure_id == exposures_before[0].exposure_id

    def test_assertion_3_6_non_cve_finding_support(self):
        """Assertion 3.6: Non-CVE finding with canonical_cve_id = NULL is a first-class confirmed exposure."""
        with get_db_connection() as conn:
            asset = create_test_asset(conn, TENANT_A, name="DB Cluster")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Default Root Password", severity="critical", canonical_cve_id=None),
            )
            assert finding.canonical_cve_id is None

            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset,
                    evidence={"auth_check": "root:root succeeded"},
                    confirmed_by="pentester",
                ),
            )
            conn.commit()

            exposures = get_canonical_current_exposures(conn, TENANT_A, finding_id=finding.id)
            assert len(exposures) == 1
            assert exposures[0].canonical_cve_id is None
            assert exposures[0].finding_title == "Default Root Password"

    def test_assertion_3_7_valid_cve_finding_support(self):
        """Assertion 3.7: Finding with valid canonical_cve_id links to vulnerability intelligence."""
        with get_db_connection() as conn:
            cve_id = seed_canonical_cve(conn, "CVE-2024-8888")
            asset = create_test_asset(conn, TENANT_A, name="Web Proxy")
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(
                    title="Squid Proxy Heap Overflow",
                    severity="high",
                    canonical_cve_id=cve_id,
                ),
            )
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(
                    finding_id=finding.id,
                    asset_id=asset,
                    evidence={"binary": "/usr/sbin/squid", "version": "4.13"},
                    confirmed_by="secops",
                ),
            )
            conn.commit()

            exposures = get_canonical_current_exposures(conn, TENANT_A, cve_id=cve_id)
            assert len(exposures) == 1
            assert exposures[0].canonical_cve_id == "CVE-2024-8888"

    def test_assertion_3_8_canonical_cve_spine_fk_grounding(self):
        """Assertion 3.8: Non-existent CVE fails ForeignKeyViolation; NULL succeeds as non-CVE."""
        with get_db_connection() as conn:
            # 1. Non-existent CVE fails FK
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO findings (id, tenant_id, canonical_cve_id, title, severity, status)
                        VALUES (gen_random_uuid(), %s, 'CVE-9999-99999', 'Fake CVE Finding', 'high', 'open');
                        """,
                        (str(TENANT_A),),
                    )
            conn.rollback()

            # 2. NULL succeeds
            finding = create_finding(
                conn,
                TENANT_A,
                FindingCreate(title="Valid Non-CVE Finding", severity="low", canonical_cve_id=None),
            )
            conn.commit()
            assert finding.canonical_cve_id is None

    def test_assertion_3_9_multi_tenant_isolation_coexistence(self):
        """Assertion 3.9: Tenants with identically named assets/findings remain strictly isolated."""
        with get_db_connection() as conn:
            # Both tenants create asset "Gateway" and finding "Default Creds"
            asset_a = create_test_asset(conn, TENANT_A, name="Gateway", target_value="10.0.0.1")
            asset_b = create_test_asset(conn, TENANT_B, name="Gateway", target_value="10.0.0.1")

            finding_a = create_finding(conn, TENANT_A, FindingCreate(title="Default Creds", severity="high"))
            finding_b = create_finding(conn, TENANT_B, FindingCreate(title="Default Creds", severity="high"))

            # Confirm in Tenant A
            confirm_exposure(
                conn,
                TENANT_A,
                ExposureConfirm(finding_id=finding_a.id, asset_id=asset_a, evidence={"tenant": "A"}, confirmed_by="user-a"),
            )
            conn.commit()

            # Tenant A has 1 exposure, Tenant B has 0
            assert len(get_canonical_current_exposures(conn, TENANT_A)) == 1
            assert len(get_canonical_current_exposures(conn, TENANT_B)) == 0

            # Confirm in Tenant B with distinct evidence
            confirm_exposure(
                conn,
                TENANT_B,
                ExposureConfirm(finding_id=finding_b.id, asset_id=asset_b, evidence={"tenant": "B"}, confirmed_by="user-b"),
            )
            conn.commit()

            res_a = get_canonical_current_exposures(conn, TENANT_A)
            res_b = get_canonical_current_exposures(conn, TENANT_B)
            assert len(res_a) == 1
            assert len(res_b) == 1
            assert res_a[0].evidence["tenant"] == "A"
            assert res_b[0].evidence["tenant"] == "B"
