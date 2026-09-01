# backend/app/exposure/service.py
"""
Service layer and repository functions for the Exposure Domain.
Encapsulates domain logic, tenant isolation checks, and the canonical current-exposure query.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Optional
import psycopg
from psycopg.rows import dict_row

from app.exposure.exceptions import (
    AssetNotFoundError,
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


def _serialize_evidence(evidence: Any) -> str:
    if not isinstance(evidence, dict) or len(evidence) == 0:
        raise InvalidEvidenceError("Evidence must be a non-empty dictionary/object")
    return json.dumps(evidence)


def create_finding(conn: psycopg.Connection, tenant_id: uuid.UUID, data: FindingCreate) -> Finding:
    """Create a new tenant finding."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO findings (
                id, tenant_id, canonical_cve_id, title, description, severity, status, created_at, updated_at
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s, %s, 'open', now(), now()
            )
            RETURNING id, tenant_id, canonical_cve_id, title, description, severity, status, created_at, updated_at, closed_at;
            """,
            (
                str(tenant_id),
                data.canonical_cve_id,
                data.title,
                data.description,
                data.severity,
            ),
        )
        row = cur.fetchone()
        return Finding.model_validate(row)


def get_finding(conn: psycopg.Connection, tenant_id: uuid.UUID, finding_id: uuid.UUID) -> Optional[Finding]:
    """Retrieve a finding by ID scoped to tenant."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, tenant_id, canonical_cve_id, title, description, severity, status, created_at, updated_at, closed_at
            FROM findings
            WHERE tenant_id = %s AND id = %s;
            """,
            (str(tenant_id), str(finding_id)),
        )
        row = cur.fetchone()
        if not row:
            return None
        return Finding.model_validate(row)


def close_finding(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: uuid.UUID,
    closed_by: str,
    reason: Optional[str] = None,
) -> Finding:
    """Close an open finding."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE findings
            SET status = 'closed',
                closed_at = now(),
                updated_at = now()
            WHERE tenant_id = %s AND id = %s
            RETURNING id, tenant_id, canonical_cve_id, title, description, severity, status, created_at, updated_at, closed_at;
            """,
            (str(tenant_id), str(finding_id)),
        )
        row = cur.fetchone()
        if row:
            return Finding.model_validate(row)

        # Diagnose why update did not return a row
        cur.execute("SELECT tenant_id FROM findings WHERE id = %s;", (str(finding_id),))
        other = cur.fetchone()
        if other:
            raise TenantMismatchError(
                f"Finding {finding_id} belongs to tenant {other['tenant_id']}, not {tenant_id}"
            )
        raise FindingNotFoundError(f"Finding {finding_id} not found")


def record_applicability_review(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    data: ReviewCreate,
) -> ApplicabilityReview:
    """Record an append-only applicability review decision."""
    with conn.cursor(row_factory=dict_row) as cur:
        # Verify finding exists and belongs to tenant
        cur.execute("SELECT tenant_id FROM findings WHERE id = %s;", (str(data.finding_id),))
        f_row = cur.fetchone()
        if not f_row:
            raise FindingNotFoundError(f"Finding {data.finding_id} not found")
        if str(f_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Finding {data.finding_id} belongs to tenant {f_row['tenant_id']}, not {tenant_id}"
            )

        # Verify asset exists and belongs to tenant
        cur.execute("SELECT tenant_id FROM assets WHERE id = %s;", (str(data.asset_id),))
        a_row = cur.fetchone()
        if not a_row:
            raise AssetNotFoundError(f"Asset {data.asset_id} not found")
        if str(a_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Asset {data.asset_id} belongs to tenant {a_row['tenant_id']}, not {tenant_id}"
            )

        cur.execute(
            """
            INSERT INTO asset_applicability_reviews (
                id, tenant_id, finding_id, asset_id, applicability, reviewed_by, reason, created_at
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s, %s, %s, clock_timestamp()
            )
            RETURNING id, tenant_id, finding_id, asset_id, applicability, reviewed_by, reason, created_at;
            """,
            (
                str(tenant_id),
                str(data.finding_id),
                str(data.asset_id),
                data.applicability,
                data.reviewed_by,
                data.reason,
            ),
        )
        row = cur.fetchone()
        return ApplicabilityReview.model_validate(row)


def list_applicability_reviews(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: Optional[uuid.UUID] = None,
    asset_id: Optional[uuid.UUID] = None,
) -> list[ApplicabilityReview]:
    """List applicability review records for a tenant with optional finding/asset filters."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT id, tenant_id, finding_id, asset_id, applicability, reviewed_by, reason, created_at
            FROM asset_applicability_reviews
            WHERE tenant_id = %s
              AND (%s::uuid IS NULL OR finding_id = %s::uuid)
              AND (%s::uuid IS NULL OR asset_id = %s::uuid)
            ORDER BY created_at DESC, id ASC;
            """,
            (
                str(tenant_id),
                str(finding_id) if finding_id else None,
                str(finding_id) if finding_id else None,
                str(asset_id) if asset_id else None,
                str(asset_id) if asset_id else None,
            ),
        )
        rows = cur.fetchall()
        return [ApplicabilityReview.model_validate(r) for r in rows]


def confirm_exposure(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    data: ExposureConfirm,
) -> AssetExposure:
    """
    Explicitly confirm an exposure with structured evidence.
    Enforces active asset and open finding in same tenant.
    Idempotently updates existing active confirmed record or creates a new one.
    """
    raw_evidence = _serialize_evidence(data.evidence)

    with conn.cursor(row_factory=dict_row) as cur:
        # Check finding
        cur.execute("SELECT tenant_id, status FROM findings WHERE id = %s;", (str(data.finding_id),))
        f_row = cur.fetchone()
        if not f_row:
            raise FindingNotFoundError(f"Finding {data.finding_id} not found")
        if str(f_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Finding {data.finding_id} belongs to tenant {f_row['tenant_id']}, not {tenant_id}"
            )
        if f_row["status"] != "open":
            raise InvalidFindingStatusError(
                f"Finding {data.finding_id} is not open (status={f_row['status']})"
            )

        # Check asset
        cur.execute("SELECT tenant_id, status FROM assets WHERE id = %s;", (str(data.asset_id),))
        a_row = cur.fetchone()
        if not a_row:
            raise AssetNotFoundError(f"Asset {data.asset_id} not found")
        if str(a_row["tenant_id"]) != str(tenant_id):
            raise TenantMismatchError(
                f"Asset {data.asset_id} belongs to tenant {a_row['tenant_id']}, not {tenant_id}"
            )
        if a_row["status"] != "active":
            raise InvalidAssetStatusError(
                f"Asset {data.asset_id} is not active (status={a_row['status']})"
            )

        cur.execute(
            """
            INSERT INTO asset_exposures (
                id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by, confirmed_at
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, 'confirmed', %s::jsonb, %s, now()
            )
            ON CONFLICT (tenant_id, finding_id, asset_id) WHERE status = 'confirmed'
            DO UPDATE SET
                evidence = EXCLUDED.evidence,
                confirmed_by = EXCLUDED.confirmed_by,
                confirmed_at = now(),
                resolved_at = NULL,
                resolved_by = NULL,
                resolution_reason = NULL
            RETURNING id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by, confirmed_at, resolved_at, resolved_by, resolution_reason;
            """,
            (
                str(tenant_id),
                str(data.finding_id),
                str(data.asset_id),
                raw_evidence,
                data.confirmed_by,
            ),
        )
        row = cur.fetchone()
        return AssetExposure.model_validate(row)


def resolve_exposure(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    exposure_id: uuid.UUID,
    data: ExposureResolve,
) -> AssetExposure:
    """Resolve an existing asset exposure."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            UPDATE asset_exposures
            SET status = %s,
                resolved_at = now(),
                resolved_by = %s,
                resolution_reason = %s
            WHERE tenant_id = %s AND id = %s
            RETURNING id, tenant_id, finding_id, asset_id, status, evidence, confirmed_by, confirmed_at, resolved_at, resolved_by, resolution_reason;
            """,
            (
                data.status,
                data.resolved_by,
                data.resolution_reason,
                str(tenant_id),
                str(exposure_id),
            ),
        )
        row = cur.fetchone()
        if row:
            return AssetExposure.model_validate(row)

        cur.execute("SELECT tenant_id FROM asset_exposures WHERE id = %s;", (str(exposure_id),))
        other = cur.fetchone()
        if other:
            raise TenantMismatchError(
                f"Exposure {exposure_id} belongs to tenant {other['tenant_id']}, not {tenant_id}"
            )
        raise ExposureNotFoundError(f"Exposure {exposure_id} not found")


def get_canonical_current_exposures(
    conn: psycopg.Connection,
    tenant_id: uuid.UUID,
    finding_id: Optional[uuid.UUID] = None,
    asset_id: Optional[uuid.UUID] = None,
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
) -> list[CanonicalExposureItem]:
    """
    Execute the single canonical current-exposure query.
    Enforces the 4-way joined status filtering and deterministic ordering:
    ORDER BY e.confirmed_at DESC, e.id ASC.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT
                e.id AS exposure_id,
                e.tenant_id,
                e.finding_id,
                e.asset_id,
                e.status AS exposure_status,
                e.evidence,
                e.confirmed_by,
                e.confirmed_at,
                f.canonical_cve_id,
                f.title AS finding_title,
                f.severity AS finding_severity,
                f.status AS finding_status,
                a.name AS asset_name,
                a.target_type AS asset_target_type,
                a.normalized_target AS asset_normalized_target,
                a.network_scope AS asset_network_scope,
                a.status AS asset_status
            FROM asset_exposures e
            JOIN findings f
              ON e.tenant_id = f.tenant_id AND e.finding_id = f.id
            JOIN assets a
              ON e.tenant_id = a.tenant_id AND e.asset_id = a.id
            WHERE e.tenant_id = %s
              AND e.status = 'confirmed'
              AND f.status = 'open'
              AND a.status = 'active'
              AND (%s::uuid IS NULL OR e.finding_id = %s::uuid)
              AND (%s::uuid IS NULL OR e.asset_id = %s::uuid)
              AND (%s::text IS NULL OR f.canonical_cve_id = %s::text)
              AND (%s::text IS NULL OR f.severity = %s::text)
            ORDER BY e.confirmed_at DESC, e.id ASC;
            """,
            (
                str(tenant_id),
                str(finding_id) if finding_id else None,
                str(finding_id) if finding_id else None,
                str(asset_id) if asset_id else None,
                str(asset_id) if asset_id else None,
                cve_id,
                cve_id,
                severity,
                severity,
            ),
        )
        rows = cur.fetchall()
        return [CanonicalExposureItem.model_validate(r) for r in rows]
