# backend/app/routes/assets.py
import uuid
from datetime import datetime, timezone
from typing import List, Optional
import psycopg
from psycopg.errors import UniqueViolation
from fastapi import APIRouter, Depends, HTTPException, status
from app.auth import AuthContext, get_auth_context, require_roles, require_module
from app.audit import record_audit_event
from app.db import get_db_connection
from app.exposure.exceptions import BoundAssetError
from app.exposure.identity_boundary import assert_asset_not_identity_boundary
from app.exposure.service import supersede_exposures_for_asset
from app.schemas import (
    AssetCreate,
    AssetUpdate,
    AssetResponse,
    ScanAuthorizationRequest,
    ScanAuthorizationApprove,
    ScanAuthorizationRevoke,
    ScanAuthorizationResponse,
    AssetStatsResponse,
)
from app.target_validator import validate_and_normalize_target, TargetValidationError
from app.target_checker import check_target_reachability, TargetCheckRequest, TargetCheckResponse
from app.collector_registry import collector_registry

router = APIRouter(prefix="/api/assets", tags=["Assets"], dependencies=[Depends(require_module("ASSETS"))])

def _collector_scan_capable(collector_id: uuid.UUID) -> bool:
    # Usable scanning route = live session AND the collector reports a working
    # nmap (the base SCOUT engine). Connection state, reachability, and scan
    # authorization are tracked separately and deliberately not folded in here.
    if not collector_registry.is_connected(collector_id):
        return False
    capabilities = collector_registry.get_collector_capabilities(collector_id)
    nmap_cap = capabilities.get("nmap") if isinstance(capabilities, dict) else None
    return bool(isinstance(nmap_cap, dict) and nmap_cap.get("available") is True)

def _validate_collector_routing(conn: psycopg.Connection, tenant_id: uuid.UUID, collector_id: Optional[uuid.UUID]):
    """
    Validates collector route: must exist in same tenant and must not be revoked.
    Returns 404 on non-existence, foreign-tenant ownership, or revoked status to ensure zero existence disclosure.
    """
    if collector_id is None:
        return
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, operator_status FROM collectors
            WHERE id = %s AND tenant_id = %s;
            """,
            (str(collector_id), str(tenant_id))
        )
        row = cur.fetchone()
        if not row or row["operator_status"] == "revoked":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Collector not found"
            )

@router.post(
    "/check-target",
    response_model=TargetCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate and check target reachability"
)
async def check_target(
    request: TargetCheckRequest,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    try:
        if request.network_scope == "internal" and request.collector_id:
            # Step 1: Validate and normalize target syntax/semantics
            norm_res = validate_and_normalize_target(request.target_type, request.target_value)

            # Step 2: Validate collector exists in same tenant and is not revoked (fails 404)
            with get_db_connection() as conn:
                _validate_collector_routing(conn, auth.tenant_id, request.collector_id)

            # Step 3: If collector is connected and active in registry, dispatch verification probe
            reachability_status = "unverified"
            verification_source = None
            message = "Internal collector required for reachability verification."

            if collector_registry.is_connected(request.collector_id):
                corr_id = request.correlation_id or f"pre-check-{uuid.uuid4()}"
                dispatch_res = await collector_registry.dispatch_verify_target(
                    collector_id=request.collector_id,
                    tenant_id=auth.tenant_id,
                    target_type=request.target_type,
                    target_value=request.target_value,
                    normalized_target=norm_res.normalized_target,
                    network_scope="internal",
                    correlation_id=corr_id,
                    asset_id=None,
                    actor_id=auth.actor_id,
                    actor_role=auth.role,
                    timeout_seconds=8.0
                )
                if dispatch_res.get("reachability_status") in ("verified", "unreachable"):
                    reachability_status = dispatch_res["reachability_status"]
                    verification_source = "internal_collector"
                    message = f"Internal target is syntactically valid and {reachability_status} via collector."
                else:
                    reachability_status = "unverified"
                    verification_source = None
                    message = "Internal collector failed to verify reachability; target remains valid."
            else:
                message = "Selected internal collector is offline/paused; target remains valid."

            result = TargetCheckResponse(
                valid=True,
                normalized_target=norm_res.normalized_target,
                address_classification=norm_res.address_classification,
                network_scope="internal",
                reachability_status=reachability_status,
                verification_source=verification_source,
                message=message
            )
        else:
            result = check_target_reachability(
                target_type=request.target_type,
                target_value=request.target_value,
                network_scope=request.network_scope
            )
    except TargetValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )

    # Record audit event without leaking raw data
    with get_db_connection() as conn:
        record_audit_event(
            conn=conn,
            tenant_id=auth.tenant_id,
            actor_id=auth.actor_id,
            actor_role=auth.role,
            event_name="asset.target_checked",
            details={
                "target_type": request.target_type,
                "normalized_target": result.normalized_target,
                "network_scope": request.network_scope,
                "reachability_status": result.reachability_status,
                "address_classification": result.address_classification,
                "collector_id": str(request.collector_id) if request.collector_id else None
            }
        )
        conn.commit()

    return result

@router.get(
    "/stats",
    response_model=AssetStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get tenant asset inventory and scan authorization statistics"
)
def get_asset_stats(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH active_assets AS (
                    SELECT id, target_type, normalized_target, network_scope, reachability_status, verification_source, collector_id
                    FROM assets
                    WHERE tenant_id = %s AND status = 'active'
                )
                SELECT
                    (SELECT COUNT(*) FROM active_assets) AS total_assets,
                    (SELECT COUNT(*) FROM active_assets WHERE reachability_status = 'verified' AND network_scope = 'internet' AND verification_source = 'tempris_cloud') AS reachable_by_scout,
                    (SELECT COUNT(DISTINCT a.id)
                     FROM active_assets a
                     JOIN asset_scan_authorizations auth
                       ON a.id = auth.asset_id
                      AND auth.tenant_id = %s
                      AND auth.status = 'approved'
                      AND auth.expires_at > now()
                      AND auth.target_type = a.target_type
                      AND auth.normalized_target = a.normalized_target
                      AND auth.network_scope = a.network_scope
                    ) AS authorized_to_scan,
                    (SELECT COUNT(DISTINCT a.id)
                     FROM active_assets a
                     JOIN asset_scan_authorizations auth
                       ON a.id = auth.asset_id
                      AND auth.tenant_id = %s
                      AND auth.status = 'pending'
                      AND auth.target_type = a.target_type
                      AND auth.normalized_target = a.normalized_target
                      AND auth.network_scope = a.network_scope
                    ) AS pending_authorization,
                    (SELECT COALESCE(json_object_agg(cid, cnt), '{}'::json) FROM (
                        SELECT COALESCE(collector_id::text, '') AS cid, COUNT(*) AS cnt
                        FROM active_assets WHERE network_scope = 'internal' GROUP BY 1
                    ) g) AS internal_by_collector
                """,
                (str(auth.tenant_id), str(auth.tenant_id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            # Internet-scope assets always have the tempris_cloud scanning route,
            # so "no scanner available" only evaluates internal-scope assets: an
            # asset counts unless its assigned collector is a same-tenant,
            # enrolled, active, connected collector with a usable nmap engine.
            internal_by_collector = row["internal_by_collector"] or {}
            no_scanner_available = 0
            if internal_by_collector:
                cur.execute(
                    """
                    SELECT id FROM collectors
                    WHERE tenant_id = %s
                      AND enrollment_status = 'enrolled'
                      AND operator_status = 'active'
                      AND id::text = ANY(%s);
                    """,
                    (str(auth.tenant_id), list(internal_by_collector.keys()))
                )
                tenant_usable_ids = {c["id"] for c in cur.fetchall()}
                for collector_key, asset_count in internal_by_collector.items():
                    if not collector_key:
                        no_scanner_available += asset_count
                        continue
                    collector_id = uuid.UUID(collector_key)
                    if collector_id not in tenant_usable_ids or not _collector_scan_capable(collector_id):
                        no_scanner_available += asset_count
            return {
                "total_assets": row["total_assets"] or 0,
                "reachable_by_scout": row["reachable_by_scout"] or 0,
                "authorized_to_scan": row["authorized_to_scan"] or 0,
                "pending_authorization": row["pending_authorization"] or 0,
                "no_scanner_available": no_scanner_available
            }

@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new asset"
)
def create_asset(
    asset_in: AssetCreate,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    # Validate and normalize target
    try:
        norm = validate_and_normalize_target(asset_in.target_type, asset_in.target_value)
    except TargetValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )

    with get_db_connection() as conn:
        # Validate collector routing if specified
        if asset_in.collector_id is not None:
            _validate_collector_routing(conn, auth.tenant_id, asset_in.collector_id)

        # Server-authoritative reachability determination
        if asset_in.network_scope == "internet":
            try:
                check_res = check_target_reachability(asset_in.target_type, asset_in.target_value, "internet")
                reachability_status = check_res.reachability_status
                verification_source = "tempris_cloud"
                last_verified_at = datetime.now(timezone.utc)
            except TargetValidationError as e:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=str(e)
                )
        else:
            reachability_status = "unverified"
            verification_source = None
            last_verified_at = None

        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO assets (
                        id, tenant_id, name, asset_type, target_type, target_value,
                        normalized_target, network_scope, environment, criticality,
                        owner, tags, collector_id, status, reachability_status, verification_source,
                        last_verified_at, created_at, updated_at
                    ) VALUES (
                        gen_random_uuid(), %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, 'active', %s, %s,
                        %s, now(), now()
                    )
                    RETURNING *;
                    """,
                    (
                        str(auth.tenant_id),
                        asset_in.name,
                        asset_in.asset_type,
                        asset_in.target_type,
                        asset_in.target_value,
                        norm.normalized_target,
                        asset_in.network_scope,
                        asset_in.environment,
                        asset_in.criticality,
                        asset_in.owner,
                        asset_in.tags,
                        str(asset_in.collector_id) if asset_in.collector_id else None,
                        reachability_status,
                        verification_source,
                        last_verified_at
                    )
                )
                row = cur.fetchone()
                created_asset = dict(row)

                record_audit_event(
                    conn=conn,
                    tenant_id=auth.tenant_id,
                    actor_id=auth.actor_id,
                    actor_role=auth.role,
                    event_name="asset.created",
                    asset_id=created_asset["id"],
                    details={
                        "name": created_asset["name"],
                        "target_type": created_asset["target_type"],
                        "normalized_target": created_asset["normalized_target"],
                        "network_scope": created_asset["network_scope"],
                        "collector_id": str(created_asset["collector_id"]) if created_asset.get("collector_id") else None
                    }
                )
                conn.commit()
                return created_asset
        except UniqueViolation:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"An active asset with normalized target '{norm.normalized_target}' already exists in this tenant."
            )

@router.get(
    "",
    response_model=List[AssetResponse],
    status_code=status.HTTP_200_OK,
    summary="List active assets for authenticated tenant"
)
def list_assets(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM assets
                WHERE tenant_id = %s AND status = 'active'
                ORDER BY created_at DESC;
                """,
                (str(auth.tenant_id),)
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]

@router.get(
    "/{id}",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Get asset by ID for authenticated tenant"
)
def get_asset(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM assets
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Asset not found"
                )
            return dict(row)

@router.put(
    "/{id}",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Update an existing asset"
)
def update_asset(
    id: uuid.UUID,
    asset_in: AssetUpdate,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM assets
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Asset not found"
                )
            if existing["status"] == "decommissioned":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot modify a decommissioned asset"
                )

            # Determine updated values
            name = asset_in.name if asset_in.name is not None else existing["name"]
            asset_type = asset_in.asset_type if asset_in.asset_type is not None else existing["asset_type"]
            target_type = asset_in.target_type if asset_in.target_type is not None else existing["target_type"]
            target_value = asset_in.target_value if asset_in.target_value is not None else existing["target_value"]
            network_scope = asset_in.network_scope if asset_in.network_scope is not None else existing["network_scope"]
            environment = asset_in.environment if asset_in.environment is not None else existing["environment"]
            criticality = asset_in.criticality if asset_in.criticality is not None else existing["criticality"]
            owner = asset_in.owner if asset_in.owner is not None else existing["owner"]
            tags = asset_in.tags if asset_in.tags is not None else existing["tags"]

            # Determine collector_id
            unset_fields = asset_in.model_dump(exclude_unset=True)
            if "collector_id" in unset_fields:
                collector_id = asset_in.collector_id
                if collector_id is not None:
                    _validate_collector_routing(conn, auth.tenant_id, collector_id)
            else:
                collector_id = existing["collector_id"]

            # Validate target if target_type or target_value changed
            try:
                norm = validate_and_normalize_target(target_type, target_value)
                normalized_target = norm.normalized_target
            except TargetValidationError as e:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=str(e)
                )

            # Check if target tuple changed
            target_tuple_changed = (
                target_type != existing["target_type"] or
                normalized_target != existing["normalized_target"] or
                network_scope != existing["network_scope"]
            )

            reachability_status = existing["reachability_status"]
            verification_source = existing["verification_source"]
            last_verified_at = existing["last_verified_at"]

            if target_tuple_changed:
                # Atomically revoke any existing pending or approved scan authorizations in same tx
                cur.execute(
                    """
                    UPDATE asset_scan_authorizations
                    SET status = 'revoked',
                        revoked_by = %s,
                        revoked_at = now(),
                        revocation_reason = 'Asset target or network scope was updated'
                    WHERE asset_id = %s AND tenant_id = %s AND status IN ('pending', 'approved');
                    """,
                    (auth.actor_id, str(id), str(auth.tenant_id))
                )

                # Server-authoritative reachability determination on target tuple change
                if network_scope == "internet":
                    try:
                        check_res = check_target_reachability(target_type, target_value, "internet")
                        reachability_status = check_res.reachability_status
                        verification_source = "tempris_cloud"
                        last_verified_at = datetime.now(timezone.utc)
                    except TargetValidationError as e:
                        raise HTTPException(
                            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=str(e)
                        )
                else:
                    reachability_status = "unverified"
                    verification_source = None
                    last_verified_at = None

            try:
                cur.execute(
                    """
                    UPDATE assets SET
                        name = %s,
                        asset_type = %s,
                        target_type = %s,
                        target_value = %s,
                        normalized_target = %s,
                        network_scope = %s,
                        environment = %s,
                        criticality = %s,
                        owner = %s,
                        tags = %s,
                        collector_id = %s,
                        reachability_status = %s,
                        verification_source = %s,
                        last_verified_at = %s,
                        target_validation_state = 'ok',
                        updated_at = now()
                    WHERE id = %s AND tenant_id = %s
                    RETURNING *;
                    """,
                    (
                        name,
                        asset_type,
                        target_type,
                        target_value,
                        normalized_target,
                        network_scope,
                        environment,
                        criticality,
                        owner,
                        tags,
                        str(collector_id) if collector_id else None,
                        reachability_status,
                        verification_source,
                        last_verified_at,
                        str(id),
                        str(auth.tenant_id)
                    )
                )
                updated_asset = dict(cur.fetchone())

                record_audit_event(
                    conn=conn,
                    tenant_id=auth.tenant_id,
                    actor_id=auth.actor_id,
                    actor_role=auth.role,
                    event_name="asset.updated",
                    asset_id=id,
                    details={
                        "target_tuple_changed": target_tuple_changed,
                        "name": name,
                        "normalized_target": normalized_target,
                        "network_scope": network_scope,
                        "collector_id": str(collector_id) if collector_id else None
                    }
                )
                conn.commit()
                return updated_asset
            except UniqueViolation:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"An active asset with normalized target '{normalized_target}' already exists in this tenant."
                )

@router.post(
    "/{id}/recheck",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Recheck reachability for an asset"
)
async def recheck_asset(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    # 1. Snapshot asset state and release DB connection before network wait
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM assets
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            asset = cur.fetchone()
            if not asset:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Asset not found"
                )
            if asset["status"] == "decommissioned":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot recheck reachability for a decommissioned asset"
                )

            snap_target_type = asset["target_type"]
            snap_target_value = asset["target_value"]
            snap_normalized_target = asset["normalized_target"]
            snap_network_scope = asset["network_scope"]
            snap_collector_id = asset.get("collector_id")

            # Check collector status if internal
            collector_valid = False
            if snap_collector_id:
                cur.execute(
                    "SELECT id, operator_status FROM collectors WHERE id = %s AND tenant_id = %s;",
                    (str(snap_collector_id), str(auth.tenant_id))
                )
                col_row = cur.fetchone()
                if col_row and col_row["operator_status"] != "revoked":
                    collector_valid = True

    # 2. Perform network probe outside of DB transaction
    if snap_network_scope == "internet":
        try:
            check_res = check_target_reachability(
                snap_target_type,
                snap_target_value,
                "internet"
            )
            reachability_status = check_res.reachability_status
            verification_source = "tempris_cloud"
            last_verified_at = datetime.now(timezone.utc)
        except TargetValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(e)
            )
    else:
        # Internal asset verification via assigned collector
        if snap_collector_id and collector_valid:
            dispatch_res = await collector_registry.dispatch_verify_target(
                collector_id=snap_collector_id,
                tenant_id=auth.tenant_id,
                target_type=snap_target_type,
                target_value=snap_target_value,
                normalized_target=snap_normalized_target,
                network_scope="internal",
                asset_id=id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                timeout_seconds=8.0
            )
            if dispatch_res.get("reachability_status") in ("verified", "unreachable"):
                reachability_status = dispatch_res["reachability_status"]
                verification_source = "internal_collector"
                last_verified_at = datetime.now(timezone.utc)
            else:
                reachability_status = "unverified"
                verification_source = None
                last_verified_at = None
        else:
            reachability_status = "unverified"
            verification_source = None
            last_verified_at = None

    # 3. Optimistic Compare-and-Set (CAS) update to prevent stale probe results
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE assets SET
                    reachability_status = %s,
                    verification_source = %s,
                    last_verified_at = %s,
                    updated_at = now()
                WHERE id = %s
                  AND tenant_id = %s
                  AND status = 'active'
                  AND target_type = %s
                  AND target_value = %s
                  AND normalized_target = %s
                  AND network_scope = %s
                  AND collector_id IS NOT DISTINCT FROM %s::uuid
                RETURNING *;
                """,
                (
                    reachability_status,
                    verification_source,
                    last_verified_at,
                    str(id),
                    str(auth.tenant_id),
                    snap_target_type,
                    snap_target_value,
                    snap_normalized_target,
                    snap_network_scope,
                    str(snap_collector_id) if snap_collector_id else None
                )
            )
            row = cur.fetchone()
            if not row:
                record_audit_event(
                    conn=conn,
                    tenant_id=auth.tenant_id,
                    actor_id=auth.actor_id,
                    actor_role=auth.role,
                    event_name="asset.recheck_discarded_conflict",
                    asset_id=id,
                    details={
                        "reason": "concurrent_mutation_or_decommission",
                        "snapshot_target": snap_normalized_target
                    }
                )
                conn.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Asset target, scope, status, or collector assignment was modified during recheck; probe result discarded."
                )

            updated_asset = dict(row)
            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="asset.rechecked",
                asset_id=id,
                details={
                    "reachability_status": reachability_status,
                    "verification_source": verification_source,
                    "network_scope": snap_network_scope,
                    "collector_id": str(snap_collector_id) if snap_collector_id else None
                }
            )
            conn.commit()
            return updated_asset

@router.post(
    "/{id}/decommission",
    response_model=AssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Decommission an active asset"
)
def decommission_asset(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM assets
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Asset not found"
                )

            if existing["status"] == "decommissioned":
                # Idempotent: supersession already ran in the first decommission;
                # re-run is a harmless no-op on any straggler current exposure.
                supersede_exposures_for_asset(
                    conn,
                    auth.tenant_id,
                    id,
                    actor_id=auth.actor_id,
                    actor_role=auth.role,
                    reason="asset decommissioned (idempotent re-run)",
                )
                return dict(existing)

            # P0-07 (§3.6.6 #7): a bound asset cannot be decommissioned until
            # the binding is replaced or cleared — rejected before ANY change
            # (no partial decommission). The migration-020 BEFORE-UPDATE
            # trigger backstops this guard for raw-SQL writers.
            try:
                assert_asset_not_identity_boundary(cur, auth.tenant_id, id)
            except BoundAssetError as e:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=str(e),
                )

            # In same transaction: mark decommissioned and revoke active authorizations
            cur.execute(
                """
                UPDATE asset_scan_authorizations
                SET status = 'revoked',
                    revoked_by = %s,
                    revoked_at = now(),
                    revocation_reason = 'Asset was decommissioned'
                WHERE asset_id = %s AND tenant_id = %s AND status IN ('pending', 'approved');
                """,
                (auth.actor_id, str(id), str(auth.tenant_id))
            )

            cur.execute(
                """
                UPDATE assets SET
                    status = 'decommissioned',
                    decommissioned_at = now(),
                    updated_at = now()
                WHERE id = %s AND tenant_id = %s
                RETURNING *;
                """,
                (str(id), str(auth.tenant_id))
            )
            decommissioned_asset = dict(cur.fetchone())

            # Exposure lifecycle authority: decommissioning is an audited
            # supersession transition — current exposures stop being current in
            # this same transaction; history is retained and reactivation never
            # revives a superseded episode.
            supersede_exposures_for_asset(
                conn,
                auth.tenant_id,
                id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                reason="asset decommissioned",
            )

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="asset.decommissioned",
                asset_id=id,
                details={
                    "normalized_target": decommissioned_asset["normalized_target"],
                    "status": "decommissioned"
                }
            )
            conn.commit()
            return decommissioned_asset

def _with_effective_status(auth_row: Optional[dict]) -> Optional[dict]:
    """Derive effective status: an approved authorization with elapsed expires_at is effective 'expired'."""
    if not auth_row:
        return None
    res = dict(auth_row)
    if res.get("status") == "approved" and res.get("expires_at"):
        exp = res["expires_at"]
        if isinstance(exp, str):
            exp = datetime.fromisoformat(exp)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            res["status"] = "expired"
    return res

@router.get(
    "/{id}/scan-authorization",
    response_model=Optional[ScanAuthorizationResponse],
    status_code=status.HTTP_200_OK,
    summary="Get current or latest scan authorization for an asset"
)
def get_scan_authorization(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Check asset exists in tenant
            cur.execute(
                "SELECT id FROM assets WHERE id = %s AND tenant_id = %s;",
                (str(id), str(auth.tenant_id))
            )
            if not cur.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Asset not found"
                )

            # Retrieve latest authorization record
            cur.execute(
                """
                SELECT * FROM asset_scan_authorizations
                WHERE asset_id = %s AND tenant_id = %s
                ORDER BY requested_at DESC, approved_at DESC NULLS LAST
                LIMIT 1;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                return None
            return _with_effective_status(dict(row))

@router.post(
    "/{id}/scan-authorization/request",
    response_model=ScanAuthorizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Request scan authorization for an asset"
)
def request_scan_authorization(
    id: uuid.UUID,
    payload: Optional[ScanAuthorizationRequest] = None,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    request_reason = payload.request_reason if payload else None

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM assets WHERE id = %s AND tenant_id = %s;",
                (str(id), str(auth.tenant_id))
            )
            asset = cur.fetchone()
            if not asset:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Asset not found"
                )
            if asset["status"] == "decommissioned":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot request scan authorization for a decommissioned asset"
                )

            # Snapshots current asset target tuple
            cur.execute(
                """
                INSERT INTO asset_scan_authorizations (
                    id, tenant_id, asset_id, target_type, normalized_target,
                    network_scope, status, requested_by, requested_at, request_reason
                ) VALUES (
                    gen_random_uuid(), %s, %s, %s, %s,
                    %s, 'pending', %s, now(), %s
                )
                RETURNING *;
                """,
                (
                    str(auth.tenant_id),
                    str(id),
                    asset["target_type"],
                    asset["normalized_target"],
                    asset["network_scope"],
                    auth.actor_id,
                    request_reason
                )
            )
            row = cur.fetchone()
            created_auth = dict(row)

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="scan_authorization.requested",
                asset_id=id,
                details={
                    "authorization_id": str(created_auth["id"]),
                    "target_type": created_auth["target_type"],
                    "normalized_target": created_auth["normalized_target"],
                    "network_scope": created_auth["network_scope"],
                    "request_reason": request_reason
                }
            )
            conn.commit()
            return created_auth

@router.post(
    "/{id}/scan-authorization/approve",
    response_model=ScanAuthorizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve scan authorization for an asset"
)
def approve_scan_authorization(
    id: uuid.UUID,
    payload: ScanAuthorizationApprove,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM assets WHERE id = %s AND tenant_id = %s;",
                (str(id), str(auth.tenant_id))
            )
            asset = cur.fetchone()
            if not asset:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Asset not found"
                )
            if asset["status"] == "decommissioned":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot approve scan authorization for a decommissioned asset"
                )

            # Find latest pending authorization matching exact current target tuple
            cur.execute(
                """
                SELECT id FROM asset_scan_authorizations
                WHERE asset_id = %s AND tenant_id = %s AND status = 'pending'
                  AND target_type = %s AND normalized_target = %s AND network_scope = %s
                ORDER BY requested_at DESC
                LIMIT 1;
                """,
                (
                    str(id),
                    str(auth.tenant_id),
                    asset["target_type"],
                    asset["normalized_target"],
                    asset["network_scope"]
                )
            )
            pending = cur.fetchone()

            if pending:
                cur.execute(
                    """
                    UPDATE asset_scan_authorizations
                    SET status = 'approved',
                        approved_by = %s,
                        approved_at = now(),
                        expires_at = %s
                    WHERE id = %s AND tenant_id = %s AND asset_id = %s AND status = 'pending'
                    RETURNING *;
                    """,
                    (auth.actor_id, payload.expires_at, pending["id"], str(auth.tenant_id), str(id))
                )
                updated_row = cur.fetchone()
                if not updated_row:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Pending scan authorization is no longer available or was concurrently modified."
                    )
                approved_auth = dict(updated_row)
            else:
                # Direct approval creates an approved authorization bound to current target tuple
                cur.execute(
                    """
                    INSERT INTO asset_scan_authorizations (
                        id, tenant_id, asset_id, target_type, normalized_target,
                        network_scope, status, requested_by, requested_at,
                        approved_by, approved_at, expires_at
                    ) VALUES (
                        gen_random_uuid(), %s, %s, %s, %s,
                        %s, 'approved', %s, now(),
                        %s, now(), %s
                    )
                    RETURNING *;
                    """,
                    (
                        str(auth.tenant_id),
                        str(id),
                        asset["target_type"],
                        asset["normalized_target"],
                        asset["network_scope"],
                        auth.actor_id,
                        auth.actor_id,
                        payload.expires_at
                    )
                )
                approved_auth = dict(cur.fetchone())

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="scan_authorization.approved",
                asset_id=id,
                details={
                    "authorization_id": str(approved_auth["id"]),
                    "normalized_target": approved_auth["normalized_target"],
                    "expires_at": payload.expires_at.isoformat()
                }
            )
            conn.commit()
            return approved_auth

@router.post(
    "/{id}/scan-authorization/revoke",
    response_model=Optional[ScanAuthorizationResponse],
    status_code=status.HTTP_200_OK,
    summary="Revoke scan authorization for an asset"
)
def revoke_scan_authorization(
    id: uuid.UUID,
    payload: Optional[ScanAuthorizationRevoke] = None,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    revocation_reason = payload.revocation_reason if payload else None

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM assets WHERE id = %s AND tenant_id = %s;",
                (str(id), str(auth.tenant_id))
            )
            asset = cur.fetchone()
            if not asset:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Asset not found"
                )

            # Revoke all active or pending authorizations
            cur.execute(
                """
                UPDATE asset_scan_authorizations
                SET status = 'revoked',
                    revoked_by = %s,
                    revoked_at = now(),
                    revocation_reason = %s
                WHERE asset_id = %s AND tenant_id = %s AND status IN ('pending', 'approved')
                RETURNING *;
                """,
                (auth.actor_id, revocation_reason, str(id), str(auth.tenant_id))
            )
            revoked_rows = cur.fetchall()

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="scan_authorization.revoked",
                asset_id=id,
                details={
                    "revocation_reason": revocation_reason,
                    "revoked_count": len(revoked_rows)
                }
            )
            conn.commit()

            if revoked_rows:
                return _with_effective_status(dict(revoked_rows[0]))

            # If no active/pending was found, return latest record if any
            cur.execute(
                """
                SELECT * FROM asset_scan_authorizations
                WHERE asset_id = %s AND tenant_id = %s
                ORDER BY requested_at DESC
                LIMIT 1;
                """,
                (str(id), str(auth.tenant_id))
            )
            last = cur.fetchone()
            return _with_effective_status(dict(last)) if last else None
