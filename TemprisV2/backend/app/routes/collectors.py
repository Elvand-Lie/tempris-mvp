# backend/app/routes/collectors.py
import asyncio
import hashlib
import json
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Response, WebSocket, WebSocketDisconnect, status
from app.auth import AuthContext, get_auth_context, require_roles, require_module
from app.services.entitlements import resolve_effective_modules
from app.audit import record_audit_event
from app.db import get_db_connection
from app.schemas import (
    CollectorCreate,
    CollectorEnrollRequest,
    CollectorResponse,
    CollectorEnrollmentResponse,
)
from app.config import COLLECTOR_SERVER_URL
from app.collector_crypto import (
    generate_enrollment_code,
    generate_auth_challenge,
    normalize_ed25519_public_key,
    build_canonical_challenge_bytes,
    verify_ed25519_signature,
)
from app.collector_registry import collector_registry

logger = logging.getLogger("collectors_router")
router = APIRouter(prefix="/api/collectors", tags=["Collectors"])

def _with_derived_collector_fields(collector_row: dict) -> dict:
    cid = collector_row["id"] if isinstance(collector_row["id"], uuid.UUID) else uuid.UUID(str(collector_row["id"]))
    conn_status = collector_registry.get_connection_status(cid)
    derived_status = collector_registry.get_derived_status(
        collector_row["enrollment_status"],
        collector_row["operator_status"],
        cid
    )
    req_rate = collector_registry.get_rate(cid)
    return {
        **collector_row,
        "connection_status": conn_status,
        "status": derived_status,
        "req_rate_per_sec": req_rate,
        "server_url": COLLECTOR_SERVER_URL
    }

@router.post(
    "",
    response_model=CollectorEnrollmentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="Create a new collector profile and generate enrollment code"
)
def create_collector(
    collector_in: CollectorCreate,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    raw_code, code_hash, expires_at = generate_enrollment_code()

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO collectors (
                    id, tenant_id, name, description, enrollment_status,
                    operator_status, enrollment_code_hash, enrollment_code_expires_at,
                    platform_metadata, created_at, updated_at
                ) VALUES (
                    gen_random_uuid(), %s, %s, %s, 'awaiting_enrollment',
                    'active', %s, %s,
                    '{}'::JSONB, now(), now()
                )
                RETURNING *;
                """,
                (
                    str(auth.tenant_id),
                    collector_in.name,
                    collector_in.description,
                    code_hash,
                    expires_at
                )
            )
            row = cur.fetchone()
            created_collector = dict(row)

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="collector.created",
                details={
                    "collector_id": str(created_collector["id"]),
                    "name": created_collector["name"]
                }
            )
            conn.commit()

            derived = _with_derived_collector_fields(created_collector)
            return {
                **derived,
                "enrollment_code": raw_code,
                "enrollment_code_expires_at": expires_at,
                "server_url": COLLECTOR_SERVER_URL
            }

@router.post(
    "/enroll",
    response_model=CollectorResponse,
    status_code=status.HTTP_200_OK,
    summary="Enroll collector with Ed25519 public key and platform metadata"
)
def enroll_collector(payload: CollectorEnrollRequest):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE id = %s
                FOR UPDATE;
                """,
                (str(payload.collector_id),)
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Collector not found"
                )

            if row["enrollment_status"] != "awaiting_enrollment":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Collector is already enrolled"
                )

            effective_modules = resolve_effective_modules(conn, row["tenant_id"])
            if "ASSETS" not in effective_modules:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Tenant does not possess active entitlement for module 'ASSETS'"
                )

            if row["operator_status"] in ("quarantined", "revoked"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot enroll {row['operator_status']} collector"
                )

            now_utc = datetime.now(timezone.utc)
            if not row["enrollment_code_expires_at"] or now_utc > row["enrollment_code_expires_at"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Enrollment code has expired"
                )

            input_hash = hashlib.sha256(payload.enrollment_code.encode("utf-8")).hexdigest()
            if input_hash != row["enrollment_code_hash"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid enrollment code"
                )

            try:
                normalized_pubkey = normalize_ed25519_public_key(payload.public_key)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid Ed25519 public key: {str(e)}"
                )

            meta = payload.platform_metadata or {}
            extracted_os = meta.get("os")
            extracted_arch = meta.get("architecture")
            extracted_hostname = meta.get("hostname")
            extracted_version = meta.get("agent_version") or meta.get("version")

            cur.execute(
                """
                UPDATE collectors
                SET enrollment_status = 'enrolled',
                    public_key = %s,
                    platform_metadata = %s,
                    os = %s,
                    architecture = %s,
                    hostname = %s,
                    version = %s,
                    enrolled_at = now(),
                    enrollment_code_hash = NULL,
                    enrollment_code_expires_at = NULL,
                    updated_at = now()
                WHERE id = %s
                RETURNING *;
                """,
                (
                    normalized_pubkey,
                    json.dumps(payload.platform_metadata or {}),
                    extracted_os,
                    extracted_arch,
                    extracted_hostname,
                    extracted_version,
                    str(payload.collector_id)
                )
            )
            updated = dict(cur.fetchone())

            record_audit_event(
                conn=conn,
                tenant_id=row["tenant_id"],
                actor_id=f"collector:{str(payload.collector_id)}",
                actor_role="collector",
                event_name="collector.enrolled",
                details={
                    "collector_id": str(payload.collector_id),
                    "name": updated["name"],
                    "platform_metadata": payload.platform_metadata
                }
            )
            conn.commit()

            return _with_derived_collector_fields(updated)

@router.get(
    "",
    response_model=List[CollectorResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="List all collectors for tenant"
)
def list_collectors(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE tenant_id = %s
                ORDER BY created_at DESC;
                """,
                (str(auth.tenant_id),)
            )
            rows = cur.fetchall()
            return [_with_derived_collector_fields(dict(r)) for r in rows]

@router.get(
    "/{id}",
    response_model=CollectorResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="Get collector details by ID"
)
def get_collector(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Collector not found"
                )
            return _with_derived_collector_fields(dict(row))

@router.post(
    "/{id}/pause",
    response_model=CollectorResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="Pause a collector"
)
def pause_collector(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Collector not found"
                )

            if row["operator_status"] == "revoked":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot pause a revoked collector"
                )

            cur.execute(
                """
                UPDATE collectors
                SET operator_status = 'paused',
                    updated_at = now()
                WHERE id = %s AND tenant_id = %s
                RETURNING *;
                """,
                (str(id), str(auth.tenant_id))
            )
            updated = dict(cur.fetchone())

            collector_registry.update_operator_status(id, "paused")

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="collector.paused",
                details={"collector_id": str(id), "name": updated["name"]}
            )
            conn.commit()

            return _with_derived_collector_fields(updated)

@router.post(
    "/{id}/resume",
    response_model=CollectorResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="Resume a paused collector"
)
def resume_collector(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Collector not found"
                )

            if row["operator_status"] in ("revoked", "quarantined"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot resume {row['operator_status']} collector; use release or re-enroll"
                )

            cur.execute(
                """
                UPDATE collectors
                SET operator_status = 'active',
                    updated_at = now()
                WHERE id = %s AND tenant_id = %s
                RETURNING *;
                """,
                (str(id), str(auth.tenant_id))
            )
            updated = dict(cur.fetchone())

            collector_registry.update_operator_status(id, "active")

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="collector.resumed",
                details={"collector_id": str(id), "name": updated["name"]}
            )
            conn.commit()

            return _with_derived_collector_fields(updated)

@router.post(
    "/{id}/quarantine",
    response_model=CollectorResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="Quarantine a collector and terminate live socket"
)
async def quarantine_collector(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Collector not found"
                )

            if row["operator_status"] == "revoked":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot quarantine a revoked collector"
                )

            cur.execute(
                """
                UPDATE collectors
                SET operator_status = 'quarantined',
                    updated_at = now()
                WHERE id = %s AND tenant_id = %s
                RETURNING *;
                """,
                (str(id), str(auth.tenant_id))
            )
            updated = dict(cur.fetchone())

            await collector_registry.terminate_socket(
                collector_id=id,
                close_code=1008,
                reason="Collector quarantined by administrator"
            )

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="collector.quarantined",
                details={"collector_id": str(id), "reason": "Operator quarantine"}
            )
            conn.commit()

            return _with_derived_collector_fields(updated)

@router.post(
    "/{id}/release",
    response_model=CollectorResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="Release a quarantined collector back to active status"
)
def release_collector(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Collector not found"
                )

            if row["operator_status"] != "quarantined":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Collector is not in quarantined status"
                )

            cur.execute(
                """
                UPDATE collectors
                SET operator_status = 'active',
                    updated_at = now()
                WHERE id = %s AND tenant_id = %s
                RETURNING *;
                """,
                (str(id), str(auth.tenant_id))
            )
            updated = dict(cur.fetchone())

            collector_registry.update_operator_status(id, "active")

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="collector.released",
                details={"collector_id": str(id), "name": updated["name"]}
            )
            conn.commit()

            return _with_derived_collector_fields(updated)

@router.post(
    "/{id}/revoke",
    response_model=CollectorResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="Permanently revoke a collector and terminate live socket"
)
async def revoke_collector(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Collector not found"
                )

            cur.execute(
                """
                UPDATE collectors
                SET operator_status = 'revoked',
                    revoked_at = now(),
                    updated_at = now()
                WHERE id = %s AND tenant_id = %s
                RETURNING *;
                """,
                (str(id), str(auth.tenant_id))
            )
            updated = dict(cur.fetchone())

            await collector_registry.terminate_socket(
                collector_id=id,
                close_code=1008,
                reason="Collector permanently revoked"
            )

            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="collector.revoked",
                details={"collector_id": str(id), "name": updated["name"]}
            )
            conn.commit()

            return _with_derived_collector_fields(updated)


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_module("ASSETS"))],
    summary="Safely delete a revoked, unreferenced collector profile"
)
def delete_collector(
    id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["admin", "superadmin"]))
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # 1. Fetch collector row scoped strictly to the authenticated tenant (FOR UPDATE to lock row)
            cur.execute(
                """
                SELECT * FROM collectors
                WHERE id = %s AND tenant_id = %s
                FOR UPDATE;
                """,
                (str(id), str(auth.tenant_id))
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Collector not found"
                )

            # 2. Gate: Operator status must be 'revoked'
            if row["operator_status"] != "revoked":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Cannot delete collector in '{row['operator_status']}' status; collector must be revoked prior to deletion."
                )

            # 3. Gate: No live session in registry
            if collector_registry.is_connected(id) or collector_registry.get_session(id) is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot delete collector with an active live session."
                )

            # 4. Gate: Zero assets (active or historical) reference collector_id
            cur.execute(
                """
                SELECT COUNT(*) AS ref_count
                FROM assets
                WHERE collector_id = %s;
                """,
                (str(id),)
            )
            asset_count_row = cur.fetchone()
            ref_count = asset_count_row["ref_count"] if isinstance(asset_count_row, dict) else asset_count_row[0]
            if ref_count > 0:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Cannot delete collector referenced by {ref_count} asset(s). Reassign or unroute assets prior to deletion."
                )

            # 5. Insert sanitized collector.deleted audit event (zero key/enrollment/secret data)
            record_audit_event(
                conn=conn,
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                actor_role=auth.role,
                event_name="collector.deleted",
                details={
                    "collector_id": str(id),
                    "name": row["name"],
                    "hostname": row.get("hostname"),
                    "os": row.get("os"),
                    "architecture": row.get("architecture"),
                    "version": row.get("version"),
                }
            )

            # 6. Execute permanent parameterized deletion
            cur.execute(
                """
                DELETE FROM collectors
                WHERE id = %s AND tenant_id = %s;
                """,
                (str(id), str(auth.tenant_id))
            )
            conn.commit()

            return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.websocket("/ws")
async def websocket_collector_endpoint(websocket: WebSocket):
    await websocket.accept()
    session_key = str(uuid.uuid4())

    # 1. Issue AUTH_CHALLENGE
    nonce, expires_at_str, expires_at_dt = generate_auth_challenge()
    collector_registry.register_challenge(session_key, nonce, expires_at_str, expires_at_dt)

    challenge_payload = {
        "type": "AUTH_CHALLENGE",
        "nonce": nonce,
        "expires_at": expires_at_str
    }
    await websocket.send_text(json.dumps(challenge_payload))

    authenticated_collector_id: Optional[uuid.UUID] = None
    try:
        raw_msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
        try:
            auth_data = json.loads(raw_msg)
        except Exception:
            await websocket.close(code=1008, reason="Invalid JSON payload")
            collector_registry.clear_challenge(session_key)
            return

        if auth_data.get("type") != "AUTH_RESPONSE":
            await websocket.close(code=1008, reason="Expected AUTH_RESPONSE")
            collector_registry.clear_challenge(session_key)
            return

        collector_id_str = auth_data.get("collector_id")
        resp_nonce = auth_data.get("nonce")
        resp_expires_at = auth_data.get("expires_at")
        signature = auth_data.get("signature")

        if not all([collector_id_str, resp_nonce, resp_expires_at, signature]):
            await websocket.close(code=1008, reason="Missing required fields in AUTH_RESPONSE")
            collector_registry.clear_challenge(session_key)
            return

        try:
            col_uuid = uuid.UUID(str(collector_id_str))
        except ValueError:
            await websocket.close(code=1008, reason="Invalid collector_id format")
            collector_registry.clear_challenge(session_key)
            return

        # Single-use challenge validation
        valid_challenge, err_reason = collector_registry.consume_challenge(session_key, resp_nonce, resp_expires_at)
        collector_registry.clear_challenge(session_key)
        if not valid_challenge:
            await websocket.close(code=1008, reason=f"Challenge verification failed: {err_reason}")
            return

        # Query database for collector record
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM collectors WHERE id = %s;",
                    (str(col_uuid),)
                )
                collector = cur.fetchone()

        if not collector:
            await websocket.close(code=1008, reason="Collector not found")
            return

        if collector["enrollment_status"] != "enrolled" or not collector["public_key"]:
            await websocket.close(code=1008, reason="Collector is not enrolled")
            return

        if collector["operator_status"] in ("quarantined", "revoked"):
            await websocket.close(code=1008, reason=f"Collector is {collector['operator_status']}")
            return

        # Reconstruct canonical challenge bytes and verify Ed25519 signature
        canonical_bytes = build_canonical_challenge_bytes(col_uuid, resp_nonce, resp_expires_at)
        if not verify_ed25519_signature(collector["public_key"], signature, canonical_bytes):
            await websocket.close(code=1008, reason="Invalid cryptographic signature")
            return

        # Validate tenant status and ASSETS module entitlement
        with get_db_connection() as conn:
            effective_modules = resolve_effective_modules(conn, collector["tenant_id"])
        if "ASSETS" not in effective_modules:
            await websocket.close(code=1008, reason="Tenant is inactive or not entitled for module 'ASSETS'")
            return

        # Authentication succeeded
        authenticated_collector_id = col_uuid
        tenant_id = collector["tenant_id"]
        operator_status = collector["operator_status"]

        session = collector_registry.register_session(
            collector_id=col_uuid,
            tenant_id=tenant_id,
            websocket=websocket,
            operator_status=operator_status
        )
        current_session_id = session.session_id

        await websocket.send_text(json.dumps({
            "type": "AUTH_SUCCESS",
            "collector_id": str(col_uuid),
            "status": "connected"
        }))

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE collectors SET last_seen_at = now(), updated_at = now() WHERE id = %s;",
                    (str(col_uuid),)
                )
            record_audit_event(
                conn=conn,
                tenant_id=tenant_id,
                actor_id=f"collector:{str(col_uuid)}",
                actor_role="collector",
                event_name="collector.connected",
                details={
                    "collector_id": str(col_uuid),
                    "name": collector["name"]
                }
            )
            conn.commit()

        # Message receive loop
        while True:
            msg_text = await websocket.receive_text()
            session.record_message()

            if session.is_rate_limit_exceeded():
                rate = session.get_rate()
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE collectors SET operator_status = 'quarantined', updated_at = now() WHERE id = %s;",
                            (str(col_uuid),)
                        )
                    record_audit_event(
                        conn=conn,
                        tenant_id=tenant_id,
                        actor_id="system:rate_guard",
                        actor_role="system",
                        event_name="collector.quarantined",
                        details={
                            "collector_id": str(col_uuid),
                            "reason": "Excessive control message rate",
                            "rate": rate
                        }
                    )
                    conn.commit()

                await websocket.close(code=1008, reason="Policy violation: excessive control message rate")
                collector_registry.unregister_session(
                    col_uuid,
                    session_id=current_session_id,
                    reason="Quarantined due to excessive control message rate."
                )
                return

            try:
                frame = json.loads(msg_text)
            except Exception:
                continue

            frame_type = frame.get("type")
            if frame_type == "HEARTBEAT":
                collector_registry.record_heartbeat(col_uuid, session_id=current_session_id)
                now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                await websocket.send_text(json.dumps({
                    "type": "HEARTBEAT_ACK",
                    "timestamp": now_iso
                }))
            elif frame_type == "VERIFY_TARGET_RESULT":
                collector_registry.handle_verify_target_result(
                    col_uuid,
                    frame,
                    session_id=current_session_id
                )

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug("WebSocket terminated for %s: %s", authenticated_collector_id, e)
    finally:
        collector_registry.clear_challenge(session_key)
        if authenticated_collector_id and 'current_session_id' in locals():
            collector_registry.unregister_session(authenticated_collector_id, session_id=current_session_id)
            try:
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE collectors SET last_seen_at = now(), updated_at = now() WHERE id = %s RETURNING tenant_id, name;",
                            (str(authenticated_collector_id),)
                        )
                        row = cur.fetchone()
                        if row:
                            record_audit_event(
                                conn=conn,
                                tenant_id=row["tenant_id"],
                                actor_id=f"collector:{str(authenticated_collector_id)}",
                                actor_role="collector",
                                event_name="collector.disconnected",
                                details={
                                    "collector_id": str(authenticated_collector_id),
                                    "name": row["name"]
                                }
                            )
                            conn.commit()
            except Exception as e:
                logger.error("Failed to record disconnect audit event: %s", e)
