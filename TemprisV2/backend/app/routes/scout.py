import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict

from app.auth import AuthContext, require_module, require_roles
from app.collector_registry import collector_registry
from app.db import get_db_connection
from app.scout import PROFILE_ENGINES, execute_job, probe_tool

router = APIRouter(
    prefix="/api/scout",
    tags=["SCOUT"],
    dependencies=[Depends(require_module("ASSETS"))],
)


class ScoutLaunch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID
    profile: Literal["SERVICE_DISCOVERY", "VULNERABILITY_ASSESSMENT"]


def _source_health(conn, tenant_id: uuid.UUID, job_id: uuid.UUID, include_excerpt: bool) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT engine, ordinal, state, engine_version, templates_version,
                   exit_code, stdout_bytes, stderr_bytes, stderr, started_at, completed_at,
                   sanitized_output_excerpt, parse_stats,
                   (
                       SELECT count(*) FROM scout_observations o
                       WHERE o.tool_run_id = t.id
                         AND o.tenant_id = t.tenant_id AND o.job_id = t.job_id
                   ) AS observation_count
            FROM scout_tool_runs t
            WHERE t.tenant_id = %s AND t.job_id = %s
            ORDER BY t.ordinal
            """,
            (str(tenant_id), str(job_id)),
        )
        health = []
        for row in cur.fetchall():
            item = dict(row)
            detail = item.pop("stderr", None) or None
            item["detail"] = detail
            if not include_excerpt:
                # The 256 KiB excerpt must not bloat the /jobs list payload.
                item["sanitized_output_excerpt"] = None
            health.append(item)
        return health


def _job_response(conn, row: dict, include_excerpt: bool = False) -> dict:
    result = dict(row)
    result["source_health"] = _source_health(conn, row["tenant_id"], row["id"], include_excerpt)
    return result


@router.get("/readiness")
def get_readiness(
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
):
    probes = {engine: probe_tool(engine) for engine in ("nmap", "nuclei")}
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, enrollment_status, operator_status, version
                FROM collectors
                WHERE tenant_id = %s
                """,
                (str(auth.tenant_id),),
            )
            collector_rows = cur.fetchall()

    engines = [
        {
            "engine": probe.engine,
            "state": probe.state,
            "engine_version": probe.engine_version,
            "templates_version": probe.templates_version,
        }
        for probe in probes.values()
    ]
    profiles = {}
    for profile, required in PROFILE_ENGINES.items():
        blockers = [engine for engine in required if not probes[engine].available]
        profiles[profile] = {"state": "blocked" if blockers else "ready", "blockers": blockers}

    collectors_list = []
    connected_count = 0
    active_count = 0
    capable_count = 0

    for row in collector_rows:
        col_id = uuid.UUID(str(row["id"]))
        is_conn = collector_registry.is_connected(col_id)
        if is_conn:
            connected_count += 1
        is_active = row["enrollment_status"] == "enrolled" and row["operator_status"] == "active"
        if is_active:
            active_count += 1
        raw_caps = collector_registry.get_collector_capabilities(col_id) or {}
        sanitized_caps = {}
        for eng in ("nmap", "nuclei"):
            c = raw_caps.get(eng, {}) if isinstance(raw_caps, dict) else {}
            sanitized_caps[eng] = {
                "available": bool(c.get("available", False)),
                "version": c.get("version"),
                "templates_version": c.get("templates_version"),
            }
        is_capable = sanitized_caps["nmap"]["available"] or sanitized_caps["nuclei"]["available"]
        if is_capable and is_conn and is_active:
            capable_count += 1

        collector_version = collector_registry.get_collector_version(col_id) or row.get("version")
        collectors_list.append({
            "id": str(col_id),
            "name": row["name"],
            "enrollment_status": row["enrollment_status"],
            "operator_status": row["operator_status"],
            "connected": is_conn,
            "version": collector_version,
            "capabilities": sanitized_caps,
        })

    return {
        "engines": engines,
        "profiles": profiles,
        "collector": {
            "state": "not_executable_in_sprint_02",
            "total": len(collector_rows),
            "connected": connected_count,
            "message": "INTERNAL Collector execution is deferred to Sprint 03.",
        },
        "collectors_summary": {
            "total": len(collector_rows),
            "connected": connected_count,
            "active": active_count,
            "capable": capable_count,
        },
        "collectors": collectors_list,
    }


@router.post("/jobs", status_code=status.HTTP_201_CREATED)
def launch_job(
    payload: ScoutLaunch,
    background: BackgroundTasks,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM assets WHERE tenant_id = %s AND id = %s FOR UPDATE",
                (str(auth.tenant_id), str(payload.asset_id)),
            )
            asset = cur.fetchone()
            if not asset:
                raise HTTPException(status_code=404, detail="Asset not found")
            if asset["status"] != "active":
                raise HTTPException(status_code=409, detail="Asset is not active")
            if asset.get("target_validation_state") == "needs_revalidation":
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Asset target requires operator revalidation: the bound host reported a "
                        "network location that no longer matches its IP target. Confirm or correct "
                        "the target and re-approve authorization before scanning."
                    )
                )

            if asset["network_scope"] == "internet":
                route = "CENTRAL_PUBLIC"
                collector_id = None
            elif asset["network_scope"] == "internal":
                route = "COLLECTOR_INTERNAL"
                collector_id_raw = asset.get("collector_id")
                if not collector_id_raw:
                    raise HTTPException(status_code=409, detail="Internal asset requires assigned collector")
                collector_id = uuid.UUID(str(collector_id_raw))

                cur.execute(
                    """
                    SELECT id, enrollment_status, operator_status
                    FROM collectors
                    WHERE tenant_id = %s AND id = %s
                    """,
                    (str(auth.tenant_id), str(collector_id)),
                )
                collector = cur.fetchone()
                if not collector:
                    raise HTTPException(status_code=409, detail="Assigned collector not found in tenant")
                if collector["enrollment_status"] != "enrolled" or collector["operator_status"] != "active":
                    raise HTTPException(status_code=409, detail=f"Assigned collector is {collector['operator_status']}")
                if not collector_registry.is_connected(collector_id):
                    raise HTTPException(status_code=409, detail="Assigned collector is offline")
            else:
                raise HTTPException(status_code=409, detail=f"Unsupported network scope {asset['network_scope']}")

            cur.execute(
                """
                SELECT * FROM asset_scan_authorizations
                WHERE tenant_id = %s AND asset_id = %s
                  AND target_type = %s AND normalized_target = %s AND network_scope = %s
                  AND status = 'approved' AND approved_at IS NOT NULL AND expires_at > now()
                ORDER BY approved_at DESC, id DESC
                LIMIT 1 FOR UPDATE
                """,
                (
                    str(auth.tenant_id), str(payload.asset_id), asset["target_type"],
                    asset["normalized_target"], asset["network_scope"],
                ),
            )
            authorization = cur.fetchone()
            if not authorization:
                raise HTTPException(status_code=409, detail="Current exact-target authorization required")

            cur.execute(
                """
                INSERT INTO scout_jobs (
                    tenant_id, asset_id, authorization_id, profile, route, target_type,
                    normalized_target, network_scope, authorization_approved_at,
                    authorization_expires_at, requested_by, collector_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    str(auth.tenant_id), str(payload.asset_id), str(authorization["id"]),
                    payload.profile, route, asset["target_type"], asset["normalized_target"],
                    asset["network_scope"], authorization["approved_at"],
                    authorization["expires_at"], auth.actor_id,
                    str(collector_id) if collector_id else None,
                ),
            )
            job = dict(cur.fetchone())
        conn.commit()
        response = _job_response(conn, job)

    background.add_task(execute_job, job["id"], auth.tenant_id)
    return response


@router.get("/jobs")
def list_jobs(
    limit: int = Query(50, ge=1, le=100),
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM scout_jobs
                WHERE tenant_id = %s
                ORDER BY created_at DESC, id DESC LIMIT %s
                """,
                (str(auth.tenant_id), limit),
            )
            rows = cur.fetchall()
        return [_job_response(conn, dict(row)) for row in rows]


@router.get("/jobs/{job_id}")
def get_job(
    job_id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM scout_jobs WHERE tenant_id = %s AND id = %s",
                (str(auth.tenant_id), str(job_id)),
            )
            row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="SCOUT job not found")
        return _job_response(conn, dict(row), include_excerpt=True)


@router.get("/jobs/{job_id}/observations")
def list_observations(
    job_id: uuid.UUID,
    auth: AuthContext = Depends(require_roles(["analyst", "admin", "superadmin"])),
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM scout_jobs WHERE tenant_id = %s AND id = %s",
                (str(auth.tenant_id), str(job_id)),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="SCOUT job not found")
            cur.execute(
                """
                SELECT o.id, o.job_id, o.tool_run_id, t.engine AS scanner,
                       o.kind, o.evidence, o.created_at,
                       linked.exposure_id, linked.finding_id, linked.canonical_cve_id,
                       linked.exposure_status
                FROM scout_observations o
                JOIN scout_tool_runs t
                  ON t.tenant_id = o.tenant_id AND t.job_id = o.job_id AND t.id = o.tool_run_id
                JOIN scout_jobs j
                  ON j.tenant_id = o.tenant_id AND j.id = o.job_id
                LEFT JOIN LATERAL (
                    SELECT e.id AS exposure_id, e.finding_id, f.canonical_cve_id,
                           e.status AS exposure_status
                    FROM asset_exposures e
                    JOIN findings f
                      ON f.tenant_id = e.tenant_id AND f.id = e.finding_id
                    WHERE e.tenant_id = o.tenant_id AND e.asset_id = j.asset_id
                      AND e.status = 'confirmed'
                      AND e.evidence->>'scout_job_id' = o.job_id::text
                      AND e.evidence->>'scout_observation_id' = o.id::text
                    ORDER BY e.confirmed_at, e.id LIMIT 1
                ) linked ON true
                WHERE o.tenant_id = %s AND o.job_id = %s
                ORDER BY o.created_at, o.id
                """,
                (str(auth.tenant_id), str(job_id)),
            )
            rows = []
            for row in cur.fetchall():
                item = dict(row)
                exposure_id = item.pop("exposure_id")
                finding_id = item.pop("finding_id")
                canonical_cve_id = item.pop("canonical_cve_id")
                exposure_status = item.pop("exposure_status")
                item["normalized_exposure"] = None if exposure_id is None else {
                    "exposure_id": exposure_id,
                    "finding_id": finding_id,
                    "canonical_cve_id": canonical_cve_id,
                    "status": exposure_status,
                }
                rows.append(item)
            return rows
