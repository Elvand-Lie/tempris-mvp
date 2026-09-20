import copy
import json
import threading
import uuid

import pytest

from app.collector_registry import collector_registry
from app.db import get_db_connection
from app.scout import ToolProbe, _job_row, _normalize_nuclei_observation, _qualifying_nuclei
from tests.conftest import TENANT_A, TENANT_B
from tests.test_scout_sprint01 import create_authorized_asset, successful_process


CVE_ID = "CVE-2999-9001"


def nuclei_event(cve_id=CVE_ID):
    return {
        "template-id": cve_id,
        "matcher-name": "exact-product",
        "type": "http",
        "host": "https://demo.example",
        "matched-at": "https://demo.example/path",
        "info": {
            "name": "Exact published vulnerability",
            "severity": "high",
            "classification": {"cve-id": [cve_id]},
        },
        "timestamp": "2026-09-01T12:00:00Z",
    }


def nuclei_payload(event=None):
    return json.dumps(event or nuclei_event()).encode()


def seed_canonical(cve_id=CVE_ID, state="PUBLISHED"):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO canonical_vulnerabilities (cve_id, state)
                VALUES (%s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET state = EXCLUDED.state
                """,
                (cve_id, state),
            )
        conn.commit()


def launch_vulnerability_job(client, headers, monkeypatch, payload=None, asset_id=None):
    successful_process(monkeypatch, nuclei_payload=payload or nuclei_payload())
    if asset_id is None:
        asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "VULNERABILITY_ASSESSMENT"},
        headers=headers,
    )
    assert response.status_code == 201
    return response.json()["id"], asset_id


def exposure_counts(asset_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(DISTINCT f.id) AS findings, count(e.id) AS exposures
                FROM findings f
                LEFT JOIN asset_exposures e
                  ON e.tenant_id = f.tenant_id AND e.finding_id = f.id
                 AND e.asset_id = %s AND e.status = 'confirmed'
                WHERE f.tenant_id = %s AND f.canonical_cve_id = %s AND f.status = 'open'
                """,
                (str(asset_id), str(TENANT_A), CVE_ID),
            )
            return cur.fetchone()


def test_readiness_is_live_redacted_tenant_scoped_and_collector_deferred(
    client, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin, platform_admin_headers, monkeypatch
):
    probes = {
        "nmap": ToolProbe("nmap", "unavailable", None),
        "nuclei": ToolProbe(
            "nuclei", "available", r"C:\Users\service\nuclei.exe",
            engine_version="v3.8.0", templates_version=None, stderr="private stderr",
        ),
    }
    monkeypatch.setattr("app.routes.scout.probe_tool", lambda engine: probes[engine])
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO collectors (tenant_id, name, enrollment_status, operator_status)
                VALUES (%s, 'A collector', 'enrolled', 'active'),
                       (%s, 'B collector', 'enrolled', 'active')
                RETURNING id, tenant_id
                """,
                (str(TENANT_A), str(TENANT_B)),
            )
            created = cur.fetchall()
        conn.commit()
    a_collector = next(row["id"] for row in created if row["tenant_id"] == TENANT_A)
    monkeypatch.setattr(
        collector_registry,
        "is_connected",
        lambda collector_id: collector_id == a_collector,
    )

    response = client.get("/api/scout/readiness", headers=auth_headers_tenant_a_admin)
    assert response.status_code == 200
    body = response.json()
    assert body["engines"] == [
        {"engine": "nmap", "state": "unavailable", "engine_version": None, "templates_version": None},
        {"engine": "nuclei", "state": "available", "engine_version": "v3.8.0", "templates_version": None},
    ]
    assert body["profiles"] == {
        "SERVICE_DISCOVERY": {"state": "blocked", "blockers": ["nmap"]},
        "VULNERABILITY_ASSESSMENT": {"state": "blocked", "blockers": ["nmap"]},
    }
    assert body["collector"] == {
        "state": "not_executable_in_sprint_02",
        "total": 1,
        "connected": 1,
        "message": "INTERNAL Collector execution is deferred to Sprint 03.",
    }
    serialized = json.dumps(body)
    assert r"C:\\Users\\service" not in serialized and "private stderr" not in serialized
    assert all("executable" not in engine and "stderr" not in engine for engine in body["engines"])

    tenant_b = client.get("/api/scout/readiness", headers=auth_headers_tenant_b_admin).json()
    assert tenant_b["collector"]["total"] == 1 and tenant_b["collector"]["connected"] == 0
    assert client.get("/api/scout/readiness", headers=platform_admin_headers).status_code == 403


def test_qualifying_nuclei_requires_every_exact_identity_field():
    valid = {"scanner": "nuclei", "event": nuclei_event()}
    assert _qualifying_nuclei("template_match", valid)["cve_id"] == CVE_ID

    invalid = []
    for path, value in (
        (("template-id",), "cve-2999-9001"),
        (("template-id",), f"prefix-{CVE_ID}"),
        (("matcher-name",), " "),
        (("matched-at",), ""),
        (("info", "name"), ""),
        (("info", "severity"), "unknown"),
        (("info", "classification", "cve-id"), []),
        (("info", "classification", "cve-id"), [CVE_ID, "CVE-2999-9002"]),
        (("info", "classification", "cve-id"), ["CVE-2999-9002"]),
    ):
        candidate = copy.deepcopy(valid)
        target = candidate["event"]
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        invalid.append(candidate)
    invalid.extend([
        {**copy.deepcopy(valid), "scanner": "nmap"},
        {"scanner": "nuclei", "event": []},
    ])

    assert all(_qualifying_nuclei("template_match", item) is None for item in invalid)
    assert _qualifying_nuclei("service", valid) is None


def test_qualifying_observation_creates_exact_frozen_domain_records_and_api_link(
    client, auth_headers_tenant_a_admin, monkeypatch
):
    seed_canonical()
    job_id, asset_id = launch_vulnerability_job(client, auth_headers_tenant_a_admin, monkeypatch)
    job = client.get(f"/api/scout/jobs/{job_id}", headers=auth_headers_tenant_a_admin).json()
    observations = client.get(
        f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_a_admin
    ).json()
    vulnerability = next(row for row in observations if row["scanner"] == "nuclei")

    assert job["status"] == "succeeded"
    assert vulnerability["normalized_exposure"]["canonical_cve_id"] == CVE_ID
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT f.*, e.id AS exposure_id, e.status AS exposure_status,
                       e.evidence, e.confirmed_by
                FROM findings f JOIN asset_exposures e
                  ON e.tenant_id = f.tenant_id AND e.finding_id = f.id
                WHERE f.tenant_id = %s AND e.asset_id = %s AND f.canonical_cve_id = %s
                """,
                (str(TENANT_A), str(asset_id), CVE_ID),
            )
            row = cur.fetchone()
    assert row["title"] == "Exact published vulnerability"
    assert row["severity"] == "high"
    assert row["exposure_status"] == "confirmed"
    assert row["confirmed_by"] == f"scout:{job_id}"
    assert row["evidence"]["source"] == "scout"
    assert row["evidence"]["scout_observation_id"] == vulnerability["id"]
    assert r"C:\Users" not in json.dumps(row["evidence"])
    assert str(row["exposure_id"]) == vulnerability["normalized_exposure"]["exposure_id"]


@pytest.mark.parametrize("canonical_state", [None, "RESERVED", "REJECTED"])
def test_non_published_canonical_identity_never_normalizes(
    client, auth_headers_tenant_a_admin, monkeypatch, canonical_state
):
    if canonical_state:
        seed_canonical(state=canonical_state)
    else:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM canonical_vulnerabilities WHERE cve_id = %s", (CVE_ID,))
            conn.commit()
    job_id, asset_id = launch_vulnerability_job(client, auth_headers_tenant_a_admin, monkeypatch)
    observations = client.get(
        f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_a_admin
    ).json()
    assert next(row for row in observations if row["scanner"] == "nuclei")["normalized_exposure"] is None
    assert exposure_counts(asset_id) == {"findings": 0, "exposures": 0}


def test_replay_and_concurrent_observations_reuse_one_current_exposure(
    client, auth_headers_tenant_a_admin, monkeypatch
):
    seed_canonical()
    job_id, asset_id = launch_vulnerability_job(client, auth_headers_tenant_a_admin, monkeypatch)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scout_jobs WHERE id = %s", (job_id,))
            job = dict(cur.fetchone())
            cur.execute(
                """
                INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                SELECT tenant_id, job_id, id, 'template_match', %s::jsonb
                FROM scout_tool_runs WHERE job_id = %s AND engine = 'nuclei'
                RETURNING id
                """,
                (json.dumps({"scanner": "nuclei", "event": nuclei_event()}), job_id),
            )
            second_observation = cur.fetchone()["id"]
        conn.commit()

    first_observation = uuid.UUID(next(
        row["id"] for row in client.get(
            f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_a_admin
        ).json() if row["scanner"] == "nuclei"
    ))
    errors = []

    def normalize(observation_id):
        try:
            with get_db_connection() as conn:
                _normalize_nuclei_observation(conn, job, observation_id)
                conn.commit()
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=normalize, args=(first_observation,)),
        threading.Thread(target=normalize, args=(second_observation,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors and all(not thread.is_alive() for thread in threads)
    assert exposure_counts(asset_id) == {"findings": 1, "exposures": 1}


def test_parent_mismatch_fails_closed(client, auth_headers_tenant_a_admin, monkeypatch):
    seed_canonical()
    job_id, _ = launch_vulnerability_job(client, auth_headers_tenant_a_admin, monkeypatch)
    other_asset, _ = create_authorized_asset(target="203.0.113.99")
    job = _job_row(uuid.UUID(job_id), TENANT_A)
    job["asset_id"] = other_asset
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT o.id FROM scout_observations o JOIN scout_tool_runs t ON t.id = o.tool_run_id
                   WHERE o.job_id = %s AND t.engine = 'nuclei'""",
                (job_id,),
            )
            observation_id = cur.fetchone()["id"]
        with pytest.raises(RuntimeError, match="parentage"):
            _normalize_nuclei_observation(conn, job, observation_id)


def test_second_job_detection_reuses_finding_and_replays_exposure(
    client, auth_headers_tenant_a_admin, monkeypatch
):
    """P0-01 fix 3/5: the two-findings-one-CVE ambiguity state this test used to
    seed is now unrepresentable — finding identity is unique per
    (tenant, canonical_cve_id) and SCOUT normalization owns no separate dedupe
    path. A second job detecting the same CVE converges: the shared allocator
    reuses the finding and the shared confirmation command replays the current
    episode (idempotent), so the job succeeds with one finding and one
    exposure."""
    seed_canonical()
    first_job_id, asset_id = launch_vulnerability_job(client, auth_headers_tenant_a_admin, monkeypatch)
    assert exposure_counts(asset_id) == {"findings": 1, "exposures": 1}

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT e.id, e.confirmed_by FROM asset_exposures e
                WHERE e.tenant_id = %s AND e.asset_id = %s AND e.status = 'confirmed'
                """,
                (str(TENANT_A), str(asset_id)),
            )
            first_row = cur.fetchone()
    assert first_row["confirmed_by"] == f"scout:{first_job_id}"

    second_job_id, _ = launch_vulnerability_job(
        client, auth_headers_tenant_a_admin, monkeypatch, asset_id=asset_id
    )
    job = client.get(f"/api/scout/jobs/{second_job_id}", headers=auth_headers_tenant_a_admin).json()
    observations = client.get(
        f"/api/scout/jobs/{second_job_id}/observations", headers=auth_headers_tenant_a_admin
    ).json()

    assert first_job_id != second_job_id
    assert job["status"] == "succeeded", job
    vulnerability = next(row for row in observations if row["scanner"] == "nuclei")
    # The replay never rewrites provenance: the standing episode's evidence still
    # names the FIRST job's observation, so this job's observation links to none.
    assert vulnerability["normalized_exposure"] is None

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT e.id, e.status, e.confirmed_by FROM asset_exposures e
                WHERE e.tenant_id = %s AND e.asset_id = %s
                """,
                (str(TENANT_A), str(asset_id)),
            )
            rows = cur.fetchall()
    # One finding, one current episode — the original confirmation stands
    assert len(rows) == 1
    assert str(rows[0]["id"]) == str(first_row["id"])
    assert rows[0]["status"] == "confirmed"
    assert rows[0]["confirmed_by"] == f"scout:{first_job_id}"
    assert exposure_counts(asset_id) == {"findings": 1, "exposures": 1}
