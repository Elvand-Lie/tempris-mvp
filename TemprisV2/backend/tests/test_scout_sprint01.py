import json
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import config

import psycopg
import pytest

from app.db import get_db_connection
from app.scout import (
    NMAP_TIMEOUT,
    NUCLEI_TIMEOUT,
    OUTPUT_LIMIT,
    ProcessResult,
    execute_job,
    nmap_argv,
    nuclei_argv,
    parse_nmap_xml,
    parse_nuclei_jsonl,
    probe_tool,
    run_bounded,
)
from migrations.runner import run_migrations
from tests.conftest import TENANT_A, TENANT_B

@pytest.fixture(autouse=True)
def _scout_nuclei_templates(monkeypatch, tmp_path):
    """Server-plane Nuclei refuses without a pinned templates dir (fail closed).

    Every central-execution test in this module points SCOUT_NUCLEI_TEMPLATES_DIR
    at a valid pinned directory so the fail-closed path stays out of the way.
    """
    templates_dir = tmp_path / "nuclei-templates"
    (templates_dir / "http").mkdir(parents=True)
    (templates_dir / "http" / "cve-test.yaml").write_text("id: cve-test\n")
    monkeypatch.setattr("app.config.SCOUT_NUCLEI_TEMPLATES_DIR", str(templates_dir))


FIXTURES = Path(__file__).parent / "fixtures" / "scout"
NMAP_EXE = r"C:\tools\nmap.exe"
NUCLEI_EXE = r"C:\tools\nuclei.exe"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def create_authorized_asset(tenant_id=TENANT_A, target="203.0.113.10"):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO assets (
                    tenant_id, name, asset_type, target_type, target_value,
                    normalized_target, network_scope, environment, criticality
                ) VALUES (%s, 'SCOUT fixture', 'server', 'ip', %s, %s,
                          'internet', 'test', 'medium')
                RETURNING id
                """,
                (str(tenant_id), target, target),
            )
            asset_id = cur.fetchone()["id"]
            cur.execute(
                """
                INSERT INTO asset_scan_authorizations (
                    tenant_id, asset_id, target_type, normalized_target, network_scope,
                    status, requested_by, approved_by, approved_at, expires_at
                ) VALUES (%s, %s, 'ip', %s, 'internet', 'approved',
                          'fixture', 'fixture', now(), now() + interval '1 hour')
                RETURNING id
                """,
                (str(tenant_id), str(asset_id), target),
            )
            authorization_id = cur.fetchone()["id"]
        conn.commit()
    return asset_id, authorization_id


def insert_job(tenant_id, asset_id, authorization_id, profile="SERVICE_DISCOVERY"):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scout_jobs (
                    tenant_id, asset_id, authorization_id, profile, target_type,
                    normalized_target, network_scope, authorization_approved_at,
                    authorization_expires_at, requested_by
                )
                SELECT %s, %s, %s, %s, a.target_type, a.normalized_target,
                       a.network_scope, au.approved_at, au.expires_at, 'fixture'
                FROM assets a JOIN asset_scan_authorizations au ON au.id = %s
                WHERE a.id = %s
                RETURNING id
                """,
                (
                    str(tenant_id), str(asset_id), str(authorization_id), profile,
                    str(authorization_id), str(asset_id),
                ),
            )
            job_id = cur.fetchone()["id"]
        conn.commit()
    return job_id


def successful_process(monkeypatch, nuclei_payload=None, after_nmap=None):
    calls = []

    monkeypatch.setattr("app.scout.shutil.which", lambda name: NMAP_EXE if name == "nmap" else NUCLEI_EXE)

    def fake(argv, timeout, *, on_started=None):
        calls.append((list(argv), timeout))
        if on_started:
            on_started()
        if argv == [NMAP_EXE, "--version"]:
            return ProcessResult("succeeded", 0, b"Nmap version 7.95", b"")
        if argv == [NUCLEI_EXE, "-version"]:
            return ProcessResult("succeeded", 0, b"Nuclei Engine Version: v3.8.0", b"")
        if argv == [NUCLEI_EXE, "-templates-version"]:
            return ProcessResult("succeeded", 0, b"Nuclei Templates Version: v10.2.0", b"")
        if "-oX" in argv:
            if after_nmap:
                after_nmap()
            return ProcessResult("succeeded", 0, fixture("nmap_valid.xml"), b"")
        if "-jsonl" in argv:
            return ProcessResult("succeeded", 0, nuclei_payload or fixture("nuclei_valid.jsonl"), b"")
        raise AssertionError(argv)

    monkeypatch.setattr("app.scout.run_bounded", fake)
    return calls


def test_migration_constraints_and_immutability():
    with get_db_connection() as conn:
        run_migrations(conn)
        run_migrations(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT conname FROM pg_constraint
                WHERE conrelid IN ('scout_jobs'::regclass, 'scout_tool_runs'::regclass,
                                   'scout_observations'::regclass)
                """
            )
            names = {row["conname"] for row in cur.fetchall()}
    assert {
        "fk_scout_job_asset", "fk_scout_job_authorization",
        "fk_scout_tool_run_job", "fk_scout_observation_tool_run",
    } <= names

    asset_id, authorization_id = create_authorized_asset()
    job_id = insert_job(TENANT_A, asset_id, authorization_id)
    with pytest.raises(psycopg.errors.RaiseException):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE scout_jobs SET normalized_target = '198.51.100.9' WHERE id = %s", (str(job_id),))


def test_database_rejects_wrong_asset_and_wrong_job_bindings():
    asset_a1, auth_a1 = create_authorized_asset(target="203.0.113.21")
    asset_a2, auth_a2 = create_authorized_asset(target="203.0.113.22")
    asset_b, auth_b = create_authorized_asset(TENANT_B, target="203.0.113.23")

    for tenant, asset, authorization in (
        (TENANT_A, asset_a1, auth_a2),
        (TENANT_A, asset_a1, auth_b),
        (TENANT_B, asset_a1, auth_a1),
    ):
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            insert_job(tenant, asset, authorization)

    job1 = insert_job(TENANT_A, asset_a1, auth_a1)
    job2 = insert_job(TENANT_A, asset_a2, auth_a2)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO scout_tool_runs (tenant_id, job_id, engine, ordinal, state)
                   VALUES (%s, %s, 'nmap', 1, 'available') RETURNING id""",
                (str(TENANT_A), str(job1)),
            )
            tool_run_id = cur.fetchone()["id"]
        conn.commit()

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO scout_observations (tenant_id, job_id, tool_run_id, kind, evidence)
                       VALUES (%s, %s, %s, 'service', '{}'::jsonb)""",
                    (str(TENANT_A), str(job2), str(tool_run_id)),
                )

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO scout_tool_runs (tenant_id, job_id, engine, ordinal, state)
                       VALUES (%s, %s, 'nmap', 1, 'available')""",
                    (str(TENANT_B), str(job1)),
                )

    assert asset_b and auth_b


def test_parsers_preserve_native_evidence_without_inference():
    valid_nmap = parse_nmap_xml(fixture("nmap_valid.xml"))
    assert valid_nmap[0][1]["scanner"] == "nmap"
    assert valid_nmap[0][1]["port"]["service"]["product"] == "Example CVE-2099-9999 banner"
    assert "cve_id" not in json.dumps(valid_nmap).lower()
    assert parse_nmap_xml(fixture("nmap_empty.xml")) == []
    assert parse_nmap_xml(fixture("nmap_partial.xml"))[0][1]["port"]["service"] is None
    with pytest.raises(Exception):
        parse_nmap_xml(fixture("nmap_malformed.xml"))

    valid_nuclei = parse_nuclei_jsonl(fixture("nuclei_valid.jsonl"))
    event = valid_nuclei[0][1]["event"]
    assert event["template-id"] == "CVE-2024-0001"
    assert event["matcher-name"] == "exact-product"
    assert parse_nuclei_jsonl(fixture("nuclei_empty.jsonl")) == []
    partial = parse_nuclei_jsonl(fixture("nuclei_partial.jsonl"))[0][1]
    assert set(partial) == {"scanner", "event"}
    # Tolerant parser (observability work): the malformed line is skipped with
    # line telemetry, the valid lines in the same payload still parse.
    assert parse_nuclei_jsonl(fixture("nuclei_malformed.jsonl")) == [
        ("template_match", {"scanner": "nuclei", "event": {"template-id": "valid-prefix", "matched-at": "https://demo.example"}})
    ]


def test_nuclei_parser_exposes_only_safe_source_native_fields():
    source = {
        "template-id": "CVE-2024-0001",
        "matcher-name": "exact-product",
        "type": "http",
        "host": "https://demo.example",
        "matched-at": "https://demo.example/path",
        "path": "/remote/path",
        "template": "http/safe.yaml",
        "info": {"classification": {"cve-id": ["CVE-2024-0001"]}},
        "meta": {
            "template_path": r"\\server\share\private.yaml",
            "keep": "source-native",
        },
        "template-path": "/home/service/private.yaml",
        "templatePath": "file:///C:/Users/service/private.yaml",
    }
    event = parse_nuclei_jsonl(json.dumps(source).encode())[0][1]["event"]

    assert event == {
        "template-id": "CVE-2024-0001",
        "matcher-name": "exact-product",
        "type": "http",
        "host": "https://demo.example",
        "matched-at": "https://demo.example/path",
        "info": {"classification": {"cve-id": ["CVE-2024-0001"]}},
    }


def test_exact_argv_profiles_and_successful_tenant_api(client, auth_headers_tenant_a_admin, auth_headers_tenant_b_admin, monkeypatch):
    calls = successful_process(monkeypatch)
    asset_a, _ = create_authorized_asset()
    asset_b, _ = create_authorized_asset(TENANT_B, target="203.0.113.30")

    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_a), "profile": "VULNERABILITY_ASSESSMENT"},
        headers=auth_headers_tenant_a_admin,
    )
    assert response.status_code == 201
    job_id = response.json()["id"]

    assert [argv for argv, _ in calls] == [
        [NMAP_EXE, "--version"],
        [NUCLEI_EXE, "-version"],
        [NUCLEI_EXE, "-templates-version"],
        nmap_argv(NMAP_EXE, "203.0.113.10"),
        nuclei_argv(NUCLEI_EXE, "203.0.113.10", config.SCOUT_NUCLEI_TEMPLATES_DIR),
    ]
    assert [timeout for _, timeout in calls][-2:] == [NMAP_TIMEOUT, NUCLEI_TIMEOUT]

    detail = client.get(f"/api/scout/jobs/{job_id}", headers=auth_headers_tenant_a_admin)
    assert detail.status_code == 200
    assert detail.json()["status"] == "succeeded"
    assert detail.json()["normalized_target"] == "203.0.113.10"
    assert [item["state"] for item in detail.json()["source_health"]] == ["succeeded", "succeeded"]
    assert "executable_path" not in json.dumps(detail.json())
    assert r"C:\tools" not in json.dumps(detail.json())

    observations = client.get(f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_a_admin)
    assert observations.status_code == 200
    assert [row["scanner"] for row in observations.json()] == ["nmap", "nuclei"]

    assert client.get(f"/api/scout/jobs/{job_id}", headers=auth_headers_tenant_b_admin).status_code == 404
    assert client.get(f"/api/scout/jobs/{job_id}/observations", headers=auth_headers_tenant_b_admin).status_code == 404
    assert all(row["id"] != job_id for row in client.get("/api/scout/jobs", headers=auth_headers_tenant_b_admin).json())
    assert client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_b), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    ).status_code == 404


def test_nuclei_template_paths_are_absent_from_storage_and_tenant_api(client, auth_headers_tenant_a_admin, monkeypatch):
    secret_path = r"C:\Users\service-account\nuclei-templates\private.yaml"
    payload = json.dumps({
        "template-id": "CVE-2024-0001",
        "matcher-name": "exact-product",
        "type": "http",
        "host": "https://demo.example",
        "matched-at": "https://demo.example/path",
        "info": {"classification": {"cve-id": ["CVE-2024-0001"]}},
        "template-path": secret_path,
    }).encode()
    successful_process(monkeypatch, nuclei_payload=payload)
    asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "VULNERABILITY_ASSESSMENT"},
        headers=auth_headers_tenant_a_admin,
    )
    job_id = response.json()["id"]

    api_rows = client.get(
        f"/api/scout/jobs/{job_id}/observations",
        headers=auth_headers_tenant_a_admin,
    ).json()
    nuclei_event = next(row["evidence"]["event"] for row in api_rows if row["scanner"] == "nuclei")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT o.evidence FROM scout_observations o
                   JOIN scout_tool_runs t ON t.id = o.tool_run_id
                   WHERE o.job_id = %s AND t.engine = 'nuclei'""",
                (job_id,),
            )
            stored_event = cur.fetchone()["evidence"]["event"]

    assert nuclei_event == stored_event
    assert secret_path not in json.dumps(nuclei_event)
    assert nuclei_event == {
        "template-id": "CVE-2024-0001",
        "matcher-name": "exact-product",
        "type": "http",
        "host": "https://demo.example",
        "matched-at": "https://demo.example/path",
        "info": {"classification": {"cve-id": ["CVE-2024-0001"]}},
    }


@pytest.mark.parametrize("field", ["target", "target_value", "cidr", "command", "args", "proxy", "collector_id", "timeout"])
def test_launch_rejects_all_caller_execution_controls(client, auth_headers_tenant_a_admin, field):
    asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY", field: "attacker-value"},
        headers=auth_headers_tenant_a_admin,
    )
    assert response.status_code == 422


def test_launch_requires_public_active_exact_current_authorization(client, auth_headers_tenant_a_admin):
    asset_id, authorization_id = create_authorized_asset()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE asset_scan_authorizations SET status = 'revoked' WHERE id = %s", (str(authorization_id),))
        conn.commit()
    assert client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    ).status_code == 409
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS count FROM scout_jobs")
            assert cur.fetchone()["count"] == 0


@pytest.mark.parametrize("gate", ["pending", "expired", "mismatch", "internal", "decommissioned"])
def test_launch_rejects_every_ineligible_asset_or_authorization(client, auth_headers_tenant_a_admin, gate):
    asset_id, authorization_id = create_authorized_asset()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            if gate == "pending":
                cur.execute("UPDATE asset_scan_authorizations SET status = 'pending' WHERE id = %s", (str(authorization_id),))
            elif gate == "expired":
                cur.execute("UPDATE asset_scan_authorizations SET expires_at = now() - interval '1 second' WHERE id = %s", (str(authorization_id),))
            elif gate == "mismatch":
                cur.execute("UPDATE asset_scan_authorizations SET normalized_target = '198.51.100.8' WHERE id = %s", (str(authorization_id),))
            elif gate == "internal":
                cur.execute("UPDATE assets SET network_scope = 'internal' WHERE id = %s", (str(asset_id),))
            else:
                cur.execute("UPDATE assets SET status = 'decommissioned' WHERE id = %s", (str(asset_id),))
        conn.commit()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    assert response.status_code == 409


def test_missing_nmap_is_honest_and_nuclei_is_still_probed(client, auth_headers_tenant_a_admin, monkeypatch):
    calls = []
    monkeypatch.setattr("app.scout.shutil.which", lambda name: None if name == "nmap" else NUCLEI_EXE)

    def fake(argv, timeout, *, on_started=None):
        calls.append(list(argv))
        if on_started:
            on_started()
        output = b"Nuclei Engine Version: v3.8.0" if "-version" in argv else b"Nuclei Templates Version: v10.2.0"
        return ProcessResult("succeeded", 0, output, b"")

    monkeypatch.setattr("app.scout.run_bounded", fake)
    asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "VULNERABILITY_ASSESSMENT"},
        headers=auth_headers_tenant_a_admin,
    )
    job = client.get(f"/api/scout/jobs/{response.json()['id']}", headers=auth_headers_tenant_a_admin).json()
    assert job["status"] == "failed"
    assert job["error_code"] == "tool_unavailable"
    assert calls == [[NUCLEI_EXE, "-version"], [NUCLEI_EXE, "-templates-version"]]
    assert [(row["engine"], row["state"]) for row in job["source_health"]] == [
        ("nmap", "unavailable"), ("nuclei", "available"),
    ]


def test_malformed_nuclei_is_atomic_and_fails_job(client, auth_headers_tenant_a_admin, monkeypatch):
    successful_process(monkeypatch, nuclei_payload=fixture("nuclei_malformed.jsonl"))
    asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "VULNERABILITY_ASSESSMENT"},
        headers=auth_headers_tenant_a_admin,
    )
    job_id = response.json()["id"]
    job = client.get(f"/api/scout/jobs/{job_id}", headers=auth_headers_tenant_a_admin).json()
    # Tolerant parser contract: an all-malformed nuclei payload is skipped with
    # line telemetry, so the job succeeds with zero nuclei observations instead
    # of failing the whole run (nmap evidence is kept either way).
    assert job["status"] == "succeeded"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT t.engine, count(o.id) AS observations
                FROM scout_tool_runs t LEFT JOIN scout_observations o ON o.tool_run_id = t.id
                WHERE t.job_id = %s GROUP BY t.engine
                """,
                (job_id,),
            )
            counts = {row["engine"]: row["observations"] for row in cur.fetchall()}
    assert counts == {"nmap": 1, "nuclei": 1}


def test_malformed_nmap_persists_zero_observations(client, auth_headers_tenant_a_admin, monkeypatch):
    calls = successful_process(monkeypatch)

    def malformed(argv, timeout, *, on_started=None):
        if "-oX" in argv:
            calls.append((list(argv), timeout))
            if on_started:
                on_started()
            return ProcessResult("succeeded", 0, fixture("nmap_malformed.xml"), b"")
        return ProcessResult("succeeded", 0, b"Nmap version 7.95", b"")

    monkeypatch.setattr("app.scout.run_bounded", malformed)
    asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    job = client.get(f"/api/scout/jobs/{response.json()['id']}", headers=auth_headers_tenant_a_admin).json()
    assert job["status"] == "failed" and job["error_code"] == "parse_failed"
    assert client.get(
        f"/api/scout/jobs/{response.json()['id']}/observations",
        headers=auth_headers_tenant_a_admin,
    ).json() == []


@pytest.mark.parametrize("mutation", ["revoke", "expire", "decommission", "target", "scope"])
def test_authorization_barrier_blocks_nuclei_after_nmap(client, auth_headers_tenant_a_admin, monkeypatch, mutation):
    asset_id, authorization_id = create_authorized_asset()
    nmap_complete = threading.Event()
    mutation_complete = threading.Event()

    def mutate():
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                if mutation == "revoke":
                    cur.execute("UPDATE asset_scan_authorizations SET status = 'revoked' WHERE id = %s", (str(authorization_id),))
                elif mutation == "expire":
                    cur.execute("UPDATE asset_scan_authorizations SET expires_at = now() - interval '1 second' WHERE id = %s", (str(authorization_id),))
                elif mutation == "decommission":
                    cur.execute("UPDATE assets SET status = 'decommissioned' WHERE id = %s", (str(asset_id),))
                elif mutation == "target":
                    cur.execute("UPDATE assets SET normalized_target = '198.51.100.99' WHERE id = %s", (str(asset_id),))
                else:
                    cur.execute("UPDATE assets SET network_scope = 'internal' WHERE id = %s", (str(asset_id),))
            conn.commit()

    def mutator():
        assert nmap_complete.wait(5)
        mutate()
        mutation_complete.set()

    thread = threading.Thread(target=mutator)
    thread.start()

    def barrier():
        nmap_complete.set()
        assert mutation_complete.wait(5)

    calls = successful_process(monkeypatch, after_nmap=barrier)
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "VULNERABILITY_ASSESSMENT"},
        headers=auth_headers_tenant_a_admin,
    )
    job = client.get(f"/api/scout/jobs/{response.json()['id']}", headers=auth_headers_tenant_a_admin).json()
    assert job["status"] == "failed"
    assert job["error_code"] == "authorization_invalid"
    assert not any("-target" in argv for argv, _ in calls)
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_terminal_job_cannot_be_replayed(client, auth_headers_tenant_a_admin, monkeypatch):
    calls = successful_process(monkeypatch)
    asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    job_id = uuid.UUID(response.json()["id"])
    before = len(calls)
    execute_job(job_id, TENANT_A)
    assert len(calls) == before


def test_live_output_limit_terminates_flooding_child():
    started = time.monotonic()
    result = run_bounded(
        [sys.executable, "-c", "import sys\nb=b'x'*65536\nwhile True:\n sys.stdout.buffer.write(b); sys.stdout.buffer.flush()"],
        timeout=10,
    )
    assert result.state == "output_limited"
    assert len(result.stdout) + len(result.stderr) == OUTPUT_LIMIT
    assert time.monotonic() - started < 5


def test_spawn_oserror_is_bounded_without_signalling_started(monkeypatch):
    started = []

    def fail_spawn(*args, **kwargs):
        raise PermissionError("scanner executable is not runnable")

    monkeypatch.setattr("app.scout.subprocess.Popen", fail_spawn)
    result = run_bounded([NMAP_EXE, "--version"], 1, on_started=lambda: started.append(True))

    assert result.state == "failed"
    assert result.returncode is None
    assert result.stdout == b""
    assert b"not runnable" in result.stderr
    assert started == []


@pytest.mark.parametrize("failure_stage", ["probe", "scan"])
def test_spawn_failure_terminalizes_job(client, auth_headers_tenant_a_admin, monkeypatch, failure_stage):
    calls = []
    monkeypatch.setattr("app.scout.shutil.which", lambda name: NMAP_EXE if name == "nmap" else NUCLEI_EXE)

    def boundary(argv, timeout, *, on_started=None):
        calls.append(list(argv))
        should_fail = (
            failure_stage == "probe" and argv == [NMAP_EXE, "--version"]
        ) or (
            failure_stage == "scan" and "-oX" in argv
        )
        if should_fail:
            return ProcessResult("failed", None, b"", b"spawn denied")
        if on_started:
            on_started()
        if argv == [NMAP_EXE, "--version"]:
            return ProcessResult("succeeded", 0, b"Nmap version 7.95", b"")
        if argv == [NUCLEI_EXE, "-version"]:
            return ProcessResult("succeeded", 0, b"Nuclei Engine Version: v3.8.0", b"")
        if argv == [NUCLEI_EXE, "-templates-version"]:
            return ProcessResult("succeeded", 0, b"Nuclei Templates Version: v10.2.0", b"")
        raise AssertionError(argv)

    monkeypatch.setattr("app.scout.run_bounded", boundary)
    asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={
            "asset_id": str(asset_id),
            "profile": "VULNERABILITY_ASSESSMENT" if failure_stage == "probe" else "SERVICE_DISCOVERY",
        },
        headers=auth_headers_tenant_a_admin,
    )
    job = client.get(
        f"/api/scout/jobs/{response.json()['id']}",
        headers=auth_headers_tenant_a_admin,
    ).json()

    assert job["status"] == "failed"
    assert job["error_code"] == ("tool_probe_failed" if failure_stage == "probe" else "tool_failed")
    assert job["source_health"][0]["state"] == "failed"
    assert job["source_health"][0]["exit_code"] is None
    assert job["source_health"][0]["completed_at"] is not None
    if failure_stage == "probe":
        assert [NUCLEI_EXE, "-templates-version"] in calls


@pytest.mark.parametrize("failure_state", ["output_limited", "timed_out"])
def test_process_boundary_failures_persist_and_fail_job(client, auth_headers_tenant_a_admin, monkeypatch, failure_state):
    monkeypatch.setattr("app.scout.shutil.which", lambda name: NMAP_EXE)
    real_runner = run_bounded

    def boundary(argv, timeout, *, on_started=None):
        if argv == [NMAP_EXE, "--version"]:
            if on_started:
                on_started()
            return ProcessResult("succeeded", 0, b"Nmap version 7.95", b"")
        if on_started:
            on_started()
        helper = (
            [sys.executable, "-c", "import sys\nb=b'x'*65536\nwhile True:\n sys.stdout.buffer.write(b); sys.stdout.buffer.flush()"]
            if failure_state == "output_limited"
            else [sys.executable, "-c", "import time; time.sleep(5)"]
        )
        return real_runner(helper, 10 if failure_state == "output_limited" else 1)

    monkeypatch.setattr("app.scout.run_bounded", boundary)
    asset_id, _ = create_authorized_asset()
    response = client.post(
        "/api/scout/jobs",
        json={"asset_id": str(asset_id), "profile": "SERVICE_DISCOVERY"},
        headers=auth_headers_tenant_a_admin,
    )
    job = client.get(f"/api/scout/jobs/{response.json()['id']}", headers=auth_headers_tenant_a_admin).json()
    assert job["status"] == "failed"
    assert job["source_health"][0]["state"] == failure_state
    assert job["source_health"][0]["stdout_bytes"] <= OUTPUT_LIMIT


def test_real_tool_probes_are_truthful_and_portable():
    for engine in ("nmap", "nuclei"):
        result = probe_tool(engine)
        assert result.engine == engine
        assert result.state in {"available", "unavailable", "failed", "timed_out", "output_limited"}
        if result.state == "unavailable":
            assert result.executable is None and result.engine_version is None
