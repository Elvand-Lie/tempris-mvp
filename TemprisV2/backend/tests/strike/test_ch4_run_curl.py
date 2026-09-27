# backend/tests/strike/test_ch4_run_curl.py
"""
Chapter 4 acceptance — the toolbox run vertical slice (amended PRD v1.12
Ch.4, Phase 1 curl GET/HEAD).

Covers:
  * catalogue shows ONLY the wired capability (curl GET/HEAD), runnable,
    no approval required;
  * run creation: scope-checked against ACTIVE registry entries (migration
    041), one target per run, durable queued record + audit event;
  * hostname targets resolve at creation and the resolved IPs are PINNED
    into the policy snapshot; a resolved IP without its own active IP/CIDR
    entry (and without the hostname entry) refuses the run;
  * expiry and revocation are enforced at creation (derived at read);
  * target hygiene: credentials/userinfo refused, non-http(s) refused,
    CIDR targets refused, unknown capability refused, methods beyond
    GET/HEAD refused;
  * the PRD run state machine: queued → running → completed | failed, with
    cancel_requested → cancelled | cancel_unconfirmed for stops — ERROR is
    an execution error code, never a state;
  * MID-RUN scope revocation: the watched executor stops the container and
    the stop is CONFIRMED (cancelled) — or honestly cancel_unconfirmed —
    never silently assumed;
  * the runner's fixed-argv container plan: cap-drop ALL, per-run network,
    resource caps, NO --internal (a default subnet DROP + /32 ACCEPTs with
    the container subnet as source is the fence), --resolve DNS pinning,
    --max-filesize output bound, no -L, shell-less execution;
  * bounded host reads: the runner never materializes more than the 64 KiB
    inline bound regardless of output size;
  * tenant isolation: cross-tenant reads are the identical not-found;
  * the superseded-model gate: legacy engagement mutations refused (410),
    unconditional.
"""
from __future__ import annotations

import io
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.auth import create_test_token
from app.db import get_db_connection
from app.strike.runs import INLINE_RESULT_LIMIT_BYTES
from runner import execution
from runner.main import process_pending
from tests.conftest import TENANT_A, TENANT_B
from tests.strike.conftest import (
    engagement_payload,
    iso,
    make_fake_collector,
    remove_fake_collector,
)


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


RESOLVED_IP = "203.0.113.10"
RESOLVED_IP_2 = "203.0.113.11"

_collector = None


@pytest.fixture(autouse=True)
def fake_strike_collector():
    """Every run is dispatched to a collector: a live registry session for
    an enrolled tenant collector whose fake socket resolves STRIKE_JOB
    futures with the scripted (default: successful) result."""
    global _collector
    _collector = make_fake_collector(TENANT_A)
    yield _collector
    remove_fake_collector(_collector)
    _collector = None


def _fake_resolver(host, *args, **kwargs):
    pairs = [(2, RESOLVED_IP)]
    if host != "single.example.com":
        pairs.append((2, RESOLVED_IP_2))
    return [(family, None, None, "", (addr, 0)) for (family, addr) in pairs]


def create_scope(client, admin_headers, entry, *, ttl=timedelta(hours=1), expires_at=None):
    payload = {
        "entry": entry,
        "expires_at": expires_at or iso(datetime.now(timezone.utc) + ttl),
    }
    r = client.post("/api/strike/scopes", json=payload, headers=admin_headers)
    assert r.status_code == 201, r.text
    return r.json()


def create_run(client, analyst_headers, *, capability="curl", method="GET", target="203.0.113.10"):
    return client.post(
        "/api/strike/runs",
        json={
            "capability": capability,
            "method": method,
            "target": target,
            "collector_id": str(_collector["id"]),
        },
        headers=analyst_headers,
    )


def insert_server_run(client, analyst_headers, admin_headers, *, target="203.0.113.10"):
    """A queued VPS-plane run: the docker-runner path is plane-gated out of
    collector dispatch, so the runner-loop invariants are exercised by
    creating through the API and resetting the row to a queued server-plane
    run."""
    run = create_run(client, analyst_headers, target=target).json()
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE strike_runs SET state = 'queued', started_at = NULL,
                    completed_at = NULL, exit_code = NULL, error_code = NULL,
                    inline_result = NULL, inline_truncated = false,
                    runner_id = NULL, stop_reason = NULL,
                    policy_snapshot = policy_snapshot - 'execution_plane'
                WHERE id = %s;
                """,
                (uuid.UUID(run["id"]),),
            )
        conn.commit()
    return run


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------


def test_catalogue_lists_the_wired_phase1_capabilities(strike_client, analyst_headers):
    r = strike_client.get("/api/strike/catalogue", headers=analyst_headers)
    assert r.status_code == 200
    catalogue = {c["capability"]: c for c in r.json()}
    # the catalogue exposes the whole reviewed toolbox (migration 048), not
    # just the Phase-1 five
    assert set(catalogue) == {
        "curl", "nmap", "nuclei", "ffuf", "dig",
        "httpie", "nc", "socat", "python", "bash", "chromium", "mitmproxy",
    }
    curl = catalogue["curl"]
    assert curl["methods"] == ["GET", "HEAD"]
    # the execution-plane token is `server` (the platform sandbox), never `vps`
    assert curl["planes"] == ["server", "collector"]
    assert curl["runnable"] is True
    assert curl["requires_approval"] is False


# ---------------------------------------------------------------------------
# Creation — scope enforcement
# ---------------------------------------------------------------------------


def test_ip_run_created_durable_with_pinned_snapshot_and_audit(strike_client, analyst_headers, admin_headers):
    scope = create_scope(strike_client, admin_headers, "203.0.113.10")
    later_scope = create_scope(
        strike_client, admin_headers, "203.0.113.10", ttl=timedelta(hours=2)
    )
    r = create_run(strike_client, analyst_headers)
    assert r.status_code == 201, r.text
    run = r.json()
    # the run dispatches synchronously to the selected collector and returns
    # with its terminal outcome (the fake collector completes successfully)
    assert run["state"] == "completed"
    assert run["target_host"] == "203.0.113.10"
    assert run["policy_snapshot"]["pinned_ips"] == ["203.0.113.10"]
    assert scope["id"] in run["policy_snapshot"]["scope_entry_ids"]
    assert later_scope["id"] in run["policy_snapshot"]["scope_entry_ids"]
    assert datetime.fromisoformat(run["policy_snapshot"]["scope_expires_at"]) == (
        datetime.fromisoformat(scope["expires_at"])
    )
    assert run["raw_purge_after"] is not None  # 30-day raw retention is armed

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_name FROM audit_events WHERE asset_id = %s;",
                (uuid.UUID(run["id"]),),
            )
            events = [row["event_name"] for row in cur.fetchall()]
    assert "strike.run.created" in events


def test_out_of_scope_ip_refused(strike_client, analyst_headers):
    r = create_run(strike_client, analyst_headers, target="198.51.100.9")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_target_out_of_scope"


def test_expired_scope_entry_refused(strike_client, analyst_headers):
    # expiry is derived at read — seed an already-expired entry directly
    # (the API itself refuses past-dated expiry at creation)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO strike_testing_scopes (
                    tenant_id, entry_kind, value, created_by, expires_at
                ) VALUES (%s, 'ip', '203.0.113.10', 'seed', now() - interval '1 minute');
                """,
                (str(TENANT_A),),
            )
        conn.commit()
    r = create_run(strike_client, analyst_headers)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_target_out_of_scope"


def test_revoked_scope_entry_refused(strike_client, analyst_headers, admin_headers):
    scope = create_scope(strike_client, admin_headers, "203.0.113.10")
    r = strike_client.post(
        f"/api/strike/scopes/{scope['id']}/revoke",
        json={"reason": "engagement ended"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    r = create_run(strike_client, analyst_headers)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_target_out_of_scope"


def test_hostname_resolves_and_pins_its_runtime_ips(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "dual.example.com")
    monkeypatch.setattr("socket.getaddrinfo", _fake_resolver)
    r = create_run(strike_client, analyst_headers, target="https://dual.example.com/status?x=1")
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["policy_snapshot"]["pinned_ips"] == [RESOLVED_IP, RESOLVED_IP_2]
    assert run["policy_snapshot"]["hostname"] == "dual.example.com"
    assert run["target_url"] == "https://dual.example.com/status?x=1"


def test_hostname_without_scope_refused_even_when_resolving(strike_client, analyst_headers, monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _fake_resolver)
    r = create_run(strike_client, analyst_headers, target="dual.example.com")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_target_out_of_scope"


def test_new_dns_ip_needs_its_own_entry(strike_client, analyst_headers, admin_headers, monkeypatch):
    # an IP entry covers one resolved address but not the other — the run is
    # refused, never silently narrowed to the covered address
    create_scope(strike_client, admin_headers, RESOLVED_IP)
    monkeypatch.setattr("socket.getaddrinfo", _fake_resolver)
    r = create_run(strike_client, analyst_headers, target="dual.example.com")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_target_out_of_scope"


def test_hostname_authorized_via_containing_cidr(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.0/24")
    monkeypatch.setattr("socket.getaddrinfo", _fake_resolver)
    r = create_run(strike_client, analyst_headers, target="dual.example.com")
    assert r.status_code == 201, r.text
    assert r.json()["policy_snapshot"]["pinned_ips"] == [RESOLVED_IP, RESOLVED_IP_2]


# ---------------------------------------------------------------------------
# Creation — target/config hygiene
# ---------------------------------------------------------------------------


def test_cidr_is_not_a_single_target(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.0/24")
    r = create_run(strike_client, analyst_headers, target="203.0.113.0/24")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_config_invalid"


def test_url_with_credentials_refused(strike_client, analyst_headers):
    r = create_run(strike_client, analyst_headers, target="http://user:pass@203.0.113.10/")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_config_invalid"


def test_non_http_scheme_refused(strike_client, analyst_headers):
    r = create_run(strike_client, analyst_headers, target="ftp://203.0.113.10/")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_config_invalid"


def test_unknown_capability_refused(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    r = create_run(strike_client, analyst_headers, capability="telnet")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "capability_not_found"


def test_method_beyond_get_head_refused(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    r = create_run(strike_client, analyst_headers, method="POST")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# The runner loop — completed / failed paths
# ---------------------------------------------------------------------------


def _executor_output(run, check_alive=None):
    return execution.ExecutionResult(0, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


def test_run_lifecycle_through_the_runner_loop(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)

    monkeypatch.setenv("TEMPRIS_RUNNER_EXECUTOR", f"{__name__}._executor_output")
    assert process_pending(once=True) == 1

    r = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers)
    assert r.status_code == 200
    done = r.json()
    assert done["state"] == "completed"
    assert done["exit_code"] == 0
    assert "200 OK" in done["inline_result"]
    assert done["started_at"] is not None and done["completed_at"] is not None


def test_failed_execution_records_error_code_not_a_state(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)

    monkeypatch.setattr(
        f"{__name__}._executor_output",
        lambda run, check_alive=None: execution.ExecutionResult(
            7, "curl: (7) Failed to connect", "curl_exit_7"),
    )
    monkeypatch.setenv("TEMPRIS_RUNNER_EXECUTOR", f"{__name__}._executor_output")
    process_pending(once=True)

    done = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers).json()
    assert done["state"] == "failed"
    assert done["error_code"] == "curl_exit_7"  # ERROR is a code, never a state


def test_inline_result_bounded_at_64kib_with_flag(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)

    big = "x" * (INLINE_RESULT_LIMIT_BYTES + 1024)
    monkeypatch.setattr(
        f"{__name__}._executor_output",
        lambda run, check_alive=None: execution.ExecutionResult(0, big),
    )
    monkeypatch.setenv("TEMPRIS_RUNNER_EXECUTOR", f"{__name__}._executor_output")
    process_pending(once=True)

    done = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers).json()
    assert done["inline_truncated"] is True
    assert len(done["inline_result"].encode()) == INLINE_RESULT_LIMIT_BYTES


def test_bounded_read_never_materializes_more_than_the_bound():
    payload = "y" * (INLINE_RESULT_LIMIT_BYTES * 4)
    assert len(execution._bounded_read(io.BytesIO(payload.encode())).encode()) == INLINE_RESULT_LIMIT_BYTES
    assert execution._bounded_read(io.BytesIO(b"short")) == "short"


# ---------------------------------------------------------------------------
# The runner loop — stops: cancellation, scope death, confirmation honesty
# ---------------------------------------------------------------------------


def test_cancel_queued_run_is_trivially_confirmed(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)
    r = strike_client.post(f"/api/strike/runs/{run['id']}/cancel", headers=analyst_headers)
    assert r.status_code == 200
    assert r.json()["state"] == "cancelled"  # nothing was ever dispatched

    # the runner can no longer claim it
    monkey_ran = process_pending(once=True)
    assert monkey_ran == 0


def test_cancel_terminal_run_refused(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)
    monkeypatch.setenv("TEMPRIS_RUNNER_EXECUTOR", f"{__name__}._executor_output")
    process_pending(once=True)
    r = strike_client.post(f"/api/strike/runs/{run['id']}/cancel", headers=analyst_headers)
    assert r.status_code == 422


class _FakeProc:
    """Blocks in poll() until stopped — a container mid-flight."""

    def __init__(self):
        self.returncode = None
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()

    def poll(self):
        return self.returncode

    def wait(self):
        if self.returncode is None:
            self.returncode = -9
        return self.returncode


def _watched(run, check_alive=None, *, stop_confirmed=True, seen=None):
    seen = seen if seen is not None else {}
    assert check_alive is not None  # the loop must watch the scope
    seen["stopped"] = False

    def popen(cmd, stdout=None, stderr=None):
        seen["argv"] = cmd
        return _FakeProc()

    def stop(r):
        seen["stopped"] = True
        return stop_confirmed

    return execution.run_in_container(
        run, check_alive, poll_seconds=0.01,
        popen=popen, stop=stop, prepare=lambda: None, teardown=lambda: None,
        cut=lambda: None,
    )


def test_mid_run_scope_revocation_confirmed_stop(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)
    scopes = strike_client.get("/api/strike/scopes", headers=admin_headers).json()
    scope_id = scopes[0]["id"]

    seen = {}

    def watched(run, check_alive=None):
        # the REAL check_alive (registry-derived) drives the watch; the stop
        # is a fake confirmed container stop
        return _watched(run, check_alive, stop_confirmed=True, seen=seen)

    # claim succeeds (scope alive at claim time); the revocation lands on a
    # side thread mid-watch; the watch must stop the container and confirm
    monkeypatch.setenv("TEMPRIS_RUNNER_EXECUTOR", f"{__name__}._executor_output")
    monkeypatch.setattr(f"{__name__}._executor_output", watched)

    # first: claim happens inside process_pending; scope is alive; the watch
    # uses the REAL check_alive (re-derived from the registry). Revoke the
    # scope on a side thread after a short delay to hit the watch tick.
    import threading

    def revoke_later():
        import time

        time.sleep(0.05)
        strike_client.post(
            f"/api/strike/scopes/{scope_id}/revoke",
            json={"reason": "revoked mid-run"},
            headers=admin_headers,
        )

    t = threading.Thread(target=revoke_later)
    t.start()
    process_pending(once=True)
    t.join()

    assert seen["stopped"] is True
    done = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers).json()
    assert done["state"] == "cancelled"
    assert execution.SCOPE_STOP_CODE in (done["stop_reason"] or "")


def test_scope_revocation_before_execution_never_runs_the_executor(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)
    scopes = strike_client.get("/api/strike/scopes", headers=admin_headers).json()
    r = strike_client.post(
        f"/api/strike/scopes/{scopes[0]['id']}/revoke",
        json={"reason": "revoked mid-flight"},
        headers=admin_headers,
    )
    assert r.status_code == 200

    def _must_not_run(run, check_alive=None):
        raise AssertionError("the executor must not run after scope death")

    monkeypatch.setattr(f"{__name__}._executor_output", _must_not_run)
    monkeypatch.setenv("TEMPRIS_RUNNER_EXECUTOR", f"{__name__}._executor_output")
    process_pending(once=True)

    done = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers).json()
    assert done["state"] == "cancelled"
    assert "expired or revoked" in done["stop_reason"]


def test_unverified_midrun_stop_keeps_fence_and_halts_runner(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)
    scopes = strike_client.get("/api/strike/scopes", headers=admin_headers).json()
    scope_id = scopes[0]["id"]

    import threading
    import time

    def watched(run, check_alive=None):
        return _watched(run, check_alive, stop_confirmed=False)

    monkeypatch.setattr(f"{__name__}._executor_output", watched)
    monkeypatch.setenv("TEMPRIS_RUNNER_EXECUTOR", f"{__name__}._executor_output")

    def revoke_later():
        time.sleep(0.05)
        strike_client.post(
            f"/api/strike/scopes/{scope_id}/revoke",
            json={"reason": "revoked mid-run"},
            headers=admin_headers,
        )

    t = threading.Thread(target=revoke_later)
    t.start()
    # BOTH PRD invariants hold: the unverified stop keeps the fence and
    # halts claiming (fatal TeardownError), AND the scope-death stop is
    # recorded as the PRD Ch4 alarm cancel_requested → cancel_unconfirmed
    with pytest.raises(execution.TeardownError, match="fence left in place"):
        process_pending(once=True)
    t.join()

    done = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers).json()
    assert done["state"] == "cancel_unconfirmed"  # never a clean cancelled
    assert execution.SCOPE_STOP_UNCONFIRMED_CODE in (done["stop_reason"] or "")
    assert done["completed_at"] is not None


# ---------------------------------------------------------------------------
# History + isolation
# ---------------------------------------------------------------------------


def test_run_history_newest_first_and_tenant_isolated(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    first = create_run(strike_client, analyst_headers, target="203.0.113.10").json()
    second = create_run(strike_client, analyst_headers, target="203.0.113.10").json()

    runs = strike_client.get("/api/strike/runs", headers=analyst_headers).json()
    assert [r["id"] for r in runs] == [second["id"], first["id"]]

    token = create_test_token(tenant_id=str(TENANT_B), actor_id="analyst-b", role="analyst")
    r = strike_client.get(
        f"/api/strike/runs/{first['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# The runner's fixed-argv container plan (review findings 1 & 2)
# ---------------------------------------------------------------------------


def _canary_run():
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "method": "HEAD",
        "target_host": "dual.example.com",
        "target_port": 8443,
        "target_url": None,
        "policy_snapshot": {
            "pinned_ips": [RESOLVED_IP, RESOLVED_IP_2],
            "scope_expires_at": "2026-09-25T00:00:00+00:00",
        },
    }


def test_container_plan_is_fixed_unprivileged_and_pinned():
    run = _canary_run()
    argv = execution.container_argv(run)
    assert argv[:2] == ["docker", "run"]
    assert "--rm" in argv and "--read-only" in argv
    assert "--internal" not in argv  # --internal would block the pinned target
    name = execution.network_name(run)
    assert argv[argv.index("--name") + 1] == name      # confirmed stops need a name
    assert argv[argv.index("--network") + 1] == name
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--pids-limit") + 1] == "64"
    assert execution.CURL_IMAGE.endswith("8.10.1")  # pinned, never floating
    curl = argv[argv.index(execution.CURL_IMAGE) + 1:]
    assert curl[0] == "curl"
    # DNS is pinned at execution: one --resolve per pinned destination
    resolves = [curl[i + 1] for i, a in enumerate(curl) if a == "--resolve"]
    assert resolves == [
        f"dual.example.com:8443:{RESOLVED_IP}",
        f"dual.example.com:8443:{RESOLVED_IP_2}",
    ]
    assert execution.MAX_ARTIFACT_BYTES == 8 * 1024 * 1024
    assert "--max-filesize" in curl
    assert curl[-1] == "http://dual.example.com:8443/"
    # redirects are never enabled, bodies are impossible, no shell anywhere
    assert "-L" not in curl and "--location" not in curl
    assert not any(a.startswith("--data") or a.startswith("-d") for a in curl)
    assert "--head" in curl  # HEAD via --head, not -X HEAD


def test_network_policy_default_drops_and_accepts_only_pinned_destinations():
    run = _canary_run()
    prepare = execution.prepare_network(run, [RESOLVED_IP, RESOLVED_IP_2])
    # plain bridge with the fixed run subnet — NOT --internal
    assert prepare[0] == ["docker", "network", "create", "--subnet",
                          execution.RUN_SUBNET, execution.network_name(run)]
    # default DROP for the whole container subnet is installed FIRST
    assert prepare[1] == ["iptables", "-I", "DOCKER-USER",
                          "-s", execution.RUN_SUBNET, "-j", "DROP"]
    # each ACCEPT: source = the CONTAINER subnet, dest = one pinned /32;
    # each is -I inserted, so the final order is ACCEPT(s) above DROP
    accepts = prepare[2:]
    assert accepts == [
        ["iptables", "-I", "DOCKER-USER", "-s", execution.RUN_SUBNET,
         "-d", f"{ip}/32", "-m", "time", "--datestop",
         "2026-09-25T00:00:00", "-j", "ACCEPT"]
        for ip in (RESOLVED_IP, RESOLVED_IP_2)
    ]

    teardown = execution.teardown_network(run, [RESOLVED_IP, RESOLVED_IP_2])
    assert teardown[-1] == ["docker", "network", "rm", "-f", execution.network_name(run)]
    assert teardown[0] == ["iptables", "-D", "DOCKER-USER", "-s", execution.RUN_SUBNET,
                           "-d", f"{RESOLVED_IP}/32", "-m", "time", "--datestop",
                           "2026-09-25T00:00:00", "-j", "ACCEPT"]
    assert ["iptables", "-D", "DOCKER-USER", "-s", execution.RUN_SUBNET, "-j", "DROP"] in teardown


# ---------------------------------------------------------------------------
# The superseded-model gate (unconditional)
# ---------------------------------------------------------------------------


def test_legacy_engagement_creation_refused(strike_client, analyst_headers):
    r = strike_client.post(
        "/api/strike/engagements",
        json=engagement_payload(),
        headers=analyst_headers,
    )
    assert r.status_code == 410
    assert r.json()["detail"]["code"] == "legacy_strike_model_superseded"


# ---------------------------------------------------------------------------
# Access control (ported from the deleted legacy authorization suite — the
# invariants are model-independent: platform sessions never reach tenant
# modules; the STRIKE entitlement is enforced; scope registry mutations, which
# define the fence, stay admin-only)
# ---------------------------------------------------------------------------


def test_platform_session_blocked_from_run_endpoints(strike_client, platform_admin_headers):
    assert strike_client.get("/api/strike/runs", headers=platform_admin_headers).status_code == 403
    assert (
        strike_client.get("/api/strike/catalogue", headers=platform_admin_headers).status_code == 403
    )


def test_strike_module_entitlement_required_for_runs(strike_client, admin_headers):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE tenant_entitlements SET module_overrides = %s::jsonb "
                "WHERE tenant_id = %s;",
                ('{"STRIKE": false}', str(TENANT_A)),
            )
        conn.commit()
    try:
        r = strike_client.get("/api/strike/runs", headers=admin_headers)
        assert r.status_code == 403
        assert "STRIKE" in r.json()["detail"]
    finally:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE tenant_entitlements SET module_overrides = '{}'::jsonb "
                    "WHERE tenant_id = %s;",
                    (str(TENANT_A),),
                )
            conn.commit()


def test_analyst_cannot_create_or_revoke_scope_entries(
    strike_client, analyst_headers, admin_headers
):
    # The scope registry IS the fence: only Tenant Admin/Superadmin may widen
    # or revoke it; an analyst-scope mutation would be privilege escalation.
    r = strike_client.post(
        "/api/strike/scopes",
        json={
            "entry": "203.0.113.99",
            "expires_at": iso(datetime.now(timezone.utc) + timedelta(hours=1)),
        },
        headers=analyst_headers,
    )
    assert r.status_code == 403

    created = create_scope(strike_client, admin_headers, "203.0.113.99")
    r = strike_client.post(
        f"/api/strike/scopes/{created['id']}/revoke",
        json={"reason": "analyst must not be able to do this"},
        headers=analyst_headers,
    )
    assert r.status_code == 403
    # revocation is derived at read: the entry is still ACTIVE for the admin
    assert strike_client.get("/api/strike/scopes", headers=admin_headers).json()[0]["state"] == (
        "active"
    )


# ---------------------------------------------------------------------------
# B1/B2 regression — the claim loop survives an executor crash, records the
# run truthfully, and never claims over fence residue
# ---------------------------------------------------------------------------


def _executor_crash(run, check_alive=None):
    raise RuntimeError("docker daemon unreachable")


def _executor_teardown_residue(run, check_alive=None):
    raise execution.TeardownError("ACCEPT rule not removed")


def test_executor_crash_records_failed_truthfully_and_loop_survives(
    strike_client, analyst_headers, admin_headers,
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    first = insert_server_run(strike_client, analyst_headers, admin_headers)
    second = insert_server_run(strike_client, analyst_headers, admin_headers)

    # B1: the crash is bounded at the process_pending boundary — the run is
    # failed truthfully and the loop stays alive
    assert process_pending(
        once=True, executor=_executor_crash, reconcile=lambda: None,
    ) == 1
    done = strike_client.get(f"/api/strike/runs/{first['id']}", headers=analyst_headers).json()
    assert done["state"] == "failed"
    assert done["error_code"] == "runner_executor_failure"
    assert done["completed_at"] is not None

    # the SAME loop invocation path then completes the next claim normally
    assert process_pending(
        once=True, executor=_executor_output, reconcile=lambda: None,
    ) == 1
    ok = strike_client.get(f"/api/strike/runs/{second['id']}", headers=analyst_headers).json()
    assert ok["state"] == "completed"


def test_teardown_failure_records_failed_and_halts_claiming(
    strike_client, analyst_headers, admin_headers,
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    first = insert_server_run(strike_client, analyst_headers, admin_headers)
    second = insert_server_run(strike_client, analyst_headers, admin_headers)  # must NOT be claimed after residue

    with pytest.raises(execution.TeardownError):
        process_pending(once=True, executor=_executor_teardown_residue, reconcile=lambda: None)

    done = strike_client.get(f"/api/strike/runs/{first['id']}", headers=analyst_headers).json()
    assert done["state"] == "failed"
    assert done["error_code"] == "runner_teardown_failed"

    # B2: a reconcile sweep failure keeps the gate shut — no claim happens
    def broken_reconcile():
        raise RuntimeError("iptables -S failed")

    with pytest.raises(RuntimeError):
        process_pending(once=True, executor=_executor_output, reconcile=broken_reconcile)
    remaining = strike_client.get("/api/strike/runs", headers=analyst_headers).json()
    assert [r["state"] for r in remaining if r["state"] == "queued"] == ["queued"]


def test_reconcile_is_gated_before_the_first_claim(
    strike_client, analyst_headers, admin_headers,
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)
    calls = []

    def counting_reconcile():
        calls.append(True)

    process_pending(once=True, executor=_executor_output, reconcile=counting_reconcile)
    assert calls == [True]  # swept BEFORE the claim, every pass
    done = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers).json()
    assert done["state"] == "completed"


# ---------------------------------------------------------------------------
# B1/B2 hardening round 2 — every claim is reconcile-gated; an unverified
# stop after an executor crash never becomes a clean cancelled and never
# tears the fence down over a live container
# ---------------------------------------------------------------------------


def _executor_crash_only_first(run, check_alive=None):
    if not getattr(_executor_crash_only_first, "crashed", False):
        _executor_crash_only_first.crashed = True
        raise RuntimeError("prepare_network failed halfway")
    return execution.ExecutionResult(0, "ok")


def test_every_claim_is_gated_by_a_fresh_reconcile_after_a_crash(
    strike_client, analyst_headers, admin_headers,
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    first = insert_server_run(strike_client, analyst_headers, admin_headers)
    second = insert_server_run(strike_client, analyst_headers, admin_headers)
    sweeps = []

    process_pending(
        once=False,
        executor=_executor_crash_only_first,
        reconcile=lambda: sweeps.append(True),
    )

    # every loop iteration is gated: claim 1, the post-crash claim 2, and
    # the terminal no-claim poll — three sweeps for one pass
    assert len(sweeps) == 3
    states = {first["id"]: None, second["id"]: None}
    for run in strike_client.get("/api/strike/runs", headers=analyst_headers).json():
        states[run["id"]] = run["state"]
    assert states[first["id"]] == "failed"
    assert states[second["id"]] == "completed"


def _executor_crash_after_start(run, check_alive=None):
    from app.strike import runs as strike_runs_module

    # the analyst cancel lands while the container is conceptually alive,
    # THEN the executor crashes — exactly the race the reviewer flagged
    with get_db_connection() as conn:
        strike_runs_module.request_scope_stop(conn, run, "cancel requested mid-run")
        conn.commit()
    raise RuntimeError("crashed after Popen")


def test_exception_after_start_with_cancel_requested_records_unconfirmed_when_stop_unverified(
    strike_client, analyst_headers, admin_headers, monkeypatch,
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)
    monkeypatch.setattr("runner.main._verify_stop", lambda r: False)

    process_pending(once=True, executor=_executor_crash_after_start, reconcile=lambda: None)

    done = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers).json()
    assert done["state"] == "cancel_unconfirmed"  # never a clean cancelled
    assert done["stop_reason"] is not None


def test_exception_after_start_with_cancel_requested_confirmed_when_stop_verified(
    strike_client, analyst_headers, admin_headers, monkeypatch,
):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    run = insert_server_run(strike_client, analyst_headers, admin_headers)
    monkeypatch.setattr("runner.main._verify_stop", lambda r: True)

    process_pending(once=True, executor=_executor_crash_after_start, reconcile=lambda: None)

    done = strike_client.get(f"/api/strike/runs/{run['id']}", headers=analyst_headers).json()
    assert done["state"] == "cancelled"


def test_live_container_crash_with_unverified_stop_keeps_fence_and_raises(monkeypatch):
    run = _canary_run()
    run["id"] = uuid.uuid4()
    proc = _FakeProc()  # poll() → None forever: "container" never exits

    def crashing_check_alive():
        raise RuntimeError("watch thread exploded while container ran")

    def refusing_stop(r):
        return False  # stop could NOT be verified

    with pytest.raises(execution.TeardownError, match="fence left in place"):
        execution.run_in_container(
            run, crashing_check_alive,
            poll_seconds=0.0, popen=lambda cmd, stdout=None, stderr=None: proc,
            stop=refusing_stop, prepare=lambda: None, teardown=lambda: None,
        )


def test_live_container_crash_with_verified_stop_still_tears_down(monkeypatch):
    run = _canary_run()
    run["id"] = uuid.uuid4()
    proc = _FakeProc()
    torn = {"down": False}

    def crashing_check_alive():
        raise RuntimeError("watch thread exploded while container ran")

    def confirming_stop(r):
        proc.returncode = -9  # kill+wait: the container IS verifiably gone
        return True

    def teardown():
        torn["down"] = True

    with pytest.raises(RuntimeError, match="watch thread exploded"):
        execution.run_in_container(
            run, crashing_check_alive,
            poll_seconds=0.0, popen=lambda cmd, stdout=None, stderr=None: proc,
            stop=confirming_stop, prepare=lambda: None, teardown=teardown,
        )
    assert torn["down"] is True  # teardown ran only AFTER the verified stop


# ---------------------------------------------------------------------------
# Stop-verification review (release blockers): Docker-outage stops are
# UNKNOWN; an unverified stop keeps the fence and is fatal on EVERY path
# ---------------------------------------------------------------------------


def test_stop_container_docker_outage_is_never_a_confirmed_stop(monkeypatch):
    outage = lambda cmd, shell=False, capture_output=True, timeout=None: (
        __import__("types").SimpleNamespace(
            returncode=1, stdout=b"", stderr=b"Cannot connect to the Docker daemon")
    )
    monkeypatch.setattr("runner.execution.subprocess.run", outage)
    assert execution.stop_container(_canary_run()) is False  # UNKNOWN ≠ confirmed


def _fenced_crash(expect_teardown: bool, *, check_alive, stop):
    """Shared harness: live container + executor-path crash, record teardown."""
    run = _canary_run()
    run["id"] = uuid.uuid4()
    proc = _FakeProc()
    torn = {"down": False}

    def teardown():
        torn["down"] = True

    with pytest.raises(execution.TeardownError, match="fence left in place"):
        execution.run_in_container(
            run, check_alive,
            poll_seconds=0.0, popen=lambda cmd, stdout=None, stderr=None: proc,
            stop=stop, prepare=lambda: None, teardown=teardown,
            cut=lambda: None,
        )
    assert torn["down"] is expect_teardown


def test_docker_outage_crash_keeps_fence_and_never_tears_down(monkeypatch):
    # real stop_container + real Docker outage: kill/wait/inspect all fail
    outage = lambda cmd, shell=False, capture_output=True, timeout=None: (
        __import__("types").SimpleNamespace(returncode=1, stdout=b"", stderr=b"no daemon"))
    monkeypatch.setattr("runner.execution.subprocess.run", outage)

    def crashing_check_alive():
        raise RuntimeError("crashed while container ran")

    _fenced_crash(False, check_alive=crashing_check_alive,
                  stop=execution.stop_container)


def test_unverified_stop_on_timeout_and_scope_death_keeps_fence():
    def crashing_check_alive():
        raise RuntimeError("boom")

    def dead_scope():
        return False

    def refusing_stop(r):
        return False

    # timeout path: unverified stop → fence kept, fatal, teardown skipped
    run = _canary_run(); run["id"] = uuid.uuid4()
    proc = _FakeProc(); torn = {"down": False}
    with pytest.raises(execution.TeardownError, match="fence left in place"):
        execution.run_in_container(
            run, None, timeout=0.01, poll_seconds=0.0,
            popen=lambda cmd, stdout=None, stderr=None: proc,
            stop=refusing_stop, prepare=lambda: None,
            teardown=lambda: torn.update(down=True),
            cut=lambda: None,
        )
    assert torn["down"] is False

    # mid-run scope-death path: same contract
    _fenced_crash(False, check_alive=dead_scope, stop=refusing_stop)

    # stop() itself raising in the crash path (Docker binary gone) → same
    def exploding_stop(r):
        raise FileNotFoundError("docker")

    _fenced_crash(False, check_alive=crashing_check_alive, stop=exploding_stop)


# ---------------------------------------------------------------------------
# Quarantine (PRD Ch4 1009-1012 / PATCH-02): on scope death / cancel, egress
# authorization dies FIRST — a top-priority subnet DROP lands before any
# stop attempt, stays in place while the stop is unverified, and a failed
# cut fails loud as containment-not-established
# ---------------------------------------------------------------------------


def test_cut_egress_is_a_top_priority_subnet_drop():
    (cmd,) = execution.cut_egress(_canary_run())
    assert cmd[0:3] == ["iptables", "-I", "DOCKER-USER"]
    assert cmd[3] == "-s" and cmd[4] == execution.RUN_SUBNET
    assert cmd[5:] == ["-j", "DROP"]
    # -I inserts at position 1: ABOVE every ACCEPT of the original fence —
    # the revoked pinned destination is unreachable the moment it lands


def test_quarantine_cut_precedes_stop_and_survives_unverified_stop():
    run = _canary_run()
    run["id"] = uuid.uuid4()
    proc = _FakeProc()
    ops: list[str] = []
    torn = {"down": False}

    with pytest.raises(execution.TeardownError, match="fence left in place"):
        execution.run_in_container(
            run, lambda: False,  # scope dead mid-run
            poll_seconds=0.0,
            popen=lambda cmd, stdout=None, stderr=None: proc,
            stop=lambda r: (ops.append("stop"), False)[1],
            prepare=lambda: ops.append("prepare"),
            teardown=lambda: torn.update(down=True),
            cut=lambda: ops.append("cut"),
        )

    # egress dies FIRST, before any stop attempt; the deny stays in place
    # (teardown skipped) while the stop is unverified
    assert ops == ["prepare", "cut", "stop"]
    assert torn["down"] is False


def test_failed_quarantine_install_fails_loud_never_runs_container_on():
    run = _canary_run()
    run["id"] = uuid.uuid4()
    proc = _FakeProc()
    ops: list[str] = []
    torn = {"down": False}

    def broken_cut():
        ops.append("cut")
        raise RuntimeError("iptables unavailable")

    with pytest.raises(execution.TeardownError, match="containment not established"):
        execution.run_in_container(
            run, lambda: False,
            poll_seconds=0.0,
            popen=lambda cmd, stdout=None, stderr=None: proc,
            stop=lambda r: (ops.append("stop"), True)[1],
            prepare=lambda: ops.append("prepare"),
            teardown=lambda: torn.update(down=True),
            cut=broken_cut,
        )

    # a container that cannot be quarantined is never given a live window:
    # the cut is attempted BEFORE the stop, and the failure is fatal
    assert "stop" not in ops
    assert torn["down"] is False
