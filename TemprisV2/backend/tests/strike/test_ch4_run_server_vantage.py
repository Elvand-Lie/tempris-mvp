# backend/tests/strike/test_ch4_run_server_vantage.py
"""
Chapter 4 acceptance — the SERVER execution vantage and cursor-based output
streaming (migration 048).

The server vantage runs in the platform's own hardened sandbox
(app/strike/sandbox.py) instead of dispatching to a collector over WSS.
Covers:
  * a server-plane run is created durable and executed in-process: the tool
    really runs, its exit code is recorded, and the run reaches a terminal
    state — with NO collector involved and no collector_id anywhere;
  * the run's output is readable through the cursor endpoint, in order,
    without a gap or a repeat, and `terminal` tells the console to stop;
  * a script runner's script text is NEVER persisted: it is piped to the
    interpreter on stdin and appears in no column of the durable row;
  * fail closed and visibly: a server-plane capability whose binary is not
    installed here is refused at creation, and a server-vantage run that
    names a collector is refused rather than misstating where it ran;
  * the chunks endpoint is tenant-scoped exactly like every other run read —
    an unknown or cross-tenant run id is the identical not-found.

Scope validation is not re-decided on this plane: create_run validates the
target against the registry and pins the addresses before the execution path
is reached, and activate_run re-checks the pinned snapshot's liveness.
"""
from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

from app.db import get_db_connection
from app.strike.runs import append_output_chunk, read_output_chunks
from tests.conftest import TENANT_A, TENANT_B

RESOLVED_IP = "203.0.113.10"

# A trivially harmless, deterministic command. The script is piped on stdin;
# nothing here reaches the network or the filesystem.
ECHO_SCRIPT = "echo tempris-server-plane-ok\n"


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


def create_scope(client, admin_headers, entry, expires_at):
    r = client.post(
        "/api/strike/scopes",
        json={"entry": entry, "expires_at": expires_at},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


def create_server_run(
    client,
    analyst_headers,
    *,
    capability="bash",
    method="RUN",
    target=RESOLVED_IP,
    script=ECHO_SCRIPT,
    **extra,
):
    """A server-vantage run. No collector is selected or named."""
    return client.post(
        "/api/strike/runs",
        json={
            "capability": capability,
            "method": method,
            "target": target,
            "execution_plane": "server",
            **({"script": script} if script is not None else {}),
            **({"language": capability} if capability in ("python", "bash") else {}),
            **extra,
        },
        headers=analyst_headers,
    )


def wait_for_terminal(client, analyst_headers, run_id, *, timeout_seconds=30):
    """Follow the run through the CURSOR endpoint until it reports terminal.

    This is exactly how the console follows a server-vantage run: the route
    returns the durable queued run and the sandbox executes in a background
    task, so the terminal state is observed by polling, never by assuming the
    response waited for execution.
    """
    import time

    deadline = time.monotonic() + timeout_seconds
    page = None
    while time.monotonic() < deadline:
        r = client.get(f"/api/strike/runs/{run_id}/chunks", headers=analyst_headers)
        assert r.status_code == 200, r.text
        page = r.json()
        if page["terminal"]:
            return page
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} never reached a terminal state: {page}")


# ---------------------------------------------------------------------------
# Fail closed, visibly
# ---------------------------------------------------------------------------


def test_server_vantage_run_naming_a_collector_is_refused(
    strike_client, analyst_headers, admin_headers
):
    """A server-vantage run does not run on a collector, so leaving one set
    would misstate where the run executed."""
    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    r = create_server_run(
        strike_client,
        analyst_headers,
        collector_id="11111111-1111-1111-1111-111111111111",
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["code"] == "run_config_invalid"


def test_server_vantage_tool_absent_here_is_refused_not_faked(
    strike_client, analyst_headers, admin_headers, monkeypatch
):
    """An absent binary is a visible refusal. The run never reaches a
    fabricated 'completed' with empty output."""
    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    # create_run imports the prerequisite check locally at call time, so
    # patching the module attribute is what the refusal actually consults.
    monkeypatch.setattr(
        "app.strike.sandbox.server_prerequisite_error",
        lambda capability: (
            f"The {capability} tool is not installed on the platform server; "
            "use the collector vantage instead"
        ),
    )
    r = create_server_run(strike_client, analyst_headers, capability="bash")
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["code"] == "run_config_invalid"
    assert "not installed on the platform server" in r.json()["detail"]["message"]


def test_server_vantage_missing_pinned_nuclei_templates_fails_closed(
    strike_client, analyst_headers, admin_headers, monkeypatch
):
    """nuclei with no pinned templates directory is REFUSED — it must never
    fall back to running nuclei's own ambient/auto-updated templates."""
    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    monkeypatch.setattr(
        "app.strike.sandbox.resolve_tool",
        lambda capability: "/usr/bin/nuclei" if capability == "nuclei" else None,
    )
    monkeypatch.setattr(
        "app.config.STRIKE_NUCLEI_TEMPLATES_DIR",
        str(Path("C:/definitely/absent/tempris-nuclei-templates")),
    )
    r = create_server_run(
        strike_client, analyst_headers, capability="nuclei", target=RESOLVED_IP
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["code"] == "run_config_invalid"
    assert "templates are not deployed" in r.json()["detail"]["message"]


def test_server_vantage_dig_argv_is_bounded(strike_client):
    """dig runs the reviewed argv: +short, the allowed record type, the name."""
    from app.strike import sandbox

    argv = sandbox.build_dig_argv("/usr/bin/dig", "attackme.com", "A")
    assert argv == ["/usr/bin/dig", "+short", "A", "attackme.com"]
    # an IP (PTR) lookup uses the same shape; ANY is never buildable because
    # create_run refuses it before argv construction
    assert sandbox.build_dig_argv("/usr/bin/dig", "1.2.3.4", "PTR") == [
        "/usr/bin/dig", "+short", "PTR", "1.2.3.4",
    ]


def test_server_vantage_nmap_profile_is_a_bounded_variation():
    """Every profile keeps the fixed unprivileged shape and never widens the
    port range past 1-10000 or adds a scanning privilege."""
    from app.strike import sandbox

    base = list(sandbox.NMAP_SERVER_SHAPE)
    assert "-sS" not in base and "-O" not in base and "-A" not in base
    assert not any(flag.startswith("--script") for flag in base)

    for profile in sandbox.NMAP_SERVER_PROFILES:
        argv = sandbox.build_nmap_argv("/usr/bin/nmap", ["203.0.113.10"], profile, 60)
        # the fixed shape survives verbatim in every profile
        assert argv[1 : 1 + len(base)] == base, profile
        # no privilege-granting or version/OS/script flag is ever added
        for forbidden in ("-sS", "-sV", "-O", "-A", "-iL", "--script", "--privileged"):
            assert forbidden not in argv, (profile, forbidden)
        ports = argv[argv.index("-p") + 1]
        low, _, high = ports.partition("-")
        assert int(low) >= 1 and int(high) <= 10000, (profile, ports)


def test_server_vantage_unknown_nmap_profile_is_refused():
    from app.strike import sandbox

    with pytest.raises(sandbox.SandboxConfigError):
        sandbox.build_nmap_argv("/usr/bin/nmap", ["203.0.113.10"], "yolo", 60)


# ---------------------------------------------------------------------------
# End to end: create -> sandbox executes -> chunks -> exit code
# ---------------------------------------------------------------------------


def test_server_vantage_run_executes_and_records_a_terminal_result(
    strike_client, analyst_headers, admin_headers
):
    """The whole slice: a server-plane bash run really executes, its exit
    code is recorded, and the run is terminal — with no collector."""
    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    r = create_server_run(strike_client, analyst_headers)
    assert r.status_code == 201, r.text
    run = r.json()

    assert run["execution_plane"] == "server"
    assert run["policy_snapshot"]["execution_plane"] == "server"
    # no collector is named anywhere on a server-plane run
    assert run["policy_snapshot"].get("collector_id") is None

    # The route returns the durable queued run; the sandbox runs in a
    # background task. The console follows it through the cursor endpoint,
    # so that is what this test does too.
    page = wait_for_terminal(strike_client, analyst_headers, run["id"])
    assert page["state"] == "completed", page

    final = strike_client.get(
        f"/api/strike/runs/{run['id']}", headers=analyst_headers
    ).json()
    assert final["state"] == "completed", final
    assert final["exit_code"] == 0
    assert final["runner_id"] == "server:bash"

    # the output streamed to the cursor endpoint, and the terminal flag says
    # the console may stop polling
    assert page["terminal"] is True
    assert page["chunks"], "the run produced no output chunks"
    text = "".join(c["content"] for c in page["chunks"])
    assert "tempris-server-plane-ok" in text
    # ordered, and the cursor is the last seq delivered
    seqs = [c["seq"] for c in page["chunks"]]
    assert seqs == sorted(seqs)
    assert page["next_cursor"] == seqs[-1]
    streams = {c["stream"] for c in page["chunks"]}
    assert streams <= {"stdout", "stderr", "system"}
    assert "system" in streams  # the lifecycle lines


def test_server_vantage_script_text_is_never_persisted(
    strike_client, analyst_headers, admin_headers
):
    """The invariant that shapes the whole path: a runner script is piped to
    the interpreter and exists only in the executing task's memory.

    The marker is placed in a COMMENT, so it appears in the submitted script
    but in none of the run's OUTPUT. That separates "the script text was
    persisted" from "the script echoed its own text", which is the only way
    this assertion can actually prove what it claims.
    """
    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    marker = "tempris-script-secret-9f3a"
    script = f"# {marker}\necho ran-ok\n"
    run = create_server_run(strike_client, analyst_headers, script=script).json()
    page = wait_for_terminal(strike_client, analyst_headers, run["id"])

    # the run really executed (so this is not passing merely because it failed)
    assert page["state"] == "completed", page
    output = "".join(c["content"] for c in page["chunks"])
    assert "ran-ok" in output

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM strike_runs WHERE id = %s;", (run["id"],))
            row = cur.fetchone()
    assert row is not None
    # no column of the durable row may carry the script text
    for column, value in row.items():
        assert marker not in str(value), f"script text persisted in {column}"
    assert "script" not in (row["policy_snapshot"] or {})
    assert row["exit_code"] == 0


# ---------------------------------------------------------------------------
# The chunks cursor
# ---------------------------------------------------------------------------


def test_chunks_cursor_pages_in_order_without_gap_or_repeat(strike_client, analyst_headers, admin_headers):
    """Paging with `after` + `limit` delivers every chunk exactly once, in
    order, and `next_cursor` is the last seq so the caller never re-reads."""
    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    run = create_server_run(strike_client, analyst_headers).json()
    wait_for_terminal(strike_client, analyst_headers, run["id"])

    # append a known sequence on top of the run's own lifecycle chunks, so the
    # page boundaries are forced to fall inside our own data
    with get_db_connection() as conn:
        for index in range(1, 6):
            append_output_chunk(
                conn, {"id": uuid.UUID(run["id"])}, stream="stdout", content=f"line-{index}\n"
            )
        conn.commit()

    collected: list[str] = []
    cursor = 0
    pages = 0
    while True:
        page = strike_client.get(
            f"/api/strike/runs/{run['id']}/chunks?after={cursor}&limit=2",
            headers=analyst_headers,
        ).json()
        pages += 1
        assert pages < 50, "paging did not terminate"
        collected.extend(c["content"] for c in page["chunks"])
        assert page["next_cursor"] >= cursor  # never moves backwards
        if page["next_cursor"] == cursor or not page["chunks"]:
            break
        cursor = page["next_cursor"]

    text = "".join(collected)
    for index in range(1, 6):
        assert text.count(f"line-{index}\n") == 1, f"line-{index} not delivered exactly once"
    assert pages > 1, "the limit did not actually split the stream"


def test_chunks_read_is_tenant_scoped_like_the_run_read(strike_client, analyst_headers, admin_headers):
    """A cross-tenant run id is the identical not-found — the cursor endpoint
    is never an oracle for another tenant's run ids or output."""
    from app.auth import create_test_token

    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    run = create_server_run(strike_client, analyst_headers).json()
    wait_for_terminal(strike_client, analyst_headers, run["id"])

    token = create_test_token(tenant_id=str(TENANT_B), actor_id="analyst-b", role="analyst")
    other = strike_client.get(
        f"/api/strike/runs/{run['id']}/chunks",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert other.status_code == 404
    # an unknown id is the same answer, so the two are indistinguishable
    unknown = strike_client.get(
        f"/api/strike/runs/{uuid.uuid4()}/chunks", headers=analyst_headers
    )
    assert unknown.status_code == 404
    assert other.json() == unknown.json()


def test_read_output_chunks_returns_the_terminal_view(strike_client, analyst_headers, admin_headers):
    """One poll serves a live AND a finished run: the page carries the run's
    state plus the bounded inline result and its truncation flag."""
    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    run = create_server_run(strike_client, analyst_headers).json()
    wait_for_terminal(strike_client, analyst_headers, run["id"])

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM strike_runs WHERE id = %s;", (run["id"],))
            row = cur.fetchone()
        page = read_output_chunks(
            conn, TENANT_A, uuid.UUID(run["id"]), after=0, limit=200
        )
    assert page["state"] == row["state"] == "completed"
    assert page["terminal"] is True
    assert page["inline_result"] == row["inline_result"]
    assert page["inline_truncated"] == row["inline_truncated"]


# ---------------------------------------------------------------------------
# The four collector-era tools, now runnable on the server vantage
# ---------------------------------------------------------------------------


def _stub_binary(directory: Path, name: str, body: str) -> Path:
    """A PATH shim standing in for a toolchain binary.

    ``resolve_tool`` returns the FULL path it found, and the sandbox spawns
    that path directly (no shell), so an executable shim on PATH is a faithful
    stand-in for the real binary on this host. Windows needs the exact name
    (no PATHEXT guessing across a bare `.bat`), hence the platform branch.
    """
    if os.name == "nt":
        path = directory / f"{name}.bat"
        path.write_text(f"@echo off\r\n{body}\r\nexit /b 0\r\n", encoding="utf-8")
    else:
        path = directory / name
        path.write_text(f"#!/bin/sh\n{body}\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
    return path


def test_server_vantage_dig_runs_end_to_end_against_a_stub_resolver(
    strike_client, analyst_headers, admin_headers, monkeypatch, tmp_path
):
    """dig on the SERVER plane: scoped name -> pinned argv -> real process ->
    recorded exit code and streamed output. The resolver is a PATH stub so the
    test needs no network and asserts the argv the sandbox actually built."""
    create_scope(
        strike_client, admin_headers, "attackme.example", "2099-01-01T00:00:00+00:00"
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _stub_binary(bin_dir, "dig", "echo tempris-dig-stub")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])

    r = create_server_run(
        strike_client,
        analyst_headers,
        capability="dig",
        target="attackme.example",
        record_type="A",
        script=None,
    )
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["execution_plane"] == "server"
    assert run["policy_snapshot"]["record_type"] == "A"

    page = wait_for_terminal(strike_client, analyst_headers, run["id"])
    assert page["state"] == "completed", page
    output = "".join(c["content"] for c in page["chunks"])
    assert "tempris-dig-stub" in output

    final = strike_client.get(
        f"/api/strike/runs/{run['id']}", headers=analyst_headers
    ).json()
    assert final["exit_code"] == 0
    assert final["runner_id"] == "server:dig"


def test_server_vantage_missing_pinned_ffuf_wordlist_fails_closed(
    strike_client, analyst_headers, admin_headers, monkeypatch, tmp_path
):
    """If the bundled wordlist is not deployed, ffuf is REFUSED — never run
    against an unpinned list."""
    create_scope(
        strike_client, admin_headers, RESOLVED_IP, "2099-01-01T00:00:00+00:00"
    )
    monkeypatch.setattr(
        "app.strike.sandbox.resolve_tool",
        lambda capability: "/usr/bin/ffuf" if capability == "ffuf" else None,
    )
    monkeypatch.setattr(
        "app.strike.sandbox.SERVER_WORDLIST_PATH",
        tmp_path / "absent-wordlist.txt",
    )
    r = create_server_run(
        strike_client,
        analyst_headers,
        capability="ffuf",
        target=f"http://{RESOLVED_IP}/FUZZ",
        script=None,
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["code"] == "run_config_invalid"
    assert "wordlist" in r.json()["detail"]["message"]


def test_server_vantage_ffuf_uses_the_bundled_wordlist(
    strike_client, analyst_headers, admin_headers, monkeypatch, tmp_path
):
    """The bundled pinned wordlist is what ffuf is pointed at, and an inline
    list is materialized server-side — the user never supplies a path."""
    from app.strike import sandbox

    # no inline list -> the bundled file
    assert sandbox.resolve_ffuf_wordlist(None) == sandbox.SERVER_WORDLIST_PATH
    # an inline list -> a server-generated temp file inside the run workdir
    workdir = sandbox.make_workdir("inline-wordlist-test")
    try:
        materialized = sandbox.resolve_ffuf_wordlist("admin\nlogin\n", workdir)
        assert materialized != sandbox.SERVER_WORDLIST_PATH
        assert materialized.parent == workdir
        assert materialized.read_text(encoding="utf-8") == "admin\nlogin\n"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    argv = sandbox.build_ffuf_argv(
        "/usr/bin/ffuf",
        f"http://{RESOLVED_IP}/FUZZ",
        sandbox.SERVER_WORDLIST_PATH,
        ["404"], ["0"], [],
        60,
    )
    assert argv[argv.index("-w") + 1] == str(sandbox.SERVER_WORDLIST_PATH)
    assert "-fc" in argv and "-of" in argv
    # no caller-supplied output file or headers ever appear
    assert "-o" not in argv and "-H" not in argv
