# backend/tests_unit/test_scout_collector_deadline.py
"""
SCOUT-01 — server-side SCOUT_JOB result deadline separation, database-free half.

The contract under test without a database (PRD-000 v1.11 Ch.2 §2.5/§2.6):
the server must wait STRICTLY LONGER for a SCOUT_JOB result than the engine
envelope it hands the collector, so that the daemon's own truthful result is
never discarded and misreported as a server-side ``collector_timeout``.

Why this is the invariant that matters: the collector daemon bounds the engine
at the SAME envelope the server sends (``collector/src/scout_runner.rs``:
``tokio::time::timeout(effective_timeout, wait_child)``), KILLS the engine when
it expires, and only THEN emits ``SCOUT_JOB_RESULT``. The server's margin
therefore has to cover engine teardown/reap, up to ``OUTPUT_LIMIT`` (4 MiB) of
serialized result, and the WSS transit back — not spare scan time.

Attribution of nmap's own bound (do NOT conflate the two execution paths):
  * CENTRAL / internet path — ``nmap_argv`` (``app/scout.py``) passes
    ``--host-timeout 120s``, so nmap self-terminates well before its envelope;
  * COLLECTOR / internal path — the daemon builds its OWN hardcoded argv
    (``scout_runner.rs`` nmap branch) that carries NO ``--host-timeout``; the
    envelope is the only bound. This is the path that needs the margin.

Scope: this pins the SERVER-side deadline invariant only. It does not, and
cannot, make the collector-side engine self-bound — that is the daemon fix and
needs a collector-capable build environment.

Purity: ``app.collector_registry`` transitively imports ``app.db``/``psycopg``,
so it is imported LAZILY inside the ``registry_modules`` fixture and every added
sys.modules entry is removed afterwards — the TES kernel purity guard
(``test_unit_suite_never_imports_db_or_app_machinery``) asserts a clean
sys.modules and must hold in any run order.
"""
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

# app.config fails closed without these. They are set only for the duration of
# the lazy import below (reverted in `finally`), never global to the suite.
_TEST_DATABASE_URL = "postgresql://scout01:scout01@127.0.0.1:5432/tempris_scout01"
_TEST_JWT_SECRET = "scout01-unit-suite-secret-material-0123456789abcdef"


class _NeverReplyingWebSocket:
    """A collector socket that accepts frames and never answers them.

    Models the pathological case the margin exists for: the daemon received the
    job but its result has not arrived back yet.
    """

    def __init__(self) -> None:
        self.sent_frames: list[dict] = []

    async def send_text(self, text: str) -> None:
        self.sent_frames.append(json.loads(text))


class _LateReplyingWebSocket:
    """A collector socket whose result arrives AFTER the engine envelope.

    This is the real-world shape for the COLLECTOR path: the daemon kills nmap
    when the envelope expires and only then sends ``SCOUT_JOB_RESULT``, so the
    frame lands outside the envelope but well inside the server's margin.
    """

    def __init__(self, registry, collector_id, delay: float) -> None:
        self._registry = registry
        self._collector_id = collector_id
        self._delay = delay
        self.sent_frames: list[dict] = []

    async def send_text(self, text: str) -> None:
        frame = json.loads(text)
        self.sent_frames.append(frame)
        loop = asyncio.get_running_loop()
        loop.call_later(self._delay, self._deliver, frame)

    def _deliver(self, frame: dict) -> None:
        now = "2026-01-01T00:00:00Z"
        self._registry.handle_scout_job_result(
            self._collector_id,
            {
                "type": "SCOUT_JOB_RESULT",
                "job_id": frame["job_id"],
                "engine": frame["engine"],
                "status": "completed",
                "exit_code": 0,
                "stdout": "<nmaprun></nmaprun>",
                "stderr": "",
                "stdout_bytes": 22,
                "stderr_bytes": 0,
                "started_at": now,
                "completed_at": now,
                "error_message": None,
            },
        )


@pytest.fixture(scope="module")
def registry_modules():
    """Import the registry + scout constant modules lazily, then revert
    sys.modules to its exact pre-import state (including every transitive
    import: app.*, psycopg, psycopg_pool, fastapi, ...)."""
    import importlib

    before = set(sys.modules)
    saved_env = {k: os.environ.get(k) for k in ("DATABASE_URL", "JWT_SECRET")}
    os.environ["DATABASE_URL"] = _TEST_DATABASE_URL
    os.environ["JWT_SECRET"] = _TEST_JWT_SECRET
    try:
        registry = importlib.import_module("app.collector_registry")
        scout = importlib.import_module("app.scout")
    finally:
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    added = set(sys.modules) - before
    yield registry, scout
    for name in added:
        sys.modules.pop(name, None)


def test_grace_is_a_named_positive_constant(registry_modules):
    """The margin is a named constant, strictly positive — not a bare literal —
    and at least the documented floor.

    The floor is the point of the change: 15s did not cover engine teardown/reap
    plus up to ``OUTPUT_LIMIT`` (4 MiB) of serialized result plus WSS transit,
    so a completed scan could be reported as ``collector_timeout``. This
    assertion fails if the margin regresses toward that too-tight value again.
    """
    registry, _ = registry_modules
    grace = registry.SCOUT_RESULT_GRACE_SECONDS
    assert isinstance(grace, int) and not isinstance(grace, bool)
    assert grace >= 30, (
        "the SCOUT result margin must remain wide enough to cover engine "
        "teardown + result transit; 15s was empirically too tight"
    )


def test_server_deadline_strictly_exceeds_daemon_envelope(registry_modules):
    """The regression this ticket exists for: for every real engine envelope the
    server sends, the server's own result deadline must be STRICTLY greater.
    Equality (or less) is the bug — it lets the server's timer win the race and
    relabel a daemon result as ``collector_timeout``."""
    registry, scout = registry_modules
    grace = registry.SCOUT_RESULT_GRACE_SECONDS

    envelopes = {"nmap": scout.NMAP_TIMEOUT, "nuclei": scout.NUCLEI_TIMEOUT}
    for engine, envelope in envelopes.items():
        server_total = int(envelope) + grace
        assert server_total > envelope, (
            f"{engine}: server deadline {server_total}s must strictly exceed the "
            f"daemon envelope {envelope}s"
        )


def test_dispatch_wait_applies_grace_and_reports_collector_timeout(registry_modules, monkeypatch):
    """Behavioural, deterministic: the wait path actually adds the grace, and a
    result that never arrives still fails closed as ``collector_timeout``.

    The engine envelope is pinned to a real value and the margin to a tiny one,
    so the run is fast while the invariant under test (grace IS added) is exact.
    """
    registry, _ = registry_modules
    monkeypatch.setattr(registry, "SCOUT_RESULT_GRACE_SECONDS", 0.05)

    tenant_id = uuid.uuid4()
    collector_id = uuid.uuid4()
    job_id = uuid.uuid4()
    ws = _NeverReplyingWebSocket()
    session = registry.collector_registry.register_session(collector_id, tenant_id, ws)

    try:
        result = asyncio.run(
            registry.collector_registry.dispatch_scout_job(
                collector_id=collector_id,
                tenant_id=tenant_id,
                job_id=job_id,
                engine="nmap",
                profile="SERVICE_DISCOVERY",
                target="10.0.1.1",
                target_type="ip",
                network_scope="internal",
                timeout_seconds=1,
            )
        )
    finally:
        # Detach the session directly: unregister_session() would touch the DB
        # via fail_all_jobs(), and this suite is database-free by construction.
        registry.collector_registry._sessions.pop(collector_id, None)

    # The frame was dispatched, and the wait honoured envelope + grace (1.05s),
    # not the bare envelope (1s).
    assert len(ws.sent_frames) == 1
    assert ws.sent_frames[0]["type"] == "SCOUT_JOB"
    assert ws.sent_frames[0]["timeout_seconds"] == 1
    assert result["status"] == "failed"
    assert result["error_code"] == "collector_timeout"
    assert "1.05" in result["error_message"]
    assert session.in_flight_jobs == {}  # the finally-block always drains it


def test_late_daemon_result_inside_grace_is_accepted_not_relabelled(registry_modules, monkeypatch):
    """The behavioural half of the fix, stated precisely.

    A daemon result that arrives AFTER the engine envelope but INSIDE the
    server's margin must be accepted as the daemon reported it. Before this fix
    the margin was 15s, so a result landing later than envelope+15s was thrown
    away and mislabelled ``collector_timeout`` — even though the engine had
    finished and the daemon had answered truthfully.

    Envelope 1s, margin 3s, result at ~1.6s: outside the envelope, inside the
    margin. Accepted. This does not assert anything about Nmap's runtime; it
    pins the attribution behaviour of the server timer.
    """
    registry, _ = registry_modules
    monkeypatch.setattr(registry, "SCOUT_RESULT_GRACE_SECONDS", 3)

    tenant_id = uuid.uuid4()
    collector_id = uuid.uuid4()
    ws = _LateReplyingWebSocket(registry.collector_registry, collector_id, delay=1.6)
    session = registry.collector_registry.register_session(collector_id, tenant_id, ws)

    try:
        result = asyncio.run(
            registry.collector_registry.dispatch_scout_job(
                collector_id=collector_id,
                tenant_id=tenant_id,
                job_id=uuid.uuid4(),
                engine="nmap",
                profile="SERVICE_DISCOVERY",
                target="10.0.1.2",
                target_type="ip",
                network_scope="internal",
                timeout_seconds=1,
            )
        )
    finally:
        registry.collector_registry._sessions.pop(collector_id, None)

    assert result.get("error_code") != "collector_timeout", (
        "a late-but-in-margin daemon result must not be relabelled as a timeout"
    )
    assert result["status"] == "completed"
    assert result["stdout"] == "<nmaprun></nmaprun>"
    assert session.in_flight_jobs == {}


def test_late_daemon_result_beyond_grace_still_fails_closed(registry_modules, monkeypatch):
    """Fail-closed is preserved: a result that never arrives within the margin
    still reports ``collector_timeout``. The change widens attribution, it does
    not remove the bound."""
    registry, _ = registry_modules
    monkeypatch.setattr(registry, "SCOUT_RESULT_GRACE_SECONDS", 0.05)

    tenant_id = uuid.uuid4()
    collector_id = uuid.uuid4()
    ws = _LateReplyingWebSocket(registry.collector_registry, collector_id, delay=5.0)
    registry.collector_registry.register_session(collector_id, tenant_id, ws)

    try:
        result = asyncio.run(
            registry.collector_registry.dispatch_scout_job(
                collector_id=collector_id,
                tenant_id=tenant_id,
                job_id=uuid.uuid4(),
                engine="nmap",
                profile="SERVICE_DISCOVERY",
                target="10.0.1.3",
                target_type="ip",
                network_scope="internal",
                timeout_seconds=1,
            )
        )
    finally:
        registry.collector_registry._sessions.pop(collector_id, None)

    assert result["status"] == "failed"
    assert result["error_code"] == "collector_timeout"
    assert "collector_transport_timeout:" in result["error_message"]
    assert "1.05" in result["error_message"]


def test_legacy_and_deadline_frames_keep_partial_output(registry_modules):
    """A daemon timeout must not collapse to the word ``timeout`` with empty counts."""
    _, scout = registry_modules
    legacy = {
        "status": "failed",
        "error_message": "timeout",
        "stdout_bytes": 40,
        "stderr_bytes": 12,
    }
    assert scout._is_collector_timeout(legacy)
    legacy_message = scout.collector_timeout_message("nuclei", legacy)
    assert legacy_message.startswith("collector_deadline:")
    assert "stdout_bytes=40" in legacy_message
    assert "stderr_bytes=12" in legacy_message
    assert "legacy_collector=true" in legacy_message

    current = {
        "status": "timed_out",
        "error_message": (
            "collector_deadline: termination=collector_deadline elapsed=300s "
            "deadline=300s stdout_bytes=18 stderr_bytes=240 profile=[MANAGED_NUCLEI]"
        ),
        "stdout": "{\"template-id\":\"example\"}\n",
        "stderr": "{\"duration\":\"15s\",\"rps\":12}\n",
        "stdout_bytes": 18,
        "stderr_bytes": 240,
    }
    assert scout._is_collector_timeout(current)
    detail = scout.collector_timeout_detail("nuclei", current)
    assert "partial_stderr:" in detail
    assert "partial_stdout:" in detail
    assert "template-id" in detail
    assert "rps" in detail

    transport = {
        "error_code": "collector_timeout",
        "error_message": (
            "collector_transport_timeout: no result frame within 330s "
            "(envelope 300s + grace 30s)"
        ),
    }
    assert scout.collector_timeout_message("nuclei", transport).startswith(
        "collector_transport_timeout:"
    )


def test_result_from_reader_thread_wakes_before_the_server_deadline(registry_modules, monkeypatch):
    """The socket reader and the scan waiter do not share an event loop.

    Completing the future with a plain ``set_result`` from the reader thread
    leaves the waiter asleep until its own deadline. Delivery has to schedule
    onto the waiter's loop or a finished engine is reported only when the
    server timer expires.
    """
    import threading
    import time

    registry, _ = registry_modules
    monkeypatch.setattr(registry, "SCOUT_RESULT_GRACE_SECONDS", 4)

    tenant_id = uuid.uuid4()
    collector_id = uuid.uuid4()

    class _OtherThreadSocket:
        def __init__(self):
            self.sent_frames = []

        async def send_text(self, text: str) -> None:
            frame = json.loads(text)
            self.sent_frames.append(frame)

            def deliver():
                time.sleep(0.2)
                registry.collector_registry.handle_scout_job_result(
                    collector_id,
                    {
                        "type": "SCOUT_JOB_RESULT",
                        "job_id": frame["job_id"],
                        "engine": frame["engine"],
                        "status": "timed_out",
                        "exit_code": None,
                        "stdout": "",
                        "stderr": "{\"rps\":8}",
                        "stdout_bytes": 0,
                        "stderr_bytes": 8,
                        "started_at": "2026-09-24T14:25:59Z",
                        "completed_at": "2026-09-24T14:30:59Z",
                        "error_message": "collector_deadline: termination=collector_deadline elapsed=300s deadline=300s",
                    },
                )

            threading.Thread(target=deliver, daemon=True).start()

    ws = _OtherThreadSocket()
    registry.collector_registry.register_session(collector_id, tenant_id, ws)
    started = time.monotonic()
    try:
        result = asyncio.run(
            registry.collector_registry.dispatch_scout_job(
                collector_id=collector_id,
                tenant_id=tenant_id,
                job_id=uuid.uuid4(),
                engine="nuclei",
                profile="VULNERABILITY_ASSESSMENT",
                target="192.0.2.10",
                target_type="ip",
                network_scope="internal",
                timeout_seconds=1,
            )
        )
    finally:
        registry.collector_registry._sessions.pop(collector_id, None)

    elapsed = time.monotonic() - started
    assert elapsed < 2.0, f"reader-thread result was only noticed after {elapsed:.2f}s"
    assert result["status"] == "timed_out"
    assert result["error_message"].startswith("collector_deadline:")
    assert result.get("error_code") != "collector_timeout"