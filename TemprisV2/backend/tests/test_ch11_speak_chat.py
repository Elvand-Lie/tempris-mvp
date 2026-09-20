# backend/tests/test_ch11_speak_chat.py
"""
Focused suite for the Chapter 11 SPEAK chat LLM integration
(PRD-000 v1.11 Ch.11 rule 6 — the system's only LLM surface).

Covers: a successful chat that answers as labeled INTERPRETATION with
server-built citations to the exact source objects it was given; the
fail-closed contract (unconfigured, misconfigured model, missing key,
timeout, upstream HTTP error, malformed body — always 503 'unavailable',
never invented numbers); secret non-leakage (the API key appears nowhere
outside the outbound Authorization header); tenant-scoped context; the
input bound; and the write-guard (no upstream state, only the tenant's
own audit event).

The provider is exercised through httpx.MockTransport substituted for the
client factory (the vuln-plane fetch clients' injection posture) — the
suite never touches a network.
"""
from __future__ import annotations

import json

import httpx
import pytest

from app.db import get_db_connection
from app.speak import llm as speak_llm
from tests.ch10_12_helpers import (
    audit_event_count,
    ch10_12_fixture,
    make_final_episode,
    upstream_row_counts,
)
from tests.conftest import TENANT_A

_clean_ch10_12 = ch10_12_fixture()

# Distinctive fake credential — asserted ABSENT from every response and
# every audit row.
LLM_ENV = {
    "SPEAK_LLM_BASE_URL": "http://127.0.0.1:3001/v1",
    "SPEAK_LLM_API_KEY": "sk-test-NOT-A-REAL-CREDENTIAL-0123456789abcdef",
    "SPEAK_LLM_MODEL": "qwen3-coder-30b:free",
}


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def configured_env(monkeypatch):
    for key, value in LLM_ENV.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def unconfigured_env(monkeypatch):
    for key in LLM_ENV:
        monkeypatch.delenv(key, raising=False)


def _ok_completion(content="Interpreted from the cited objects only."):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "id": "chatcmpl-test",
            "model": LLM_ENV["SPEAK_LLM_MODEL"],
            "choices": [{
                "index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }],
        })
    return handler


def _mock_provider(monkeypatch, handler, seen=None):
    """Substitute the client factory with a MockTransport-backed one that
    records the outbound request into ``seen``."""
    def factory(config):
        def recording(request: httpx.Request) -> httpx.Response:
            if seen is not None:
                seen["url"] = str(request.url)
                seen["auth"] = request.headers.get("authorization")
                seen["body"] = json.loads(request.content)
            return handler(request)
        return httpx.Client(transport=httpx.MockTransport(recording))
    monkeypatch.setattr(speak_llm, "_build_client", factory)


# ---------------------------------------------------------------------------
# Success: interpretation + citations
# ---------------------------------------------------------------------------


class TestChatSuccess:
    def test_chat_answers_as_cited_interpretation(
        self, client, analyst_headers, configured_env, monkeypatch
    ):
        episode = make_final_episode("CVE-2026-81201")
        seen: dict = {}
        _mock_provider(monkeypatch, _ok_completion(), seen)

        r = client.post(
            "/api/speak/chat",
            json={"message": "What is our worst exposure and why?"},
            headers=analyst_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["answer"] == "Interpreted from the cited objects only."
        assert body["model"] == LLM_ENV["SPEAK_LLM_MODEL"]
        assert body["authority"] == "interpretation_only"
        assert "never a source of record" in body["disclaimer"]
        assert body["as_of"]

        # citations are SERVER-BUILT from the objects actually provided to
        # the model — never a model claim
        cited = {c["exposure_id"] for c in body["citations"]["exposures"]}
        assert str(episode["exposure_id"]) in cited

        # the outbound call carried the explicit config and the tenant scope
        assert seen["url"] == "http://127.0.0.1:3001/v1/chat/completions"
        assert seen["auth"] == f"Bearer {LLM_ENV['SPEAK_LLM_API_KEY']}"
        outbound = seen["body"]
        assert outbound["model"] == LLM_ENV["SPEAK_LLM_MODEL"]
        assert outbound["stream"] is False
        system, question = outbound["messages"][0], outbound["messages"][-1]
        assert system["role"] == "system"
        assert "INTERPRETATION, never authority" in system["content"]
        assert str(episode["exposure_id"]) in system["content"]
        assert question["role"] == "user"
        assert "What is our worst exposure and why?" in question["content"]

        # the only write: the tenant's own audit event, metadata only
        assert audit_event_count("speak.chat_completed") == 1

    def test_tenant_b_never_sees_tenant_a_context(
        self, client, analyst_headers, auth_headers_tenant_b_admin,
        configured_env, monkeypatch,
    ):
        episode = make_final_episode("CVE-2026-81202")
        seen: dict = {}
        _mock_provider(monkeypatch, _ok_completion(), seen)

        r = client.post(
            "/api/speak/chat",
            json={"message": "Summarize our exposure."},
            headers=auth_headers_tenant_b_admin,
        )
        assert r.status_code == 200, r.text
        # tenant A's exposure id appears nowhere in tenant B's outbound
        # context — nor in tenant B's answer envelope
        assert str(episode["exposure_id"]) not in seen["body"]["messages"][0]["content"]
        assert str(episode["exposure_id"]) not in r.text


# ---------------------------------------------------------------------------
# Fail closed: unconfigured / misconfigured / upstream failures
# ---------------------------------------------------------------------------


class TestChatFailsClosed:
    def test_unconfigured_provider(
        self, client, analyst_headers, unconfigured_env
    ):
        r = client.post(
            "/api/speak/chat",
            json={"message": "What is our worst exposure?"},
            headers=analyst_headers,
        )
        assert r.status_code == 503
        detail = r.json()["detail"]
        assert detail["code"] == "llm_unavailable"
        # no invented numbers anywhere in the failure — 'unavailable' only
        assert "9.2" not in r.text and "tes 9" not in r.text.lower()
        assert audit_event_count("speak.chat_completed") == 0

    @pytest.mark.parametrize("bad_model", ["auto", "gpt-4o", "qwen3-coder-30b"])
    def test_misconfigured_model_fails_closed(
        self, client, analyst_headers, configured_env, monkeypatch, bad_model
    ):
        monkeypatch.setenv("SPEAK_LLM_MODEL", bad_model)
        r = client.post(
            "/api/speak/chat", json={"message": "hi"}, headers=analyst_headers
        )
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "llm_unavailable"

    def test_missing_api_key_fails_closed(
        self, client, analyst_headers, configured_env, monkeypatch
    ):
        monkeypatch.delenv("SPEAK_LLM_API_KEY")
        r = client.post(
            "/api/speak/chat", json={"message": "hi"}, headers=analyst_headers
        )
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "llm_unavailable"

    def test_timeout_fails_closed(
        self, client, analyst_headers, configured_env, monkeypatch
    ):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("timed out", request=request)

        _mock_provider(monkeypatch, handler)
        r = client.post(
            "/api/speak/chat", json={"message": "hi"}, headers=analyst_headers
        )
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "llm_unavailable"

    def test_upstream_http_error_fails_closed_and_hides_body(
        self, client, analyst_headers, configured_env, monkeypatch
    ):
        marker = "UPSTREAM-ERROR-BODY-MARKER-should-never-surface"
        _mock_provider(
            monkeypatch,
            lambda request: httpx.Response(500, text=marker),
        )
        r = client.post(
            "/api/speak/chat", json={"message": "hi"}, headers=analyst_headers
        )
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "llm_unavailable"
        assert marker not in r.text

    @pytest.mark.parametrize(
        "payload",
        [
            "not json at all",
            {},
            {"choices": []},
            {"choices": [{}]},
            {"choices": [{"message": {"content": None}}]},
            {"choices": [{"message": {"content": "   "}}]},
            {"choices": [{"message": {"content": 42}}]},
        ],
        ids=[
            "non-json", "empty-object", "no-choices", "empty-choice",
            "null-content", "blank-content", "non-string-content",
        ],
    )
    def test_malformed_response_fails_closed(
        self, client, analyst_headers, configured_env, monkeypatch, payload
    ):
        if isinstance(payload, str):
            response = lambda request: httpx.Response(200, text=payload)
        else:
            response = lambda request: httpx.Response(200, json=payload)
        _mock_provider(monkeypatch, response)
        r = client.post(
            "/api/speak/chat", json={"message": "hi"}, headers=analyst_headers
        )
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "llm_unavailable"


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------


class TestSecretNonLeakage:
    def test_api_key_never_leaves_the_authorization_header(
        self, client, analyst_headers, configured_env, monkeypatch
    ):
        """Across success, upstream-error and timeout paths the key appears
        NOWHERE in the API envelope — and never in the audit chain."""
        key = LLM_ENV["SPEAK_LLM_API_KEY"]

        def timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("timed out", request=request)

        for handler in (_ok_completion(),
                        lambda request: httpx.Response(503, text="gateway down"),
                        timeout):
            _mock_provider(monkeypatch, handler)
            r = client.post(
                "/api/speak/chat", json={"message": "hi"},
                headers=analyst_headers,
            )
            assert r.status_code in (200, 503)
            assert key not in r.text

        # and the audit rows (the only written state) carry no key either
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT details FROM audit_events "
                    "WHERE event_name = 'speak.chat_completed';"
                )
                rows = cur.fetchall()
        dumped = json.dumps([dict(r) if not isinstance(r, dict) else r for r in rows], default=str)
        assert key not in dumped


# ---------------------------------------------------------------------------
# Input bound + write guard
# ---------------------------------------------------------------------------


class TestBoundAndWriteGuard:
    def test_message_is_bounded(self, client, analyst_headers, configured_env):
        r = client.post(
            "/api/speak/chat",
            json={"message": "x" * 4001},
            headers=analyst_headers,
        )
        assert r.status_code == 422

    def test_chat_writes_no_upstream_state(
        self, client, analyst_headers, configured_env, monkeypatch
    ):
        make_final_episode("CVE-2026-81203")
        _mock_provider(monkeypatch, _ok_completion())
        before = upstream_row_counts()
        r = client.post(
            "/api/speak/chat", json={"message": "hi"}, headers=analyst_headers
        )
        assert r.status_code == 200, r.text
        assert upstream_row_counts() == before
        # the module's only write is its own audit event
        assert audit_event_count("speak.chat_completed") == 1
