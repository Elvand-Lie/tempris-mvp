# backend/tests/strike/test_ch4_run_tools.py
"""
Chapter 4 acceptance — the Phase 1 toolbox expansion (nmap / nuclei / ffuf /
dig alongside curl, all collector-plane).

Covers:
  * the catalogue lists all five wired capabilities; nmap/nuclei/ffuf/dig
    are marked collector-required (no VPS plane);
  * nmap: a CIDR target is accepted ONLY when the whole range sits inside
    ONE active scope CIDR entry (partially-covered ranges are refused,
    never split); hostname targets resolve + pin like curl; the dispatch
    frame carries pinned_targets;
  * nuclei: the frame names the capability and carries the pinned target
    (the collector applies its managed templates — argv proven in Rust);
  * ffuf: FUZZ placement hygiene — missing FUZZ, FUZZ in the authority, and
    FUZZ in the query are all refused at the API;
  * dig: hostname targets require an active hostname scope entry; an IP
    target (PTR) requires its own IP entry; ANY/AXFR and everything off the
    allow-list is refused with 422; the record type travels on the frame;
  * every tool fails closed when the SELECTED collector does not report the
    capability as available (UNKNOWN is NOT ready).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import TENANT_A
from tests.strike.conftest import iso, make_fake_collector, remove_fake_collector

RESOLVED_IP = "203.0.113.10"

ALL_READY = {
    "curl": {"available": True},
    "nmap": {"available": True},
    "nuclei": {"available": True},
    "ffuf": {"available": True},
    "dig": {"available": True},
}

_collector = None


@pytest.fixture(autouse=True)
def fake_strike_collector():
    global _collector
    _collector = make_fake_collector(TENANT_A)
    _collector["session"].capabilities = dict(ALL_READY)
    yield _collector
    remove_fake_collector(_collector)
    _collector = None


@pytest.fixture
def analyst_headers(auth_headers_tenant_a_analyst):
    return auth_headers_tenant_a_analyst


@pytest.fixture
def admin_headers(auth_headers_tenant_a_admin):
    return auth_headers_tenant_a_admin


def _fake_resolver(host, *args, **kwargs):
    return [(2, None, None, "", (RESOLVED_IP, 0))]


def create_scope(client, admin_headers, entry, *, ttl=timedelta(hours=1)):
    r = client.post(
        "/api/strike/scopes",
        json={"entry": entry, "expires_at": iso(datetime.now(timezone.utc) + ttl)},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


def create_run(client, analyst_headers, *, capability, target, method="RUN", **extra):
    return client.post(
        "/api/strike/runs",
        json={
            "capability": capability,
            "method": method,
            "target": target,
            "collector_id": str(_collector["id"]),
            **extra,
        },
        headers=analyst_headers,
    )


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------


def test_catalogue_lists_all_five_tools(strike_client, analyst_headers):
    r = strike_client.get("/api/strike/catalogue", headers=analyst_headers)
    assert r.status_code == 200
    catalogue = {c["capability"]: c for c in r.json()}
    # migration 048 widens the catalogue to the whole reviewed toolbox
    assert set(catalogue) == {
        "curl", "nmap", "nuclei", "ffuf", "dig",
        "httpie", "nc", "socat", "python", "bash", "chromium", "mitmproxy",
    }
    assert catalogue["curl"]["planes"] == ["server", "collector"]
    for tool in ("nmap", "nuclei", "ffuf", "dig"):
        assert catalogue[tool]["requires_collector"] is False
        assert catalogue[tool]["planes"] == ["server", "collector"]
        assert catalogue[tool]["runnable"] is True
        assert catalogue[tool]["requires_approval"] is False
    # both-vantage tools: the reviewed mechanism exists on either plane
    for tool in ("httpie", "nc", "socat", "python", "bash"):
        assert catalogue[tool]["planes"] == ["server", "collector"]
        assert catalogue[tool]["requires_collector"] is False
        assert catalogue[tool]["runnable"] is True
    # server-vantage-only tools: the collector vantage reports itself
    # unavailable rather than faking a browser/proxy it does not have
    for tool in ("chromium", "mitmproxy"):
        assert catalogue[tool]["planes"] == ["server"]
        assert catalogue[tool]["requires_collector"] is False
        assert catalogue[tool]["runnable"] is True


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------


def test_nmap_cidr_wholly_inside_one_scope_entry_accepted(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.0/24")
    r = create_run(strike_client, analyst_headers, capability="nmap", target="203.0.113.0/25")
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["policy_snapshot"]["pinned_targets"] == ["203.0.113.0/25"]
    assert run["state"] == "completed"

    frames = _collector["socket"].sent_frames
    assert frames[-1]["capability"] == "nmap"
    assert frames[-1]["pinned_targets"] == ["203.0.113.0/25"]
    assert "url" not in frames[-1]


def test_nmap_partially_covered_cidr_refused(strike_client, analyst_headers, admin_headers):
    # two adjacent /25s cover the /24 — a whole-/24 target spans BOTH entries
    # and is refused, never silently split
    create_scope(strike_client, admin_headers, "203.0.113.0/25")
    create_scope(strike_client, admin_headers, "203.0.113.128/25")
    r = create_run(strike_client, analyst_headers, capability="nmap", target="203.0.113.0/24")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_target_out_of_scope"


def test_nmap_cidr_with_host_bits_refused(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.0/24")
    r = create_run(strike_client, analyst_headers, capability="nmap", target="203.0.113.10/24")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_config_invalid"


def test_nmap_hostname_resolves_and_pins(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.0/24")
    monkeypatch.setattr("socket.getaddrinfo", _fake_resolver)
    r = create_run(strike_client, analyst_headers, capability="nmap", target="host.example.com")
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["policy_snapshot"]["pinned_ips"] == [RESOLVED_IP]
    assert run["policy_snapshot"]["pinned_targets"] == [RESOLVED_IP]


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------


def test_nuclei_frame_carries_pinned_target(strike_client, analyst_headers, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.0/24")
    monkeypatch.setattr("socket.getaddrinfo", _fake_resolver)
    r = create_run(strike_client, analyst_headers, capability="nuclei", target="https://host.example.com/")
    assert r.status_code == 201, r.text
    frame = _collector["socket"].sent_frames[-1]
    assert frame["capability"] == "nuclei"
    assert frame["url"] == "https://host.example.com/"
    assert frame["pinned_ips"] == [RESOLVED_IP]


def test_nuclei_out_of_scope_target_refused(strike_client, analyst_headers):
    r = create_run(strike_client, analyst_headers, capability="nuclei", target="https://198.51.100.9/")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_target_out_of_scope"


# ---------------------------------------------------------------------------
# ffuf
# ---------------------------------------------------------------------------


def _ffuf_scope(strike_client, admin_headers, monkeypatch):
    create_scope(strike_client, admin_headers, "203.0.113.0/24")
    monkeypatch.setattr("socket.getaddrinfo", _fake_resolver)


def test_ffuf_valid_path_fuzz_accepted(strike_client, analyst_headers, admin_headers, monkeypatch):
    _ffuf_scope(strike_client, admin_headers, monkeypatch)
    r = create_run(
        strike_client, analyst_headers, capability="ffuf",
        target="https://host.example.com/api/FUZZ/",
    )
    assert r.status_code == 201, r.text
    frame = _collector["socket"].sent_frames[-1]
    assert frame["capability"] == "ffuf"
    assert frame["url"] == "https://host.example.com/api/FUZZ/"
    assert frame["pinned_ips"] == [RESOLVED_IP]


def test_ffuf_missing_fuzz_refused(strike_client, analyst_headers, admin_headers, monkeypatch):
    _ffuf_scope(strike_client, admin_headers, monkeypatch)
    r = create_run(
        strike_client, analyst_headers, capability="ffuf",
        target="https://host.example.com/api/items",
    )
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_config_invalid"


def test_ffuf_fuzz_in_authority_refused(strike_client, analyst_headers):
    r = create_run(
        strike_client, analyst_headers, capability="ffuf",
        target="https://FUZZ.example.com/api/",
    )
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_config_invalid"


def test_ffuf_fuzz_in_query_refused(strike_client, analyst_headers):
    r = create_run(
        strike_client, analyst_headers, capability="ffuf",
        target="https://host.example.com/api?q=FUZZ",
    )
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_config_invalid"


# ---------------------------------------------------------------------------
# dig
# ---------------------------------------------------------------------------


def test_dig_hostname_scope_required_and_dispatched(strike_client, analyst_headers, admin_headers):
    scope = create_scope(strike_client, admin_headers, "scoped.example.com")
    r = create_run(
        strike_client, analyst_headers, capability="dig",
        target="scoped.example.com", record_type="TXT",
    )
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["policy_snapshot"]["pinned_ips"] == []  # no IP pinning for a name lookup
    assert run["policy_snapshot"]["hostname"] == "scoped.example.com"
    assert scope["id"] in run["policy_snapshot"]["scope_entry_ids"]
    frame = _collector["socket"].sent_frames[-1]
    assert frame["capability"] == "dig"
    assert frame["record_type"] == "TXT"
    assert "url" not in frame


def test_dig_hostname_without_scope_entry_refused(strike_client, analyst_headers, admin_headers):
    # even an IP entry covering the name's address is NOT enough: dig pins
    # the NAME, which needs its own hostname entry
    create_scope(strike_client, admin_headers, "203.0.113.10")
    r = create_run(
        strike_client, analyst_headers, capability="dig",
        target="scoped.example.com", record_type="A",
    )
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "run_target_out_of_scope"


def test_dig_ptr_with_ip_scope_accepted(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    r = create_run(
        strike_client, analyst_headers, capability="dig",
        target="203.0.113.10", record_type="PTR",
    )
    assert r.status_code == 201, r.text
    assert _collector["socket"].sent_frames[-1]["record_type"] == "PTR"


def test_dig_any_and_axfr_refused_at_api(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "scoped.example.com")
    for qtype in ("ANY", "AXFR", "IXFR", "HINFO", "*"):
        r = create_run(
            strike_client, analyst_headers, capability="dig",
            target="scoped.example.com", record_type=qtype,
        )
        assert r.status_code == 422, qtype
        assert r.json()["detail"]["code"] == "run_config_invalid"


def test_dig_missing_record_type_refused(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "scoped.example.com")
    r = create_run(strike_client, analyst_headers, capability="dig", target="scoped.example.com")
    assert r.status_code == 422


def test_record_type_on_non_dig_refused(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    r = create_run(
        strike_client, analyst_headers, capability="curl", target="203.0.113.10",
        method="GET", record_type="TXT",
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Fail-closed capability gating on the SELECTED collector
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("capability,target,extra", [
    ("nmap", "203.0.113.10", {}),
    ("nuclei", "https://203.0.113.10/", {}),
    ("ffuf", "https://203.0.113.10/FUZZ", {}),
    ("dig", "scoped.example.com", {"record_type": "A"}),
])
def test_tool_refused_when_collector_does_not_report_it(
    strike_client, analyst_headers, admin_headers, capability, target, extra, monkeypatch
):
    create_scope(strike_client, admin_headers, "203.0.113.0/24")
    create_scope(strike_client, admin_headers, "scoped.example.com")
    monkeypatch.setattr("socket.getaddrinfo", _fake_resolver)
    _collector["session"].capabilities = {"curl": {"available": True}}  # UNKNOWN = NOT ready
    r = create_run(strike_client, analyst_headers, capability=capability, target=target, **extra)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "collector_not_ready"


# ---------------------------------------------------------------------------
# Curl slice regression: the curl frame shape is unchanged (additive only)
# ---------------------------------------------------------------------------


def test_curl_frame_unchanged_shape(strike_client, analyst_headers, admin_headers):
    create_scope(strike_client, admin_headers, "203.0.113.10")
    r = create_run(strike_client, analyst_headers, capability="curl", target="203.0.113.10", method="GET")
    assert r.status_code == 201, r.text
    frame = _collector["socket"].sent_frames[-1]
    assert frame["capability"] == "curl"
    assert frame["method"] == "GET"
    assert frame["url"] == "http://203.0.113.10:80"
    assert frame["pinned_ips"] == [RESOLVED_IP]
