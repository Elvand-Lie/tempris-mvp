# backend/tests/test_target_checker.py
import socket
from unittest.mock import patch
from starlette.testclient import TestClient

def test_check_target_internal_scope_zero_io(client: TestClient, auth_headers_tenant_a_admin):
    # For internal scope, zero network I/O should occur
    with patch("socket.create_connection") as mock_connect, \
         patch("socket.getaddrinfo") as mock_dns:
        resp = client.post(
            "/api/assets/check-target",
            json={
                "target_type": "ip",
                "target_value": "10.0.0.5",
                "network_scope": "internal"
            },
            headers=auth_headers_tenant_a_admin
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["normalized_target"] == "10.0.0.5"
        assert data["network_scope"] == "internal"
        assert data["reachability_status"] == "unverified"
        assert data["verification_source"] is None
        assert data["message"] == "Internal collector required for reachability verification."

        # Zero sockets created, zero DNS calls
        mock_connect.assert_not_called()
        mock_dns.assert_not_called()

def test_check_target_internet_scope_unreachable(client: TestClient, auth_headers_tenant_a_admin):
    # Unreachable target remains valid=True with reachability_status='unreachable'
    with patch("socket.create_connection", side_effect=socket.timeout("Connection timed out")):
        resp = client.post(
            "/api/assets/check-target",
            json={
                "target_type": "domain",
                "target_value": "unreachable.test-target.example",
                "network_scope": "internet"
            },
            headers=auth_headers_tenant_a_admin
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["normalized_target"] == "unreachable.test-target.example"
        assert data["network_scope"] == "internet"
        assert data["reachability_status"] == "unreachable"
        assert data["verification_source"] == "tempris_cloud"

def test_check_target_invalid_syntax_returns_422(client: TestClient, auth_headers_tenant_a_admin):
    resp = client.post(
        "/api/assets/check-target",
        json={
            "target_type": "ip",
            "target_value": "127.0.0.1",
            "network_scope": "internet"
        },
        headers=auth_headers_tenant_a_admin
    )
    assert resp.status_code == 422
    assert "prohibited" in resp.json()["detail"]

def test_check_target_hostname_resolving_to_loopback_rejected_with_zero_socket_connections(client: TestClient, auth_headers_tenant_a_admin):
    # Proves hostname resolving to loopback 127.0.0.1 is rejected and zero socket connections occur
    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo) as mock_dns, \
         patch("socket.create_connection") as mock_connect:
        resp = client.post(
            "/api/assets/check-target",
            json={
                "target_type": "hostname",
                "target_value": "rebinding-target.local",
                "network_scope": "internet"
            },
            headers=auth_headers_tenant_a_admin
        )
        assert resp.status_code == 422
        assert "prohibited" in resp.json()["detail"]
        mock_dns.assert_called_once()
        mock_connect.assert_not_called()

def test_check_target_hostname_connects_to_pinned_resolved_ip(client: TestClient, auth_headers_tenant_a_admin):
    # Proves connection connects directly to the pinned resolved IP address (bypassing secondary DNS lookups)
    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo) as mock_dns, \
         patch("socket.create_connection") as mock_connect:
        resp = client.post(
            "/api/assets/check-target",
            json={
                "target_type": "domain",
                "target_value": "example.com",
                "network_scope": "internet"
            },
            headers=auth_headers_tenant_a_admin
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["reachability_status"] == "verified"
        mock_dns.assert_called_once()
        mock_connect.assert_called_once_with(("93.184.216.34", 443), timeout=2.0)
