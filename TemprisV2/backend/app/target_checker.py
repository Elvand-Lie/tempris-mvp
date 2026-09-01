# backend/app/target_checker.py
import ipaddress
import socket
import uuid
from typing import Optional, List
from pydantic import BaseModel, Field
from app.target_validator import validate_and_normalize_target, validate_ip_safety, TargetValidationError

class TargetCheckRequest(BaseModel):
    target_type: str
    target_value: str
    network_scope: str
    collector_id: Optional[uuid.UUID] = None
    correlation_id: Optional[str] = None

class TargetCheckResponse(BaseModel):
    valid: bool
    normalized_target: str
    address_classification: str
    network_scope: str
    reachability_status: str
    verification_source: Optional[str] = None
    message: str

def check_target_reachability(
    target_type: str,
    target_value: str,
    network_scope: str
) -> TargetCheckResponse:
    if network_scope not in ("internet", "internal"):
        raise TargetValidationError(f"Invalid network_scope: '{network_scope}'. Must be 'internet' or 'internal'.")

    # Step 1: Validate and normalize target syntax/semantics
    norm_res = validate_and_normalize_target(target_type, target_value)

    # Step 2: If internal scope, strictly 0 network I/O
    if network_scope == "internal":
        return TargetCheckResponse(
            valid=True,
            normalized_target=norm_res.normalized_target,
            address_classification=norm_res.address_classification,
            network_scope="internal",
            reachability_status="unverified",
            verification_source=None,
            message="Internal collector required for reachability verification."
        )

    # Step 3: Internet scope - resolve candidate IPs once and validate each against safety rules
    candidate_ips: List[str] = []
    if target_type == "ip":
        candidate_ips = [norm_res.normalized_target]
    elif target_type in ("hostname", "domain"):
        try:
            # Resolve DNS once
            addr_info = socket.getaddrinfo(norm_res.normalized_target, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            return TargetCheckResponse(
                valid=True,
                normalized_target=norm_res.normalized_target,
                address_classification=norm_res.address_classification,
                network_scope="internet",
                reachability_status="unreachable",
                verification_source="tempris_cloud",
                message="Target is syntactically valid but unreachable (DNS resolution failed)."
            )

        for res in addr_info:
            sockaddr = res[4]
            ip_str = sockaddr[0]
            if ip_str not in candidate_ips:
                candidate_ips.append(ip_str)

        if not candidate_ips:
            return TargetCheckResponse(
                valid=True,
                normalized_target=norm_res.normalized_target,
                address_classification=norm_res.address_classification,
                network_scope="internet",
                reachability_status="unreachable",
                verification_source="tempris_cloud",
                message="Target is syntactically valid but unreachable (no DNS records found)."
            )

    # Validate every candidate resolved IP with the exact same prohibited-address rules as literal targets
    for ip_str in candidate_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise TargetValidationError(f"Invalid resolved IP address '{ip_str}'.")
        validate_ip_safety(ip_obj, ip_str)

    # Connect ONLY to the pinned validated IP addresses without a second DNS lookup
    # 0 bytes transmitted, 2.0s timeout per port
    reachable = False
    connected_port: Optional[int] = None

    for ip_str in candidate_ips:
        for port in (443, 80):
            try:
                sock = socket.create_connection((ip_str, port), timeout=2.0)
                sock.close()
                reachable = True
                connected_port = port
                break
            except (socket.timeout, socket.error, OSError):
                continue
        if reachable:
            break

    if reachable:
        return TargetCheckResponse(
            valid=True,
            normalized_target=norm_res.normalized_target,
            address_classification=norm_res.address_classification,
            network_scope="internet",
            reachability_status="verified",
            verification_source="tempris_cloud",
            message=f"Target is reachable via TCP port {connected_port}."
        )
    else:
        return TargetCheckResponse(
            valid=True,
            normalized_target=norm_res.normalized_target,
            address_classification=norm_res.address_classification,
            network_scope="internet",
            reachability_status="unreachable",
            verification_source="tempris_cloud",
            message="Target is syntactically valid but unreachable on ports 443/80."
        )
