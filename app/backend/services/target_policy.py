"""Authoritative SCOUT Target Normalization, Classification, and Network Policy Service.

Enforces strict Wave 1 security gates:
- External public attack-surface scanning ONLY.
- Non-routable, private, loopback, link-local, metadata, and special-use IP rejection.
- Strict DNS resolution and rebinding prevention.
- Safe IDNA and URL sanitization.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import NamedTuple, Optional
from urllib.parse import urlsplit


# Cloud metadata addresses and known non-global IPv6/IPv4 blocks
BLOCKED_EXACT_IPS = {
    "169.254.169.254",  # AWS/GCP/Azure/DigitalOcean metadata
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",    # AWS IPv6 metadata
}

HOSTNAME_LABEL_REGEX = re.compile(r"^(?!-)[a-z0-9-_]{1,63}(?<!-)$", re.IGNORECASE)


class TargetValidationResult(NamedTuple):
    is_valid: bool
    canonical_target: str
    target_kind: str  # public_hostname, public_ipv4, public_ipv6, public_url, or invalid / private kinds
    resolved_ips: list[str]
    dns_resolved_at: Optional[datetime]
    error: Optional[str]
    is_public_scannable: bool


def is_ip_globally_routable(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Determine whether an IP address is genuinely globally routable and safe for external scanning."""
    ip_str = str(ip_obj)
    if ip_str in BLOCKED_EXACT_IPS:
        return False

    # Check for IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1)
    if getattr(ip_obj, "ipv4_mapped", None):
        mapped = ip_obj.ipv4_mapped
        return is_ip_globally_routable(mapped)

    # Standard python ipaddress checks
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
        return False

    # Additional standard checks for global routability
    # In Python 3.11+, is_global checks against IANA special registry
    if hasattr(ip_obj, "is_global") and not ip_obj.is_global:
        return False

    # Explicitly catch carrier-grade NAT (100.64.0.0/10) if not caught
    if isinstance(ip_obj, ipaddress.IPv4Address):
        cgnat = ipaddress.IPv4Network("100.64.0.0/10")
        if ip_obj in cgnat:
            return False
        # Catch 0.0.0.0/8
        if ip_obj in ipaddress.IPv4Network("0.0.0.0/8"):
            return False

    # Catch IPv6 Unique Local Addresses (fc00::/7) if is_private missed it
    if isinstance(ip_obj, ipaddress.IPv6Address):
        ula = ipaddress.IPv6Network("fc00::/7")
        if ip_obj in ula:
            return False

    return True


def clean_target_input(raw: str) -> str:
    """Strip protocol, whitespace, trailing slash/dot, and path."""
    val = (raw or "").strip()
    if not val:
        return ""
    # Reject credentials
    if "@" in val:
        return ""
    # Strip protocol if present
    if "://" in val:
        try:
            parsed = urlsplit(val)
            if parsed.scheme not in {"http", "https"}:
                return ""
            val = parsed.netloc
        except Exception:
            return ""
    elif ":" in val:
        prefix = val.split(":", 1)[0].lower()
        if prefix in {"javascript", "mailto", "data", "file", "ftp", "ssh", "tel", "ws", "wss", "gopher"}:
            return ""

    # Strip path / query
    val = val.split("/")[0].split("?")[0].split("#")[0].strip()
    # Strip port if present on hostname (unless IPv6 in brackets)
    if ":" in val:
        if val.startswith("[") and "]" in val:
            # IPv6 with bracket
            val = val.split("]")[0].replace("[", "")
        elif val.count(":") == 1:
            # host:port
            val = val.split(":")[0]
    return val.strip().rstrip(".")


def validate_and_resolve_target(target: str) -> TargetValidationResult:
    """Strictly validate and resolve a target string.

    Accepts:
    - Public IPv4 literal
    - Public IPv6 literal
    - Public FQDN resolving exclusively to globally routable IP addresses

    Rejects:
    - CIDR notations, wildcards, lists
    - Private / RFC1918, loopback, link-local, cloud metadata
    - Hostnames resolving to ANY non-global IP
    """
    raw = (target or "").strip()
    if not raw:
        return TargetValidationResult(
            is_valid=False,
            canonical_target="",
            target_kind="invalid",
            resolved_ips=[],
            dns_resolved_at=None,
            error="Target cannot be empty",
            is_public_scannable=False,
        )

    # Reject CIDR or multiple targets
    if "/" in raw or "," in raw or " " in raw or "*" in raw or ";" in raw or "|" in raw:
        return TargetValidationResult(
            is_valid=False,
            canonical_target=raw,
            target_kind="invalid",
            resolved_ips=[],
            dns_resolved_at=None,
            error="CIDR ranges, wildcards, and multiple targets are prohibited in Wave 1",
            is_public_scannable=False,
        )

    cleaned = clean_target_input(raw)
    if not cleaned:
        return TargetValidationResult(
            is_valid=False,
            canonical_target=raw,
            target_kind="invalid",
            resolved_ips=[],
            dns_resolved_at=None,
            error="Invalid target format or unsupported URL scheme",
            is_public_scannable=False,
        )

    # 1. Try parsing as direct IP literal
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        is_v4 = isinstance(ip_obj, ipaddress.IPv4Address)
        kind = "public_ipv4" if is_v4 else "public_ipv6"
        if not is_ip_globally_routable(ip_obj):
            private_kind = "private_ipv4" if is_v4 else "private_ipv6"
            return TargetValidationResult(
                is_valid=False,
                canonical_target=str(ip_obj),
                target_kind=private_kind,
                resolved_ips=[str(ip_obj)],
                dns_resolved_at=datetime.now(timezone.utc),
                error=f"Target IP {ip_obj} is private, internal, or restricted and cannot be scanned centrally",
                is_public_scannable=False,
            )
        return TargetValidationResult(
            is_valid=True,
            canonical_target=str(ip_obj),
            target_kind=kind,
            resolved_ips=[str(ip_obj)],
            dns_resolved_at=datetime.now(timezone.utc),
            error=None,
            is_public_scannable=True,
        )
    except ValueError:
        pass

    # 2. Hostname validation and IDNA handling
    try:
        idna_host = cleaned.encode("idna").decode("ascii").lower()
    except Exception:
        return TargetValidationResult(
            is_valid=False,
            canonical_target=cleaned,
            target_kind="invalid",
            resolved_ips=[],
            dns_resolved_at=None,
            error="Invalid internationalized domain name (IDNA)",
            is_public_scannable=False,
        )

    labels = idna_host.split(".")
    if len(labels) < 2 or any(not HOSTNAME_LABEL_REGEX.match(label) for label in labels):
        return TargetValidationResult(
            is_valid=False,
            canonical_target=idna_host,
            target_kind="invalid_hostname",
            resolved_ips=[],
            dns_resolved_at=None,
            error=f"Invalid FQDN hostname structure: {cleaned}",
            is_public_scannable=False,
        )

    # 3. DNS Resolution
    resolved_ips: list[str] = []
    now = datetime.now(timezone.utc)
    try:
        addrinfo = socket.getaddrinfo(idna_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in addrinfo:
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except (socket.gaierror, socket.herror) as e:
        return TargetValidationResult(
            is_valid=False,
            canonical_target=idna_host,
            target_kind="unresolvable_hostname",
            resolved_ips=[],
            dns_resolved_at=now,
            error=f"DNS resolution failed for hostname '{idna_host}': {e}",
            is_public_scannable=False,
        )
    except Exception as e:
        return TargetValidationResult(
            is_valid=False,
            canonical_target=idna_host,
            target_kind="dns_error",
            resolved_ips=[],
            dns_resolved_at=now,
            error=f"DNS error resolving '{idna_host}': {e}",
            is_public_scannable=False,
        )

    if not resolved_ips:
        return TargetValidationResult(
            is_valid=False,
            canonical_target=idna_host,
            target_kind="unresolvable_hostname",
            resolved_ips=[],
            dns_resolved_at=now,
            error=f"No A or AAAA records found for '{idna_host}'",
            is_public_scannable=False,
        )

    # 4. Strict Non-Global IP Rejection across ALL resolved addresses
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not is_ip_globally_routable(ip_obj):
                return TargetValidationResult(
                    is_valid=False,
                    canonical_target=idna_host,
                    target_kind="internal_hostname",
                    resolved_ips=resolved_ips,
                    dns_resolved_at=now,
                    error=f"Hostname '{idna_host}' resolves to non-global IP address {ip_str}. Central scanning is prohibited.",
                    is_public_scannable=False,
                )
        except ValueError:
            return TargetValidationResult(
                is_valid=False,
                canonical_target=idna_host,
                target_kind="invalid_resolved_ip",
                resolved_ips=resolved_ips,
                dns_resolved_at=now,
                error=f"Hostname resolved to malformed IP: {ip_str}",
                is_public_scannable=False,
            )

    return TargetValidationResult(
        is_valid=True,
        canonical_target=idna_host,
        target_kind="public_hostname",
        resolved_ips=resolved_ips,
        dns_resolved_at=now,
        error=None,
        is_public_scannable=True,
    )


def classify_asset_target(
    ip_address: Optional[str] = None,
    hostname: Optional[str] = None,
    name: Optional[str] = None,
) -> dict:
    """Classifies an Asset's target metadata for UI display and scanning capability."""
    target_to_eval = (hostname or ip_address or name or "").strip()
    if not target_to_eval:
        return {
            "target": None,
            "target_kind": "unspecified",
            "is_public_scannable": False,
            "resolved_ips": [],
            "reason": "Asset has no hostname or IP address configured",
        }

    res = validate_and_resolve_target(target_to_eval)
    if res.is_valid:
        return {
            "target": res.canonical_target,
            "target_kind": res.target_kind,
            "is_public_scannable": True,
            "resolved_ips": res.resolved_ips,
            "reason": "Globally routable public target",
        }

    return {
        "target": res.canonical_target or target_to_eval,
        "target_kind": res.target_kind,
        "is_public_scannable": False,
        "resolved_ips": res.resolved_ips,
        "reason": res.error or "Not scannable by central SCOUT",
    }
