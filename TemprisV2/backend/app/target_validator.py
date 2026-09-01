# backend/app/target_validator.py
import ipaddress
import re
from typing import Tuple, Optional
from pydantic import BaseModel

LABEL_REGEX = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")

class TargetValidationResult(BaseModel):
    valid: bool
    normalized_target: str
    target_type: str
    address_classification: str
    error_message: Optional[str] = None

class TargetValidationError(ValueError):
    pass

def validate_ip_safety(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, raw_repr: str = "") -> None:
    """Enforces safety invariants on IP objects (rejects loopback, unspecified, multicast, reserved, broadcast)."""
    if ip_obj.is_loopback:
        raise TargetValidationError(f"Loopback IP address '{ip_obj}' is strictly prohibited.")
    if ip_obj.is_unspecified:
        raise TargetValidationError(f"Unspecified IP address '{ip_obj}' is strictly prohibited.")
    if ip_obj.is_multicast:
        raise TargetValidationError(f"Multicast IP address '{ip_obj}' is strictly prohibited.")
    if ip_obj.is_reserved:
        raise TargetValidationError(f"Reserved IP address '{ip_obj}' is strictly prohibited.")

    # Check for IPv4 limited broadcast
    if ip_obj.version == 4 and (raw_repr == "255.255.255.255" or str(ip_obj) == "255.255.255.255"):
        raise TargetValidationError("Broadcast IP address '255.255.255.255' is strictly prohibited.")

def validate_and_normalize_target(target_type: str, target_value: str) -> TargetValidationResult:
    """
    Validates and normalizes target based on target_type: 'ip', 'hostname', 'domain'.
    Enforces strict security rules:
    - Rejects loopback, unspecified, multicast, limited broadcast, localhost.
    - Rejects URLs, schemes, paths, ports, and CIDR ranges.
    - Preserves scope independence (private IPs are valid for both internet and internal).
    """
    if not target_value or not isinstance(target_value, str):
        raise TargetValidationError("target_value must be a non-empty string.")

    raw = target_value.strip()

    # Reject URLs, schemes, paths, query params
    if "://" in raw or raw.startswith("//"):
        raise TargetValidationError("URLs or schemes are not permitted in target_value.")
    if "/" in raw:
        raise TargetValidationError("Paths or CIDR notations are not permitted in target_value.")
    if "?" in raw or "#" in raw:
        raise TargetValidationError("Query parameters or fragments are not permitted in target_value.")
    if "@" in raw:
        raise TargetValidationError("Userinfo/credentials are not permitted in target_value.")

    if target_type == "ip":
        return _validate_ip(raw)
    elif target_type == "hostname":
        return _validate_hostname(raw)
    elif target_type == "domain":
        return _validate_domain(raw)
    else:
        raise TargetValidationError(f"Invalid target_type: '{target_type}'. Must be 'ip', 'hostname', or 'domain'.")

def _validate_ip(raw: str) -> TargetValidationResult:
    # Check for port in IPv4 (e.g. 1.2.3.4:80) or bracketed IPv6 with port (e.g. [::1]:80)
    if ":" in raw and not (raw.count(":") >= 2): # IPv6 has >= 2 colons
        raise TargetValidationError("Port specifications are not permitted in IP target_value.")
    if raw.startswith("[") and "]" in raw:
        raise TargetValidationError("Bracketed IP or port specifications are not permitted in IP target_value.")

    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        raise TargetValidationError(f"Invalid IP address format: '{raw}'.")

    # Safety checks
    validate_ip_safety(ip_obj, raw)

    # Canonical normalized format (RFC 5952 for IPv6, standard dotted quad for IPv4)
    normalized = str(ip_obj)

    # Address classification
    if ip_obj.is_private or ip_obj.is_link_local:
        classification = "private"
    else:
        classification = "public"

    return TargetValidationResult(
        valid=True,
        normalized_target=normalized,
        target_type="ip",
        address_classification=classification
    )

def _validate_hostname(raw: str) -> TargetValidationResult:
    # Check for port
    if ":" in raw:
        raise TargetValidationError("Port specifications are not permitted in hostname target_value.")

    clean = raw.rstrip(".").lower()
    if not clean:
        raise TargetValidationError("Hostname cannot be empty.")

    if clean == "localhost":
        raise TargetValidationError("Localhost hostname is strictly prohibited.")

    if ".." in clean:
        raise TargetValidationError("Hostname cannot contain consecutive dots.")

    if len(clean) > 253:
        raise TargetValidationError("Hostname exceeds maximum allowed length of 253 characters.")

    labels = clean.split(".")
    for label in labels:
        if not label:
            raise TargetValidationError("Hostname contains empty label.")
        if not LABEL_REGEX.match(label):
            raise TargetValidationError(f"Invalid hostname label: '{label}'. Must be 1-63 alphanumeric chars with hyphens.")

    # Classification
    if len(labels) == 1 or clean.endswith((".local", ".internal", ".lan", ".corp", ".home.arpa")):
        classification = "private"
    else:
        classification = "public"

    return TargetValidationResult(
        valid=True,
        normalized_target=clean,
        target_type="hostname",
        address_classification=classification
    )

def _validate_domain(raw: str) -> TargetValidationResult:
    # Check for port
    if ":" in raw:
        raise TargetValidationError("Port specifications are not permitted in domain target_value.")

    clean = raw.rstrip(".").lower()
    if not clean:
        raise TargetValidationError("Domain cannot be empty.")

    if clean == "localhost" or clean.endswith(".localhost"):
        raise TargetValidationError("Localhost domain is strictly prohibited.")

    if ".." in clean:
        raise TargetValidationError("Domain cannot contain consecutive dots.")

    if len(clean) > 253:
        raise TargetValidationError("Domain exceeds maximum allowed length of 253 characters.")

    labels = clean.split(".")
    if len(labels) < 2:
        raise TargetValidationError(f"Domain '{clean}' must contain at least two labels (e.g. example.com). For single-label names, use target_type 'hostname'.")

    for label in labels:
        if not label:
            raise TargetValidationError("Domain contains empty label.")
        if not LABEL_REGEX.match(label):
            raise TargetValidationError(f"Invalid domain label: '{label}'. Must be 1-63 alphanumeric chars with hyphens.")

    # Top-level label must not be all-numeric
    if labels[-1].isdigit():
        raise TargetValidationError(f"Top-level domain '{labels[-1]}' cannot be purely numeric.")

    if clean.endswith((".local", ".internal", ".lan", ".corp", ".home.arpa")):
        classification = "private"
    else:
        classification = "public"

    return TargetValidationResult(
        valid=True,
        normalized_target=clean,
        target_type="domain",
        address_classification=classification
    )
