# backend/tests/test_target_validator.py
import pytest
from app.target_validator import validate_and_normalize_target, TargetValidationError

def test_ip_validation_and_normalization():
    # Valid IPv4
    res = validate_and_normalize_target("ip", "  192.168.1.10  ")
    assert res.valid is True
    assert res.normalized_target == "192.168.1.10"
    assert res.address_classification == "private"

    # Valid Public IPv4
    res_pub = validate_and_normalize_target("ip", "93.184.216.34")
    assert res_pub.valid is True
    assert res_pub.normalized_target == "93.184.216.34"
    assert res_pub.address_classification == "public"

    # Valid IPv6 canonical normalization
    res_v6 = validate_and_normalize_target("ip", "2607:f8b0:4005:0805:0000:0000:0000:200e")
    assert res_v6.valid is True
    assert res_v6.normalized_target == "2607:f8b0:4005:805::200e"
    assert res_v6.address_classification == "public"

def test_hostname_validation_and_normalization():
    res = validate_and_normalize_target("hostname", "  PROD-SRV-01.local.  ")
    assert res.valid is True
    assert res.normalized_target == "prod-srv-01.local"
    assert res.address_classification == "private"

    res2 = validate_and_normalize_target("hostname", "app-worker")
    assert res2.valid is True
    assert res2.normalized_target == "app-worker"
    assert res2.address_classification == "private"

def test_domain_validation_and_normalization():
    res = validate_and_normalize_target("domain", "  API.EXAMPLE.COM.  ")
    assert res.valid is True
    assert res.normalized_target == "api.example.com"
    assert res.address_classification == "public"

def test_prohibited_targets_rejected():
    # Loopback
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("ip", "127.0.0.1")
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("ip", "127.0.100.5")
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("ip", "::1")
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("hostname", "localhost")
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("domain", "app.localhost")

    # Unspecified
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("ip", "0.0.0.0")
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("ip", "::")

    # Multicast
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("ip", "224.0.0.1")
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("ip", "ff02::1")

    # Broadcast
    with pytest.raises(TargetValidationError, match="prohibited"):
        validate_and_normalize_target("ip", "255.255.255.255")

    # Schemes / URLs / Ports / CIDR
    with pytest.raises(TargetValidationError, match="URLs or schemes"):
        validate_and_normalize_target("domain", "https://example.com")
    with pytest.raises(TargetValidationError, match="URLs or schemes"):
        validate_and_normalize_target("ip", "http://10.0.0.1")
    with pytest.raises(TargetValidationError, match="Port"):
        validate_and_normalize_target("domain", "example.com:8080")
    with pytest.raises(TargetValidationError, match="Port"):
        validate_and_normalize_target("ip", "10.0.0.1:443")
    with pytest.raises(TargetValidationError, match="Paths or CIDR"):
        validate_and_normalize_target("ip", "192.168.1.0/24")

    # Malformed labels
    with pytest.raises(TargetValidationError, match="consecutive dots"):
        validate_and_normalize_target("domain", "bad..domain.com")
    with pytest.raises(TargetValidationError, match="Invalid domain label"):
        validate_and_normalize_target("domain", "-badlabel.com")
    with pytest.raises(TargetValidationError, match="must contain at least two labels"):
        validate_and_normalize_target("domain", "singlelabel")

def test_scope_independence():
    # Private IP is accepted regardless of what scope it is used in
    res_priv = validate_and_normalize_target("ip", "10.0.0.5")
    assert res_priv.valid is True
    assert res_priv.address_classification == "private"

    # Public IP is accepted regardless of scope
    res_pub = validate_and_normalize_target("ip", "8.8.8.8")
    assert res_pub.valid is True
    assert res_pub.address_classification == "public"
