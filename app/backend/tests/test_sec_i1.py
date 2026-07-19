import pytest
import os
import sys
import importlib
from fastapi.testclient import TestClient

# Adjust sys.path to run tests from the correct backend directory context
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Clean environment variables before test execution
def clean_env():
    for key in [
        "ENVIRONMENT", "ENV", "TEMPRIS_PASS_SUPERADMIN", "TEMPRIS_PASS_ADMIN",
        "TEMPRIS_PASS_ANALYST", "TEMPRIS_PASS_VIEWER", "TEMPRIS_PASS_READONLY",
        "AUDIT_HMAC_KEY"
    ]:
        os.environ.pop(key, None)

@pytest.fixture(autouse=True)
def run_around_tests():
    # Save original environment variables to prevent polluting other test files
    old_env = dict(os.environ)
    clean_env()
    yield
    # Restore original env completely
    os.environ.clear()
    os.environ.update(old_env)
    
    import routers.auth
    import routers.audit
    import index
    importlib.reload(routers.auth)
    importlib.reload(routers.audit)
    importlib.reload(index)


# 1. Missing ENVIRONMENT refuses startup
def test_missing_environment_refuses_startup():
    clean_env()
    # ENVIRONMENT is not set at all
    with pytest.raises((RuntimeError, SystemExit)):
        import index
        importlib.reload(index)

# 2. An invalid environment value refuses startup
def test_invalid_environment_refuses_startup():
    os.environ["ENVIRONMENT"] = "invalid_env"
    with pytest.raises((RuntimeError, SystemExit)):
        import index
        importlib.reload(index)


# 3. Explicit demo mode permits demo credentials
def test_explicit_demo_mode_allows_demo():
    os.environ["ENVIRONMENT"] = "demo"
    import routers.auth
    importlib.reload(routers.auth)
    
    from index import app
    import index
    index.auth.USERS = routers.auth.USERS
    
    client = TestClient(app)
    response = client.post(
        "/api/auth/login",
        json={"email": "sherie@tempris.com", "password": "demo"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

# 4. Development does not silently permit demo credentials
def test_development_refuses_demo_credentials():
    os.environ["ENVIRONMENT"] = "development"
    # unique passwords not set -> refuses startup
    import routers.auth
    with pytest.raises(RuntimeError) as excinfo:
        importlib.reload(routers.auth)
    assert "Missing unique credentials" in str(excinfo.value)

# 5. Staging refuses missing credentials
def test_staging_refuses_missing_credentials():
    os.environ["ENVIRONMENT"] = "staging"
    # Only some credentials provided
    os.environ["TEMPRIS_PASS_SUPERADMIN"] = "secret1"
    os.environ["TEMPRIS_PASS_ADMIN"] = "secret2"
    
    import routers.auth
    with pytest.raises(RuntimeError) as excinfo:
        importlib.reload(routers.auth)
    assert "Missing unique credentials" in str(excinfo.value)

# 6. Production refuses demo credentials
def test_production_refuses_demo_credentials():
    os.environ["ENVIRONMENT"] = "production"
    os.environ["TEMPRIS_PASS_SUPERADMIN"] = "secret1"
    os.environ["TEMPRIS_PASS_ADMIN"] = "secret2"
    os.environ["TEMPRIS_PASS_ANALYST"] = "secret3"
    os.environ["TEMPRIS_PASS_VIEWER"] = "secret4"
    os.environ["TEMPRIS_PASS_READONLY"] = "demo"  # Refused
    
    import routers.auth
    with pytest.raises(RuntimeError) as excinfo:
        importlib.reload(routers.auth)
    assert "cannot be 'demo' outside ENVIRONMENT=demo" in str(excinfo.value)

# 7. Staging and production reject duplicated privileged passwords
def test_duplicated_passwords_rejected():
    os.environ["ENVIRONMENT"] = "production"
    os.environ["TEMPRIS_PASS_SUPERADMIN"] = "same_secret_123"
    os.environ["TEMPRIS_PASS_ADMIN"] = "same_secret_123"  # Duplicate
    os.environ["TEMPRIS_PASS_ANALYST"] = "secret3"
    os.environ["TEMPRIS_PASS_VIEWER"] = "secret4"
    os.environ["TEMPRIS_PASS_READONLY"] = "secret5"
    
    import routers.auth
    with pytest.raises(RuntimeError) as excinfo:
        importlib.reload(routers.auth)
    assert "Shared/duplicated passwords are not permitted" in str(excinfo.value)

# 8. Staging and production refuse missing or weak HMAC keys
def test_staging_production_refuse_weak_hmac_keys(tmp_path):
    os.environ["ENVIRONMENT"] = "production"
    os.environ["TEMPRIS_PASS_SUPERADMIN"] = "sec1"
    os.environ["TEMPRIS_PASS_ADMIN"] = "sec2"
    os.environ["TEMPRIS_PASS_ANALYST"] = "sec3"
    os.environ["TEMPRIS_PASS_VIEWER"] = "sec4"
    os.environ["TEMPRIS_PASS_READONLY"] = "sec5"
    os.environ["EVIDENCE_STORAGE_ROOT"] = str(tmp_path)
    
    # CASE A: Key is missing
    import index
    with pytest.raises(SystemExit):
        importlib.reload(index)
        
    # CASE B: Key is weak placeholder
    os.environ["AUDIT_HMAC_KEY"] = "test_audit_hmac_weak_placeholder"
    with pytest.raises(SystemExit):
        importlib.reload(index)

    # CASE C: Key is too short (under 32 bytes)
    os.environ["AUDIT_HMAC_KEY"] = "short_key"
    with pytest.raises(SystemExit):
        importlib.reload(index)

# 9. Valid staging and production configuration succeeds
def test_valid_production_configuration_succeeds(tmp_path):
    os.environ["ENVIRONMENT"] = "production"
    os.environ["TEMPRIS_PASS_SUPERADMIN"] = "sec1"
    os.environ["TEMPRIS_PASS_ADMIN"] = "sec2"
    os.environ["TEMPRIS_PASS_ANALYST"] = "sec3"
    os.environ["TEMPRIS_PASS_VIEWER"] = "sec4"
    os.environ["TEMPRIS_PASS_READONLY"] = "sec5"
    os.environ["AUDIT_HMAC_KEY"] = "very_long_secure_hmac_secret_key_exceeding_32_bytes_long_123"
    os.environ["EVIDENCE_STORAGE_ROOT"] = str(tmp_path)
    
    import routers.auth
    import routers.audit
    import index
    
    importlib.reload(routers.auth)
    importlib.reload(routers.audit)
    # Reload index shouldn't raise SystemExit
    importlib.reload(index)

# 10. Configuration errors never expose supplied secret values
def test_errors_do_not_leak_secrets():
    os.environ["ENVIRONMENT"] = "production"
    os.environ["TEMPRIS_PASS_SUPERADMIN"] = "MY_SUPERADMIN_SECRET_PASSWORD"
    os.environ["TEMPRIS_PASS_ADMIN"] = "sec2"
    os.environ["TEMPRIS_PASS_ANALYST"] = "sec3"
    os.environ["TEMPRIS_PASS_VIEWER"] = "sec4"
    os.environ["TEMPRIS_PASS_READONLY"] = "demo"  # Triggers error
    
    import routers.auth
    with pytest.raises(RuntimeError) as excinfo:
        importlib.reload(routers.auth)
    
    err_msg = str(excinfo.value)
    # Check that exception message is sanitized
    assert "MY_SUPERADMIN_SECRET_PASSWORD" not in err_msg
