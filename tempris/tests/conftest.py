import os
import sys
import pytest
import jwt
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

# Ensure api directory is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

# Must set env BEFORE importing the app, so auth.py picks up matching secret
_TEST_JWT_SECRET = "tempris_dev_only_change_in_prod_" + "x" * 32
os.environ.setdefault("JWT_SECRET_KEY", _TEST_JWT_SECRET)

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

import services.database as db_module
from services.database import Base
from index import app

# â”€â”€ Test Database Setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Use IN-MEMORY SQLite with StaticPool so ALL connections (TestClient + direct
# SessionLocal imports in audit.py) share a single connection. No disk I/O.

test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# â”€â”€ Monkey-patch the ENTIRE database module â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# This ensures that code importing SessionLocal directly (like audit.py line 126)
# also uses the test database, not the production one.
db_module.engine = test_engine
db_module.SessionLocal = TestingSessionLocal

# Override FastAPI dependency
from services.database import get_db
app.dependency_overrides[get_db] = override_get_db


# â”€â”€ JWT Token Fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

JWT_SECRET = _TEST_JWT_SECRET
JWT_ALGORITHM = "HS256"


def make_token(email: str, role: str, expired: bool = False) -> str:
    """Generate a JWT token for testing."""
    exp = datetime.now(timezone.utc) + (timedelta(hours=-1) if expired else timedelta(hours=24))
    payload = {"sub": email, "role": role, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# â”€â”€ Fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all tables before tests, drop after."""
    # Import all models so they register with Base.metadata
    import models  # noqa: F401
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(autouse=True)
def clean_tables():
    """Clean all table data and auth state between tests for isolation."""
    # Clear brute-force lockout state BEFORE each test
    import routers.auth as auth_mod
    auth_mod._login_attempts.clear()
    # Clear rate limiter buckets
    import middleware.rate_limit as rl_mod
    rl_mod._buckets.clear()
    if hasattr(rl_mod, "_probe_windows"):
        rl_mod._probe_windows.clear()
    yield
    # Clean DB tables after test
    db = TestingSessionLocal()
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.commit()
    db.close()
    # Clear lockout state again after test
    auth_mod._login_attempts.clear()
    rl_mod._buckets.clear()
    if hasattr(rl_mod, "_probe_windows"):
        rl_mod._probe_windows.clear()


@pytest.fixture
def db():
    """Provide a clean database session for tests."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def superadmin_token():
    """JWT token for Superadmin role."""
    return make_token("sherie@tempris.com", "Superadmin")


@pytest.fixture
def admin_token():
    """JWT token for Admin role."""
    return make_token("admin@tempris.com", "Admin")


@pytest.fixture
def viewer_token():
    """JWT token for Viewer role."""
    return make_token("viewer@tempris.com", "Viewer")


@pytest.fixture
def expired_token():
    """Expired JWT token."""
    return make_token("expired@tempris.tech", "Admin", expired=True)


@pytest.fixture
def superadmin_headers(superadmin_token):
    """Auth headers for Superadmin."""
    return {"Authorization": f"Bearer {superadmin_token}"}


@pytest.fixture
def admin_headers(admin_token):
    """Auth headers for Admin."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    """Auth headers for Viewer."""
    return {"Authorization": f"Bearer {viewer_token}"}


@pytest.fixture
def expired_headers(expired_token):
    """Auth headers with expired token."""
    return {"Authorization": f"Bearer {expired_token}"}


@pytest.fixture
def no_auth_headers():
    """No auth headers â€” anonymous request."""
    return {}


# â”€â”€ Sample Data Fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@pytest.fixture
def sample_asset(db):
    """Insert a sample asset into the test DB."""
    from models import Asset
    asset = Asset(
        id="ASSET-TEST-001",
        name="Test Server",
        asset_type="server",
        ip_address="192.168.1.100",
        hostname="test-server.local",
        criticality="high",
        owner="test@tempris.tech",
        environment="production",
        status="active",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@pytest.fixture
def sample_audit_entries(db):
    """Insert sample audit log entries with hash chain."""
    import hashlib
    from models import AuditLog
    entries = []
    prev_hash = "0" * 64
    for i in range(5):
        raw = f"{prev_hash}|superadmin@tempris.tech|TEST_ACTION_{i}|AUDIT|Test entry {i}"
        current_hash = hashlib.sha256(raw.encode()).hexdigest()
        entry = AuditLog(
            user_email="superadmin@tempris.tech",
            action=f"TEST_ACTION_{i}",
            module="AUDIT",
            detail=f"Test entry {i}",
            hash=current_hash,
        )
        db.add(entry)
        entries.append(entry)
        prev_hash = current_hash
    db.commit()
    return entries


# â”€â”€ Mock Fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@pytest.fixture
def mock_llm():
    """Mock the FreeLLM API client to avoid network calls."""
    with patch("services.llm_client.chat_completion") as mock:
        mock.return_value = "This is a mocked AI response for testing purposes."
        yield mock


@pytest.fixture
def mock_rag():
    """Mock the RAG engine to avoid ChromaDB dependency."""
    with patch("services.rag_engine.semantic_search") as mock_search, \
         patch("services.rag_engine.sync_knowledge_base") as mock_sync:
        mock_search.return_value = []
        mock_sync.return_value = None
        yield {"search": mock_search, "sync": mock_sync}


@pytest.fixture
def mock_kev():
    """Mock KEV data loader."""
    with patch("services.kev_loader.get_all_findings") as mock:
        mock.return_value = [
            {
                "cve": "CVE-2024-0001",
                "title": "Test Vulnerability",
                "vendor": "TestVendor",
                "product": "TestProduct",
                "cvss": 9.8,
                "priority": "P0",
                "ransomware": True,
                "date_added": "2024-01-01",
            },
            {
                "cve": "CVE-2024-0002",
                "title": "Another Vulnerability",
                "vendor": "TestVendor",
                "product": "TestProduct2",
                "cvss": 7.5,
                "priority": "P1",
                "ransomware": False,
                "date_added": "2024-01-02",
            },
        ]
        yield mock


