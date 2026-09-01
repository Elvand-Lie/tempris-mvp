# backend/app/config.py
import os
import uuid
from pathlib import Path
from dotenv import load_dotenv

# Load .env from root or backend directory
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

ALLOWED_JWT_ALGORITHMS = ("HS256",)

# Dedicated platform login-context tenant. Platform administrators hold their
# single active membership here. This tenant owns no module entitlement and no
# operational data; the operational Tempris tenant remains
# 11111111-1111-1111-1111-111111111111 (Assets/Collectors).
PLATFORM_TENANT_ID = uuid.UUID("f0000000-0000-4000-8000-000000000001")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required and must not be empty.")

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET or not JWT_SECRET.strip():
    raise RuntimeError("JWT_SECRET environment variable is required and must not be empty.")

cleaned_jwt_secret = JWT_SECRET.strip()
if cleaned_jwt_secret.lower() in ("<jwt_secret>", "jwt_secret", "changeme", "secret", "placeholder") or (cleaned_jwt_secret.startswith("<") and cleaned_jwt_secret.endswith(">")):
    raise RuntimeError("JWT_SECRET must not be a placeholder value.")

if len(cleaned_jwt_secret.encode("utf-8")) < 32:
    raise RuntimeError("JWT_SECRET must be at least 32 UTF-8 bytes.")

JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
if JWT_ALGORITHM not in ALLOWED_JWT_ALGORITHMS:
    raise RuntimeError(
        f"JWT_ALGORITHM '{JWT_ALGORITHM}' is not allowed. Permitted algorithms: {list(ALLOWED_JWT_ALGORITHMS)}"
    )

PORT = int(os.environ.get("PORT", 8000))
COLLECTOR_SERVER_URL = os.environ.get("COLLECTOR_SERVER_URL", "http://127.0.0.1:8000")

# Vulnerability Intelligence synchronization configuration
# Disabled by default so tests/startup never call the Internet unexpectedly.
VULN_SYNC_ENABLED = os.environ.get("VULN_SYNC_ENABLED", "false").lower() in ("true", "1", "yes")
VULN_SYNC_CHECK_INTERVAL = int(os.environ.get("VULN_SYNC_CHECK_INTERVAL", "60"))
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip() or None

