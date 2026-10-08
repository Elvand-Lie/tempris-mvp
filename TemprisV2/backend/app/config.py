# backend/app/config.py
import json
import os
import uuid
from pathlib import Path
from typing import NamedTuple, Optional

from dotenv import load_dotenv

# Load .env from root or backend directory
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

ALLOWED_JWT_ALGORITHMS = ("HS256",)

_SECRET_PLACEHOLDERS = ("<jwt_secret>", "jwt_secret", "changeme", "secret", "placeholder")


def _validate_secret_material(secret: str, name: str) -> str:
    """Shared hygiene gate for every symmetric signing secret: non-empty,
    no known placeholder, >= 32 UTF-8 bytes (PRD Ch.5 transport/config
    hardening)."""
    cleaned = secret.strip()
    if not cleaned:
        raise RuntimeError(f"{name} must not be empty.")
    if cleaned.lower() in _SECRET_PLACEHOLDERS or (cleaned.startswith("<") and cleaned.endswith(">")):
        raise RuntimeError(f"{name} must not be a placeholder value.")
    if len(cleaned.encode("utf-8")) < 32:
        raise RuntimeError(f"{name} must be at least 32 UTF-8 bytes.")
    return cleaned

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

cleaned_jwt_secret = _validate_secret_material(JWT_SECRET, "JWT_SECRET")
JWT_SECRET = cleaned_jwt_secret

JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
if JWT_ALGORITHM not in ALLOWED_JWT_ALGORITHMS:
    raise RuntimeError(
        f"JWT_ALGORITHM '{JWT_ALGORITHM}' is not allowed. Permitted algorithms: {list(ALLOWED_JWT_ALGORITHMS)}"
    )

# ---------------------------------------------------------------------------
# JWT key set with kid + rotation path (PRD Ch.5 Target architecture item 5).
#
# Default (no JWT_KEYS configured): single-secret mode, exactly the historical
# behavior — tokens are minted and verified against JWT_SECRET with no `kid`
# header. Rotation: configure JWT_KEYS as {"kid": "secret", ...} (each value
# passing the same hygiene gate as JWT_SECRET) plus JWT_ACTIVE_KID naming the
# minting key. New tokens carry that kid; tokens signed with keys still listed
# in JWT_KEYS keep verifying; dropping a kid from JWT_KEYS retires it.
# The reserved id "default" always maps to JWT_SECRET (tokens without a kid
# header) and cannot be overridden via JWT_KEYS.
# ---------------------------------------------------------------------------
JWT_KEYS, JWT_ACTIVE_KID = None, None  # replaced by _load_jwt_key_set() below


def _load_jwt_key_set():
    keys: dict = {}
    raw = os.environ.get("JWT_KEYS", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"JWT_KEYS must be a JSON object of {{kid: secret}}: {exc}") from exc
        if not isinstance(parsed, dict) or not parsed:
            raise RuntimeError("JWT_KEYS must be a non-empty JSON object of {kid: secret}")
        for kid, secret in parsed.items():
            if (
                not isinstance(kid, str) or not (1 <= len(kid) <= 64)
                or not all(c.isalnum() or c in "._-" for c in kid)
            ):
                raise RuntimeError("JWT_KEYS key ids must be 1-64 characters of [A-Za-z0-9._-]")
            if kid == "default":
                raise RuntimeError('JWT_KEYS key id "default" is reserved (tokens without a kid header).')
            if not isinstance(secret, str):
                raise RuntimeError(f"JWT_KEYS['{kid}'] secret must be a string")
            keys[kid] = _validate_secret_material(secret, f"JWT_KEYS['{kid}']")

    active = os.environ.get("JWT_ACTIVE_KID", "").strip() or None
    if raw or active:
        if active is None:
            raise RuntimeError("JWT_ACTIVE_KID is required when JWT_KEYS is configured.")
        if active not in keys:
            raise RuntimeError("JWT_ACTIVE_KID must name one of the JWT_KEYS entries.")
    keys["default"] = JWT_SECRET
    return keys, (active if (raw or active) else None)


JWT_KEYS, JWT_ACTIVE_KID = _load_jwt_key_set()


def jwt_signing_key() -> tuple:
    """(kid, secret) for minting new tokens. kid is None in single-secret
    mode (no kid header is emitted)."""
    if JWT_ACTIVE_KID is None:
        return None, JWT_SECRET
    return JWT_ACTIVE_KID, JWT_KEYS[JWT_ACTIVE_KID]


def jwt_verification_secret(kid):
    """Resolve the verification secret for a token's `kid` header. Tokens
    without a kid verify against JWT_SECRET; an unknown kid raises KeyError
    (the caller fails closed with 401)."""
    if not kid:
        return JWT_SECRET
    secret = JWT_KEYS.get(kid)
    if secret is None:
        raise KeyError(f"Unknown token key id '{kid}'")
    return secret

PORT = int(os.environ.get("PORT", 8000))
COLLECTOR_SERVER_URL = os.environ.get("COLLECTOR_SERVER_URL", "http://127.0.0.1:8000")

# CORS origin pinning (PRD Ch.5 Target architecture item 5). Comma-separated
# explicit allowlist. Empty (default) allows NO cross-origin browser access —
# fail-closed; the same-origin frontend is unaffected. The wildcard default
# with credentials (`allow_origins=["*"]`) is retired.
CORS_ALLOW_ORIGINS = [
    origin.strip() for origin in os.environ.get("CORS_ALLOW_ORIGINS", "").split(",")
    if origin.strip()
]

# Vulnerability Intelligence synchronization configuration
# Disabled by default so tests/startup never call the Internet unexpectedly.
VULN_SYNC_ENABLED = os.environ.get("VULN_SYNC_ENABLED", "false").lower() in ("true", "1", "yes")
VULN_SYNC_CHECK_INTERVAL = int(os.environ.get("VULN_SYNC_CHECK_INTERVAL", "60"))
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip() or None

# STRIKE server-vantage pinned nuclei templates (Ch.4). The server plane runs
# nuclei against THIS directory and nothing else — template paths and content
# are never accepted from the request, exactly as on the collector. The shape
# is only a sane default: if the directory is absent at run time the run fails
# closed ("tool not available on server" family) rather than letting nuclei
# fall back to its ambient/auto-updated template set.
# SCOUT server-plane pinned Nuclei templates. Same fail-closed contract as
# STRIKE_NUCLEI_TEMPLATES_DIR but a dedicated value so the two planes can pin
# independently; empty means "not deployed" and Nuclei server runs refuse.
SCOUT_NUCLEI_TEMPLATES_DIR = os.environ.get(
    "SCOUT_NUCLEI_TEMPLATES_DIR", ""
).strip() or None

STRIKE_NUCLEI_TEMPLATES_DIR = os.environ.get(
    "STRIKE_NUCLEI_TEMPLATES_DIR", "/opt/tempris/strike/nuclei-templates"
).strip()


# ---------------------------------------------------------------------------
# SPEAK LLM provider (PRD-000 Ch.11 — the system's only LLM surface lives in
# SPEAK). Credentials arrive ONLY via the environment — never code, never the
# API envelope. Read at CALL TIME (the audit-key pattern) so reconfiguration
# needs no restart and tests can pin it per-test.
#
# Unconfigured or misconfigured → None → the AI surface fails closed (503
# 'unavailable', never invented content). The model MUST be an explicit free-
# tier id ending ':free'; V1's `model: "auto"` default is a retired defect.
# ---------------------------------------------------------------------------
SPEAK_LLM_DEFAULT_BASE_URL = "http://127.0.0.1:3001/v1"  # VPS loopback gateway
_SPEAK_LLM_FORBIDDEN_MODELS = {"auto"}


class SpeakLlmConfig(NamedTuple):
    base_url: str
    api_key: str
    model: str


def get_speak_llm_config() -> Optional[SpeakLlmConfig]:
    """The SPEAK chat provider configuration, or None when the AI surface
    must fail closed. ``SPEAK_LLM_BASE_URL`` defaults to the VPS loopback
    gateway; ``SPEAK_LLM_API_KEY`` and ``SPEAK_LLM_MODEL`` have NO defaults
    and are required. A model that is 'auto' or does not end ':free' is a
    misconfiguration, not a fallback: it fails closed like an unset key."""
    base_url = os.environ.get("SPEAK_LLM_BASE_URL", "").strip() or SPEAK_LLM_DEFAULT_BASE_URL
    api_key = os.environ.get("SPEAK_LLM_API_KEY", "").strip()
    model = os.environ.get("SPEAK_LLM_MODEL", "").strip()
    if not api_key or not model:
        return None
    if model.lower() in _SPEAK_LLM_FORBIDDEN_MODELS:
        return None
    if not model.endswith(":free"):
        return None
    if not (base_url.startswith("http://") or base_url.startswith("https://")):
        return None
    return SpeakLlmConfig(base_url=base_url, api_key=api_key, model=model)
