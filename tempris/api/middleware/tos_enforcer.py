"""
ToS Enforcement Middleware — Pattern classifier for distillation detection.

Detects:
1. Bulk sequential requests to AI endpoints (>10 in 60 seconds)
2. Systematic CVE enumeration patterns
3. Response harvesting patterns (all unique queries, no repeated interactions)

When classifier fires → auto-suspend account + audit log entry.
"""
import time
import logging
from collections import defaultdict
from datetime import datetime, timezone
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request

logger = logging.getLogger("tempris.tos_enforcer")

# ── Pattern tracking (in-memory) ──────────────────────────────────────────────

# {email: [timestamps]} — tracks AI endpoint request times
_ai_request_times: dict[str, list[float]] = defaultdict(list)

# {email: set(query_hashes)} — tracks unique queries per session window
_unique_queries: dict[str, list[tuple[str, float]]] = defaultdict(list)

# {email: int} — sequential CVE query counter
_cve_enumeration_counter: dict[str, int] = defaultdict(int)

# In-memory suspension cache for fast lookups
_suspended_accounts: set[str] = set()

# Window settings
BURST_WINDOW_SECONDS = 60
BURST_THRESHOLD = 10           # >10 AI requests in 60 seconds
UNIQUE_QUERY_WINDOW = 300      # 5-minute window
UNIQUE_QUERY_THRESHOLD = 20   # 20+ unique queries in 5 min = harvesting
CVE_ENUM_THRESHOLD = 15        # 15+ sequential CVE-pattern queries


def load_suspended_accounts():
    """Load active suspensions from DB into memory cache."""
    try:
        from services.database import SessionLocal
        from models import AccountSuspension
        db = SessionLocal()
        active = db.query(AccountSuspension.email).filter(
            AccountSuspension.is_active == True
        ).all()
        _suspended_accounts.clear()
        _suspended_accounts.update(r[0] for r in active)
        db.close()
        if _suspended_accounts:
            logger.info(f"Loaded {len(_suspended_accounts)} suspended accounts.")
    except Exception as e:
        logger.error(f"Failed to load suspended accounts: {e}")


def suspend_account(email: str, reason: str):
    """Auto-suspend an account and persist to DB."""
    _suspended_accounts.add(email)
    try:
        from services.database import SessionLocal
        from models import AccountSuspension
        db = SessionLocal()

        # Check if already suspended
        existing = db.query(AccountSuspension).filter(
            AccountSuspension.email == email,
            AccountSuspension.is_active == True,
        ).first()
        if existing:
            db.close()
            return

        db.add(AccountSuspension(
            email=email,
            reason=reason,
            suspended_by="system:tos_enforcer",
            auto_suspended=True,
        ))
        db.commit()
        db.close()

        # Audit log
        try:
            from routers.audit import append_to_audit_log, AuditEntry
            append_to_audit_log(AuditEntry(
                user="system:tos_enforcer",
                action="ACCOUNT_SUSPENDED",
                module="SECURITY",
                detail=f"Account {email} auto-suspended: {reason}",
            ))
        except Exception:
            pass

        logger.critical(f"ACCOUNT SUSPENDED: {email} — {reason}")
    except Exception as e:
        logger.error(f"Failed to persist suspension for {email}: {e}")


def is_suspended(email: str) -> bool:
    """Check if an account is suspended."""
    return email in _suspended_accounts


def _detect_burst(email: str) -> bool:
    """Detect rapid-fire AI endpoint requests (>BURST_THRESHOLD in BURST_WINDOW)."""
    now = time.monotonic()
    times = _ai_request_times[email]
    # Prune old entries
    times[:] = [t for t in times if now - t < BURST_WINDOW_SECONDS]
    times.append(now)
    return len(times) > BURST_THRESHOLD


def _detect_harvesting(email: str, query_text: str) -> bool:
    """Detect response harvesting — many unique queries with no repeated interactions."""
    import hashlib
    now = time.monotonic()
    query_hash = hashlib.sha256(query_text.encode()).hexdigest()[:16]
    queries = _unique_queries[email]

    queries[:] = [(h, t) for h, t in queries if now - t < UNIQUE_QUERY_WINDOW]
    if query_hash not in {h for h, _ in queries}:
        queries.append((query_hash, now))
    return len(queries) > UNIQUE_QUERY_THRESHOLD


def _detect_cve_enumeration(email: str, query_text: str) -> bool:
    """Detect systematic CVE ID enumeration."""
    import re
    cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    if cve_pattern.search(query_text):
        _cve_enumeration_counter[email] += 1
        return _cve_enumeration_counter[email] > CVE_ENUM_THRESHOLD
    else:
        # Reset counter if non-CVE query
        _cve_enumeration_counter[email] = max(0, _cve_enumeration_counter[email] - 1)
    return False


class ToSEnforcerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Only check authenticated AI-sensitive endpoints
        if not any(ep in path for ep in ["/speak/", "/spotlight", "/spectrum/findings"]):
            return await call_next(request)

        # Get account email from rate limiter state or JWT
        email = getattr(request.state, "account_email", None)
        if not email:
            # Try to extract from JWT
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                try:
                    import jwt as pyjwt
                    payload = pyjwt.decode(auth_header[7:], options={"verify_signature": False})
                    email = payload.get("sub")
                except Exception:
                    pass

        if not email:
            return await call_next(request)

        # ── Check suspension ──────────────────────────────────────────────
        if is_suspended(email):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Account suspended due to Terms of Service violation. "
                              "Contact support for reinstatement.",
                    "code": "ACCOUNT_SUSPENDED",
                },
            )

        # ── Pattern detection (only on POST/write endpoints) ─────────────
        is_ai_endpoint = "/speak/chat" in path or "/spotlight" in path

        if is_ai_endpoint and request.method == "POST":
            # Detect burst: >10 AI requests in 60 seconds
            if _detect_burst(email):
                suspend_account(
                    email,
                    f"Automated bulk request pattern detected: "
                    f">{BURST_THRESHOLD} AI queries within {BURST_WINDOW_SECONDS}s"
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Account suspended: Automated query pattern detected. "
                                  "This violates our Terms of Service.",
                        "code": "TOS_VIOLATION_BURST",
                    },
                )

            # Try to read request body for content-based detection
            try:
                body = await request.body()
                import json
                body_data = json.loads(body) if body else {}
                query_text = body_data.get("message", "") or body_data.get("custom_focus", "")

                # Detect response harvesting
                if query_text and _detect_harvesting(email, query_text):
                    suspend_account(
                        email,
                        f"Response harvesting pattern detected: "
                        f">{UNIQUE_QUERY_THRESHOLD} unique queries in {UNIQUE_QUERY_WINDOW}s window"
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": "Account suspended: Response harvesting pattern detected.",
                            "code": "TOS_VIOLATION_HARVESTING",
                        },
                    )

                # Detect CVE enumeration
                if query_text and _detect_cve_enumeration(email, query_text):
                    suspend_account(
                        email,
                        f"Systematic CVE enumeration detected: "
                        f">{CVE_ENUM_THRESHOLD} sequential CVE-pattern queries"
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": "Account suspended: Systematic data extraction pattern detected.",
                            "code": "TOS_VIOLATION_ENUMERATION",
                        },
                    )
            except Exception:
                # If body parsing fails, still allow the request through
                pass

        response = await call_next(request)
        return response
