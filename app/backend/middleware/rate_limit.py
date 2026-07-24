"""
H-04: Rate Limiting Middleware â€” Per-IP + Per-Account with Anomaly Detection.

IP-based: Token-bucket per client IP with LRU eviction (existing).
Account-based: Daily query caps per account with 3Ã— anomaly flagging (new).
AI endpoints get stricter caps to prevent distillation attacks.
"""
import time
import logging
import jwt
from typing import Any
from datetime import datetime, timedelta, timezone
from collections import OrderedDict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request

logger = logging.getLogger("tempris.ratelimit")

# â”€â”€ Token-bucket per IP (existing) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class _Bucket:
    __slots__ = ("tokens", "last_refill", "capacity", "rate")

    def __init__(self, capacity: int, rate: float):
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self.capacity = capacity
        self.rate = rate          # tokens per second

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


# â”€â”€ H-04 FIX: LRU-bounded bucket storage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

MAX_BUCKETS = 10_000  # Prevent unbounded memory growth under DDoS

class _LRUBuckets(OrderedDict):
    """OrderedDict that evicts least-recently-used entries when full."""
    def __getitem__(self, key):
        # Move to end on access (most recently used)
        self.move_to_end(key)
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) > MAX_BUCKETS:
            # Evict oldest entry
            evicted_key, _ = self.popitem(last=False)
            logger.debug(f"Rate limiter evicted bucket: {evicted_key}")


# â”€â”€ IP-based config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# path prefix â†’ (bucket capacity, refill rate tokens/sec)
_LIMITS = {
    "/api/surge/public/submit": (5, 5 / 3600),  # 5 confidential reports per IP/hour
    "/api/auth/login": (5, 5 / 60),     # 5 login attempts per minute
    "/api/scanner": (10, 10 / 60),      # 10 per minute
}
_DEFAULT_LIMIT = (100, 100 / 60)        # 100 per minute

_buckets = _LRUBuckets()


def _key(ip: str, prefix: str) -> str:
    return f"{ip}:{prefix}"


def _get_limit(path: str) -> tuple[int, float]:
    for prefix, limit in _LIMITS.items():
        if path.startswith(prefix):
            return limit
    return _DEFAULT_LIMIT


def _bucket_group(path: str) -> str:
    for prefix in _LIMITS:
        if path.startswith(prefix):
            return prefix
    return "default"


# â”€â”€ Per-account daily caps (anti-distillation) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# endpoint_group â†’ daily cap
ACCOUNT_DAILY_CAPS = {
    "speak":     50,    # AI chat queries
    "spotlight": 10,    # AI report generation
    "edip":      200,   # EDIP classification API
    "general":   1000,  # Everything else
}

ANOMALY_MULTIPLIER = 3.0  # Flag at 3Ã— rolling average

# In-memory daily counters: {(email, group, date_str): count}
_daily_counters: dict[tuple[str, str, str], int] = {}
# Rolling averages: {(email, group): avg_count_per_day}
_rolling_averages: dict[tuple[str, str], float] = {}


def _classify_endpoint(path: str) -> str:
    """Map request path to an endpoint group for account-level rate limiting."""
    if "/speak/" in path or path.endswith("/speak"):
        return "speak"
    if "/spotlight" in path:
        return "spotlight"
    if "/edip" in path or "/spectrum" in path:
        return "edip"
    return "general"


def _extract_account_email(request: Request) -> str | None:
    """Extract account email from JWT without full verification (for rate limiting only)."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]
    try:
        # Decode without verification â€” we just need the email for rate limit keying.
        # Full JWT verification happens in the auth dependency.
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("sub")
    except Exception:
        return None


def _check_account_limit(email: str, group: str) -> tuple[bool, bool]:
    """Check per-account daily limit. Returns (allowed, anomaly_flagged)."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = (email, group, today)
    cap = ACCOUNT_DAILY_CAPS.get(group, 1000)

    count = _daily_counters.get(key, 0)
    count += 1
    _daily_counters[key] = count

    # Check hard cap
    if count > cap:
        logger.warning(f"Account {email} exceeded daily cap for {group}: {count}/{cap}")
        return False, True

    # Check anomaly: 3Ã— rolling average
    avg_key = (email, group)
    avg = _rolling_averages.get(avg_key, cap / 2)  # Default to half cap if no history
    anomaly = count > (avg * ANOMALY_MULTIPLIER) and count > 10  # Ignore low counts

    if anomaly:
        logger.warning(f"ANOMALY: Account {email} {group} queries at {count} (avg: {avg:.0f}, ratio: {count/avg:.1f}Ã—)")

    return True, anomaly


def persist_daily_stats():
    """Persist daily counters to DB and update rolling averages.
    Called periodically or at end of day."""
    try:
        from services.database import SessionLocal
        from models import AccountQueryLog
        db = SessionLocal()

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for (email, group, date_str), count in _daily_counters.items():
            if date_str != today:
                continue
            cap = ACCOUNT_DAILY_CAPS.get(group, 1000)
            avg = _rolling_averages.get((email, group), cap / 2)
            anomaly = count > cap or (count > (avg * ANOMALY_MULTIPLIER) and count > 10)
            ratio = count / avg if avg else 0
            existing = db.query(AccountQueryLog).filter(
                AccountQueryLog.account_email == email,
                AccountQueryLog.endpoint_group == group,
                AccountQueryLog.query_date == date_str,
            ).first()
            if existing:
                existing.daily_count = count
                if anomaly:
                    existing.flagged_anomaly = True
                    existing.anomaly_ratio = ratio
            else:
                db.add(AccountQueryLog(
                    account_email=email, endpoint_group=group,
                    query_date=date_str, daily_count=count,
                    flagged_anomaly=anomaly,
                    anomaly_ratio=ratio if anomaly else None,
                ))

        db.commit()

        # Update rolling averages from last 7 days
        seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
        accounts = db.query(AccountQueryLog.account_email, AccountQueryLog.endpoint_group).distinct().all()
        for email, group in accounts:
            from sqlalchemy import func
            avg = db.query(func.avg(AccountQueryLog.daily_count)).filter(
                AccountQueryLog.account_email == email,
                AccountQueryLog.endpoint_group == group,
                AccountQueryLog.query_date >= seven_days_ago,
            ).scalar()
            if avg:
                _rolling_averages[(email, group)] = float(avg)

        db.close()
    except Exception as e:
        logger.error(f"Failed to persist rate limit stats: {e}")


# â”€â”€ Combined Middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


# -- EDIP/TES probe detection -------------------------------------------------
PROBE_WINDOW_SECONDS = 60
PROBE_MIN_REQUESTS = 6
PROBE_MIN_VARIANTS = 4
_probe_windows: dict[tuple[str, str], list[tuple[float, tuple]]] = {}


def _rounded_fingerprint(payload: Any) -> Any:
    if isinstance(payload, dict):
        items = []
        for key in sorted(payload):
            items.append((key, _rounded_fingerprint(payload[key])))
        return tuple(items)
    elif isinstance(payload, list):
        return tuple(_rounded_fingerprint(x) for x in payload)
    elif isinstance(payload, (int, float)):
        return round(float(payload), 1)
    else:
        return payload


def detect_probe_attempt(account: str, path: str, payload: dict) -> bool:
    """Flag repeated near-variant TES scoring probes for one account/path."""
    now = time.monotonic()
    key = (account or "anonymous", path)
    cutoff = now - PROBE_WINDOW_SECONDS
    window = [(ts, fp) for ts, fp in _probe_windows.get(key, []) if ts >= cutoff]
    window.append((now, _rounded_fingerprint(payload)))
    _probe_windows[key] = window
    variants = {fp for _, fp in window}
    return len(window) >= PROBE_MIN_REQUESTS and len(variants) >= PROBE_MIN_VARIANTS
class RateLimitMiddleware(BaseHTTPMiddleware):
    _persist_counter = 0

    async def dispatch(self, request: Request, call_next):
        # Skip health check
        if request.url.path == "/api/health":
            return await call_next(request)

        ip = request.client.host if request.client else "0.0.0.0"
        path = request.url.path

        # â”€â”€ 1. IP-based rate limit (existing) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cap, rate = _get_limit(path)
        k = _key(ip, _bucket_group(path))

        bucket = _buckets.get(k)
        if bucket is None:
            bucket = _Bucket(cap, rate)
            _buckets[k] = bucket

        if not bucket.consume():
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please try again shortly."},
                headers={"Retry-After": str(int(1 / rate))},
            )

        # â”€â”€ 2. Per-account daily limit (anti-distillation) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        email = _extract_account_email(request)
        if email:
            group = _classify_endpoint(path)
            allowed, anomaly = _check_account_limit(email, group)

            if not allowed:
                persist_daily_stats()

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": f"Daily query limit reached for {group} endpoints. "
                                  f"Your account has been flagged for review.",
                        "code": "ACCOUNT_RATE_LIMIT",
                    },
                )

            # Set anomaly header for downstream ToS enforcer
            request.state.anomaly_flagged = anomaly
            request.state.account_email = email
            request.state.endpoint_group = group
            if anomaly:
                persist_daily_stats()

        # ── 3. Structured Probe Detection (CORE-C04) ──────────────────────
        if request.method == "POST" and "/api/spectrum" in path:
            try:
                body = await request.body()
                async def receive():
                    return {"type": "http.request", "body": body}
                request._receive = receive
                
                import json
                payload = json.loads(body) if body else {}
                if detect_probe_attempt(email or "anonymous", path, payload):
                    logger.warning(f"STRUCTURED_PROBE_DETECTION: Probe attempt detected for {email or 'anonymous'} on {path}.")
                    try:
                        from services.database import SessionLocal
                        from models import AuditLog
                        db = SessionLocal()
                        from routers.audit import append_to_audit_log_db, AuditEntry
                        append_to_audit_log_db(db, AuditEntry(
                            user="system:rate_limiter",
                            action="STRUCTURED_PROBE_DETECTED",
                            module="RATE_LIMIT",
                            detail=f"Structured probe query sequence blocked on {path} for account {email or 'anonymous'}."
                        ))
                        db.commit()
                        db.close()
                    except Exception:
                        pass
                        
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Structured probe sequence detected. Request blocked by security controls."},
                        headers={"X-Tempris-Block": "PROBE_DETECTION"}
                    )
            except Exception:
                pass

        response = await call_next(request)

        # Periodically persist stats (every 100 requests)
        RateLimitMiddleware._persist_counter += 1
        if RateLimitMiddleware._persist_counter >= 100:
            RateLimitMiddleware._persist_counter = 0
            persist_daily_stats()

        return response

