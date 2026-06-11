"""
H-04: Rate Limiting Middleware
In-memory token-bucket per client IP with LRU eviction.
Auth = 5/min, Scanner = 10/min, API = 100/min.
"""
import time
import logging
from collections import OrderedDict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request

logger = logging.getLogger("tempris.ratelimit")

# ── Token-bucket per IP ───────────────────────────────────────────────────────

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


# ── H-04 FIX: LRU-bounded bucket storage ─────────────────────────────────────

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


# ── Config ────────────────────────────────────────────────────────────────────

# path prefix → (bucket capacity, refill rate tokens/sec)
_LIMITS = {
    "/api/auth":    (5,  5 / 60),       # 5 per minute
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


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip health check
        if request.url.path == "/api/health":
            return await call_next(request)

        ip = request.client.host if request.client else "0.0.0.0"
        path = request.url.path
        cap, rate = _get_limit(path)
        k = _key(ip, path.split("/")[2] if path.count("/") >= 3 else "api")

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

        response = await call_next(request)
        return response
