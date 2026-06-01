"""
Application-level rate limiting middleware for Tempris API.
Implements per-IP rate limiting using an in-memory sliding window.
"""
import time
from collections import defaultdict
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware with different limits per endpoint category:
    - /api/auth/*: 5 requests per 60 seconds (brute force protection)
    - /api/scanner/*: 10 requests per 60 seconds (scan abuse prevention)
    - /api/*: 100 requests per 60 seconds (general API)
    """

    def __init__(self, app):
        super().__init__(app)
        # {category: {ip: [timestamps]}}
        self.requests: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        self.limits = {
            "auth": {"rate": 5, "window": 60},
            "scanner": {"rate": 10, "window": 60},
            "api": {"rate": 100, "window": 60},
        }

    def _get_category(self, path: str) -> str | None:
        if path.startswith("/api/auth"):
            return "auth"
        elif path.startswith("/api/scanner"):
            return "scanner"
        elif path.startswith("/api/"):
            return "api"
        return None  # No rate limit for non-API routes (frontend)

    def _is_rate_limited(self, category: str, client_ip: str) -> tuple[bool, int]:
        now = time.time()
        limit = self.limits[category]
        window = limit["window"]
        max_requests = limit["rate"]

        # Clean old entries outside the window
        self.requests[category][client_ip] = [
            t for t in self.requests[category][client_ip] if now - t < window
        ]

        current_count = len(self.requests[category][client_ip])

        if current_count >= max_requests:
            # Calculate retry-after
            oldest = self.requests[category][client_ip][0]
            retry_after = int(window - (now - oldest)) + 1
            return True, retry_after

        # Record this request
        self.requests[category][client_ip].append(now)
        return False, 0

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        category = self._get_category(path)

        if category is None:
            return await call_next(request)

        client_ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
        is_limited, retry_after = self._is_rate_limited(category, client_ip)

        if is_limited:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded for {category} endpoints. Try again in {retry_after}s.",
                    "retry_after": retry_after
                },
                headers={"Retry-After": str(retry_after)}
            )

        response = await call_next(request)
        return response
