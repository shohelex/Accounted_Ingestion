import time
import uuid
import logging
from datetime import datetime
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette import status

from api.dependencies import key_id, request_client_ip
from collectors.api_collector import APIRequest, APIResponse
from config import settings
from database.cache import cache_manager

logger = logging.getLogger(__name__)


_PROVENANCE_PREFIX = settings.api_prefix + "/provenance"
_HEALTH_PATHS = ("/health", "/health/")


class ProvenanceMiddleware(BaseHTTPMiddleware):
    """Records each API request and its response through the request-path collector."""

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        start_time = time.time()
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        collector = getattr(request.app.state, 'api_collector', None)
        # Not the provenance API itself (each ingest call would add a second event), nor health probes.
        if collector and (request.url.path.startswith(_PROVENANCE_PREFIX)
                          or request.url.path in _HEALTH_PATHS):
            collector = None

        if collector:
            api_request = APIRequest(
                method=request.method,
                path=str(request.url.path),
                headers=dict(request.headers),
                query_params=dict(request.query_params),
                user_id=self._get_user_id(request),
                tenant_id=request.headers.get("x-tenant-id", settings.default_tenant_id),
                timestamp=datetime.utcnow(),
                request_id=request_id,
                source_ip=request_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                body_size=int(request.headers.get("content-length", 0))
            )
            await collector.log_request(api_request)

        # The closing record is written even when the handler raises.
        response = None
        try:
            response = await call_next(request)
        finally:
            if collector:
                api_response = APIResponse(
                    status_code=response.status_code if response is not None else 500,
                    headers=dict(response.headers) if response is not None else {},
                    body_size=0,
                    duration_ms=int((time.time() - start_time) * 1000),
                    timestamp=datetime.utcnow()
                )
                await collector.log_response(request_id, api_response)

        response.headers["X-Request-ID"] = request_id
        return response

    def _get_user_id(self, request: Request) -> str:
        api_key = request.headers.get("x-api-key")
        if api_key:
            return f"key:{key_id(api_key)}"
        return "anonymous"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limit per API key or client address, kept in Redis."""

    def __init__(self, app, requests_per_minute: int):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.window_size = 60

    async def dispatch(self, request: Request, call_next):
        # Health probes are not limited; a non-positive limit disables the limiter.
        if (request.url.path in _HEALTH_PATHS or request.method == "OPTIONS"
                or self.requests_per_minute <= 0):
            return await call_next(request)

        client_id = self._get_client_id(request)
        is_allowed, remaining, reset_time = await self._check_rate_limit(client_id)

        if not is_allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Limit: {self.requests_per_minute}/minute",
                    "retry_after": reset_time
                },
                headers={
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(reset_time),
                    "Retry-After": str(reset_time)
                }
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)
        return response

    def _get_client_id(self, request: Request) -> str:
        api_key = request.headers.get("x-api-key")
        if api_key:
            return f"api_key:{key_id(api_key)}"
        # X-Forwarded-For is believed only from a trusted proxy, so a client cannot pick its bucket.
        return f"ip:{request_client_ip(request)}"

    async def _check_rate_limit(self, client_id: str) -> tuple[bool, int, int]:
        """(allowed, remaining, reset time). Without Redis, or on a Redis error, the request is allowed."""
        try:
            if not cache_manager.redis_client:
                return True, self.requests_per_minute, 0

            current_time = int(time.time())
            window_start = current_time - self.window_size
            key = f"rate_limit:{client_id}"

            await cache_manager.redis_client.zremrangebyscore(key, 0, window_start)
            current_requests = await cache_manager.redis_client.zcard(key)

            if current_requests >= self.requests_per_minute:
                oldest_request = await cache_manager.redis_client.zrange(key, 0, 0, withscores=True)
                reset_time = int(oldest_request[0][1]) + self.window_size if oldest_request else current_time + self.window_size
                return False, 0, reset_time

            await cache_manager.redis_client.zadd(key, {str(uuid.uuid4()): current_time})
            await cache_manager.redis_client.expire(key, self.window_size)

            remaining = self.requests_per_minute - current_requests - 1
            reset_time = current_time + self.window_size
            return True, remaining, reset_time

        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            return True, self.requests_per_minute, 0
