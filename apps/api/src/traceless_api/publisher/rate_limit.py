"""Small bounded in-process publisher rate limiter."""

from __future__ import annotations

import hashlib
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from threading import Lock
from time import monotonic

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp


@dataclass(slots=True)
class _Bucket:
    values: deque[float]
    last_seen: float


class PublisherRateLimitMiddleware:
    """Bounded defense in depth; production still needs a shared edge limiter."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        feed_per_minute: int,
        admin_per_minute: int,
        max_buckets: int = 50_000,
    ) -> None:
        self.app = app
        self.feed_limit = feed_per_minute
        self.admin_limit = admin_per_minute
        self.max_buckets = max_buckets
        self._requests: OrderedDict[str, _Bucket] = OrderedDict()
        self._lock = Lock()

    async def __call__(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        if path.startswith("/health/") or path.startswith("/.well-known/"):
            await self.app(scope, receive, send)
            return
        limit = self.feed_limit if path.startswith("/v") else self.admin_limit
        key = self._key(scope, path.startswith("/v"))
        allowed, retry_after = self._consume(key, limit)
        if not allowed:
            await JSONResponse(
                status_code=429,
                content={"detail": "Publisher request rate exceeded"},
                headers={"Retry-After": str(retry_after)},
            )(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _key(self, scope: dict, feed: bool) -> str:
        headers = Headers(scope=scope)
        authorization = headers.get("authorization", "")
        client = scope.get("client") or ("unknown", 0)
        material = authorization or str(client[0])
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
        return f"{'feed' if feed else 'admin'}:{digest}"

    def _consume(self, key: str, limit: int) -> tuple[bool, int]:
        now = monotonic()
        threshold = now - 60.0
        with self._lock:
            self._prune_expired(threshold)
            bucket = self._requests.pop(key, None)
            if bucket is None:
                while len(self._requests) >= self.max_buckets:
                    self._requests.popitem(last=False)
                bucket = _Bucket(values=deque(), last_seen=now)
            while bucket.values and bucket.values[0] <= threshold:
                bucket.values.popleft()
            bucket.last_seen = now
            self._requests[key] = bucket
            if len(bucket.values) >= limit:
                retry_after = max(1, int(61 - (now - bucket.values[0])))
                return False, retry_after
            bucket.values.append(now)
            return True, 0

    def _prune_expired(self, threshold: float) -> None:
        while self._requests:
            key, bucket = next(iter(self._requests.items()))
            if bucket.last_seen > threshold:
                break
            self._requests.pop(key, None)
