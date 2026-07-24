"""Privacy-preserving structured request telemetry for production collection."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable
from time import monotonic
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_logger = logging.getLogger("traceless.http")


def request_id_for_scope(scope: dict) -> str:
    state = scope.setdefault("state", {})
    existing = state.get("request_id")
    if isinstance(existing, str) and _REQUEST_ID_PATTERN.fullmatch(existing):
        return existing
    supplied = Headers(scope=scope).get("x-request-id", "")
    request_id = supplied if _REQUEST_ID_PATTERN.fullmatch(supplied) else str(uuid4())
    state["request_id"] = request_id
    return request_id


class RequestObservabilityMiddleware:
    """Emit bounded JSON events without URLs, query strings, bodies or tokens."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = monotonic()
        request_id = request_id_for_scope(scope)
        status_code = 500

        async def send_observed(message: dict) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_observed)
        finally:
            state = scope.get("state") or {}
            principal = state.get("principal")
            route = scope.get("route")
            route_template = getattr(route, "path", "unmatched")
            event = {
                "event": "http_request_completed",
                "request_id": request_id,
                "method": scope.get("method", "UNKNOWN"),
                "route": route_template,
                "status_code": status_code,
                "duration_ms": round((monotonic() - started) * 1_000, 2),
            }
            if principal is not None:
                event["organization_id"] = str(principal.organization_id)
                event["authentication_method"] = principal.authentication_method
            _logger.info(json.dumps(event, separators=(",", ":"), sort_keys=True))
