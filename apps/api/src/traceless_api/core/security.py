"""Small HTTP hardening middleware for the API surface."""

from collections.abc import Awaitable, Callable

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from traceless_api.core.observability import request_id_for_scope


class _RequestBodyTooLarge(Exception):
    pass


class SecurityHeadersMiddleware:
    """Apply API-appropriate browser and cache security headers."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        use_hsts: bool = False,
        max_request_body_bytes: int = 10_000_000,
    ) -> None:
        self.app = app
        self.use_hsts = use_hsts
        self.max_request_body_bytes = max_request_body_bytes

    async def __call__(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                request_id = request_id_for_scope(scope)
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = (
                    "camera=(), microphone=(), geolocation=(), payment=()"
                )
                headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
                headers["Cache-Control"] = "no-store"
                headers["X-Request-ID"] = request_id
                if self.use_hsts:
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        request_headers = Headers(scope=scope)
        content_length = request_headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                await JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header"},
                )(scope, receive, send_with_headers)
                return
            if declared_length < 0:
                await JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header"},
                )(scope, receive, send_with_headers)
                return
            if declared_length > self.max_request_body_bytes:
                await self._too_large(scope, receive, send_with_headers)
                return

        consumed = 0

        async def receive_bounded() -> dict:
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > self.max_request_body_bytes:
                    raise _RequestBodyTooLarge
            return message

        try:
            await self.app(scope, receive_bounded, send_with_headers)
        except _RequestBodyTooLarge:
            await self._too_large(scope, receive, send_with_headers)

    async def _too_large(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        await JSONResponse(
            status_code=413,
            content={"detail": "Request body exceeds the configured limit"},
        )(scope, receive, send)
