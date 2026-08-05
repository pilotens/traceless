"""FastAPI application factory and default ASGI application."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from traceless_api import __version__
from traceless_api.api.router import router as api_router
from traceless_api.api.routes.health import router as health_router
from traceless_api.core.config import Settings, get_settings
from traceless_api.core.observability import RequestObservabilityMiddleware
from traceless_api.core.oidc import OidcJwtVerifier
from traceless_api.core.security import SecurityHeadersMiddleware
from traceless_api.db.session import (
    create_database_engine,
    create_schema,
    create_session_factory,
)
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalNotFoundError,
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    docs_enabled = settings.enable_docs and settings.environment != "production"
    engine = create_database_engine(settings.database_url)
    session_factory = create_session_factory(engine)

    def http_client_factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": f"traceless/{__version__}"},
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if settings.auto_create_schema:
            create_schema(engine)
        yield
        engine.dispose()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Traceless security-analysis API. Operational routes persist an explicitly "
            "authorized, organization-scoped evidence-to-risk pipeline."
        ),
        debug=settings.debug,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.http_client_factory = http_client_factory
    app.state.oidc_verifier = (
        OidcJwtVerifier(
            issuer=settings.oidc_issuer,
            audience=settings.oidc_audience,
            jwks_url=settings.oidc_jwks_url,
            http_client_factory=http_client_factory,
            cache_seconds=settings.oidc_jwks_cache_seconds,
            clock_skew_seconds=settings.oidc_clock_skew_seconds,
            max_token_bytes=settings.oidc_max_token_bytes,
            max_jwks_bytes=settings.oidc_max_jwks_bytes,
        )
        if settings.oidc_issuer is not None
        and settings.oidc_audience is not None
        and settings.oidc_jwks_url is not None
        else None
    )

    @app.exception_handler(OperationalNotFoundError)
    async def operational_not_found(_: Request, error: OperationalNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(error)})

    @app.exception_handler(OperationalConflictError)
    async def operational_conflict(_: Request, error: OperationalConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(error)})

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "OPTIONS"],
        allow_headers=[
            "Accept",
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-Actor",
            "X-Request-ID",
        ],
        expose_headers=[
            "Content-Disposition",
            "X-Content-SHA256",
            "X-Request-ID",
            "X-TLP",
        ],
        max_age=600,
    )
    app.add_middleware(
        SecurityHeadersMiddleware,
        use_hsts=settings.environment == "production",
        max_request_body_bytes=settings.max_request_body_bytes,
    )
    app.add_middleware(RequestObservabilityMiddleware)

    app.include_router(health_router)
    app.include_router(api_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()
