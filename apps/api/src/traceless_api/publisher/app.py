"""FastAPI applications for separated publisher trust surfaces."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from traceless_api.core.observability import RequestObservabilityMiddleware
from traceless_api.core.oidc import OidcJwtVerifier
from traceless_api.core.security import SecurityHeadersMiddleware
from traceless_api.publisher.auth import (
    PublisherAdminPrincipal,
    PublisherClient,
    PublisherIngestPrincipal,
    PublisherReviewerPrincipal,
    PublisherSession,
)
from traceless_api.publisher.config import PublisherSettings, get_publisher_settings
from traceless_api.publisher.db import (
    create_publisher_engine,
    create_publisher_schema,
    create_publisher_session_factory,
)
from traceless_api.publisher.models import (
    PublisherClientCreate,
    PublisherClientCredential,
    PublisherClientPage,
    PublisherClientUpdate,
    PublisherClientView,
    PublisherHealth,
    PublisherImportBatch,
    PublisherImportResult,
    PublisherPublishResult,
    PublisherRecordPage,
    PublisherSigningKeyView,
)
from traceless_api.publisher.models_v2 import (
    PublisherAccountCreate,
    PublisherAccountPage,
    PublisherAccountView,
    PublisherCredentialMetadata,
    PublisherCredentialPage,
    PublisherFeedPageV2,
    PublisherImportRunPage,
    PublisherInstallationCreate,
    PublisherInstallationCredential,
    PublisherInstallationPage,
    PublisherPublicationDecisionPage,
    PublisherPublicationRequest,
    PublisherRejectionRequest,
    PublisherSigningKeyItem,
    PublisherSigningKeySetView,
)
from traceless_api.publisher.rate_limit import PublisherRateLimitMiddleware
from traceless_api.publisher.service import (
    PublisherConflictError,
    PublisherCursorError,
    PublisherNotFoundError,
    PublisherService,
    sign_payload,
    signing_public_key_base64,
)
from traceless_api.publisher.service_v2 import (
    PublisherPlatformService,
    signing_key_set,
    synchronize_signing_key_registry,
)


def create_publisher_app(settings: PublisherSettings | None = None) -> FastAPI:
    settings = settings or get_publisher_settings()
    engine = create_publisher_engine(settings.database_url)
    session_factory = create_publisher_session_factory(engine)
    docs_enabled = settings.enable_docs and settings.environment != "production"

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.auto_create_schema:
            create_publisher_schema(engine)
        if settings.surface in {"combined", "admin"}:
            with session_factory() as session:
                synchronize_signing_key_registry(session, settings)
                session.commit()
        app.state.publisher_oidc_verifier = _oidc_verifier(settings)
        yield
        engine.dispose()

    app = FastAPI(
        title="Traceless Intelligence Publisher",
        description=(
            "Central intelligence staging, review and signed delta distribution for "
            "customer-local Traceless installations."
        ),
        version="0.3.0",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.publisher_settings = settings
    app.state.publisher_engine = engine
    app.state.publisher_session_factory = session_factory
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(
        SecurityHeadersMiddleware,
        use_hsts=settings.environment == "production",
        max_request_body_bytes=settings.max_request_body_bytes,
    )
    app.add_middleware(
        PublisherRateLimitMiddleware,
        feed_per_minute=settings.feed_rate_limit_per_minute,
        admin_per_minute=settings.admin_rate_limit_per_minute,
        max_buckets=settings.rate_limit_max_buckets,
    )
    app.add_middleware(RequestObservabilityMiddleware)

    @app.exception_handler(PublisherNotFoundError)
    async def not_found(_: Request, error: PublisherNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(error)})

    @app.exception_handler(PublisherConflictError)
    async def conflict(_: Request, error: PublisherConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(error)})

    @app.exception_handler(PublisherCursorError)
    async def invalid_cursor(_: Request, error: PublisherCursorError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(error)})

    @app.get("/health/live", response_model=PublisherHealth, tags=["health"])
    def health_live() -> PublisherHealth:
        return PublisherHealth(status="ok")

    @app.get("/health/ready", response_model=PublisherHealth, tags=["health"])
    def health_ready(session: PublisherSession) -> PublisherHealth:
        session.execute(text("SELECT 1"))
        if not settings.auto_create_schema:
            revision = session.scalar(text("SELECT version_num FROM alembic_version"))
            if revision != settings.required_schema_revision:
                raise HTTPException(
                    status_code=503,
                    detail="Publisher schema revision is not ready",
                )
        if settings.expected_database_role is not None:
            current_role = session.scalar(text("SELECT current_user"))
            if current_role != settings.expected_database_role:
                raise HTTPException(status_code=503, detail="Publisher database role is not ready")
        if settings.surface in {"combined", "admin", "feed"}:
            key_set = signing_key_set(session, settings)
            active = next(
                (
                    item
                    for item in key_set.keys
                    if item.key_id == settings.signing_key_id and item.status == "active"
                ),
                None,
            )
            if active is None:
                raise HTTPException(
                    status_code=503,
                    detail="Publisher signing key registry is not ready",
                )
            expected_fingerprint = hashlib.sha256(
                base64.b64decode(signing_public_key_base64(settings))
            ).hexdigest()
            if active.fingerprint_sha256 != expected_fingerprint:
                raise HTTPException(
                    status_code=503,
                    detail="Publisher signing key fingerprint is not ready",
                )
            sign_payload(settings, b"traceless-publisher-readiness")
        return PublisherHealth(status="ready")

    if settings.surface in {"combined", "feed"}:
        _register_public_routes(app, settings)
    if settings.surface in {"combined", "admin"}:
        _register_admin_routes(app, settings)
    if settings.surface in {"combined", "ingest"}:
        _register_ingest_routes(app, settings)
    if settings.surface in {"combined", "review"}:
        _register_review_routes(app, settings)
    return app


def _register_public_routes(app: FastAPI, settings: PublisherSettings) -> None:
    @app.get(
        "/.well-known/traceless-intelligence-signing-key",
        response_model=PublisherSigningKeyView,
        tags=["public"],
    )
    def current_signing_key() -> PublisherSigningKeyView:
        return PublisherSigningKeyView(
            key_id=settings.signing_key_id,
            public_key_base64=signing_public_key_base64(settings),
        )

    @app.get(
        "/.well-known/traceless-intelligence-signing-keys",
        response_model=PublisherSigningKeySetView,
        tags=["public"],
    )
    def signing_keys(session: PublisherSession) -> PublisherSigningKeySetView:
        result = signing_key_set(session, settings)
        if result.keys:
            return result
        public_key = signing_public_key_base64(settings)
        fingerprint = hashlib.sha256(base64.b64decode(public_key)).hexdigest()
        return PublisherSigningKeySetView(
            generated_at=datetime.now(UTC),
            active_key_id=settings.signing_key_id,
            keys=[
                PublisherSigningKeyItem(
                    key_id=settings.signing_key_id,
                    public_key_base64=public_key,
                    fingerprint_sha256=fingerprint,
                    status="active",
                    not_before=datetime.now(UTC),
                )
            ],
        )

    if settings.legacy_v1_enabled():

        @app.get("/v1/datapoints", response_class=Response, tags=["customer-feed"])
        def customer_feed_v1(
            client: PublisherClient,
            session: PublisherSession,
            limit: int = Query(default=250, ge=1, le=1_000),
            cursor: str | None = Query(default=None, min_length=1, max_length=2_048),
        ) -> Response:
            if client.client is None:
                raise HTTPException(status_code=404, detail="Legacy publisher feed is unavailable")
            page = PublisherService(session, settings).build_feed_page(
                client.client,
                limit=limit,
                cursor=cursor,
            )
            return _signed_json_response(settings, page.model_dump(mode="json"))

    @app.get(
        "/v2/datapoints",
        response_model=None,
        response_class=Response,
        tags=["customer-feed"],
    )
    def customer_feed_v2(
        client: PublisherClient,
        session: PublisherSession,
        limit: int = Query(default=250, ge=1, le=1_000),
        cursor: str | None = Query(default=None, min_length=1, max_length=2_048),
        sync_token: str | None = Query(default=None, min_length=1, max_length=2_048),
    ) -> Response:
        page: PublisherFeedPageV2 = PublisherPlatformService(
            session,
            settings,
        ).build_feed_page_v2(
            client,
            limit=limit,
            cursor=cursor,
            sync_token=sync_token,
        )
        return _signed_json_response(settings, page.model_dump(mode="json"))


def _register_admin_routes(app: FastAPI, settings: PublisherSettings) -> None:
    @app.post(
        "/admin/v2/accounts",
        response_model=PublisherAccountView,
        status_code=status.HTTP_201_CREATED,
        tags=["publisher-admin"],
    )
    def create_account(
        payload: PublisherAccountCreate,
        session: PublisherSession,
        principal: PublisherAdminPrincipal,
    ) -> PublisherAccountView:
        return PublisherPlatformService(session, settings).create_account(payload, principal)

    @app.get(
        "/admin/v2/accounts",
        response_model=PublisherAccountPage,
        tags=["publisher-admin"],
    )
    def list_accounts(
        session: PublisherSession,
        _: PublisherAdminPrincipal,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> PublisherAccountPage:
        return PublisherPlatformService(session, settings).list_accounts(
            limit=limit,
            offset=offset,
        )

    @app.post(
        "/admin/v2/accounts/{account_key}/installations",
        response_model=PublisherInstallationCredential,
        status_code=status.HTTP_201_CREATED,
        tags=["publisher-admin"],
    )
    def create_account_installation(
        account_key: str,
        payload: PublisherInstallationCreate,
        session: PublisherSession,
        principal: PublisherAdminPrincipal,
    ) -> PublisherInstallationCredential:
        return PublisherPlatformService(session, settings).create_account_installation(
            account_key,
            payload,
            principal,
        )

    @app.post(
        "/admin/v2/installations/{client_id}/rotate-key",
        response_model=PublisherInstallationCredential,
        tags=["publisher-admin"],
    )
    def rotate_account_installation_key(
        client_id: str,
        session: PublisherSession,
        principal: PublisherAdminPrincipal,
    ) -> PublisherInstallationCredential:
        return PublisherPlatformService(session, settings).rotate_installation_key(
            client_id,
            principal,
        )

    @app.post(
        "/admin/v1/clients",
        response_model=PublisherClientCredential,
        status_code=status.HTTP_201_CREATED,
        tags=["publisher-admin"],
    )
    def create_client(
        payload: PublisherClientCreate,
        session: PublisherSession,
        principal: PublisherAdminPrincipal,
    ) -> PublisherClientCredential:
        return PublisherPlatformService(session, settings).create_client(payload, principal)

    @app.get(
        "/admin/v1/clients",
        response_model=PublisherClientPage,
        tags=["publisher-admin"],
    )
    def list_clients(
        session: PublisherSession,
        _: PublisherAdminPrincipal,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> PublisherClientPage:
        return PublisherPlatformService(session, settings).list_clients(
            limit=limit,
            offset=offset,
        )

    @app.patch(
        "/admin/v1/clients/{client_id}",
        response_model=PublisherClientView,
        tags=["publisher-admin"],
    )
    def update_client(
        client_id: str,
        payload: PublisherClientUpdate,
        session: PublisherSession,
        principal: PublisherAdminPrincipal,
    ) -> PublisherClientView:
        return PublisherPlatformService(session, settings).update_client(
            client_id,
            payload,
            principal,
        )

    @app.post(
        "/admin/v1/clients/{client_id}/rotate-key",
        response_model=PublisherClientCredential,
        tags=["publisher-admin"],
    )
    def rotate_client_key(
        client_id: str,
        session: PublisherSession,
        principal: PublisherAdminPrincipal,
    ) -> PublisherClientCredential:
        return PublisherPlatformService(session, settings).rotate_client_key(
            client_id,
            principal,
        )

    @app.get(
        "/admin/v1/installations",
        response_model=PublisherInstallationPage,
        tags=["publisher-admin"],
    )
    def list_installations(
        session: PublisherSession,
        _: PublisherAdminPrincipal,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> PublisherInstallationPage:
        return PublisherPlatformService(session, settings).list_installations(
            limit=limit,
            offset=offset,
        )

    @app.get(
        "/admin/v1/clients/{client_id}/credentials",
        response_model=PublisherCredentialPage,
        tags=["publisher-admin"],
    )
    def list_credentials(
        client_id: str,
        session: PublisherSession,
        _: PublisherAdminPrincipal,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> PublisherCredentialPage:
        return PublisherPlatformService(session, settings).list_credentials(
            client_id,
            limit=limit,
            offset=offset,
        )

    @app.delete(
        "/admin/v1/clients/{client_id}/credentials/{credential_id}",
        response_model=PublisherCredentialMetadata,
        tags=["publisher-admin"],
    )
    def revoke_credential(
        client_id: str,
        credential_id: UUID,
        session: PublisherSession,
        principal: PublisherAdminPrincipal,
    ) -> PublisherCredentialMetadata:
        return PublisherPlatformService(session, settings).revoke_credential(
            client_id,
            credential_id,
            principal,
        )

    @app.get(
        "/admin/v1/imports",
        response_model=PublisherImportRunPage,
        tags=["publisher-admin"],
    )
    def list_import_runs(
        session: PublisherSession,
        _: PublisherAdminPrincipal,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> PublisherImportRunPage:
        return PublisherPlatformService(session, settings).list_import_runs(
            limit=limit,
            offset=offset,
        )


def _register_ingest_routes(app: FastAPI, settings: PublisherSettings) -> None:
    @app.post(
        "/admin/v1/imports",
        response_model=PublisherImportResult,
        tags=["publisher-ingest"],
    )
    def import_records(
        payload: PublisherImportBatch,
        session: PublisherSession,
        principal: PublisherIngestPrincipal,
    ) -> PublisherImportResult:
        return PublisherPlatformService(session, settings).import_batch(payload, principal)


def _register_review_routes(app: FastAPI, settings: PublisherSettings) -> None:
    @app.get(
        "/admin/v1/records",
        response_model=PublisherRecordPage,
        tags=["publisher-review"],
    )
    def list_records(
        session: PublisherSession,
        _: PublisherReviewerPrincipal,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> PublisherRecordPage:
        return PublisherPlatformService(session, settings).list_records(
            limit=limit,
            offset=offset,
        )

    @app.get(
        "/admin/v1/records/{record_id}/decisions",
        response_model=PublisherPublicationDecisionPage,
        tags=["publisher-review"],
    )
    def list_decisions(
        record_id: UUID,
        session: PublisherSession,
        _: PublisherReviewerPrincipal,
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> PublisherPublicationDecisionPage:
        return PublisherPlatformService(session, settings).list_publication_decisions(
            record_id,
            limit=limit,
            offset=offset,
        )

    @app.post(
        "/admin/v1/records/{record_id}/publish",
        response_model=PublisherPublishResult,
        tags=["publisher-review"],
    )
    def publish_record(
        record_id: UUID,
        payload: PublisherPublicationRequest,
        session: PublisherSession,
        principal: PublisherReviewerPrincipal,
    ) -> PublisherPublishResult:
        return PublisherPlatformService(session, settings).publish_record(
            record_id,
            payload,
            principal,
        )

    @app.post(
        "/admin/v1/records/{record_id}/reject",
        response_model=PublisherPublishResult,
        tags=["publisher-review"],
    )
    def reject_record(
        record_id: UUID,
        payload: PublisherRejectionRequest,
        session: PublisherSession,
        principal: PublisherReviewerPrincipal,
    ) -> PublisherPublishResult:
        return PublisherPlatformService(session, settings).reject_record(
            record_id,
            payload,
            principal,
        )


def _signed_json_response(settings: PublisherSettings, document: object) -> Response:
    payload = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    headers = sign_payload(settings, payload)
    headers["Cache-Control"] = "private, no-store"
    headers["X-Traceless-Signature-Version"] = "1"
    return Response(content=payload, media_type="application/json", headers=headers)


def _oidc_verifier(settings: PublisherSettings) -> OidcJwtVerifier | None:
    if settings.oidc_issuer is None:
        return None
    assert settings.oidc_audience is not None
    assert settings.oidc_jwks_url is not None

    def client_factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(follow_redirects=False, trust_env=False)

    return OidcJwtVerifier(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        jwks_url=settings.oidc_jwks_url,
        http_client_factory=client_factory,
        cache_seconds=settings.oidc_jwks_cache_seconds,
        clock_skew_seconds=settings.oidc_clock_skew_seconds,
        max_token_bytes=settings.oidc_max_token_bytes,
        max_jwks_bytes=settings.oidc_max_jwks_bytes,
    )


app = create_publisher_app()
