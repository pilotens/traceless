"""Authentication boundaries for publisher administration and customer feeds."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from traceless_api.core.oidc import OidcJwtVerifier, OidcTokenError
from traceless_api.publisher.config import PublisherRole, PublisherSettings
from traceless_api.publisher.db import PublisherClientRow, get_publisher_session
from traceless_api.publisher.db_v2 import (
    PublisherClientCredentialRow,
    PublisherInstallationRow,
)
from traceless_api.publisher.service import api_key_sha256

_bearer = HTTPBearer(auto_error=False)
PublisherSession = Annotated[Session, Depends(get_publisher_session)]


@dataclass(frozen=True, slots=True)
class PublisherPrincipal:
    actor: str
    roles: frozenset[PublisherRole]
    authentication_method: Literal["service_key", "oidc"]


@dataclass(frozen=True, slots=True)
class PublisherAuthenticatedClient:
    client: PublisherClientRow | None
    installation: PublisherInstallationRow
    credential: PublisherClientCredentialRow


async def require_publisher_admin(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> PublisherPrincipal:
    return await _require_publisher_roles(
        request,
        credentials,
        {"publisher_admin"},
    )


async def require_publisher_ingest(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> PublisherPrincipal:
    return await _require_publisher_roles(
        request,
        credentials,
        {"publisher_admin", "publisher_ingest"},
    )


async def require_publisher_reviewer(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> PublisherPrincipal:
    return await _require_publisher_roles(
        request,
        credentials,
        {"publisher_admin", "publisher_reviewer"},
    )


async def _require_publisher_roles(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    permitted: set[PublisherRole],
) -> PublisherPrincipal:
    supplied = credentials.credentials if credentials is not None else ""
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise _unauthorized("Valid publisher credentials are required")

    settings: PublisherSettings = request.app.state.publisher_settings
    static_principals = (
        (
            settings.admin_key_value(),
            settings.admin_actor,
            frozenset(
                {"publisher_admin", "publisher_ingest", "publisher_reviewer"}
            ),
        ),
        (
            settings.ingest_key_value(),
            settings.ingest_actor,
            frozenset({"publisher_ingest"}),
        ),
        (
            settings.reviewer_key_value(),
            settings.reviewer_actor,
            frozenset({"publisher_reviewer"}),
        ),
    )
    for expected, actor, roles in static_principals:
        if expected is not None and hmac.compare_digest(supplied, expected):
            typed_roles = frozenset(roles)  # type: ignore[arg-type]
            if not permitted.intersection(typed_roles):
                raise _forbidden("Publisher role is not permitted for this operation")
            return PublisherPrincipal(
                actor=actor,
                roles=typed_roles,
                authentication_method="service_key",
            )

    verifier: OidcJwtVerifier | None = getattr(
        request.app.state,
        "publisher_oidc_verifier",
        None,
    )
    if verifier is None:
        raise _unauthorized("Valid publisher credentials are required")
    try:
        verified = await verifier.verify(supplied)
    except OidcTokenError as error:
        raise _unauthorized("Valid publisher credentials are required") from error

    raw_roles = verified.claims.get(settings.oidc_roles_claim, [])
    role_values = [raw_roles] if isinstance(raw_roles, str) else raw_roles
    if not isinstance(role_values, list):
        raise _forbidden("Publisher OIDC role claim is invalid")
    mapped: set[PublisherRole] = set()
    normalized_map = {
        source.casefold(): target for source, target in settings.oidc_role_map.items()
    }
    for raw_role in role_values:
        if isinstance(raw_role, str):
            target = normalized_map.get(raw_role.casefold())
            if target is not None:
                mapped.add(target)
    if not permitted.intersection(mapped):
        raise _forbidden("Publisher role is not permitted for this operation")
    subject = verified.claims.get("sub")
    assert isinstance(subject, str)
    return PublisherPrincipal(
        actor=f"oidc:{subject}",
        roles=frozenset(mapped),
        authentication_method="oidc",
    )


def require_publisher_client(
    session: PublisherSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> PublisherAuthenticatedClient:
    supplied = credentials.credentials if credentials is not None else ""
    correct_scheme = credentials is not None and credentials.scheme.casefold() == "bearer"
    prefix, separator, remainder = supplied.partition(".")
    client_id, second_separator, secret = remainder.partition(".")
    if (
        not correct_scheme
        or prefix != "traceless"
        or not separator
        or not second_separator
        or not client_id
        or not secret
    ):
        raise _unauthorized("Valid publisher client credentials are required")

    installation = session.scalar(
        select(PublisherInstallationRow).where(
            PublisherInstallationRow.client_id == client_id
        )
    )
    client = session.scalar(
        select(PublisherClientRow).where(PublisherClientRow.client_id == client_id)
    )
    if (
        installation is None
        or not installation.enabled
        or (client is not None and not client.enabled)
    ):
        raise _unauthorized("Valid publisher client credentials are required")

    now = datetime.now(UTC)
    supplied_hash = api_key_sha256(supplied)
    credential = session.scalar(
        select(PublisherClientCredentialRow).where(
            PublisherClientCredentialRow.installation_id == installation.id,
            PublisherClientCredentialRow.key_sha256 == supplied_hash,
            PublisherClientCredentialRow.not_before <= now,
            PublisherClientCredentialRow.revoked_at.is_(None),
            or_(
                PublisherClientCredentialRow.expires_at.is_(None),
                PublisherClientCredentialRow.expires_at > now,
            ),
        )
    )
    if credential is None or not hmac.compare_digest(
        credential.key_sha256,
        supplied_hash,
    ):
        raise _unauthorized("Valid publisher client credentials are required")
    return PublisherAuthenticatedClient(
        client=client,
        installation=installation,
        credential=credential,
    )


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


PublisherAdminPrincipal = Annotated[PublisherPrincipal, Depends(require_publisher_admin)]
PublisherIngestPrincipal = Annotated[PublisherPrincipal, Depends(require_publisher_ingest)]
PublisherReviewerPrincipal = Annotated[PublisherPrincipal, Depends(require_publisher_reviewer)]
PublisherClient = Annotated[PublisherAuthenticatedClient, Depends(require_publisher_client)]

# Compatibility alias retained for callers that previously consumed an actor string.
PublisherAdminActor = PublisherAdminPrincipal
