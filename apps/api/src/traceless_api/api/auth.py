"""Authenticated organization and role context for operational routes."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Annotated, Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from traceless_api.core.oidc import OidcTokenError

Role = Literal["admin", "analyst", "viewer", "scanner"]
CAPABILITY_ORDER = (
    "read_operational",
    "analyze",
    "manage_scans",
    "ingest_intelligence",
    "administer",
)


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Server-derived identity used for authorization, tenancy and audit."""

    subject: str
    actor: str
    organization_id: UUID
    organization_key: str
    organization_name: str
    roles: frozenset[str]
    authentication_method: Literal["local", "api_key", "oidc", "worker"]
    # None means explicitly unrestricted. An empty set means no assignments.
    # Production authentication paths below always set these fields.
    project_ids: frozenset[UUID] | None = None
    system_ids: frozenset[UUID] | None = None

    def has_any_role(self, *roles: Role) -> bool:
        return bool(self.roles.intersection(roles))


_bearer = HTTPBearer(auto_error=False)


def _organization_uuid(issuer: str, value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError:
        return uuid5(NAMESPACE_URL, f"{issuer.rstrip('/')}#organization:{value}")


def _claim_values(claims: dict[str, Any], name: str) -> list[str]:
    value = claims.get(name)
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []


def _claim_uuid_values(claims: dict[str, Any], name: str) -> frozenset[UUID]:
    values = _claim_values(claims, name)
    try:
        return frozenset(UUID(value) for value in values)
    except ValueError:
        raise _forbidden("The access token contains an invalid resource assignment") from None


def _resource_scope_from_claims(
    claims: dict[str, Any], project_claim: str, system_claim: str
) -> tuple[frozenset[UUID] | None, frozenset[UUID] | None]:
    project_values = _claim_values(claims, project_claim)
    system_values = _claim_values(claims, system_claim)
    if "*" in {*project_values, *system_values}:
        if project_values not in ([], ["*"]) or system_values not in ([], ["*"]):
            raise _forbidden("The access token contains an ambiguous resource assignment")
        return None, None
    return (
        _claim_uuid_values(claims, project_claim),
        _claim_uuid_values(claims, system_claim),
    )


async def require_operational_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    local_actor: Annotated[
        str | None,
        Header(alias="X-Actor", min_length=2, max_length=160),
    ] = None,
) -> AuthenticatedPrincipal:
    """Authenticate a request and derive its immutable tenant/role boundary."""

    settings = request.app.state.settings
    configured_key = settings.operational_api_key
    supplied = credentials.credentials if credentials is not None else ""
    correct_scheme = credentials is not None and credentials.scheme.casefold() == "bearer"

    if (
        configured_key is not None
        and correct_scheme
        and hmac.compare_digest(supplied, configured_key.get_secret_value())
    ):
        organization_id = settings.operational_organization_id
        unrestricted = settings.operational_resource_scope_all or (
            "admin" in settings.operational_roles
            and not settings.operational_project_ids
            and not settings.operational_system_ids
        )
        return _bind_principal(
            request,
            AuthenticatedPrincipal(
                subject=settings.operational_actor_name,
                actor=f"api-key:{settings.operational_actor_name}",
                organization_id=organization_id,
                organization_key=settings.operational_organization_key,
                organization_name=settings.operational_organization_name,
                roles=frozenset(settings.operational_roles),
                authentication_method="api_key",
                project_ids=(
                    None if unrestricted else frozenset(settings.operational_project_ids)
                ),
                system_ids=(
                    None if unrestricted else frozenset(settings.operational_system_ids)
                ),
            ),
        )

    if settings.oidc_issuer is not None:
        if not correct_scheme or not supplied:
            raise _unauthorized("An OIDC access token is required")
        try:
            verified = await request.app.state.oidc_verifier.verify(supplied)
        except (OidcTokenError, httpx.HTTPError, ValueError):
            # Do not disclose whether signature, issuer, timing or key retrieval
            # caused validation to fail.
            raise _unauthorized("The OIDC access token is invalid") from None
        claims = dict(verified.claims)
        organization_value = claims.get(settings.oidc_organization_claim)
        if not isinstance(organization_value, str) or not organization_value:
            raise _forbidden("The access token has no organization assignment")
        subject = claims.get("oid") or claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise _unauthorized("The OIDC access token is invalid")
        claim_roles = _claim_values(claims, settings.oidc_roles_claim)
        explicit_role_map = {
            source.casefold(): target for source, target in settings.oidc_role_map.items()
        }
        mapped_roles = {
            explicit_role_map[role.casefold()]
            for role in claim_roles
            if role.casefold() in explicit_role_map
        }
        if not mapped_roles:
            raise _forbidden("No Traceless application role is assigned")
        organization_name_claim = claims.get(settings.oidc_organization_name_claim)
        organization_name = (
            organization_name_claim
            if isinstance(organization_name_claim, str) and organization_name_claim
            else organization_value
        )
        issuer = settings.oidc_issuer
        project_ids, system_ids = _resource_scope_from_claims(
            claims,
            settings.oidc_project_ids_claim,
            settings.oidc_system_ids_claim,
        )
        return _bind_principal(
            request,
            AuthenticatedPrincipal(
                subject=subject,
                actor=f"oidc:{subject}",
                organization_id=_organization_uuid(issuer, organization_value),
                organization_key=organization_value[:255],
                organization_name=organization_name[:160],
                roles=frozenset(mapped_roles),
                authentication_method="oidc",
                project_ids=project_ids,
                system_ids=system_ids,
            ),
        )

    if configured_key is not None:
        raise _unauthorized("Valid operational credentials are required")
    if settings.environment == "production":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Operational authentication is not configured",
        )
    organization_id = settings.operational_organization_id
    return _bind_principal(
        request,
        AuthenticatedPrincipal(
            subject=local_actor or "local-operator",
            actor=f"local:{local_actor or 'local-operator'}",
            organization_id=organization_id,
            organization_key=settings.operational_organization_key,
            organization_name=settings.operational_organization_name,
            roles=frozenset({"admin", "analyst", "viewer", "scanner"}),
            authentication_method="local",
            project_ids=None,
            system_ids=None,
        ),
    )


def _bind_principal(
    request: Request, principal: AuthenticatedPrincipal
) -> AuthenticatedPrincipal:
    request.state.principal = principal
    return principal


def require_read_access(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> AuthenticatedPrincipal:
    return _require_roles(principal, "admin", "analyst", "viewer")


def require_analyst_access(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> AuthenticatedPrincipal:
    return _require_roles(principal, "admin", "analyst")


def require_scanner_access(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> AuthenticatedPrincipal:
    return _require_roles(principal, "admin", "scanner")


def require_ingest_access(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> AuthenticatedPrincipal:
    return _require_roles(principal, "admin", "analyst")


def require_org_wide_intelligence_access(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> AuthenticatedPrincipal:
    _require_roles(principal, "admin", "analyst")
    if principal.project_ids is not None or principal.system_ids is not None:
        raise _forbidden(
            "Organization-wide intelligence changes require an unrestricted resource scope"
        )
    return principal


def require_org_wide_intelligence_read_access(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> AuthenticatedPrincipal:
    # Raw organization-wide intelligence can contain source material that is
    # intentionally absent from operational, system-scoped views. Keep this
    # analyst-only instead of letting a read-only operational viewer traverse
    # the tenant's complete intelligence corpus.
    _require_roles(principal, "admin", "analyst")
    if principal.project_ids is not None or principal.system_ids is not None:
        raise _forbidden(
            "Organization-wide intelligence reads require an unrestricted resource scope"
        )
    return principal


def require_org_wide_admin_access(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> AuthenticatedPrincipal:
    _require_roles(principal, "admin")
    if principal.project_ids is not None or principal.system_ids is not None:
        raise _forbidden(
            "Organization-wide administration requires an unrestricted resource scope"
        )
    return principal


def require_admin_access(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> AuthenticatedPrincipal:
    return _require_roles(principal, "admin")


def operational_actor(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_operational_principal)],
) -> str:
    return principal.actor


def principal_capabilities(principal: AuthenticatedPrincipal) -> list[str]:
    capabilities: set[str] = set()
    if principal.has_any_role("admin", "analyst", "viewer"):
        capabilities.add("read_operational")
    if principal.has_any_role("admin", "analyst"):
        capabilities.update({"analyze", "ingest_intelligence"})
    if principal.has_any_role("admin", "scanner"):
        capabilities.add("manage_scans")
    if principal.has_any_role("admin"):
        capabilities.add("administer")
    return [item for item in CAPABILITY_ORDER if item in capabilities]


def _require_roles(
    principal: AuthenticatedPrincipal, *roles: Role
) -> AuthenticatedPrincipal:
    if not principal.has_any_role(*roles):
        raise _forbidden("The authenticated principal is not allowed to perform this action")
    return principal


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


OperationalPrincipal = Annotated[
    AuthenticatedPrincipal, Depends(require_operational_principal)
]
OperationalActor = Annotated[str, Depends(operational_actor)]
