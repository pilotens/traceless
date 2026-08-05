"""Tenant fencing for process-configured private integrations.

Private upstream credentials in :class:`Settings` are process-global.  They may
therefore be used only for the single organization selected by the operator.
Public enrichment providers use a different trust model and deliberately do not
pass through this guard.
"""

from uuid import UUID

from traceless_api.core.config import Settings
from traceless_api.core.tenancy import DEFAULT_ORGANIZATION_ID


class PrivateIntegrationUnavailableError(PermissionError):
    """Raised without upstream or tenant metadata when a private source is unavailable."""


def require_private_integration_scope(
    *,
    settings: Settings,
    configured_organization_id: UUID | None,
    request_organization_id: UUID | None,
) -> None:
    """Allow a process-global private source for exactly one organization.

    Development and test retain a narrow convenience default: an omitted binding
    means the fixed built-in operational organization, never whichever tenant made
    the request. Production validation requires an explicit binding whenever the
    corresponding source is configured.
    """

    owner_organization_id = configured_organization_id
    if owner_organization_id is None and settings.environment != "production":
        owner_organization_id = DEFAULT_ORGANIZATION_ID
    if (
        request_organization_id is None
        or owner_organization_id is None
        or request_organization_id != owner_organization_id
    ):
        raise PrivateIntegrationUnavailableError
