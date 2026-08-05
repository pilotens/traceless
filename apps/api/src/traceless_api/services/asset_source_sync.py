"""Orchestration for configured, read-only external asset sources."""

from uuid import UUID

from traceless_api.core.config import Settings
from traceless_api.db.models import AssetSourceSnapshotRow
from traceless_api.integrations.asset_sources import AsyncHttpClient, NetBoxAssetSource
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalRepository,
)
from traceless_api.services.private_integration_scope import require_private_integration_scope


async def sync_netbox_asset_source(
    *,
    settings: Settings,
    repository: OperationalRepository,
    system_id: UUID,
    client: AsyncHttpClient,
    actor: str,
) -> AssetSourceSnapshotRow:
    """Fetch and persist a bounded NetBox snapshot for later analyst review."""

    require_private_integration_scope(
        settings=settings,
        configured_organization_id=settings.netbox_organization_id,
        request_organization_id=repository.organization_id,
    )
    repository.get_system(system_id)
    # End the short existence-check transaction before the potentially slow
    # external fetch. The request-scoped session starts a fresh transaction when
    # the immutable snapshot is persisted below.
    repository.session.commit()
    if settings.netbox_base_url is None:
        raise OperationalConflictError("NetBox asset source is not configured")

    token = settings.netbox_token.get_secret_value() if settings.netbox_token else None
    connector = NetBoxAssetSource(
        client,
        settings.netbox_base_url,
        token=token,
        auth_scheme=settings.netbox_auth_scheme,
        page_size=settings.netbox_page_size,
        max_pages=settings.netbox_max_pages,
        max_records=settings.netbox_max_records,
        max_page_bytes=settings.netbox_max_page_bytes,
        timeout_seconds=settings.netbox_timeout_seconds,
        allow_insecure_http=settings.netbox_allow_insecure_http,
        allowed_hosts=settings.netbox_allowed_hosts,
    )
    snapshot = await connector.fetch()
    return repository.save_asset_source_snapshot(
        system_id=system_id,
        snapshot=snapshot,
        actor=actor,
    )
