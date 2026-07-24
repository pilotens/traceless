"""Read-only asset-source synchronization and evidence inspection routes."""

from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status

from traceless_api.api.auth import (
    OperationalActor,
    require_analyst_access,
    require_read_access,
)
from traceless_api.api.dependencies import OperationalRepositoryDependency
from traceless_api.integrations.asset_sources import AssetSourceError
from traceless_api.models.operational import (
    AssetSourceSnapshotDetail,
    AssetSourceSnapshotSummary,
)
from traceless_api.services.asset_source_sync import sync_netbox_asset_source
from traceless_api.services.private_integration_scope import (
    PrivateIntegrationUnavailableError,
    require_private_integration_scope,
)

router = APIRouter(prefix="/operational", tags=["asset-sources"])


@router.post(
    "/systems/{system_id}/asset-sources/netbox/sync",
    response_model=AssetSourceSnapshotSummary,
    dependencies=[Depends(require_analyst_access)],
)
async def sync_netbox(
    system_id: UUID,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> AssetSourceSnapshotSummary:
    try:
        require_private_integration_scope(
            settings=request.app.state.settings,
            configured_organization_id=request.app.state.settings.netbox_organization_id,
            request_organization_id=repository.organization_id,
        )
    except PrivateIntegrationUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Private integration is not available for this organization",
        ) from None
    async with request.app.state.http_client_factory() as client:
        try:
            row = await sync_netbox_asset_source(
                settings=request.app.state.settings,
                repository=repository,
                system_id=system_id,
                client=client,
                actor=actor,
            )
        except PrivateIntegrationUnavailableError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Private integration is not available for this organization",
            ) from None
        except (AssetSourceError, httpx.HTTPError, ValueError) as error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"NetBox synchronization failed ({type(error).__name__})",
            ) from error
    return AssetSourceSnapshotSummary.model_validate(row)


@router.get(
    "/systems/{system_id}/asset-sources/snapshots",
    response_model=list[AssetSourceSnapshotSummary],
    dependencies=[Depends(require_read_access)],
)
def list_asset_source_snapshots(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
) -> list[AssetSourceSnapshotSummary]:
    return [
        AssetSourceSnapshotSummary.model_validate(row)
        for row in repository.list_asset_source_snapshots(system_id)
    ]


@router.get(
    "/systems/{system_id}/asset-sources/snapshots/{snapshot_id}",
    response_model=AssetSourceSnapshotDetail,
    dependencies=[Depends(require_read_access)],
)
def get_asset_source_snapshot(
    system_id: UUID,
    snapshot_id: UUID,
    repository: OperationalRepositoryDependency,
) -> AssetSourceSnapshotDetail:
    row = repository.get_asset_source_snapshot(snapshot_id)
    if row.system_id != system_id:
        # Do not reveal whether a snapshot exists in another system.
        raise HTTPException(status_code=404, detail="Asset-source snapshot was not found")
    return AssetSourceSnapshotDetail(
        **AssetSourceSnapshotSummary.model_validate(row).model_dump(),
        records=row.snapshot.get("records", []),
        pages=row.snapshot.get("pages", []),
    )
