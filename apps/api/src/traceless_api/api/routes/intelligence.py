"""Configured intelligence-provider synchronization routes."""

from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from traceless_api.api.auth import (
    OperationalActor,
    require_analyst_access,
    require_org_wide_admin_access,
    require_org_wide_intelligence_access,
    require_org_wide_intelligence_read_access,
)
from traceless_api.api.dependencies import OperationalRepositoryDependency
from traceless_api.integrations.intelligence import (
    ExternalIntelligenceConnectorUpdate,
    ExternalIntelligenceConnectorView,
    ExternalIntelligencePullRequest,
    ExternalIntelligencePullResult,
    ExternalIntelligenceSyncRunList,
    ExternalIntelligenceSyncStatus,
    IntelligenceIntegrationError,
)
from traceless_api.models.intelligence_hub import (
    CanonicalIntelFeed,
    GlobalIntelPage,
    GlobalIntelRecordView,
    IntelCorrelationResult,
    IntelImportResult,
    IntelReviewRequest,
    IntelReviewResult,
)
from traceless_api.models.operational import IntelligenceSyncResult
from traceless_api.services.external_intelligence_pull import (
    get_external_connector,
    get_external_sync_status,
    list_external_sync_runs,
    pull_external_intelligence,
    upsert_external_connector,
)
from traceless_api.services.intelligence_correlation_jobs import (
    enqueue_import_recorrelation_jobs,
)
from traceless_api.services.intelligence_hub import IntelligenceHubService
from traceless_api.services.intelligence_review import review_intelligence_record
from traceless_api.services.intelligence_sync import (
    sync_cisa_kev,
    sync_first_epss,
    sync_nvd,
)

router = APIRouter(prefix="/operational", tags=["intelligence"])


@router.put(
    "/intelligence/connectors/external",
    response_model=ExternalIntelligenceConnectorView,
    dependencies=[Depends(require_org_wide_admin_access)],
)
def configure_external_datapoints(
    payload: ExternalIntelligenceConnectorUpdate,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ExternalIntelligenceConnectorView:
    return upsert_external_connector(
        settings=request.app.state.settings,
        repository=repository,
        payload=payload,
        actor=actor,
    )


@router.get(
    "/intelligence/connectors/external",
    response_model=ExternalIntelligenceConnectorView,
    dependencies=[Depends(require_org_wide_admin_access)],
)
def external_datapoint_configuration(
    repository: OperationalRepositoryDependency,
) -> ExternalIntelligenceConnectorView:
    return get_external_connector(repository=repository)


@router.get(
    "/intelligence/sync/external/status",
    response_model=ExternalIntelligenceSyncStatus,
    dependencies=[Depends(require_org_wide_intelligence_read_access)],
)
def external_datapoint_sync_status(
    request: Request,
    repository: OperationalRepositoryDependency,
) -> ExternalIntelligenceSyncStatus:
    return get_external_sync_status(settings=request.app.state.settings, repository=repository)


@router.get(
    "/intelligence/sync/external/runs",
    response_model=ExternalIntelligenceSyncRunList,
    dependencies=[Depends(require_org_wide_intelligence_read_access)],
)
def external_datapoint_sync_history(
    repository: OperationalRepositoryDependency,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> ExternalIntelligenceSyncRunList:
    return list_external_sync_runs(
        repository=repository,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/intelligence/sync/external",
    response_model=ExternalIntelligencePullResult,
    dependencies=[Depends(require_org_wide_intelligence_access)],
)
async def sync_external_datapoints(
    payload: ExternalIntelligencePullRequest,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ExternalIntelligencePullResult:
    """Pull normalized datapoints; scraping remains outside Traceless."""

    async with request.app.state.http_client_factory() as client:
        try:
            return await pull_external_intelligence(
                settings=request.app.state.settings,
                repository=repository,
                client=client,
                actor=actor,
                cursor=payload.cursor,
                max_pages=payload.max_pages,
            )
        except (IntelligenceIntegrationError, httpx.HTTPError, ValueError) as error:
            raise _provider_failure("external intelligence API", error) from error


@router.post(
    "/intelligence/records/import",
    response_model=IntelImportResult,
    dependencies=[Depends(require_org_wide_intelligence_access)],
)
def import_global_intelligence(
    payload: CanonicalIntelFeed,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> IntelImportResult:
    outcome = IntelligenceHubService(repository).import_feed(payload, actor)
    enqueue_import_recorrelation_jobs(
        settings=request.app.state.settings,
        repository=repository,
        outcome=outcome,
        actor=actor,
    )
    return outcome


@router.get(
    "/intelligence/records",
    response_model=GlobalIntelPage,
    dependencies=[Depends(require_org_wide_intelligence_read_access)],
)
def list_global_intelligence(
    repository: OperationalRepositoryDependency,
    source_kind: str | None = Query(default=None, pattern="^(news|misp|vulnerability|other)$"),
    record_type: str | None = Query(
        default=None,
        pattern="^(report|threat|vulnerability|indicator|campaign|malware|threat_actor)$",
    ),
    query: str | None = Query(default=None, min_length=2, max_length=160),
    review_status: str | None = Query(
        default=None,
        pattern="^(pending|approved|rejected)$",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> GlobalIntelPage:
    return IntelligenceHubService(repository).list_records(
        source_kind=source_kind,
        record_type=record_type,
        query=query,
        review_status=review_status,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/intelligence/records/{record_id}",
    response_model=GlobalIntelRecordView,
    dependencies=[Depends(require_org_wide_intelligence_read_access)],
)
def get_global_intelligence(
    record_id: UUID,
    repository: OperationalRepositoryDependency,
) -> GlobalIntelRecordView:
    return IntelligenceHubService(repository).get_record(record_id)


@router.patch(
    "/intelligence/records/{record_id}/review",
    response_model=IntelReviewResult,
    dependencies=[Depends(require_org_wide_intelligence_access)],
)
def review_global_intelligence(
    record_id: UUID,
    payload: IntelReviewRequest,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> IntelReviewResult:
    return review_intelligence_record(
        settings=request.app.state.settings,
        repository=repository,
        record_id=record_id,
        payload=payload,
        actor=actor,
    )


@router.post(
    "/systems/{system_id}/intelligence/correlate",
    response_model=IntelCorrelationResult,
    dependencies=[Depends(require_analyst_access)],
)
def correlate_global_intelligence(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> IntelCorrelationResult:
    return IntelligenceHubService(repository).correlate(system_id, actor)


@router.post(
    "/systems/{system_id}/intelligence/sync/kev",
    response_model=IntelligenceSyncResult,
    dependencies=[Depends(require_analyst_access)],
)
async def sync_kev(
    system_id: UUID,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> IntelligenceSyncResult:
    async with request.app.state.http_client_factory() as client:
        try:
            return await sync_cisa_kev(
                settings=request.app.state.settings,
                repository=repository,
                system_id=system_id,
                client=client,
                actor=actor,
            )
        except (IntelligenceIntegrationError, httpx.HTTPError, ValueError) as error:
            raise _provider_failure("CISA KEV", error) from error


@router.post(
    "/systems/{system_id}/intelligence/sync/epss",
    response_model=IntelligenceSyncResult,
    dependencies=[Depends(require_analyst_access)],
)
async def sync_epss(
    system_id: UUID,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> IntelligenceSyncResult:
    async with request.app.state.http_client_factory() as client:
        try:
            return await sync_first_epss(
                settings=request.app.state.settings,
                repository=repository,
                system_id=system_id,
                client=client,
                actor=actor,
            )
        except (IntelligenceIntegrationError, httpx.HTTPError, ValueError) as error:
            raise _provider_failure("FIRST EPSS", error) from error


@router.post(
    "/systems/{system_id}/intelligence/sync/nvd",
    response_model=IntelligenceSyncResult,
    dependencies=[Depends(require_analyst_access)],
)
async def sync_nvd_cves(
    system_id: UUID,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> IntelligenceSyncResult:
    async with request.app.state.http_client_factory() as client:
        try:
            return await sync_nvd(
                settings=request.app.state.settings,
                repository=repository,
                system_id=system_id,
                client=client,
                actor=actor,
            )
        except (IntelligenceIntegrationError, httpx.HTTPError, ValueError) as error:
            raise _provider_failure("NVD", error) from error


def _provider_failure(provider: str, error: Exception) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"{provider} synchronization failed ({type(error).__name__})",
    )
