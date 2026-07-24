"""Paginated operational collection and on-demand detail routes."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from traceless_api.api.auth import require_read_access
from traceless_api.api.dependencies import OperationalRepositoryDependency
from traceless_api.models.listing import (
    FindingSummaryView,
    RiskSummaryView,
    ThreatSummaryView,
    VulnerabilityObservationSummaryView,
)
from traceless_api.models.operational import (
    AssetView,
    FindingView,
    RiskView,
    ServiceView,
    ThreatView,
    VulnerabilityObservationView,
)
from traceless_api.models.pagination import Page
from traceless_api.services.operational_listing import (
    get_finding,
    get_risk,
    get_threat,
    get_vulnerability_observation,
    list_current_asset_page,
    list_current_service_page,
    list_finding_page,
    list_risk_page,
    list_threat_page,
    list_vulnerability_observation_page,
)

router = APIRouter(prefix="/operational", tags=["operational-collections"])


@router.get(
    "/systems/{system_id}/assets/page",
    response_model=Page[AssetView],
    dependencies=[Depends(require_read_access)],
)
def assets_page(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AssetView]:
    result = list_current_asset_page(repository, system_id, limit=limit, offset=offset)
    return Page[AssetView].from_items(
        [AssetView.model_validate(row) for row in result.rows],
        total=result.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/systems/{system_id}/services/page",
    response_model=Page[ServiceView],
    dependencies=[Depends(require_read_access)],
)
def services_page(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    asset_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ServiceView]:
    result = list_current_service_page(
        repository,
        system_id,
        asset_id=asset_id,
        limit=limit,
        offset=offset,
    )
    return Page[ServiceView].from_items(
        [ServiceView.model_validate(row) for row in result.rows],
        total=result.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/systems/{system_id}/findings",
    response_model=Page[FindingSummaryView],
    dependencies=[Depends(require_read_access)],
)
def findings_page(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    lifecycle_status: Annotated[
        Literal["open", "fixed", "accepted", "false_positive", "out_of_scope", "reopened"] | None,
        Query(),
    ] = None,
    finding_type: Annotated[
        Literal["vulnerability", "misconfiguration", "informational"] | None,
        Query(),
    ] = None,
    needs_review: Annotated[bool | None, Query()] = None,
) -> Page[FindingSummaryView]:
    result = list_finding_page(
        repository,
        system_id,
        limit=limit,
        offset=offset,
        lifecycle_status=lifecycle_status,
        finding_type=finding_type,
        needs_review=needs_review,
    )
    return Page[FindingSummaryView].from_items(
        [FindingSummaryView.model_validate(row) for row in result.rows],
        total=result.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/systems/{system_id}/findings/{finding_id}",
    response_model=FindingView,
    dependencies=[Depends(require_read_access)],
)
def finding_detail(
    system_id: UUID,
    finding_id: UUID,
    repository: OperationalRepositoryDependency,
) -> FindingView:
    return FindingView.model_validate(get_finding(repository, system_id, finding_id))


@router.get(
    "/systems/{system_id}/risks",
    response_model=Page[RiskSummaryView],
    dependencies=[Depends(require_read_access)],
)
def risks_page(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    risk_status: Annotated[
        Literal["open", "closed"] | None,
        Query(alias="status"),
    ] = None,
) -> Page[RiskSummaryView]:
    result = list_risk_page(
        repository,
        system_id,
        limit=limit,
        offset=offset,
        status=risk_status,
    )
    return Page[RiskSummaryView].from_items(
        [RiskSummaryView.model_validate(row) for row in result.rows],
        total=result.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/systems/{system_id}/risks/{risk_id}",
    response_model=RiskView,
    dependencies=[Depends(require_read_access)],
)
def risk_detail(
    system_id: UUID,
    risk_id: UUID,
    repository: OperationalRepositoryDependency,
) -> RiskView:
    return RiskView.model_validate(get_risk(repository, system_id, risk_id))


@router.get(
    "/systems/{system_id}/threats",
    response_model=Page[ThreatSummaryView],
    dependencies=[Depends(require_read_access)],
)
def threats_page(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ThreatSummaryView]:
    result = list_threat_page(repository, system_id, limit=limit, offset=offset)
    return Page[ThreatSummaryView].from_items(
        [ThreatSummaryView.model_validate(row) for row in result.rows],
        total=result.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/systems/{system_id}/threats/{threat_id}",
    response_model=ThreatView,
    dependencies=[Depends(require_read_access)],
)
def threat_detail(
    system_id: UUID,
    threat_id: UUID,
    repository: OperationalRepositoryDependency,
) -> ThreatView:
    return ThreatView.model_validate(get_threat(repository, system_id, threat_id))


@router.get(
    "/systems/{system_id}/vulnerability-observations/page",
    response_model=Page[VulnerabilityObservationSummaryView],
    dependencies=[Depends(require_read_access)],
)
def vulnerability_observations_page(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    import_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[VulnerabilityObservationSummaryView]:
    result = list_vulnerability_observation_page(
        repository,
        system_id,
        import_id=import_id,
        limit=limit,
        offset=offset,
    )
    return Page[VulnerabilityObservationSummaryView].from_items(
        [VulnerabilityObservationSummaryView.model_validate(row) for row in result.rows],
        total=result.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/systems/{system_id}/vulnerability-observations/{observation_id}",
    response_model=VulnerabilityObservationView,
    dependencies=[Depends(require_read_access)],
)
def vulnerability_observation_detail(
    system_id: UUID,
    observation_id: UUID,
    repository: OperationalRepositoryDependency,
) -> VulnerabilityObservationView:
    return VulnerabilityObservationView.model_validate(
        get_vulnerability_observation(repository, system_id, observation_id)
    )
