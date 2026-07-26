"""Persistent project, scan and analysis routes."""

import hashlib
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from traceless_api.api.auth import (
    OperationalActor,
    require_admin_access,
    require_analyst_access,
    require_ingest_access,
    require_org_wide_admin_access,
    require_read_access,
    require_scanner_access,
)
from traceless_api.api.dependencies import OperationalRepositoryDependency
from traceless_api.core.scan_authorization import (
    InvalidScanAuthorizationError,
    scope_sha256,
    validate_authorization_window,
)
from traceless_api.integrations.scanners import (
    NaabuJsonlParser,
    NaabuOutputError,
    NmapOutputError,
    NmapXmlParser,
    ScannerScope,
    ScopeValidationError,
)
from traceless_api.integrations.vulnerability_scanners import NessusReportError, NessusXmlParser
from traceless_api.models.operational import (
    ArchitectureSnapshotView,
    ArchitectureVersionCreate,
    AssetView,
    CyberRiskGraphView,
    FindingEvidenceView,
    FindingLifecycleUpdate,
    FindingView,
    LiveScanCreate,
    OperationalSystemCreate,
    OperationalSystemView,
    PipelineOverview,
    ProjectCreate,
    ProjectView,
    RiskView,
    ScanAuthorizationCreate,
    ScanAuthorizationView,
    ScanJobView,
    ServiceView,
    ThreatView,
    VulnerabilityImportResult,
    VulnerabilityObservationView,
    VulnerabilityScanImportCreate,
    VulnerabilityScanImportView,
)
from traceless_api.services.operational_listing import (
    list_current_asset_page,
    list_current_service_page,
    list_finding_page,
    list_risk_page,
    list_threat_page,
)
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalNotFoundError,
)
from traceless_api.services.risk_graph import build_cyber_risk_graph
from traceless_api.services.scan_ingestion import ingest_scanner_result

router = APIRouter(prefix="/operational", tags=["operational"])
_MAX_SYNCHRONOUS_VULNERABILITY_BYTES = 1 * 1024 * 1024
_MAX_SYNCHRONOUS_VULNERABILITY_OBSERVATIONS = 250


@router.post(
    "/projects",
    response_model=ProjectView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_org_wide_admin_access)],
)
def create_project(
    payload: ProjectCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ProjectView:
    return ProjectView.model_validate(repository.create_project(payload, actor))


@router.get(
    "/projects",
    response_model=list[ProjectView],
    dependencies=[Depends(require_read_access)],
)
def list_projects(repository: OperationalRepositoryDependency) -> list[ProjectView]:
    return [ProjectView.model_validate(row) for row in repository.list_projects()]


@router.post(
    "/projects/{project_id}/systems",
    response_model=OperationalSystemView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_system(
    project_id: UUID,
    payload: OperationalSystemCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> OperationalSystemView:
    return OperationalSystemView.model_validate(
        repository.create_system(project_id, payload, actor)
    )


@router.get(
    "/projects/{project_id}/systems",
    response_model=list[OperationalSystemView],
    dependencies=[Depends(require_read_access)],
)
def list_systems(
    project_id: UUID, repository: OperationalRepositoryDependency
) -> list[OperationalSystemView]:
    return [
        OperationalSystemView.model_validate(row) for row in repository.list_systems(project_id)
    ]


@router.post(
    "/systems/{system_id}/scan-authorizations",
    response_model=ScanAuthorizationView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin_access)],
)
def create_scan_authorization(
    system_id: UUID,
    payload: ScanAuthorizationCreate,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ScanAuthorizationView:
    settings = request.app.state.settings
    try:
        validate_authorization_window(payload.expires_at)
        scope = ScannerScope.from_strings(
            payload.targets,
            allow_public_targets=settings.allow_public_scan_targets,
            max_hosts=settings.scan_max_hosts,
        )
        targets = list(scope.validate_targets(payload.targets).argv)
    except (InvalidScanAuthorizationError, ScopeValidationError) as error:
        raise OperationalConflictError(str(error)) from error
    digest = scope_sha256(targets, payload.profile, payload.expires_at)
    row = repository.create_authorization(
        system_id=system_id,
        targets=targets,
        profile=payload.profile,
        approved_by=payload.approved_by,
        purpose=payload.purpose,
        expires_at=payload.expires_at,
        scope_sha256=digest,
        actor=actor,
    )
    return ScanAuthorizationView.model_validate(row)


@router.post(
    "/systems/{system_id}/scans",
    response_model=ScanJobView,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_scanner_access)],
)
def queue_scan(
    system_id: UUID,
    payload: LiveScanCreate,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ScanJobView:
    row = repository.create_scan_job(
        system_id=system_id,
        authorization_id=payload.authorization_id,
        mode="live",
        actor=actor,
        max_attempts=request.app.state.settings.scan_max_attempts,
    )
    return ScanJobView.model_validate(row)


@router.get(
    "/systems/{system_id}/scans",
    response_model=list[ScanJobView],
    dependencies=[Depends(require_read_access)],
)
def list_scans(system_id: UUID, repository: OperationalRepositoryDependency) -> list[ScanJobView]:
    return [ScanJobView.model_validate(row) for row in repository.list_scan_jobs(system_id)]


@router.post(
    "/systems/{system_id}/scans/import/nmap",
    response_model=ScanJobView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scanner_access)],
    responses={
        413: {"description": "Nmap XML exceeds the configured evidence limit"},
        422: {"description": "Malformed or out-of-scope Nmap XML"},
    },
)
async def import_nmap_xml(
    system_id: UUID,
    request: Request,
    repository: OperationalRepositoryDependency,
    authorization_id: Annotated[UUID, Query()],
    actor: OperationalActor,
) -> ScanJobView:
    settings = request.app.state.settings
    raw_payload = await _read_bounded_body(request, settings.max_nmap_xml_bytes)

    authorization = repository.get_authorization(authorization_id)
    if authorization.system_id != system_id:
        raise OperationalConflictError("Authorization belongs to another system")
    if authorization.status != "active":
        raise OperationalConflictError("Authorization is not active")

    try:
        scope = ScannerScope.from_strings(
            authorization.targets,
            allow_public_targets=settings.allow_public_scan_targets,
            max_hosts=settings.scan_max_hosts,
        )
        validated_targets = scope.validate_targets(authorization.targets)
        scanner_result = NmapXmlParser().parse(raw_payload, targets=validated_targets)
    except (NmapOutputError, ScopeValidationError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    scan = repository.create_scan_job(
        system_id=system_id,
        authorization_id=authorization_id,
        mode="import",
        actor=actor,
    )
    ingest_scanner_result(
        repository=repository,
        scan=scan,
        result=scanner_result,
        raw_payload=raw_payload,
        retain_raw_evidence=settings.retain_raw_scan_evidence,
        actor=actor,
    )
    return ScanJobView.model_validate(scan)


@router.post(
    "/systems/{system_id}/scans/import/naabu",
    response_model=ScanJobView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scanner_access)],
    responses={422: {"description": "Malformed or out-of-scope Naabu JSONL"}},
)
async def import_naabu_jsonl(
    system_id: UUID,
    request: Request,
    repository: OperationalRepositoryDependency,
    authorization_id: Annotated[UUID, Query()],
    actor: OperationalActor,
) -> ScanJobView:
    settings = request.app.state.settings
    raw_payload = await _read_bounded_body(request, settings.max_nmap_xml_bytes)
    authorization = repository.get_authorization(authorization_id)
    if authorization.system_id != system_id:
        raise OperationalConflictError("Authorization belongs to another system")
    if authorization.status != "active":
        raise OperationalConflictError("Authorization is not active")
    try:
        scope = ScannerScope.from_strings(
            authorization.targets,
            allow_public_targets=settings.allow_public_scan_targets,
            max_hosts=settings.scan_max_hosts,
        )
        validated_targets = scope.validate_targets(authorization.targets)
        scanner_result = NaabuJsonlParser().parse(raw_payload, targets=validated_targets)
    except (NaabuOutputError, ScopeValidationError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    scan = repository.create_scan_job(
        system_id=system_id,
        authorization_id=authorization_id,
        mode="import",
        actor=actor,
        scanner="naabu",
    )
    ingest_scanner_result(
        repository=repository,
        scan=scan,
        result=scanner_result,
        raw_payload=raw_payload,
        retain_raw_evidence=settings.retain_raw_scan_evidence,
        actor=actor,
    )
    return ScanJobView.model_validate(scan)


async def _read_bounded_body(request: Request, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Scanner evidence exceeds the configured limit",
            )
        chunks.append(chunk)
    payload = b"".join(chunks)
    if not payload:
        raise HTTPException(status_code=422, detail="Scanner evidence payload is empty")
    return payload


@router.get(
    "/scans/{scan_id}",
    response_model=ScanJobView,
    dependencies=[Depends(require_read_access)],
)
def get_scan(scan_id: UUID, repository: OperationalRepositoryDependency) -> ScanJobView:
    return ScanJobView.model_validate(repository.get_scan_job(scan_id))


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanJobView,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_scanner_access)],
)
def cancel_scan(
    scan_id: UUID,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ScanJobView:
    return ScanJobView.model_validate(repository.request_scan_cancellation(scan_id, actor))


@router.get(
    "/systems/{system_id}/architecture/latest",
    response_model=ArchitectureSnapshotView,
    dependencies=[Depends(require_read_access)],
)
def latest_architecture(
    system_id: UUID, repository: OperationalRepositoryDependency
) -> ArchitectureSnapshotView:
    repository.get_system(system_id)
    row = repository.latest_architecture(system_id)
    if row is None:
        raise OperationalNotFoundError("Architecture snapshot was not found")
    return ArchitectureSnapshotView.model_validate(row)


@router.get(
    "/systems/{system_id}/architecture/observed/latest",
    response_model=ArchitectureSnapshotView,
    dependencies=[Depends(require_read_access)],
)
def latest_observed_architecture(
    system_id: UUID, repository: OperationalRepositoryDependency
) -> ArchitectureSnapshotView:
    repository.get_system(system_id)
    row = repository.latest_observed_topology(system_id)
    if row is None:
        raise OperationalNotFoundError("Observed architecture snapshot was not found")
    return ArchitectureSnapshotView.model_validate(row)


@router.get(
    "/systems/{system_id}/architecture/versions",
    response_model=list[ArchitectureSnapshotView],
    dependencies=[Depends(require_read_access)],
)
def list_architecture_versions(
    system_id: UUID, repository: OperationalRepositoryDependency
) -> list[ArchitectureSnapshotView]:
    return [
        ArchitectureSnapshotView.model_validate(row)
        for row in repository.list_architecture_versions(system_id)
    ]


@router.post(
    "/systems/{system_id}/architecture/versions",
    response_model=ArchitectureSnapshotView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_architecture_version(
    system_id: UUID,
    payload: ArchitectureVersionCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ArchitectureSnapshotView:
    return ArchitectureSnapshotView.model_validate(
        repository.create_manual_architecture_version(system_id, payload, actor)
    )


@router.post(
    "/systems/{system_id}/vulnerability-scans/import/nessus",
    response_model=VulnerabilityImportResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_ingest_access)],
    responses={
        413: {"description": "Nessus report exceeds the configured evidence limit"},
        422: {"description": "Malformed or unsupported .nessus XML report"},
    },
)
async def import_nessus_report(
    system_id: UUID,
    request: Request,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
    source_name: Annotated[str, Query(min_length=1, max_length=255)] = "scan.nessus",
) -> VulnerabilityImportResult:
    settings = request.app.state.settings
    raw_payload = await _read_bounded_body(
        request,
        min(
            settings.max_vulnerability_scan_bytes,
            _MAX_SYNCHRONOUS_VULNERABILITY_BYTES,
        ),
    )
    try:
        payload = NessusXmlParser().parse(
            raw_payload,
            source_name=source_name,
            max_observations=settings.max_vulnerability_observations,
        )
    except NessusReportError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if len(payload.observations) > _MAX_SYNCHRONOUS_VULNERABILITY_OBSERVATIONS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This import exceeds the synchronous safety limit; use "
                f"/systems/{system_id}/vulnerability-scans/import/nessus/async"
            ),
        )
    return _persist_vulnerability_import(
        repository,
        system_id,
        payload,
        actor,
        raw_sha256=hashlib.sha256(raw_payload).hexdigest(),
        source_format="nessus-xml",
    )


@router.post(
    "/systems/{system_id}/vulnerability-scans/import",
    response_model=VulnerabilityImportResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_ingest_access)],
)
def import_normalized_vulnerability_report(
    system_id: UUID,
    payload: VulnerabilityScanImportCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> VulnerabilityImportResult:
    if len(payload.observations) > _MAX_SYNCHRONOUS_VULNERABILITY_OBSERVATIONS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This import exceeds the synchronous safety limit; use "
                f"/systems/{system_id}/vulnerability-scans/import/async"
            ),
        )
    canonical = json.dumps(
        payload.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _persist_vulnerability_import(
        repository,
        system_id,
        payload,
        actor,
        raw_sha256=hashlib.sha256(canonical).hexdigest(),
        source_format="normalized-json",
    )


@router.get(
    "/systems/{system_id}/vulnerability-scans",
    response_model=list[VulnerabilityScanImportView],
    dependencies=[Depends(require_read_access)],
)
def list_vulnerability_scan_imports(
    system_id: UUID, repository: OperationalRepositoryDependency
) -> list[VulnerabilityScanImportView]:
    return [
        VulnerabilityScanImportView.model_validate(row)
        for row in repository.list_vulnerability_scan_imports(system_id)
    ]


@router.get(
    "/systems/{system_id}/vulnerability-observations",
    response_model=list[VulnerabilityObservationView],
    dependencies=[Depends(require_read_access)],
)
def list_vulnerability_observations(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    import_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=2_000)] = 500,
) -> list[VulnerabilityObservationView]:
    return [
        VulnerabilityObservationView.model_validate(row)
        for row in repository.list_vulnerability_observations(
            system_id, import_id=import_id, limit=limit
        )
    ]


def _persist_vulnerability_import(
    repository: OperationalRepositoryDependency,
    system_id: UUID,
    payload: VulnerabilityScanImportCreate,
    actor: str,
    *,
    raw_sha256: str,
    source_format: str,
) -> VulnerabilityImportResult:
    row, replay, matched_assets, matched_services, promoted, warnings = (
        repository.import_vulnerability_scan(
            system_id,
            payload,
            actor,
            raw_sha256=raw_sha256,
            source_format=source_format,
        )
    )
    return VulnerabilityImportResult(
        import_record=VulnerabilityScanImportView.model_validate(row),
        imported=row.observation_count,
        matched_assets=matched_assets,
        matched_services=matched_services,
        promoted_findings=promoted,
        idempotent_replay=replay,
        warnings=warnings,
    )


@router.patch(
    "/systems/{system_id}/findings/{finding_id}/lifecycle",
    response_model=FindingView,
    dependencies=[Depends(require_analyst_access)],
)
def update_finding_lifecycle(
    system_id: UUID,
    finding_id: UUID,
    payload: FindingLifecycleUpdate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> FindingView:
    return FindingView.model_validate(
        repository.update_finding_lifecycle(
            system_id,
            finding_id,
            payload.lifecycle_status,
            payload.reason,
            actor,
        )
    )


@router.get(
    "/systems/{system_id}/findings/{finding_id}/evidence",
    response_model=list[FindingEvidenceView],
    dependencies=[Depends(require_read_access)],
)
def list_finding_evidence(
    system_id: UUID,
    finding_id: UUID,
    repository: OperationalRepositoryDependency,
) -> list[FindingEvidenceView]:
    return [
        FindingEvidenceView.model_validate(row)
        for row in repository.list_finding_evidence(system_id, finding_id)
    ]


@router.get(
    "/systems/{system_id}/risk-graph",
    response_model=CyberRiskGraphView,
    dependencies=[Depends(require_read_access)],
)
def cyber_risk_graph(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
) -> CyberRiskGraphView:
    return build_cyber_risk_graph(repository, system_id)


@router.get(
    "/systems/{system_id}/overview",
    response_model=PipelineOverview,
    dependencies=[Depends(require_read_access)],
)
def pipeline_overview(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    collection_limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> PipelineOverview:
    asset_page = list_current_asset_page(repository, system_id, limit=collection_limit, offset=0)
    service_page = list_current_service_page(
        repository, system_id, limit=collection_limit, offset=0
    )
    finding_page = list_finding_page(repository, system_id, limit=collection_limit, offset=0)
    threat_page = list_threat_page(repository, system_id, limit=collection_limit, offset=0)
    risk_page = list_risk_page(repository, system_id, limit=collection_limit, offset=0)
    collection_totals = {
        "assets": asset_page.total,
        "services": service_page.total,
        "findings": finding_page.total,
        "threats": threat_page.total,
        "risks": risk_page.total,
    }
    return PipelineOverview(
        system=OperationalSystemView.model_validate(repository.get_system(system_id)),
        latest_scan=(
            ScanJobView.model_validate(scan)
            if (scan := repository.latest_scan(system_id)) is not None
            else None
        ),
        latest_architecture=(
            ArchitectureSnapshotView.model_validate(architecture)
            if (architecture := repository.latest_architecture(system_id)) is not None
            else None
        ),
        assets=[AssetView.model_validate(row) for row in asset_page.rows],
        services=[ServiceView.model_validate(row) for row in service_page.rows],
        findings=[FindingView.model_validate(row) for row in finding_page.rows],
        threats=[ThreatView.model_validate(row) for row in threat_page.rows],
        risks=[RiskView.model_validate(row) for row in risk_page.rows],
        collection_totals=collection_totals,
        collection_limit=collection_limit,
        collections_truncated=any(total > collection_limit for total in collection_totals.values()),
    )
