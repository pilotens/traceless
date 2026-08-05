"""Async enqueue and lifecycle endpoints for durable operational work."""

import hashlib
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status

from traceless_api.api.auth import (
    OperationalActor,
    require_analyst_access,
    require_ingest_access,
    require_read_access,
)
from traceless_api.api.dependencies import BackgroundJobServiceDependency
from traceless_api.integrations.vulnerability_scanners import NessusReportError, NessusXmlParser
from traceless_api.models.jobs import (
    BackgroundJobEnqueueResult,
    BackgroundJobList,
    BackgroundJobRetryRequest,
    BackgroundJobStatus,
    BackgroundJobType,
    BackgroundJobView,
)
from traceless_api.models.operational import ReportCreate, VulnerabilityScanImportCreate

router = APIRouter(prefix="/operational", tags=["background-jobs"])


@router.post(
    "/systems/{system_id}/vulnerability-scans/import/async",
    response_model=BackgroundJobEnqueueResult,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_ingest_access)],
)
def enqueue_normalized_vulnerability_import(
    system_id: UUID,
    payload: VulnerabilityScanImportCreate,
    request: Request,
    jobs: BackgroundJobServiceDependency,
    actor: OperationalActor,
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key", min_length=8, max_length=200),
    ] = None,
) -> BackgroundJobEnqueueResult:
    report = payload.model_dump(mode="json")
    raw_sha256 = hashlib.sha256(
        json.dumps(
            report,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    row, replay = jobs.enqueue(
        system_id=system_id,
        job_type="normalized_vulnerability_import",
        payload={
            "report": report,
            "raw_sha256": raw_sha256,
            "source_format": "normalized-json",
        },
        actor=actor,
        max_attempts=request.app.state.settings.background_job_max_attempts,
        idempotency_key=idempotency_key,
    )
    return BackgroundJobEnqueueResult(
        job=BackgroundJobView.model_validate(row),
        idempotent_replay=replay,
    )


@router.post(
    "/systems/{system_id}/vulnerability-scans/import/nessus/async",
    response_model=BackgroundJobEnqueueResult,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_ingest_access)],
    responses={
        413: {"description": "Nessus report exceeds the configured evidence limit"},
        422: {"description": "Malformed or unsupported .nessus XML report"},
    },
)
async def enqueue_nessus_vulnerability_import(
    system_id: UUID,
    request: Request,
    jobs: BackgroundJobServiceDependency,
    actor: OperationalActor,
    source_name: Annotated[str, Query(min_length=1, max_length=255)] = "scan.nessus",
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key", min_length=8, max_length=200),
    ] = None,
) -> BackgroundJobEnqueueResult:
    settings = request.app.state.settings
    raw_payload = await _read_bounded_body(
        request, settings.max_vulnerability_scan_bytes
    )
    try:
        report = NessusXmlParser().parse(
            raw_payload,
            source_name=source_name,
            max_observations=settings.max_vulnerability_observations,
        )
    except NessusReportError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    row, replay = jobs.enqueue(
        system_id=system_id,
        job_type="normalized_vulnerability_import",
        payload={
            "report": report.model_dump(mode="json"),
            "raw_sha256": hashlib.sha256(raw_payload).hexdigest(),
            "source_format": "nessus-xml",
        },
        actor=actor,
        max_attempts=settings.background_job_max_attempts,
        idempotency_key=idempotency_key,
    )
    return BackgroundJobEnqueueResult(
        job=BackgroundJobView.model_validate(row),
        idempotent_replay=replay,
    )


@router.post(
    "/systems/{system_id}/reports/async",
    response_model=BackgroundJobEnqueueResult,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_analyst_access)],
)
def enqueue_report(
    system_id: UUID,
    payload: ReportCreate,
    request: Request,
    jobs: BackgroundJobServiceDependency,
    actor: OperationalActor,
    idempotency_key: Annotated[
        str,
        Header(alias="Idempotency-Key", min_length=8, max_length=200),
    ],
) -> BackgroundJobEnqueueResult:
    row, replay = jobs.enqueue(
        system_id=system_id,
        job_type="report_generation",
        payload=payload.model_dump(mode="json"),
        actor=actor,
        max_attempts=request.app.state.settings.background_job_max_attempts,
        idempotency_key=idempotency_key,
    )
    return BackgroundJobEnqueueResult(
        job=BackgroundJobView.model_validate(row),
        idempotent_replay=replay,
    )


@router.get(
    "/jobs",
    response_model=BackgroundJobList,
    dependencies=[Depends(require_read_access)],
)
def list_background_jobs(
    jobs: BackgroundJobServiceDependency,
    job_status: Annotated[BackgroundJobStatus | None, Query(alias="status")] = None,
    job_type: Annotated[BackgroundJobType | None, Query()] = None,
    system_id: Annotated[UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> BackgroundJobList:
    rows, total = jobs.list(
        status=job_status,
        job_type=job_type,
        system_id=system_id,
        limit=limit,
        offset=offset,
    )
    return BackgroundJobList(
        items=[BackgroundJobView.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/jobs/{job_id}",
    response_model=BackgroundJobView,
    dependencies=[Depends(require_read_access)],
)
def get_background_job(
    job_id: UUID,
    jobs: BackgroundJobServiceDependency,
) -> BackgroundJobView:
    return BackgroundJobView.model_validate(jobs.get(job_id))


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=BackgroundJobView,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_analyst_access)],
)
def cancel_background_job(
    job_id: UUID,
    jobs: BackgroundJobServiceDependency,
    actor: OperationalActor,
) -> BackgroundJobView:
    return BackgroundJobView.model_validate(jobs.request_cancellation(job_id, actor))


@router.post(
    "/jobs/{job_id}/retry",
    response_model=BackgroundJobView,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_analyst_access)],
)
def retry_background_job(
    job_id: UUID,
    payload: BackgroundJobRetryRequest,
    jobs: BackgroundJobServiceDependency,
    actor: OperationalActor,
) -> BackgroundJobView:
    return BackgroundJobView.model_validate(
        jobs.retry(job_id, actor, payload.reason)
    )


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
