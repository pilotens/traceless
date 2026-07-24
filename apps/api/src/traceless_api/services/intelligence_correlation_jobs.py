"""Queue tenant-wide intelligence correlation after a source lifecycle change."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from traceless_api.core.config import Settings
from traceless_api.db.models import ProjectRow, ScanJobRow, SystemRow
from traceless_api.models.intelligence_hub import IntelImportResult
from traceless_api.services.background_jobs import BackgroundJobService
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalNotFoundError,
    OperationalRepository,
)


def enqueue_tenant_correlation_jobs(
    *,
    settings: Settings,
    repository: OperationalRepository,
    trigger_type: str,
    trigger_id: UUID,
    manifest_sha256: str,
    actor: str,
    available_at: datetime | None = None,
) -> list[UUID]:
    """Queue one idempotent job per accessible tenant system with inventory."""

    if repository.organization_id is None:
        raise OperationalConflictError("An organization scope is required")
    if trigger_type not in {
        "external_sync",
        "intel_review",
        "intel_superseded",
        "intel_temporal_boundary",
        "inventory_generation",
    }:
        raise ValueError("Unsupported intelligence correlation trigger")
    if len(manifest_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in manifest_sha256
    ):
        raise ValueError("Correlation manifest must be a lowercase SHA-256 digest")
    tenant_system_ids = list(
        repository.session.scalars(
            select(SystemRow.id)
            .join(ProjectRow, ProjectRow.id == SystemRow.project_id)
            .where(
                ProjectRow.organization_id == repository.organization_id,
                select(ScanJobRow.id)
                .where(
                    ScanJobRow.system_id == SystemRow.id,
                    ScanJobRow.status == "completed",
                )
                .exists(),
            )
            .order_by(SystemRow.id)
        )
    )
    system_ids: list[UUID] = []
    for system_id in tenant_system_ids:
        try:
            repository.get_system(system_id)
        except OperationalNotFoundError:
            continue
        system_ids.append(system_id)
    if not system_ids:
        return []
    jobs = BackgroundJobService(
        repository.session,
        organization_id=repository.organization_id,
        organization_key=repository.organization_key or str(repository.organization_id),
        organization_name=repository.organization_name or str(repository.organization_id),
        allowed_project_ids=repository.allowed_project_ids,
        allowed_system_ids=repository.allowed_system_ids,
    )
    queued_ids: list[UUID] = []
    for system_id in system_ids:
        row, _ = jobs.enqueue(
            system_id=system_id,
            job_type="intelligence_correlation",
            payload={
                "trigger_type": trigger_type,
                "trigger_id": str(trigger_id),
                "manifest_sha256": manifest_sha256,
            },
            actor=actor,
            max_attempts=settings.background_job_max_attempts,
            idempotency_key=f"{trigger_type}:{trigger_id}:{manifest_sha256}",
            available_at=available_at,
        )
        queued_ids.append(row.id)
    return queued_ids


def enqueue_import_recorrelation_jobs(
    *,
    settings: Settings,
    repository: OperationalRepository,
    outcome: IntelImportResult,
    actor: str,
) -> list[UUID]:
    """Fail closed when a previously materializable record changes."""

    record_ids = outcome._records_requiring_recorrelation
    manifest = outcome._recorrelation_manifest_sha256
    if not record_ids or manifest is None:
        return []
    return enqueue_tenant_correlation_jobs(
        settings=settings,
        repository=repository,
        trigger_type="intel_superseded",
        trigger_id=record_ids[0],
        manifest_sha256=manifest,
        actor=actor,
    )
