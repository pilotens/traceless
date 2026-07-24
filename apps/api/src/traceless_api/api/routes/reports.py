"""Immutable report creation and download routes."""

import hashlib
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select

from traceless_api.api.auth import (
    OperationalActor,
    require_analyst_access,
    require_read_access,
)
from traceless_api.api.dependencies import OperationalRepositoryDependency
from traceless_api.db.models import AssetRow, FindingRow, ReportRow, RiskRow, ServiceRow, ThreatRow
from traceless_api.models.operational import ReportCreate, ReportView
from traceless_api.services.operational_repository import OperationalConflictError
from traceless_api.services.reporting import (
    build_report_snapshot,
    ensure_report_remains_exportable,
    prepare_report_transaction,
    render_report,
)

router = APIRouter(prefix="/operational", tags=["reports"])
_MAX_SYNCHRONOUS_REPORT_ROWS = 500


@router.post(
    "/systems/{system_id}/reports",
    response_model=ReportView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_report(
    system_id: UUID,
    payload: ReportCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ReportView:
    prepare_report_transaction(repository.session)
    repository.get_system(system_id)
    row_count = sum(
        int(
            repository.session.scalar(
                select(func.count()).select_from(model).where(model.system_id == system_id)
            )
            or 0
        )
        for model in (AssetRow, FindingRow, RiskRow, ThreatRow)
    )
    row_count += int(
        repository.session.scalar(
            select(func.count())
            .select_from(ServiceRow)
            .join(AssetRow, AssetRow.id == ServiceRow.asset_id)
            .where(AssetRow.system_id == system_id)
        )
        or 0
    )
    if row_count > _MAX_SYNCHRONOUS_REPORT_ROWS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This report exceeds the synchronous safety limit; use "
                f"/systems/{system_id}/reports/async"
            ),
        )
    snapshot = build_report_snapshot(repository, system_id)
    content = render_report(snapshot, format=payload.format, report_type=payload.report_type)
    row = repository.save_report(
        system_id=system_id,
        report_type=payload.report_type,
        format=payload.format,
        snapshot=snapshot,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        actor=actor,
    )
    return _report_view(repository, row)


@router.get(
    "/systems/{system_id}/reports",
    response_model=list[ReportView],
    dependencies=[Depends(require_read_access)],
)
def list_reports(system_id: UUID, repository: OperationalRepositoryDependency) -> list[ReportView]:
    repository.get_system(system_id)
    return [_report_view(repository, row) for row in repository.list_reports(system_id)]


@router.get(
    "/reports/{report_id}/download",
    dependencies=[Depends(require_read_access)],
)
def download_report(report_id: UUID, repository: OperationalRepositoryDependency) -> Response:
    row = repository.get_report(report_id)
    ensure_report_remains_exportable(repository, row.snapshot)
    media_types = {
        "pdf": "application/pdf",
        "json": "application/json; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
    }
    filename = f"traceless-{row.report_type}-{row.id}.{row.format}"
    return Response(
        content=row.content,
        media_type=media_types[row.format],
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, no-store",
            "X-Content-SHA256": row.sha256,
            "X-TLP": row.snapshot.get("distribution_tlp", "TLP:AMBER"),
        },
    )


def _report_view(
    repository: OperationalRepositoryDependency, row: ReportRow
) -> ReportView:
    withdrawal_reason: str | None = None
    try:
        ensure_report_remains_exportable(repository, row.snapshot)
        export_status = "available"
    except OperationalConflictError as exc:
        export_status = "withdrawn"
        withdrawal_reason = str(exc)
    snapshot_tlp = row.snapshot.get("distribution_tlp", "TLP:AMBER")
    return ReportView(
        id=row.id,
        system_id=row.system_id,
        format=row.format,
        report_type=row.report_type,
        sha256=row.sha256,
        distribution_tlp=snapshot_tlp,
        export_status=export_status,
        withdrawal_reason=withdrawal_reason,
        created_at=row.created_at,
    )
