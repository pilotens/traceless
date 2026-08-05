"""Database-backed pagination for operational collections."""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, or_, select

from traceless_api.db.models import (
    AssetRow,
    FindingRow,
    RiskRow,
    ServiceRow,
    ThreatRow,
    VulnerabilityObservationRow,
)
from traceless_api.services.intelligence_hub import IntelligenceHubService
from traceless_api.services.operational_repository import (
    OperationalNotFoundError,
    OperationalRepository,
)


@dataclass(frozen=True, slots=True)
class QueryPage[RowT]:
    rows: list[RowT]
    total: int


def get_finding(repository: OperationalRepository, system_id: UUID, finding_id: UUID) -> FindingRow:
    _reconcile_current_intelligence(repository, system_id)
    repository.get_system(system_id)
    row = repository.session.scalar(
        select(FindingRow).where(
            FindingRow.system_id == system_id,
            FindingRow.id == finding_id,
        )
    )
    if row is None:
        raise OperationalNotFoundError("Finding was not found")
    return row


def get_risk(repository: OperationalRepository, system_id: UUID, risk_id: UUID) -> RiskRow:
    _reconcile_current_intelligence(repository, system_id)
    repository.get_system(system_id)
    row = repository.session.scalar(
        select(RiskRow).where(RiskRow.system_id == system_id, RiskRow.id == risk_id)
    )
    if row is None:
        raise OperationalNotFoundError("Risk was not found")
    return row


def get_threat(repository: OperationalRepository, system_id: UUID, threat_id: UUID) -> ThreatRow:
    _reconcile_current_intelligence(repository, system_id)
    repository.get_system(system_id)
    row = repository.session.scalar(
        select(ThreatRow).where(
            ThreatRow.system_id == system_id,
            ThreatRow.id == threat_id,
        )
    )
    if row is None:
        raise OperationalNotFoundError("Threat was not found")
    return row


def get_vulnerability_observation(
    repository: OperationalRepository, system_id: UUID, observation_id: UUID
) -> VulnerabilityObservationRow:
    repository.get_system(system_id)
    row = repository.session.scalar(
        select(VulnerabilityObservationRow).where(
            VulnerabilityObservationRow.system_id == system_id,
            VulnerabilityObservationRow.id == observation_id,
        )
    )
    if row is None:
        raise OperationalNotFoundError("Vulnerability observation was not found")
    return row


def list_current_asset_page(
    repository: OperationalRepository,
    system_id: UUID,
    *,
    limit: int,
    offset: int,
) -> QueryPage[AssetRow]:
    scan = repository.latest_completed_scan(system_id)
    if scan is None:
        return QueryPage(rows=[], total=0)
    filters = [AssetRow.system_id == system_id, AssetRow.source_scan_id == scan.id]
    total = repository.session.scalar(select(func.count()).select_from(AssetRow).where(*filters))
    rows = list(
        repository.session.scalars(
            select(AssetRow)
            .where(*filters)
            .order_by(AssetRow.primary_ip, AssetRow.id)
            .offset(offset)
            .limit(limit)
        )
    )
    return QueryPage(rows=rows, total=total or 0)


def list_current_service_page(
    repository: OperationalRepository,
    system_id: UUID,
    *,
    asset_id: UUID | None = None,
    limit: int,
    offset: int,
) -> QueryPage[ServiceRow]:
    scan = repository.latest_completed_scan(system_id)
    if scan is None:
        return QueryPage(rows=[], total=0)
    filters = [
        AssetRow.system_id == system_id,
        ServiceRow.scan_job_id == scan.id,
        func.lower(ServiceRow.state) == "open",
    ]
    if asset_id is not None:
        filters.append(ServiceRow.asset_id == asset_id)
    total = repository.session.scalar(
        select(func.count())
        .select_from(ServiceRow)
        .join(AssetRow, ServiceRow.asset_id == AssetRow.id)
        .where(*filters)
    )
    rows = list(
        repository.session.scalars(
            select(ServiceRow)
            .join(AssetRow, ServiceRow.asset_id == AssetRow.id)
            .where(*filters)
            .order_by(ServiceRow.port, ServiceRow.id)
            .offset(offset)
            .limit(limit)
        )
    )
    return QueryPage(rows=rows, total=total or 0)


def list_finding_page(
    repository: OperationalRepository,
    system_id: UUID,
    *,
    limit: int,
    offset: int,
    lifecycle_status: str | None = None,
    finding_type: str | None = None,
    needs_review: bool | None = None,
) -> QueryPage[FindingRow]:
    _reconcile_current_intelligence(repository, system_id)
    repository.get_system(system_id)
    filters = [FindingRow.system_id == system_id]
    if lifecycle_status is not None:
        filters.append(FindingRow.lifecycle_status == lifecycle_status)
    if finding_type is not None:
        filters.append(FindingRow.finding_type == finding_type)
    if needs_review is True:
        filters.append(FindingRow.status.in_(("candidate", "likely")))
    elif needs_review is False:
        filters.append(FindingRow.status.in_(("confirmed", "false_positive")))
    total = repository.session.scalar(select(func.count()).select_from(FindingRow).where(*filters))
    rows = list(
        repository.session.scalars(
            select(FindingRow)
            .where(*filters)
            .order_by(FindingRow.last_seen_at.desc(), FindingRow.id)
            .offset(offset)
            .limit(limit)
        )
    )
    return QueryPage(rows=rows, total=total or 0)


def list_risk_page(
    repository: OperationalRepository,
    system_id: UUID,
    *,
    limit: int,
    offset: int,
    status: str | None = None,
) -> QueryPage[RiskRow]:
    _reconcile_current_intelligence(repository, system_id)
    repository.get_system(system_id)
    threat_filters = _current_threat_filters(repository, system_id)
    current_threat_ids = select(ThreatRow.id).where(*threat_filters)
    filters = [
        RiskRow.system_id == system_id,
        or_(
            RiskRow.finding_id.is_not(None),
            RiskRow.threat_id.in_(current_threat_ids),
        ),
    ]
    if status is not None:
        filters.append(RiskRow.status == status)
    total = repository.session.scalar(select(func.count()).select_from(RiskRow).where(*filters))
    rows = list(
        repository.session.scalars(
            select(RiskRow)
            .where(*filters)
            .order_by(RiskRow.score.desc(), RiskRow.updated_at.desc(), RiskRow.id)
            .offset(offset)
            .limit(limit)
        )
    )
    return QueryPage(rows=rows, total=total or 0)


def list_threat_page(
    repository: OperationalRepository,
    system_id: UUID,
    *,
    limit: int,
    offset: int,
) -> QueryPage[ThreatRow]:
    _reconcile_current_intelligence(repository, system_id)
    repository.get_system(system_id)
    filters = _current_threat_filters(repository, system_id)
    total = repository.session.scalar(select(func.count()).select_from(ThreatRow).where(*filters))
    rows = list(
        repository.session.scalars(
            select(ThreatRow)
            .where(*filters)
            .order_by(ThreatRow.modified_at.desc(), ThreatRow.id)
            .offset(offset)
            .limit(limit)
        )
    )
    return QueryPage(rows=rows, total=total or 0)


def _reconcile_current_intelligence(
    repository: OperationalRepository, system_id: UUID
) -> None:
    repository.get_system(system_id)
    marker = f"current_intelligence_effects_reconciled:{system_id}"
    if repository.session.info.get(marker) is True:
        return
    IntelligenceHubService(repository).retire_nonprocessable_effects(
        system_ids={system_id}
    )
    repository.session.info[marker] = True


def _current_threat_filters(repository: OperationalRepository, system_id: UUID) -> list[object]:
    scan = repository.latest_completed_scan(system_id)
    if scan is None:
        # Preserve one query shape while ensuring a system without an observed
        # inventory never exposes threat matches from an obsolete snapshot.
        return [ThreatRow.system_id == system_id, ThreatRow.id.is_(None)]
    now = datetime.now(UTC).isoformat()
    return [
        ThreatRow.system_id == system_id,
        ThreatRow.provenance["matched_scan_id"].as_string() == str(scan.id),
        func.json_array_length(ThreatRow.matched_asset_ids) > 0,
        or_(
            ThreatRow.provenance["valid_from"].as_string().is_(None),
            ThreatRow.provenance["valid_from"].as_string() <= now,
        ),
        or_(
            ThreatRow.provenance["valid_until"].as_string().is_(None),
            ThreatRow.provenance["valid_until"].as_string() > now,
        ),
        or_(
            ThreatRow.provenance["revoked"].as_boolean().is_(None),
            ThreatRow.provenance["revoked"].as_boolean().is_(False),
        ),
    ]


def list_vulnerability_observation_page(
    repository: OperationalRepository,
    system_id: UUID,
    *,
    limit: int,
    offset: int,
    import_id: UUID | None = None,
) -> QueryPage[VulnerabilityObservationRow]:
    repository.get_system(system_id)
    filters = [VulnerabilityObservationRow.system_id == system_id]
    if import_id is not None:
        filters.append(VulnerabilityObservationRow.import_id == import_id)
    total = repository.session.scalar(
        select(func.count()).select_from(VulnerabilityObservationRow).where(*filters)
    )
    rows = list(
        repository.session.scalars(
            select(VulnerabilityObservationRow)
            .where(*filters)
            .order_by(
                VulnerabilityObservationRow.created_at.desc(),
                VulnerabilityObservationRow.id,
            )
            .offset(offset)
            .limit(limit)
        )
    )
    return QueryPage(rows=rows, total=total or 0)
