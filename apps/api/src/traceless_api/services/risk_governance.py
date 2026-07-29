"""Closed-loop risk governance and business-context services."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select

from traceless_api.db.governance_models import (
    AnalysisManifestRow,
    ControlAssessmentRow,
    ControlRow,
    RiskEvidenceLinkRow,
    RiskTreatmentRow,
    SystemContextVersionRow,
)
from traceless_api.db.models import RiskRow, SystemRow
from traceless_api.models.governance import (
    AnalysisManifestCreate,
    AnalysisManifestView,
    BusinessImpactProfile,
    ControlAssessmentCreate,
    ControlAssessmentView,
    ControlCreate,
    ControlView,
    GovernanceOverview,
    PortfolioGovernanceItem,
    PortfolioGovernanceView,
    RiskEvidenceLinkCreate,
    RiskEvidenceLinkView,
    RiskTreatmentCreate,
    RiskTreatmentUpdate,
    RiskTreatmentView,
    SystemContextCreate,
    SystemContextView,
)
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalNotFoundError,
    OperationalRepository,
)
from traceless_api.services.risk_engine import POLICY_VERSION, risk_level


def _risk(repository: OperationalRepository, system_id: UUID, risk_id: UUID) -> RiskRow:
    repository.get_system(system_id)
    row = repository.session.scalar(
        select(RiskRow).where(RiskRow.id == risk_id, RiskRow.system_id == system_id)
    )
    if row is None:
        raise OperationalNotFoundError("Risk was not found")
    return row


def _context_view(row: SystemContextVersionRow) -> SystemContextView:
    return SystemContextView(
        id=row.id,
        system_id=row.system_id,
        version=row.version,
        status=row.status,
        business_owner=row.business_owner,
        capabilities=row.capabilities,
        processes=row.processes,
        data_categories=row.data_categories,
        regulations=row.regulations,
        recovery_time_objective_hours=row.recovery_time_objective_hours,
        recovery_point_objective_hours=row.recovery_point_objective_hours,
        impact_profile=BusinessImpactProfile.model_validate(row.impact_profile),
        created_by=row.created_by,
        created_at=row.created_at,
        published_by=row.published_by,
        published_at=row.published_at,
    )


def latest_context(
    repository: OperationalRepository,
    system_id: UUID,
    *,
    status: str | None = None,
) -> SystemContextVersionRow | None:
    repository.get_system(system_id)
    statement = select(SystemContextVersionRow).where(
        SystemContextVersionRow.system_id == system_id
    )
    if status is not None:
        statement = statement.where(SystemContextVersionRow.status == status)
    return repository.session.scalar(
        statement.order_by(
            SystemContextVersionRow.version.desc(),
            SystemContextVersionRow.created_at.desc(),
        )
    )


def create_context(
    repository: OperationalRepository,
    system_id: UUID,
    payload: SystemContextCreate,
    actor: str,
) -> SystemContextView:
    repository.get_system(system_id)
    repository.session.execute(select(SystemRow).where(SystemRow.id == system_id).with_for_update())
    current_version = repository.session.scalar(
        select(func.max(SystemContextVersionRow.version)).where(
            SystemContextVersionRow.system_id == system_id
        )
    )
    row = SystemContextVersionRow(
        system_id=system_id,
        version=int(current_version or 0) + 1,
        business_owner=payload.business_owner,
        capabilities=payload.capabilities,
        processes=payload.processes,
        data_categories=payload.data_categories,
        regulations=payload.regulations,
        recovery_time_objective_hours=payload.recovery_time_objective_hours,
        recovery_point_objective_hours=payload.recovery_point_objective_hours,
        impact_profile=payload.impact_profile.model_dump(mode="json"),
        created_by=actor,
    )
    repository.session.add(row)
    repository.session.flush()
    repository.audit(
        actor,
        "system_context.created",
        "system_context",
        row.id,
        {"system_id": str(system_id), "version": row.version},
    )
    return _context_view(row)


def list_contexts(repository: OperationalRepository, system_id: UUID) -> list[SystemContextView]:
    repository.get_system(system_id)
    rows = repository.session.scalars(
        select(SystemContextVersionRow)
        .where(SystemContextVersionRow.system_id == system_id)
        .order_by(SystemContextVersionRow.version.desc())
    )
    return [_context_view(row) for row in rows]


def publish_context(
    repository: OperationalRepository,
    system_id: UUID,
    context_id: UUID,
    actor: str,
) -> SystemContextView:
    repository.get_system(system_id)
    repository.session.execute(select(SystemRow).where(SystemRow.id == system_id).with_for_update())
    target = repository.session.scalar(
        select(SystemContextVersionRow).where(
            SystemContextVersionRow.id == context_id,
            SystemContextVersionRow.system_id == system_id,
        )
    )
    if target is None:
        raise OperationalNotFoundError("System context version was not found")
    if target.status == "superseded":
        raise OperationalConflictError("A superseded context cannot be republished")
    current = repository.session.scalar(
        select(SystemContextVersionRow).where(
            SystemContextVersionRow.system_id == system_id,
            SystemContextVersionRow.status == "published",
        )
    )
    if current is not None and current.id != target.id:
        current.status = "superseded"
    target.status = "published"
    target.published_by = actor
    target.published_at = datetime.now(UTC)
    repository.session.flush()
    repository.audit(
        actor,
        "system_context.published",
        "system_context",
        target.id,
        {"system_id": str(system_id), "version": target.version},
    )
    return _context_view(target)


def add_risk_evidence(
    repository: OperationalRepository,
    system_id: UUID,
    risk_id: UUID,
    payload: RiskEvidenceLinkCreate,
    actor: str,
) -> RiskEvidenceLinkView:
    risk = _risk(repository, system_id, risk_id)
    row = RiskEvidenceLinkRow(
        risk_id=risk.id,
        evidence_type=payload.evidence_type,
        evidence_id=payload.evidence_id,
        label=payload.label,
        source_version=payload.source_version,
        metadata_payload=payload.metadata,
        created_by=actor,
    )
    repository.session.add(row)
    repository.session.flush()
    repository.audit(
        actor,
        "risk_evidence.created",
        "risk_evidence",
        row.id,
        {"risk_id": str(risk.id), "evidence_type": row.evidence_type},
    )
    return RiskEvidenceLinkView(
        id=row.id,
        risk_id=row.risk_id,
        evidence_type=row.evidence_type,
        evidence_id=row.evidence_id,
        label=row.label,
        source_version=row.source_version,
        metadata=row.metadata_payload,
        created_by=row.created_by,
        created_at=row.created_at,
    )


def list_risk_evidence(
    repository: OperationalRepository,
    system_id: UUID,
    risk_id: UUID,
) -> list[RiskEvidenceLinkView]:
    risk = _risk(repository, system_id, risk_id)
    rows = repository.session.scalars(
        select(RiskEvidenceLinkRow)
        .where(RiskEvidenceLinkRow.risk_id == risk.id)
        .order_by(RiskEvidenceLinkRow.created_at)
    )
    return [
        RiskEvidenceLinkView(
            id=row.id,
            risk_id=row.risk_id,
            evidence_type=row.evidence_type,
            evidence_id=row.evidence_id,
            label=row.label,
            source_version=row.source_version,
            metadata=row.metadata_payload,
            created_by=row.created_by,
            created_at=row.created_at,
        )
        for row in rows
    ]


def _treatment_view(row: RiskTreatmentRow) -> RiskTreatmentView:
    return RiskTreatmentView(
        id=row.id,
        system_id=row.system_id,
        risk_id=row.risk_id,
        strategy=row.strategy,
        title=row.title,
        description=row.description,
        owner=row.owner,
        approver=row.approver,
        status=row.status,
        priority=row.priority,
        due_at=row.due_at,
        sla_days=row.sla_days,
        verification_criteria=row.verification_criteria,
        decision_note=row.decision_note,
        external_system=row.external_system,
        external_key=row.external_key,
        external_url=row.external_url,
        residual_likelihood=row.residual_likelihood,
        residual_impact=row.residual_impact,
        residual_score=row.residual_score,
        residual_level=row.residual_level,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        approved_by=row.approved_by,
        approved_at=row.approved_at,
        verified_by=row.verified_by,
        verified_at=row.verified_at,
        overdue=(
            row.due_at is not None
            and row.due_at < datetime.now(UTC)
            and row.status not in {"closed", "cancelled"}
        ),
    )


def create_treatment(
    repository: OperationalRepository,
    system_id: UUID,
    risk_id: UUID,
    payload: RiskTreatmentCreate,
    actor: str,
) -> RiskTreatmentView:
    risk = _risk(repository, system_id, risk_id)
    due_at = payload.due_at
    if due_at is None and payload.sla_days is not None:
        due_at = datetime.now(UTC) + timedelta(days=payload.sla_days)
    row = RiskTreatmentRow(
        system_id=system_id,
        risk_id=risk.id,
        strategy=payload.strategy,
        title=payload.title,
        description=payload.description,
        owner=payload.owner,
        approver=payload.approver,
        priority=payload.priority,
        due_at=due_at,
        sla_days=payload.sla_days,
        verification_criteria=payload.verification_criteria,
        external_system=payload.external_system,
        external_key=payload.external_key,
        external_url=payload.external_url,
        created_by=actor,
    )
    repository.session.add(row)
    repository.session.flush()
    repository.audit(
        actor,
        "risk_treatment.created",
        "risk_treatment",
        row.id,
        {"risk_id": str(risk.id), "owner": row.owner, "strategy": row.strategy},
    )
    return _treatment_view(row)


def list_treatments(
    repository: OperationalRepository,
    system_id: UUID,
    *,
    risk_id: UUID | None = None,
) -> list[RiskTreatmentView]:
    repository.get_system(system_id)
    statement = select(RiskTreatmentRow).where(RiskTreatmentRow.system_id == system_id)
    if risk_id is not None:
        _risk(repository, system_id, risk_id)
        statement = statement.where(RiskTreatmentRow.risk_id == risk_id)
    rows = repository.session.scalars(
        statement.order_by(
            RiskTreatmentRow.status,
            RiskTreatmentRow.priority.desc(),
            RiskTreatmentRow.due_at,
        )
    )
    return [_treatment_view(row) for row in rows]


def update_treatment(
    repository: OperationalRepository,
    system_id: UUID,
    treatment_id: UUID,
    payload: RiskTreatmentUpdate,
    actor: str,
) -> RiskTreatmentView:
    repository.get_system(system_id)
    row = repository.session.scalar(
        select(RiskTreatmentRow)
        .where(
            RiskTreatmentRow.id == treatment_id,
            RiskTreatmentRow.system_id == system_id,
        )
        .with_for_update()
    )
    if row is None:
        raise OperationalNotFoundError("Risk treatment was not found")
    update = payload.model_dump(exclude_unset=True)
    status = update.pop("status", None)
    residual_likelihood = update.pop("residual_likelihood", None)
    residual_impact = update.pop("residual_impact", None)
    for key, value in update.items():
        setattr(row, key, value)
    if residual_likelihood is not None and residual_impact is not None:
        row.residual_likelihood = residual_likelihood
        row.residual_impact = residual_impact
        row.residual_score = residual_likelihood * residual_impact
        row.residual_level = risk_level(row.residual_score)
    now = datetime.now(UTC)
    if status is not None:
        if status == "approved":
            if not row.decision_note:
                raise OperationalConflictError("Approval requires a decision note")
            row.approved_by = actor
            row.approved_at = now
        if status == "closed":
            if row.residual_score is None:
                raise OperationalConflictError(
                    "Closing a treatment requires a residual-risk assessment"
                )
            if not row.verification_criteria:
                raise OperationalConflictError("Closing a treatment requires verification criteria")
            row.verified_by = actor
            row.verified_at = now
        row.status = status
    repository.session.flush()
    repository.audit(
        actor,
        "risk_treatment.updated",
        "risk_treatment",
        row.id,
        {"status": row.status, "risk_id": str(row.risk_id)},
    )
    return _treatment_view(row)


def create_control(
    repository: OperationalRepository,
    system_id: UUID,
    payload: ControlCreate,
    actor: str,
) -> ControlView:
    repository.get_system(system_id)
    row = ControlRow(system_id=system_id, created_by=actor, **payload.model_dump())
    repository.session.add(row)
    repository.session.flush()
    repository.audit(
        actor,
        "control.created",
        "control",
        row.id,
        {"system_id": str(system_id), "control_key": row.control_key},
    )
    return ControlView.model_validate(row)


def list_controls(repository: OperationalRepository, system_id: UUID) -> list[ControlView]:
    repository.get_system(system_id)
    rows = repository.session.scalars(
        select(ControlRow)
        .where(ControlRow.system_id == system_id)
        .order_by(ControlRow.status, ControlRow.control_key)
    )
    return [ControlView.model_validate(row) for row in rows]


def assess_control(
    repository: OperationalRepository,
    system_id: UUID,
    control_id: UUID,
    payload: ControlAssessmentCreate,
    actor: str,
) -> ControlAssessmentView:
    repository.get_system(system_id)
    control = repository.session.scalar(
        select(ControlRow).where(
            ControlRow.id == control_id,
            ControlRow.system_id == system_id,
        )
    )
    if control is None:
        raise OperationalNotFoundError("Control was not found")
    row = ControlAssessmentRow(
        control_id=control.id,
        assessed_by=actor,
        **payload.model_dump(),
    )
    repository.session.add(row)
    repository.session.flush()
    repository.audit(
        actor,
        "control_assessment.created",
        "control_assessment",
        row.id,
        {"control_id": str(control.id), "result": row.result},
    )
    return ControlAssessmentView.model_validate(row)


def list_control_assessments(
    repository: OperationalRepository,
    system_id: UUID,
    control_id: UUID,
) -> list[ControlAssessmentView]:
    repository.get_system(system_id)
    control = repository.session.scalar(
        select(ControlRow).where(
            ControlRow.id == control_id,
            ControlRow.system_id == system_id,
        )
    )
    if control is None:
        raise OperationalNotFoundError("Control was not found")
    rows = repository.session.scalars(
        select(ControlAssessmentRow)
        .where(ControlAssessmentRow.control_id == control.id)
        .order_by(ControlAssessmentRow.assessed_at.desc())
    )
    return [ControlAssessmentView.model_validate(row) for row in rows]


def create_analysis_manifest(
    repository: OperationalRepository,
    system_id: UUID,
    payload: AnalysisManifestCreate,
    actor: str,
) -> AnalysisManifestView:
    repository.get_system(system_id)
    scan = repository.latest_completed_scan(system_id)
    architecture = repository.latest_architecture(system_id)
    context = latest_context(repository, system_id, status="published")
    components = {
        "scan_job_id": str(scan.id) if scan is not None else None,
        "architecture_snapshot_id": str(architecture.id) if architecture is not None else None,
        "system_context_version_id": str(context.id) if context is not None else None,
        "risk_policy_version": POLICY_VERSION,
        "risk_ids": [
            str(value)
            for value in repository.session.scalars(
                select(RiskRow.id).where(RiskRow.system_id == system_id).order_by(RiskRow.id)
            )
        ],
        "control_assessment_ids": [
            str(value)
            for value in repository.session.scalars(
                select(ControlAssessmentRow.id)
                .join(ControlRow, ControlRow.id == ControlAssessmentRow.control_id)
                .where(ControlRow.system_id == system_id)
                .order_by(ControlAssessmentRow.id)
            )
        ],
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            components,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    existing = repository.session.scalar(
        select(AnalysisManifestRow).where(
            AnalysisManifestRow.system_id == system_id,
            AnalysisManifestRow.purpose == payload.purpose,
            AnalysisManifestRow.source_fingerprint == fingerprint,
        )
    )
    if existing is not None:
        return AnalysisManifestView.model_validate(existing)
    row = AnalysisManifestRow(
        system_id=system_id,
        purpose=payload.purpose,
        architecture_snapshot_id=architecture.id if architecture is not None else None,
        system_context_version_id=context.id if context is not None else None,
        scan_job_id=scan.id if scan is not None else None,
        risk_policy_version=POLICY_VERSION,
        source_fingerprint=fingerprint,
        components=components,
        created_by=actor,
    )
    repository.session.add(row)
    repository.session.flush()
    repository.audit(
        actor,
        "analysis_manifest.created",
        "analysis_manifest",
        row.id,
        {"system_id": str(system_id), "purpose": row.purpose},
    )
    return AnalysisManifestView.model_validate(row)


def list_analysis_manifests(
    repository: OperationalRepository, system_id: UUID
) -> list[AnalysisManifestView]:
    repository.get_system(system_id)
    rows = repository.session.scalars(
        select(AnalysisManifestRow)
        .where(AnalysisManifestRow.system_id == system_id)
        .order_by(AnalysisManifestRow.created_at.desc())
        .limit(100)
    )
    return [AnalysisManifestView.model_validate(row) for row in rows]


def governance_overview(repository: OperationalRepository, system_id: UUID) -> GovernanceOverview:
    repository.get_system(system_id)
    published = latest_context(repository, system_id, status="published")
    draft = latest_context(repository, system_id, status="draft")
    open_risks = int(
        repository.session.scalar(
            select(func.count(RiskRow.id)).where(
                RiskRow.system_id == system_id, RiskRow.status == "open"
            )
        )
        or 0
    )
    active_risk_ids = set(
        repository.session.scalars(
            select(RiskTreatmentRow.risk_id).where(
                RiskTreatmentRow.system_id == system_id,
                RiskTreatmentRow.status.not_in(("closed", "cancelled")),
            )
        )
    )
    treatment_owners = set(
        repository.session.scalars(
            select(RiskTreatmentRow.risk_id).where(
                RiskTreatmentRow.system_id == system_id,
                RiskTreatmentRow.owner != "",
                RiskTreatmentRow.status.not_in(("closed", "cancelled")),
            )
        )
    )
    overdue = int(
        repository.session.scalar(
            select(func.count(RiskTreatmentRow.id)).where(
                RiskTreatmentRow.system_id == system_id,
                RiskTreatmentRow.due_at < datetime.now(UTC),
                RiskTreatmentRow.status.not_in(("closed", "cancelled")),
            )
        )
        or 0
    )
    controls = int(
        repository.session.scalar(
            select(func.count(ControlRow.id)).where(ControlRow.system_id == system_id)
        )
        or 0
    )
    assessed_controls = int(
        repository.session.scalar(
            select(func.count(func.distinct(ControlAssessmentRow.control_id)))
            .join(ControlRow, ControlRow.id == ControlAssessmentRow.control_id)
            .where(
                ControlRow.system_id == system_id,
                ControlAssessmentRow.result != "not_tested",
                (ControlAssessmentRow.valid_until.is_(None))
                | (ControlAssessmentRow.valid_until >= datetime.now(UTC)),
            )
        )
        or 0
    )
    context_points = 1 if published is not None else 0
    risk_points = 1 if open_risks == 0 else min(1, len(active_risk_ids) / open_risks)
    owner_points = 1 if open_risks == 0 else min(1, len(treatment_owners) / open_risks)
    control_points = 1 if controls == 0 else min(1, assessed_controls / controls)
    coverage = round(
        100
        * (0.25 * context_points + 0.30 * risk_points + 0.20 * owner_points + 0.25 * control_points)
    )
    manifest = repository.session.scalar(
        select(AnalysisManifestRow)
        .where(AnalysisManifestRow.system_id == system_id)
        .order_by(AnalysisManifestRow.created_at.desc())
    )
    return GovernanceOverview(
        system_id=system_id,
        published_context=_context_view(published) if published is not None else None,
        draft_context=_context_view(draft) if draft is not None else None,
        open_risks=open_risks,
        risks_with_active_treatment=len(active_risk_ids),
        risks_without_owner=max(0, open_risks - len(treatment_owners)),
        overdue_treatments=overdue,
        controls=controls,
        controls_with_current_assessment=assessed_controls,
        coverage_percent=coverage,
        latest_manifest=(
            AnalysisManifestView.model_validate(manifest) if manifest is not None else None
        ),
    )


def portfolio_governance(
    repository: OperationalRepository,
) -> PortfolioGovernanceView:
    items: list[PortfolioGovernanceItem] = []
    for project in repository.list_projects():
        for system in repository.list_systems(project.id):
            overview = governance_overview(repository, system.id)
            context = overview.published_context
            items.append(
                PortfolioGovernanceItem(
                    system_id=system.id,
                    system_name=system.name,
                    project_id=project.id,
                    criticality=system.criticality,
                    business_owner=(
                        context.business_owner if context is not None else system.owner
                    ),
                    open_risks=overview.open_risks,
                    overdue_treatments=overview.overdue_treatments,
                    risks_without_owner=overview.risks_without_owner,
                    coverage_percent=overview.coverage_percent,
                )
            )
    return PortfolioGovernanceView(
        systems=items,
        open_risks=sum(item.open_risks for item in items),
        overdue_treatments=sum(item.overdue_treatments for item in items),
        risks_without_owner=sum(item.risks_without_owner for item in items),
        average_coverage_percent=(
            round(sum(item.coverage_percent for item in items) / len(items)) if items else 0
        ),
    )
