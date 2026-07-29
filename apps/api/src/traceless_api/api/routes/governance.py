"""Business context, controls and closed-loop risk governance routes."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from traceless_api.api.auth import (
    OperationalActor,
    require_analyst_access,
    require_read_access,
)
from traceless_api.api.dependencies import OperationalRepositoryDependency
from traceless_api.models.governance import (
    AnalysisManifestCreate,
    AnalysisManifestView,
    ControlAssessmentCreate,
    ControlAssessmentView,
    ControlCreate,
    ControlView,
    GovernanceOverview,
    PortfolioGovernanceView,
    RiskEvidenceLinkCreate,
    RiskEvidenceLinkView,
    RiskTreatmentCreate,
    RiskTreatmentUpdate,
    RiskTreatmentView,
    SystemContextCreate,
    SystemContextView,
)
from traceless_api.services.risk_governance import (
    add_risk_evidence,
    assess_control,
    create_analysis_manifest,
    create_context,
    create_control,
    create_treatment,
    governance_overview,
    list_analysis_manifests,
    list_contexts,
    list_control_assessments,
    list_controls,
    list_risk_evidence,
    list_treatments,
    portfolio_governance,
    publish_context,
    update_treatment,
)

router = APIRouter(prefix="/operational", tags=["risk-governance"])


@router.get(
    "/portfolio/governance",
    response_model=PortfolioGovernanceView,
    dependencies=[Depends(require_read_access)],
)
def portfolio(
    repository: OperationalRepositoryDependency,
) -> PortfolioGovernanceView:
    return portfolio_governance(repository)


@router.get(
    "/systems/{system_id}/governance/overview",
    response_model=GovernanceOverview,
    dependencies=[Depends(require_read_access)],
)
def overview(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
) -> GovernanceOverview:
    return governance_overview(repository, system_id)


@router.post(
    "/systems/{system_id}/context/versions",
    response_model=SystemContextView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_context_version(
    system_id: UUID,
    payload: SystemContextCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> SystemContextView:
    return create_context(repository, system_id, payload, actor)


@router.get(
    "/systems/{system_id}/context/versions",
    response_model=list[SystemContextView],
    dependencies=[Depends(require_read_access)],
)
def context_versions(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
) -> list[SystemContextView]:
    return list_contexts(repository, system_id)


@router.post(
    "/systems/{system_id}/context/versions/{context_id}/publish",
    response_model=SystemContextView,
    dependencies=[Depends(require_analyst_access)],
)
def publish_context_version(
    system_id: UUID,
    context_id: UUID,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> SystemContextView:
    return publish_context(repository, system_id, context_id, actor)


@router.post(
    "/systems/{system_id}/risks/{risk_id}/evidence",
    response_model=RiskEvidenceLinkView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_risk_evidence(
    system_id: UUID,
    risk_id: UUID,
    payload: RiskEvidenceLinkCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> RiskEvidenceLinkView:
    return add_risk_evidence(repository, system_id, risk_id, payload, actor)


@router.get(
    "/systems/{system_id}/risks/{risk_id}/evidence",
    response_model=list[RiskEvidenceLinkView],
    dependencies=[Depends(require_read_access)],
)
def risk_evidence(
    system_id: UUID,
    risk_id: UUID,
    repository: OperationalRepositoryDependency,
) -> list[RiskEvidenceLinkView]:
    return list_risk_evidence(repository, system_id, risk_id)


@router.post(
    "/systems/{system_id}/risks/{risk_id}/treatments",
    response_model=RiskTreatmentView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_risk_treatment(
    system_id: UUID,
    risk_id: UUID,
    payload: RiskTreatmentCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> RiskTreatmentView:
    return create_treatment(repository, system_id, risk_id, payload, actor)


@router.get(
    "/systems/{system_id}/treatments",
    response_model=list[RiskTreatmentView],
    dependencies=[Depends(require_read_access)],
)
def treatments(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
    risk_id: Annotated[UUID | None, Query()] = None,
) -> list[RiskTreatmentView]:
    return list_treatments(repository, system_id, risk_id=risk_id)


@router.patch(
    "/systems/{system_id}/treatments/{treatment_id}",
    response_model=RiskTreatmentView,
    dependencies=[Depends(require_analyst_access)],
)
def patch_treatment(
    system_id: UUID,
    treatment_id: UUID,
    payload: RiskTreatmentUpdate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> RiskTreatmentView:
    return update_treatment(repository, system_id, treatment_id, payload, actor)


@router.post(
    "/systems/{system_id}/controls",
    response_model=ControlView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_system_control(
    system_id: UUID,
    payload: ControlCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ControlView:
    return create_control(repository, system_id, payload, actor)


@router.get(
    "/systems/{system_id}/controls",
    response_model=list[ControlView],
    dependencies=[Depends(require_read_access)],
)
def controls(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
) -> list[ControlView]:
    return list_controls(repository, system_id)


@router.post(
    "/systems/{system_id}/controls/{control_id}/assessments",
    response_model=ControlAssessmentView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_control_assessment(
    system_id: UUID,
    control_id: UUID,
    payload: ControlAssessmentCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> ControlAssessmentView:
    return assess_control(repository, system_id, control_id, payload, actor)


@router.get(
    "/systems/{system_id}/controls/{control_id}/assessments",
    response_model=list[ControlAssessmentView],
    dependencies=[Depends(require_read_access)],
)
def control_assessments(
    system_id: UUID,
    control_id: UUID,
    repository: OperationalRepositoryDependency,
) -> list[ControlAssessmentView]:
    return list_control_assessments(repository, system_id, control_id)


@router.post(
    "/systems/{system_id}/analysis-manifests",
    response_model=AnalysisManifestView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_analyst_access)],
)
def create_manifest(
    system_id: UUID,
    payload: AnalysisManifestCreate,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> AnalysisManifestView:
    return create_analysis_manifest(repository, system_id, payload, actor)


@router.get(
    "/systems/{system_id}/analysis-manifests",
    response_model=list[AnalysisManifestView],
    dependencies=[Depends(require_read_access)],
)
def manifests(
    system_id: UUID,
    repository: OperationalRepositoryDependency,
) -> list[AnalysisManifestView]:
    return list_analysis_manifests(repository, system_id)
