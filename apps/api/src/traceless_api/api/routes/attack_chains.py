"""Hidden preview routes for reasoning-ready CTI attack-chain analysis."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status

from traceless_api.api.auth import (
    OperationalActor,
    require_org_wide_intelligence_access,
    require_org_wide_intelligence_read_access,
)
from traceless_api.api.dependencies import OperationalRepositoryDependency
from traceless_api.models.attack_chains import (
    AttackChainAnalysisPage,
    AttackChainAnalysisView,
    AttackChainAnalyzeRequest,
    AttackChainAnalyzeResponse,
    AttackChainReasonRequest,
    ReasoningResult,
)
from traceless_api.services.attack_chains import AttackChainService

router = APIRouter(prefix="/operational/intelligence/attack-chains", tags=["attack-chains"])


@router.post(
    "/analyze",
    response_model=AttackChainAnalyzeResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_org_wide_intelligence_access)],
    include_in_schema=False,
)
def analyze_attack_chain(
    payload: AttackChainAnalyzeRequest,
    response: Response,
    repository: OperationalRepositoryDependency,
    actor: OperationalActor,
) -> AttackChainAnalyzeResponse:
    analysis, reused = AttackChainService(repository).analyze(payload, actor)
    response.headers["X-TLP"] = analysis.distribution_tlp
    if reused:
        response.status_code = status.HTTP_200_OK
    return AttackChainAnalyzeResponse(analysis=analysis, reused=reused)


@router.get(
    "",
    response_model=AttackChainAnalysisPage,
    dependencies=[Depends(require_org_wide_intelligence_read_access)],
    include_in_schema=False,
)
def list_attack_chains(
    repository: OperationalRepositoryDependency,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AttackChainAnalysisPage:
    return AttackChainService(repository).list(limit=limit, offset=offset)


@router.get(
    "/{analysis_id}",
    response_model=AttackChainAnalysisView,
    dependencies=[Depends(require_org_wide_intelligence_read_access)],
    include_in_schema=False,
)
def get_attack_chain(
    analysis_id: UUID,
    response: Response,
    repository: OperationalRepositoryDependency,
) -> AttackChainAnalysisView:
    analysis = AttackChainService(repository).get(analysis_id)
    response.headers["X-TLP"] = analysis.distribution_tlp
    return analysis


@router.post(
    "/{analysis_id}/reason",
    response_model=ReasoningResult,
    dependencies=[Depends(require_org_wide_intelligence_access)],
    include_in_schema=False,
)
def rerun_attack_chain_reasoning(
    analysis_id: UUID,
    payload: AttackChainReasonRequest,
    response: Response,
    repository: OperationalRepositoryDependency,
) -> ReasoningResult:
    service = AttackChainService(repository)
    analysis = service.get(analysis_id)
    response.headers["X-TLP"] = analysis.distribution_tlp
    return service.reason_again(analysis_id, payload)
