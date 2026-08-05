"""API router composition."""

from fastapi import APIRouter, Depends

from traceless_api import __version__
from traceless_api.api.auth import require_operational_principal
from traceless_api.api.routes import (
    asset_sources,
    attack_chains,
    authentication,
    collections,
    intelligence,
    jobs,
    operational,
    reports,
)
from traceless_api.models.api import ApiRootResponse

router = APIRouter()
router.include_router(authentication.router)


@router.get("", response_model=ApiRootResponse, tags=["meta"])
def api_root() -> ApiRootResponse:
    return ApiRootResponse(version=__version__)


operational_dependencies = [Depends(require_operational_principal)]
router.include_router(asset_sources.router, dependencies=operational_dependencies)
router.include_router(operational.router, dependencies=operational_dependencies)
router.include_router(collections.router, dependencies=operational_dependencies)
router.include_router(reports.router, dependencies=operational_dependencies)
router.include_router(intelligence.router, dependencies=operational_dependencies)
router.include_router(attack_chains.router, dependencies=operational_dependencies)
router.include_router(jobs.router, dependencies=operational_dependencies)
