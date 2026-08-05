"""Unversioned infrastructure probes."""

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from traceless_api import __version__
from traceless_api.api.dependencies import SessionDependency
from traceless_api.models.common import HealthResponse, ReadinessResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=HealthResponse)
def liveness() -> HealthResponse:
    return HealthResponse(version=__version__)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={503: {"description": "Required application data is unavailable"}},
)
def readiness(
    response: Response,
    session: SessionDependency,
) -> ReadinessResponse:
    database_ready = True
    try:
        session.execute(text("SELECT 1"))
    except Exception:
        database_ready = False
    ready = database_ready
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    state = "ready" if ready else "not_ready"
    return ReadinessResponse(
        status=state,
        checks={
            "database": "ready" if database_ready else "not_ready",
        },
    )
