"""Reusable FastAPI dependency annotations."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from traceless_api.api.auth import OperationalPrincipal
from traceless_api.db.session import apply_tenant_rls_scope, get_session
from traceless_api.services.background_jobs import BackgroundJobService
from traceless_api.services.operational_repository import OperationalRepository

SessionDependency = Annotated[Session, Depends(get_session)]


def get_operational_repository(
    session: SessionDependency,
    principal: OperationalPrincipal,
) -> OperationalRepository:
    apply_tenant_rls_scope(session, principal.organization_id)
    return OperationalRepository(
        session,
        organization_id=principal.organization_id,
        organization_key=principal.organization_key,
        organization_name=principal.organization_name,
        allowed_project_ids=principal.project_ids,
        allowed_system_ids=principal.system_ids,
    )


OperationalRepositoryDependency = Annotated[
    OperationalRepository, Depends(get_operational_repository)
]


def get_background_job_service(
    session: SessionDependency,
    principal: OperationalPrincipal,
) -> BackgroundJobService:
    apply_tenant_rls_scope(session, principal.organization_id)
    return BackgroundJobService(
        session,
        organization_id=principal.organization_id,
        organization_key=principal.organization_key,
        organization_name=principal.organization_name,
        allowed_project_ids=principal.project_ids,
        allowed_system_ids=principal.system_ids,
    )


BackgroundJobServiceDependency = Annotated[
    BackgroundJobService, Depends(get_background_job_service)
]
