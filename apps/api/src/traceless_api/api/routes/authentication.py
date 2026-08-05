"""Server-derived current identity and authorization capabilities."""

from fastapi import APIRouter

from traceless_api.api.auth import OperationalPrincipal, principal_capabilities
from traceless_api.models.api import CurrentPrincipalResponse

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/me", response_model=CurrentPrincipalResponse)
def current_principal(principal: OperationalPrincipal) -> CurrentPrincipalResponse:
    return CurrentPrincipalResponse(
        subject=principal.subject,
        actor=principal.actor,
        organization_id=principal.organization_id,
        organization_name=principal.organization_name,
        roles=sorted(principal.roles),  # type: ignore[arg-type]
        capabilities=principal_capabilities(principal),  # type: ignore[arg-type]
        authentication_method=principal.authentication_method,
        project_ids=(
            sorted(principal.project_ids, key=str)
            if principal.project_ids is not None
            else None
        ),
        system_ids=(
            sorted(principal.system_ids, key=str)
            if principal.system_ids is not None
            else None
        ),
    )
