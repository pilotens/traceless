"""Public API metadata responses."""

from typing import Literal
from uuid import UUID

from traceless_api.models.common import StrictModel


class ApiRootResponse(StrictModel):
    name: str = "Traceless API"
    version: str
    api_version: Literal["v1"] = "v1"
    data_mode: Literal["persistent_operational"] = "persistent_operational"
    authentication: Literal["oidc_or_scoped_service_key"] = "oidc_or_scoped_service_key"
    rbac_implemented: Literal[True] = True
    tenant_isolation_implemented: Literal[True] = True
    external_collection: Literal["normalized_pull_connector"] = "normalized_pull_connector"


class CurrentPrincipalResponse(StrictModel):
    subject: str
    actor: str
    organization_id: UUID
    organization_name: str
    roles: list[Literal["admin", "analyst", "viewer", "scanner"]]
    capabilities: list[
        Literal[
            "read_operational",
            "analyze",
            "manage_scans",
            "ingest_intelligence",
            "administer",
        ]
    ]
    authentication_method: Literal["local", "api_key", "oidc", "worker"]
    project_ids: list[UUID] | None
    system_ids: list[UUID] | None
