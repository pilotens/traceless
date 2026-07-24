import json
from collections.abc import Iterator, Mapping
from secrets import token_urlsafe
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from traceless_api.api.auth import AuthenticatedPrincipal, require_operational_principal
from traceless_api.core.config import Settings
from traceless_api.core.tenancy import DEFAULT_ORGANIZATION_ID
from traceless_api.main import create_app
from traceless_api.services.private_integration_scope import (
    PrivateIntegrationUnavailableError,
    require_private_integration_scope,
)


def _principal(organization_id: UUID) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject=f"analyst-{organization_id}",
        actor=f"oidc:analyst-{organization_id}",
        organization_id=organization_id,
        organization_key=str(organization_id),
        organization_name=f"Organization {organization_id}",
        roles=frozenset({"admin", "analyst", "viewer"}),
        authentication_method="oidc",
    )


def _create_system(client: TestClient, suffix: str) -> str:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": f"Project {suffix}", "description": f"Tenant {suffix}"},
    )
    assert project.status_code == 201, project.text
    system = client.post(
        f"/api/v1/operational/projects/{project.json()['id']}/systems",
        json={
            "name": f"System {suffix}",
            "description": f"Private inventory {suffix}",
            "owner": f"Owner {suffix}",
            "criticality": "high",
        },
    )
    assert system.status_code == 201, system.text
    return str(system.json()["id"])


class _ForbiddenNetworkFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        raise AssertionError("a tenant-scope rejection must happen before HTTP client creation")


class _JsonResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.content = json.dumps(payload).encode()
        self.headers = {"Content-Type": "application/json"}
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None


class _JsonClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.response = _JsonResponse(payload)

    async def __aenter__(self) -> "_JsonClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(
        self,
        _: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> _JsonResponse:
        assert headers is not None
        assert timeout is not None
        assert follow_redirects is False
        return self.response


class _RecordingNetworkFactory:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.calls = 0

    def __call__(self) -> _JsonClient:
        self.calls += 1
        return _JsonClient(self.payload)


@pytest.fixture
def private_source_client() -> Iterator[
    tuple[TestClient, dict[str, AuthenticatedPrincipal], UUID, UUID]
]:
    organization_a = uuid4()
    organization_b = uuid4()
    current = {"principal": _principal(organization_a)}
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            netbox_base_url="https://netbox.example.test/",
            netbox_token=SecretStr(token_urlsafe(32)),
            netbox_organization_id=organization_a,
            netbox_allowed_hosts=["netbox.example.test"],
            intelligence_allowed_hosts=[
                "www.cisa.gov",
                "api.first.org",
                "services.nvd.nist.gov",
            ],
        )
    )
    app.dependency_overrides[require_operational_principal] = lambda: current["principal"]
    with TestClient(app) as client:
        yield client, current, organization_a, organization_b


def test_process_private_source_rejects_another_tenant_before_network_without_metadata_leak(
    private_source_client: tuple[TestClient, dict[str, AuthenticatedPrincipal], UUID, UUID],
) -> None:
    client, current, _, organization_b = private_source_client
    system_a = _create_system(client, "A")
    current["principal"] = _principal(organization_b)
    system_b = _create_system(client, "B")
    unknown_system = str(uuid4())
    forbidden_network = _ForbiddenNetworkFactory()
    client.app.state.http_client_factory = forbidden_network

    responses = []
    for system_id in (system_a, system_b, unknown_system):
        responses.append(
            client.post(f"/api/v1/operational/systems/{system_id}/asset-sources/netbox/sync")
        )

    expected = {"detail": "Private integration is not available for this organization"}
    assert all(response.status_code == 404 for response in responses)
    assert all(response.json() == expected for response in responses)
    assert forbidden_network.calls == 0
    combined_responses = " ".join(response.text for response in responses)
    assert system_a not in combined_responses
    assert "netbox.example.test" not in combined_responses
    assert (
        client.get(f"/api/v1/operational/systems/{system_b}/asset-sources/snapshots").json() == []
    )


def test_legacy_internal_intelligence_sync_route_is_not_registered(
    private_source_client: tuple[TestClient, dict[str, AuthenticatedPrincipal], UUID, UUID],
) -> None:
    client, _, _, _ = private_source_client
    system_id = _create_system(client, "No legacy CTI route")
    forbidden_network = _ForbiddenNetworkFactory()
    client.app.state.http_client_factory = forbidden_network

    response = client.post(
        f"/api/v1/operational/systems/{system_id}/intelligence/sync/internal"
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
    assert forbidden_network.calls == 0
    assert (
        "/api/v1/operational/systems/{system_id}/intelligence/sync/internal"
        not in client.get("/openapi.json").json()["paths"]
    )


def test_public_kev_sync_is_not_restricted_by_private_source_binding(
    private_source_client: tuple[TestClient, dict[str, AuthenticatedPrincipal], UUID, UUID],
) -> None:
    client, current, _, organization_b = private_source_client
    current["principal"] = _principal(organization_b)
    system_b = _create_system(client, "Public")
    public_network = _RecordingNetworkFactory(
        {
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2026.07.21",
            "dateReleased": "2026-07-21T09:00:00Z",
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2099-90001",
                    "vendorProject": "Example",
                    "product": "Public catalogue fixture",
                    "vulnerabilityName": "Public KEV route fixture",
                    "dateAdded": "2026-07-20",
                    "shortDescription": "A bounded non-empty catalogue fixture.",
                    "requiredAction": "Apply vendor guidance.",
                    "dueDate": "2026-08-10",
                    "knownRansomwareCampaignUse": "Unknown",
                    "notes": "",
                    "cwes": [],
                }
            ],
        }
    )
    client.app.state.http_client_factory = public_network

    response = client.post(f"/api/v1/operational/systems/{system_b}/intelligence/sync/kev")

    assert response.status_code == 200, response.text
    assert response.json()["provider"] == "cisa-kev"
    assert public_network.calls == 1


def test_development_fallback_is_limited_to_the_fixed_default_organization() -> None:
    settings = Settings(environment="test")
    require_private_integration_scope(
        settings=settings,
        configured_organization_id=None,
        request_organization_id=DEFAULT_ORGANIZATION_ID,
    )

    with pytest.raises(PrivateIntegrationUnavailableError):
        require_private_integration_scope(
            settings=settings,
            configured_organization_id=None,
            request_organization_id=uuid4(),
        )


@pytest.mark.parametrize(
    ("private_source", "message"),
    [
        (
            {
                "netbox_base_url": "https://netbox.example.test/",
                "netbox_allowed_hosts": ["netbox.example.test"],
            },
            "netbox_organization_id",
        ),
        (
            {
                "internal_threat_feed_url": "https://cti.example.test/feed",
                "intelligence_allowed_hosts": [
                    "www.cisa.gov",
                    "api.first.org",
                    "services.nvd.nist.gov",
                    "cti.example.test",
                ],
            },
            "internal_threat_feed_organization_id",
        ),
    ],
)
def test_production_private_sources_require_an_explicit_organization_binding(
    private_source: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(
            environment="production",
            database_url="postgresql+psycopg://traceless@db/traceless",
            auto_create_schema=False,
            operational_api_key=SecretStr(token_urlsafe(32)),
            **private_source,
        )
