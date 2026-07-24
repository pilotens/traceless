from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from traceless_api.api.auth import AuthenticatedPrincipal, require_operational_principal
from traceless_api.core.config import Settings
from traceless_api.main import create_app


def _principal(organization_id: UUID, roles: set[str]) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject=f"user-{organization_id}",
        actor=f"oidc:user-{organization_id}",
        organization_id=organization_id,
        organization_key=str(organization_id),
        organization_name=f"Organization {organization_id}",
        roles=frozenset(roles),
        authentication_method="oidc",
    )


@pytest.fixture
def tenant_job_client() -> Iterator[
    tuple[TestClient, dict[str, AuthenticatedPrincipal]]
]:
    organization_id = uuid4()
    current = {
        "principal": _principal(
            organization_id, {"admin", "analyst", "viewer", "scanner"}
        )
    }
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
        )
    )
    app.dependency_overrides[require_operational_principal] = lambda: current["principal"]
    with TestClient(app) as client:
        yield client, current


def _create_job(client: TestClient) -> tuple[str, str]:
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Tenant jobs", "description": "Isolation"},
    ).json()
    system = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Tenant system",
            "description": "Tenant-bound job",
            "owner": "Security",
            "criticality": "high",
        },
    ).json()
    job = client.post(
        f"/api/v1/operational/systems/{system['id']}/vulnerability-scans/import/async",
        json={
            "provider": "generic",
            "source_name": "tenant-source.json",
            "observations": [
                {
                    "provider_finding_id": "tenant-1",
                    "asset_identifier": "host.internal",
                    "hostname": "host.internal",
                    "title": "Tenant observation",
                    "severity": "medium",
                }
            ],
        },
    )
    assert job.status_code == 202, job.text
    return str(system["id"]), str(job.json()["job"]["id"])


def test_background_jobs_fail_closed_across_tenants(
    tenant_job_client: tuple[TestClient, dict[str, AuthenticatedPrincipal]],
) -> None:
    client, current = tenant_job_client
    system_id, job_id = _create_job(client)

    current["principal"] = _principal(
        uuid4(), {"admin", "analyst", "viewer", "scanner"}
    )
    assert client.get("/api/v1/operational/jobs").json()["items"] == []
    assert client.get(f"/api/v1/operational/jobs/{job_id}").status_code == 404
    assert client.post(f"/api/v1/operational/jobs/{job_id}/cancel").status_code == 404
    hidden_system = client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
        json={
            "provider": "generic",
            "source_name": "foreign.json",
            "observations": [
                {
                    "provider_finding_id": "foreign-1",
                    "asset_identifier": "foreign.internal",
                    "title": "Foreign tenant observation",
                    "severity": "low",
                }
            ],
        },
    )
    assert hidden_system.status_code == 404


def test_job_rbac_allows_viewers_to_read_but_denies_job_control(
    tenant_job_client: tuple[TestClient, dict[str, AuthenticatedPrincipal]],
) -> None:
    client, current = tenant_job_client
    organization_id = current["principal"].organization_id
    system_id, job_id = _create_job(client)

    current["principal"] = _principal(organization_id, {"viewer"})
    assert client.get("/api/v1/operational/jobs").status_code == 200
    assert client.get(f"/api/v1/operational/jobs/{job_id}").status_code == 200
    assert client.post(f"/api/v1/operational/jobs/{job_id}/cancel").status_code == 403
    assert (
        client.post(
            f"/api/v1/operational/systems/{system_id}/reports/async",
            json={"format": "json", "report_type": "technical"},
            headers={"Idempotency-Key": "viewer-cannot-enqueue"},
        ).status_code
        == 403
    )

    current["principal"] = _principal(organization_id, {"scanner"})
    assert client.get("/api/v1/operational/jobs").status_code == 403
    assert (
        client.post(
            f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import/async",
            json={
                "provider": "generic",
                "source_name": "scanner-role.json",
                "observations": [
                    {
                        "provider_finding_id": "scanner-role-1",
                        "asset_identifier": "host.internal",
                        "title": "Denied scanner role import",
                        "severity": "low",
                    }
                ],
            },
        ).status_code
        == 403
    )
