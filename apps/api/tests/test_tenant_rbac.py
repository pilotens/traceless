from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from traceless_api.api.auth import AuthenticatedPrincipal, require_operational_principal
from traceless_api.core.config import Settings
from traceless_api.db.models import AuditEventRow
from traceless_api.main import create_app
from traceless_api.services.intelligence_hub import IntelligenceHubService


@pytest.fixture
def tenant_client() -> Iterator[tuple[TestClient, dict[str, AuthenticatedPrincipal]]]:
    organization_a = uuid4()
    current = {
        "principal": AuthenticatedPrincipal(
            subject="admin-a",
            actor="oidc:admin-a",
            organization_id=organization_a,
            organization_key=str(organization_a),
            organization_name="Organization A",
            roles=frozenset({"admin", "analyst", "viewer", "scanner"}),
            authentication_method="oidc",
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


def _principal(
    organization_id: UUID,
    *,
    roles: set[str],
    project_ids: frozenset[UUID] | None = None,
    system_ids: frozenset[UUID] | None = None,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject=f"user-{organization_id}",
        actor=f"oidc:user-{organization_id}",
        organization_id=organization_id,
        organization_key=str(organization_id),
        organization_name=f"Organization {organization_id}",
        roles=frozenset(roles),
        authentication_method="oidc",
        project_ids=project_ids,
        system_ids=system_ids,
    )


def _intel_feed() -> dict[str, object]:
    now = datetime.now(UTC).isoformat()
    return {
        "schema_version": "1.0",
        "feed_id": "separate-scraper",
        "feed_version": "1",
        "generated_at": now,
        "items": [
            {
                "source_kind": "news",
                "provider": "separate-scraper",
                "external_id": "article-42",
                "record_type": "report",
                "title": "Threat report article",
                "summary": "Source-grounded normalized datapoint.",
                "modified_at": now,
                "retrieved_at": now,
                "raw_evidence": {"source_id": "article-42"},
            }
        ],
    }


def test_projects_systems_and_global_intelligence_are_tenant_isolated(
    tenant_client: tuple[TestClient, dict[str, AuthenticatedPrincipal]],
) -> None:
    client, current = tenant_client
    project_a = client.post(
        "/api/v1/operational/projects",
        json={"name": "Project A", "description": "Tenant A"},
    )
    assert project_a.status_code == 201, project_a.text
    system_a = client.post(
        f"/api/v1/operational/projects/{project_a.json()['id']}/systems",
        json={
            "name": "System A",
            "description": "Tenant A system",
            "owner": "Owner A",
            "criticality": "high",
        },
    )
    assert system_a.status_code == 201, system_a.text
    imported_a = client.post(
        "/api/v1/operational/intelligence/records/import", json=_intel_feed()
    )
    assert imported_a.status_code == 200, imported_a.text

    organization_b = uuid4()
    current["principal"] = _principal(
        organization_b, roles={"admin", "analyst", "viewer", "scanner"}
    )
    assert client.get("/api/v1/operational/projects").json() == []
    hidden = client.get(
        f"/api/v1/operational/systems/{system_a.json()['id']}/overview"
    )
    assert hidden.status_code == 404
    assert client.get("/api/v1/operational/intelligence/records").json()["items"] == []

    # The same upstream identity can exist in another tenant without collision.
    imported_b = client.post(
        "/api/v1/operational/intelligence/records/import", json=_intel_feed()
    )
    assert imported_b.status_code == 200, imported_b.text
    assert imported_b.json()["created"] == 1
    assert client.get("/api/v1/operational/intelligence/records").json()["total"] == 1

    with client.app.state.session_factory() as session:
        audit_orgs = set(
            session.scalars(
                select(AuditEventRow.organization_id).where(
                    AuditEventRow.action == "intelligence.global_feed_imported"
                )
            )
        )
    assert len(audit_orgs) == 2


def test_rbac_denies_writes_but_keeps_read_access(
    tenant_client: tuple[TestClient, dict[str, AuthenticatedPrincipal]],
) -> None:
    client, current = tenant_client
    current["principal"] = _principal(uuid4(), roles={"viewer"})

    assert client.get("/api/v1/operational/projects").status_code == 200
    denied = client.post(
        "/api/v1/operational/projects",
        json={"name": "Forbidden", "description": "Viewer cannot create"},
    )
    assert denied.status_code == 403
    assert "not allowed" in denied.json()["detail"]


def test_scanner_role_cannot_browse_or_import_analysis_data(
    tenant_client: tuple[TestClient, dict[str, AuthenticatedPrincipal]],
) -> None:
    client, current = tenant_client
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Scanner boundary", "description": "Role isolation"},
    )
    system = client.post(
        f"/api/v1/operational/projects/{project.json()['id']}/systems",
        json={
            "name": "Protected analysis",
            "description": "Scanner must not browse this data",
            "owner": "Security",
            "criticality": "high",
        },
    )
    system_id = system.json()["id"]
    current["principal"] = _principal(
        UUID(current["principal"].organization_key), roles={"scanner"}
    )

    assert client.get("/api/v1/operational/projects").status_code == 403
    assert (
        client.get(f"/api/v1/operational/systems/{system_id}/findings").status_code
        == 403
    )
    assert (
        client.get(f"/api/v1/operational/systems/{system_id}/risks").status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/operational/intelligence/records/import", json=_intel_feed()
        ).status_code
        == 403
    )


def test_project_and_system_assignments_are_enforced_as_object_boundaries(
    tenant_client: tuple[TestClient, dict[str, AuthenticatedPrincipal]],
) -> None:
    client, current = tenant_client
    organization_id = current["principal"].organization_id

    def create_project_with_system(name: str) -> tuple[UUID, UUID]:
        project = client.post(
            "/api/v1/operational/projects",
            json={"name": name, "description": f"Scoped {name}"},
        )
        assert project.status_code == 201, project.text
        system = client.post(
            f"/api/v1/operational/projects/{project.json()['id']}/systems",
            json={
                "name": f"{name} system",
                "description": "Object authorization test",
                "owner": "Security",
                "criticality": "high",
            },
        )
        assert system.status_code == 201, system.text
        return UUID(project.json()["id"]), UUID(system.json()["id"])

    project_a, system_a = create_project_with_system("Project A")
    project_b, system_b = create_project_with_system("Project B")

    current["principal"] = _principal(
        organization_id,
        roles={"viewer"},
        project_ids=frozenset({project_a}),
        system_ids=frozenset(),
    )
    assert [item["id"] for item in client.get("/api/v1/operational/projects").json()] == [
        str(project_a)
    ]
    assert client.get(
        f"/api/v1/operational/projects/{project_b}/systems"
    ).status_code == 404
    assert client.get(
        f"/api/v1/operational/systems/{system_a}/overview"
    ).status_code == 200
    assert client.get(
        f"/api/v1/operational/systems/{system_b}/overview"
    ).status_code == 404

    current["principal"] = _principal(
        organization_id,
        roles={"viewer"},
        project_ids=frozenset(),
        system_ids=frozenset({system_b}),
    )
    assert [item["id"] for item in client.get("/api/v1/operational/projects").json()] == [
        str(project_b)
    ]
    visible_systems = client.get(
        f"/api/v1/operational/projects/{project_b}/systems"
    )
    assert visible_systems.status_code == 200
    assert [item["id"] for item in visible_systems.json()] == [str(system_b)]
    assert client.get(
        f"/api/v1/operational/systems/{system_a}/overview"
    ).status_code == 404

    current["principal"] = _principal(
        organization_id,
        roles={"analyst"},
        project_ids=frozenset(),
        system_ids=frozenset({system_b}),
    )
    sibling = client.post(
        f"/api/v1/operational/projects/{project_b}/systems",
        json={
            "name": "Unauthorized sibling",
            "description": "System-only access cannot expand its own scope",
            "owner": "Security",
            "criticality": "medium",
        },
    )
    assert sibling.status_code == 404


def test_unauthorized_system_read_cannot_trigger_temporal_reconciliation(
    tenant_client: tuple[TestClient, dict[str, AuthenticatedPrincipal]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, current = tenant_client
    organization_id = current["principal"].organization_id
    project = client.post(
        "/api/v1/operational/projects",
        json={"name": "Scoped reconciliation", "description": "Authorization ordering"},
    ).json()
    allowed = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Allowed",
            "description": "Visible system",
            "owner": "Security",
            "criticality": "medium",
        },
    ).json()
    hidden = client.post(
        f"/api/v1/operational/projects/{project['id']}/systems",
        json={
            "name": "Hidden",
            "description": "Out-of-scope system",
            "owner": "Security",
            "criticality": "medium",
        },
    ).json()
    current["principal"] = _principal(
        organization_id,
        roles={"viewer"},
        project_ids=frozenset(),
        system_ids=frozenset({UUID(allowed["id"])}),
    )
    reconciled: list[set[UUID] | None] = []

    def record_reconciliation(
        _service: IntelligenceHubService,
        *,
        now: datetime | None = None,
        system_ids: set[UUID] | None = None,
    ) -> int:
        del now
        reconciled.append(system_ids)
        return 0

    monkeypatch.setattr(
        IntelligenceHubService,
        "retire_nonprocessable_effects",
        record_reconciliation,
    )

    denied = client.get(
        f"/api/v1/operational/systems/{hidden['id']}/overview"
    )
    assert denied.status_code == 404
    assert reconciled == []
    permitted = client.get(
        f"/api/v1/operational/systems/{allowed['id']}/overview"
    )
    assert permitted.status_code == 200
    assert reconciled == [{UUID(allowed["id"])}]
