from collections.abc import Iterator
from secrets import token_urlsafe
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import select

from traceless_api.core.config import Settings
from traceless_api.core.oidc import VerifiedAccessToken
from traceless_api.db.models import AuditEventRow
from traceless_api.main import create_app

API_KEY = token_urlsafe(32)


@pytest.fixture
def protected_client() -> Iterator[TestClient]:
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            cors_origins=["http://localhost:3000"],
            database_url="sqlite+pysqlite:///:memory:",
            auto_create_schema=True,
            operational_api_key=SecretStr(API_KEY),
            operational_actor_name="ci-service-principal",
        )
    )
    with TestClient(app) as client:
        yield client


def test_operational_routes_require_the_configured_bearer_key(
    protected_client: TestClient,
) -> None:
    missing = protected_client.get("/api/v1/operational/projects")
    wrong = protected_client.get(
        "/api/v1/operational/projects",
        headers={"Authorization": f"Bearer {token_urlsafe(32)}"},
    )
    accepted = protected_client.get(
        "/api/v1/operational/projects",
        headers={"Authorization": f"Bearer {API_KEY}"},
    )

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert wrong.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json() == []


def test_authenticated_audit_actor_is_server_derived(protected_client: TestClient) -> None:
    response = protected_client.post(
        "/api/v1/operational/projects",
        json={"name": "Protected project", "description": "Authentication test"},
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "X-Actor": "spoofed-browser-value",
        },
    )
    assert response.status_code == 201, response.text

    with protected_client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEventRow).where(AuditEventRow.action == "project.created")
        )
        assert event is not None
        assert event.actor == "api-key:ci-service-principal"


def test_resource_scoped_admin_cannot_mutate_organization_wide_configuration() -> None:
    scoped_key = token_urlsafe(32)
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            operational_api_key=SecretStr(scoped_key),
            operational_roles=["admin"],
            operational_project_ids=[uuid4()],
        )
    )
    headers = {"Authorization": f"Bearer {scoped_key}"}
    with TestClient(app) as client:
        project = client.post(
            "/api/v1/operational/projects",
            json={"name": "Out of scope", "description": "Must be rejected"},
            headers=headers,
        )
        connector = client.put(
            "/api/v1/operational/intelligence/connectors/external",
            json={
                "endpoint": "https://intel.example/api/datapoints",
                "credential_reference": "tenant-feed",
            },
            headers=headers,
        )

    assert project.status_code == 403
    assert connector.status_code == 403
    assert "unrestricted resource scope" in project.json()["detail"]


def test_production_refuses_to_start_without_operational_authentication() -> None:
    with pytest.raises(ValidationError, match="configured OIDC or an operational service API key"):
        Settings(
            environment="production",
            database_url="postgresql+psycopg://traceless@db/traceless",
            auto_create_schema=False,
        )


def test_oidc_claims_derive_tenant_role_and_audit_identity() -> None:
    organization_id = "00000000-0000-4000-8000-000000000001"
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            oidc_issuer="https://identity.example/tenant/v2.0",
            oidc_audience="api://traceless",
            oidc_jwks_url="https://identity.example/tenant/keys",
            oidc_allowed_hosts=["identity.example"],
        )
    )

    class StubVerifier:
        async def verify(self, _: str) -> VerifiedAccessToken:
            return VerifiedAccessToken(
                claims={
                    "iss": "https://identity.example/tenant/v2.0",
                    "sub": "subject-1",
                    "oid": "object-1",
                    "tid": organization_id,
                    "tenant_name": "Example tenant",
                    "roles": ["Traceless.Admin"],
                    "traceless_project_ids": "*",
                }
            )

    app.state.oidc_verifier = StubVerifier()
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/operational/projects",
            json={"name": "OIDC project", "description": "Scoped project"},
            headers={"Authorization": f"Bearer {token_urlsafe(32)}"},
        )
        assert response.status_code == 201, response.text
        with client.app.state.session_factory() as session:
            event = session.scalar(
                select(AuditEventRow).where(AuditEventRow.action == "project.created")
            )
            assert event is not None
            assert event.actor == "oidc:object-1"
            assert str(event.organization_id) == organization_id


def test_oidc_without_an_application_role_is_forbidden() -> None:
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            oidc_issuer="https://identity.example/tenant/v2.0",
            oidc_audience="api://traceless",
            oidc_jwks_url="https://identity.example/tenant/keys",
            oidc_allowed_hosts=["identity.example"],
        )
    )

    class StubVerifier:
        async def verify(self, _: str) -> VerifiedAccessToken:
            return VerifiedAccessToken(
                claims={
                    "sub": "subject-1",
                    "tid": "00000000-0000-4000-8000-000000000001",
                    "roles": ["Unrelated.Role"],
                }
            )

    app.state.oidc_verifier = StubVerifier()
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/operational/projects",
            headers={"Authorization": f"Bearer {token_urlsafe(32)}"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "No Traceless application role is assigned"


def test_oidc_non_admin_receives_explicit_project_and_system_scope() -> None:
    project_id = uuid4()
    system_id = uuid4()
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            oidc_issuer="https://identity.example/tenant/v2.0",
            oidc_audience="api://traceless",
            oidc_jwks_url="https://identity.example/tenant/keys",
            oidc_allowed_hosts=["identity.example"],
        )
    )

    class StubVerifier:
        async def verify(self, _: str) -> VerifiedAccessToken:
            return VerifiedAccessToken(
                claims={
                    "sub": "scoped-analyst",
                    "tid": str(uuid4()),
                    "roles": ["Traceless.Analyst"],
                    "traceless_project_ids": [str(project_id)],
                    "traceless_system_ids": str(system_id),
                }
            )

    app.state.oidc_verifier = StubVerifier()
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token_urlsafe(32)}"},
        )

    assert response.status_code == 200, response.text
    assert response.json()["project_ids"] == [str(project_id)]
    assert response.json()["system_ids"] == [str(system_id)]


def test_oidc_invalid_resource_assignment_fails_closed() -> None:
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            oidc_issuer="https://identity.example/tenant/v2.0",
            oidc_audience="api://traceless",
            oidc_jwks_url="https://identity.example/tenant/keys",
            oidc_allowed_hosts=["identity.example"],
        )
    )

    class StubVerifier:
        async def verify(self, _: str) -> VerifiedAccessToken:
            return VerifiedAccessToken(
                claims={
                    "sub": "scoped-viewer",
                    "tid": str(uuid4()),
                    "roles": ["Traceless.Viewer"],
                    "traceless_project_ids": ["not-a-uuid"],
                }
            )

    app.state.oidc_verifier = StubVerifier()
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token_urlsafe(32)}"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "The access token contains an invalid resource assignment"
    )


def test_global_request_body_limit_rejects_json_before_validation() -> None:
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            max_request_body_bytes=1_024,
        )
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/operational/projects",
            json={"name": "Bounded body", "description": "x" * 2_000},
        )

    assert response.status_code == 413
    assert response.json()["detail"] == "Request body exceeds the configured limit"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_intelligence_endpoints_require_https_and_an_explicit_host_allowlist() -> None:
    with pytest.raises(ValidationError, match="HTTPS"):
        Settings(cisa_kev_url="http://www.cisa.gov/kev.json")
    with pytest.raises(ValidationError, match="allowlisted"):
        Settings(
            internal_threat_feed_url="https://cti.example.test/feed",
        )

    settings = Settings(
        internal_threat_feed_url="https://cti.example.test/feed",
        intelligence_allowed_hosts=[
            "www.cisa.gov",
            "api.first.org",
            "services.nvd.nist.gov",
            "cti.example.test",
        ],
    )
    assert settings.internal_threat_feed_url == "https://cti.example.test/feed"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"api_v1_prefix": "api/v1"}, "must start"),
        ({"cors_origins": ["*"]}, "Wildcard CORS"),
        ({"netbox_token": SecretStr("x" * 5)}, "netbox_base_url"),
        ({"netbox_base_url": "https://netbox.example.test/"}, "netbox_allowed_hosts"),
        ({"intelligence_allowed_hosts": []}, "explicit hostnames"),
        ({"operational_api_key": SecretStr("x" * 5)}, "between 32 and 512"),
        ({"operational_api_key": SecretStr("x" * 32 + "\n")}, "control characters"),
        (
            {
                "external_intelligence_max_page_bytes": 2_000_000,
                "external_intelligence_max_snapshot_bytes": 1_048_576,
            },
            "must not exceed the snapshot byte quota",
        ),
    ],
)
def test_invalid_security_configuration_fails_closed(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(**overrides)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"debug": True}, "Debug mode"),
        ({"allowed_hosts": ["*"]}, "Wildcard hosts"),
        ({"database_url": "sqlite+pysqlite:///production.db"}, "PostgreSQL"),
        (
            {
                "database_url": "postgresql+psycopg://traceless@db/traceless",
                "auto_create_schema": True,
            },
            "Alembic",
        ),
        (
            {
                "database_url": "postgresql+psycopg://traceless@db/traceless",
                "auto_create_schema": False,
                "netbox_allow_insecure_http": True,
            },
            "must use HTTPS",
        ),
        (
            {
                "database_url": "postgresql+psycopg://traceless@db/traceless",
                "auto_create_schema": False,
                "operational_api_key": SecretStr(API_KEY),
                "nmap_enabled": True,
                "nmap_binary": "nmap",
            },
            "absolute Nmap",
        ),
    ],
)
def test_production_security_configuration_fails_closed(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(environment="production", **overrides)
