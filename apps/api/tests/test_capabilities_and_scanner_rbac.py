from collections.abc import Iterator
from datetime import UTC, datetime
from secrets import token_urlsafe

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from traceless_api.core.config import Settings
from traceless_api.core.oidc import VerifiedAccessToken
from traceless_api.main import create_app


@pytest.fixture
def scanner_client() -> Iterator[TestClient]:
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            operational_api_key=SecretStr("s" * 32),
            operational_roles=["scanner"],
        )
    )
    with TestClient(app) as client:
        yield client


def _scanner_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {'s' * 32}"}


def test_scanner_principal_has_only_scan_capability_and_no_broad_read(
    scanner_client: TestClient,
) -> None:
    identity = scanner_client.get("/api/v1/auth/me", headers=_scanner_headers())

    assert identity.status_code == 200, identity.text
    assert identity.json()["roles"] == ["scanner"]
    assert identity.json()["capabilities"] == ["manage_scans"]
    assert (
        scanner_client.get(
            "/api/v1/operational/projects", headers=_scanner_headers()
        ).status_code
        == 403
    )
    assert (
        scanner_client.get(
            "/api/v1/operational/intelligence/records", headers=_scanner_headers()
        ).status_code
        == 403
    )


def test_scanner_cannot_import_or_pull_intelligence(scanner_client: TestClient) -> None:
    now = datetime.now(UTC).isoformat()
    imported = scanner_client.post(
        "/api/v1/operational/intelligence/records/import",
        headers=_scanner_headers(),
        json={
            "feed_id": "scanner-must-not-import",
            "feed_version": "1",
            "generated_at": now,
            "items": [
                {
                    "source_kind": "news",
                    "provider": "external",
                    "external_id": "article-1",
                    "record_type": "report",
                    "title": "Untrusted scanner-supplied CTI",
                    "summary": "Scanner identities do not own the intelligence plane.",
                    "modified_at": now,
                    "retrieved_at": now,
                    "raw_evidence": {"source": "scanner"},
                }
            ],
        },
    )
    pulled = scanner_client.post(
        "/api/v1/operational/intelligence/sync/external",
        headers=_scanner_headers(),
        json={},
    )

    assert imported.status_code == 403
    assert pulled.status_code == 403


def test_oidc_internal_role_name_is_rejected_without_explicit_mapping() -> None:
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
                    "tid": "3d1f3772-d637-4cc6-ad43-3ae158c52c29",
                    "roles": ["admin"],
                }
            )

    app.state.oidc_verifier = StubVerifier()
    with TestClient(app) as client:
        denied = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token_urlsafe(32)}"},
        )

    assert denied.status_code == 403
    assert denied.json()["detail"] == "No Traceless application role is assigned"


def test_oidc_role_mapping_is_explicit_and_server_derived() -> None:
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url="sqlite+pysqlite:///:memory:",
            oidc_issuer="https://identity.example/tenant/v2.0",
            oidc_audience="api://traceless",
            oidc_jwks_url="https://identity.example/tenant/keys",
            oidc_allowed_hosts=["identity.example"],
            oidc_role_map={"Identity.SecurityReaders": "viewer"},
        )
    )

    class StubVerifier:
        async def verify(self, _: str) -> VerifiedAccessToken:
            return VerifiedAccessToken(
                claims={
                    "sub": "subject-2",
                    "tid": "3d1f3772-d637-4cc6-ad43-3ae158c52c29",
                    "tenant_name": "Tenant",
                    "roles": ["Identity.SecurityReaders"],
                }
            )

    app.state.oidc_verifier = StubVerifier()
    with TestClient(app) as client:
        identity = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token_urlsafe(32)}"},
        )

    assert identity.status_code == 200, identity.text
    assert identity.json()["roles"] == ["viewer"]
    assert identity.json()["capabilities"] == ["read_operational"]
