import asyncio
import base64
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from traceless_api.publisher.app import create_publisher_app
from traceless_api.publisher.auth import require_publisher_admin
from traceless_api.publisher.config import PublisherSettings

ADMIN_KEY = "publisher-v2-admin-" + "a" * 32
INGEST_KEY = "publisher-v2-ingest-" + "b" * 32
REVIEWER_KEY = "publisher-v2-review-" + "c" * 32
CURSOR_SECRET = "publisher-v2-cursor-" + "d" * 32
SIGNING_SEED = base64.b64encode(bytes(range(32))).decode("ascii")


@pytest.fixture
def client() -> TestClient:
    app = create_publisher_app(
        PublisherSettings(
            environment="test",
            database_url="sqlite+pysqlite:///:memory:",
            auto_create_schema=True,
            admin_api_key=ADMIN_KEY,
            ingest_api_key=INGEST_KEY,
            reviewer_api_key=REVIEWER_KEY,
            cursor_secret=CURSOR_SECRET,
            signing_private_key=SIGNING_SEED,
            signing_key_id="publisher-v2-test-key",
            allowed_hosts=["testserver"],
            credential_overlap_seconds=3_600,
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def _headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _item(
    external_id: str,
    *,
    modified_at: datetime,
    status: str = "active",
    tlp: str = "TLP:CLEAR",
    provider: str = "central-analysis",
) -> dict[str, object]:
    revoked = status != "active"
    return {
        "status": status,
        "status_changed_at": modified_at.isoformat() if revoked else None,
        "status_reason": "Source lifecycle was withdrawn." if revoked else None,
        "record": {
            "source_kind": "news",
            "provider": provider,
            "external_id": external_id,
            "record_type": "threat",
            "title": f"Publisher v2 {external_id}",
            "summary": "Reviewed normalized intelligence.",
            "modified_at": modified_at.isoformat(),
            "retrieved_at": modified_at.isoformat(),
            "markings": [tlp],
            "revoked": revoked,
            "raw_evidence": {"source_id": external_id},
        },
    }


def _import(
    client: TestClient,
    items: list[dict[str, object]],
    *,
    version: str,
    publish: bool,
) -> dict[str, object]:
    response = client.post(
        "/admin/v1/imports",
        headers=_headers(INGEST_KEY),
        json={
            "feed_id": "publisher-v2-test",
            "feed_version": version,
            "generated_at": datetime.now(UTC).isoformat(),
            "idempotency_key": f"publisher-v2-{version}",
            "publish": publish,
            "items": items,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_split_roles_delta_sync_and_entitlement_reset(client: TestClient) -> None:
    created = client.post(
        "/admin/v1/clients",
        headers=_headers(ADMIN_KEY),
        json={
            "client_id": "customer-v2",
            "name": "Customer v2",
            "max_tlp": "TLP:AMBER",
        },
    )
    assert created.status_code == 201, created.text
    customer_key = created.json()["api_key"]

    observed_at = datetime.now(UTC)
    imported = _import(
        client,
        [_item("article-1", modified_at=observed_at)],
        version="1",
        publish=False,
    )
    record_id = next(iter(imported["record_ids"].values()))

    assert client.post(
        f"/admin/v1/records/{record_id}/publish",
        headers=_headers(INGEST_KEY),
        json={"reason": "This key must not be able to review a publication."},
    ).status_code == 403
    published = client.post(
        f"/admin/v1/records/{record_id}/publish",
        headers=_headers(REVIEWER_KEY),
        json={"reason": "Source evidence and normalized content were reviewed."},
    )
    assert published.status_code == 200, published.text

    full = client.get(
        "/v2/datapoints",
        headers=_headers(customer_key),
    )
    assert full.status_code == 200, full.text
    full_payload = full.json()
    assert full_payload["schema_version"] == "2.0"
    assert full_payload["mode"] == "full"
    assert full_payload["reset_required"] is False
    assert full_payload["items"][0]["record"]["external_id"] == "article-1"
    assert full_payload["next_sync_token"]
    sync_token = full_payload["next_sync_token"]

    _import(
        client,
        [_item("article-2", modified_at=observed_at + timedelta(minutes=1))],
        version="2",
        publish=True,
    )
    delta = client.get(
        "/v2/datapoints",
        params={"sync_token": sync_token},
        headers=_headers(customer_key),
    )
    assert delta.status_code == 200, delta.text
    assert delta.json()["mode"] == "delta"
    assert [
        item["record"]["external_id"] for item in delta.json()["items"]
    ] == ["article-2"]
    delta_token = delta.json()["next_sync_token"]

    narrowed = client.patch(
        "/admin/v1/clients/customer-v2",
        headers=_headers(ADMIN_KEY),
        json={"allowed_providers": ["central-analysis"]},
    )
    assert narrowed.status_code == 200, narrowed.text
    reset = client.get(
        "/v2/datapoints",
        params={"sync_token": delta_token},
        headers=_headers(customer_key),
    )
    assert reset.status_code == 200, reset.text
    assert reset.json()["mode"] == "full"
    assert reset.json()["reset_required"] is True
    assert {
        item["record"]["external_id"] for item in reset.json()["items"]
    } == {"article-1", "article-2"}


def test_revocation_is_fail_closed_and_rotation_has_overlap(client: TestClient) -> None:
    created = client.post(
        "/admin/v1/clients",
        headers=_headers(ADMIN_KEY),
        json={
            "client_id": "revocation-v2",
            "name": "Revocation customer",
            "max_tlp": "TLP:CLEAR",
        },
    )
    old_key = created.json()["api_key"]
    observed_at = datetime.now(UTC)
    _import(
        client,
        [_item("article-revoked", modified_at=observed_at)],
        version="revocation-1",
        publish=True,
    )
    first = client.get("/v2/datapoints", headers=_headers(old_key)).json()
    sync_token = first["next_sync_token"]

    revoked = _import(
        client,
        [
            _item(
                "article-revoked",
                modified_at=observed_at + timedelta(minutes=1),
                status="revoked",
            )
        ],
        version="revocation-2",
        publish=False,
    )
    assert revoked["staged"] == 1
    delta = client.get(
        "/v2/datapoints",
        params={"sync_token": sync_token},
        headers=_headers(old_key),
    )
    assert delta.status_code == 200, delta.text
    assert delta.json()["items"][0]["status"] == "revoked"

    rotated = client.post(
        "/admin/v1/clients/revocation-v2/rotate-key",
        headers=_headers(ADMIN_KEY),
    )
    assert rotated.status_code == 200, rotated.text
    new_key = rotated.json()["api_key"]
    assert new_key != old_key
    assert client.get("/v2/datapoints", headers=_headers(old_key)).status_code == 200
    assert client.get("/v2/datapoints", headers=_headers(new_key)).status_code == 200


def test_signing_key_set_and_client_supplied_actor_are_not_trusted(
    client: TestClient,
) -> None:
    keys = client.get("/.well-known/traceless-intelligence-signing-keys")
    assert keys.status_code == 200
    assert keys.json()["active_key_id"] == "publisher-v2-test-key"
    assert keys.json()["keys"][0]["fingerprint_sha256"]

    created = client.post(
        "/admin/v1/clients",
        headers={**_headers(ADMIN_KEY), "X-Actor": "forged-human-reviewer"},
        json={"client_id": "actor-v2", "name": "Actor customer"},
    )
    assert created.status_code == 201


def test_production_oidc_only_rejects_development_fallback_key() -> None:
    settings = PublisherSettings(
        environment="production",
        surface="admin",
        database_url="postgresql+psycopg://publisher@localhost/traceless_publisher",
        auto_create_schema=False,
        cursor_secret=CURSOR_SECRET,
        signing_private_key=SIGNING_SEED,
        oidc_issuer="https://identity.example",
        oidc_audience="traceless-publisher",
        oidc_jwks_url="https://identity.example/.well-known/jwks.json",
        oidc_allowed_hosts=["identity.example"],
        oidc_role_map={"Publisher.Admin": "publisher_admin"},
    )
    assert settings.admin_key_value() is None
    assert settings.ingest_key_value() is None
    assert settings.reviewer_key_value() is None

    class State:
        publisher_settings = settings
        publisher_oidc_verifier = None

    class App:
        state = State()

    class Request:
        app = App()

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="development-publisher-admin-key-not-for-production",
    )
    with pytest.raises(HTTPException) as error:
        asyncio.run(require_publisher_admin(Request(), credentials))  # type: ignore[arg-type]
    assert error.value.status_code == 401


def test_management_routes_reject_and_revoke_credentials(client: TestClient) -> None:
    created = client.post(
        "/admin/v1/clients",
        headers=_headers(ADMIN_KEY),
        json={"client_id": "managed-v2", "name": "Managed customer"},
    )
    assert created.status_code == 201, created.text

    installations = client.get(
        "/admin/v1/installations",
        headers=_headers(ADMIN_KEY),
    )
    assert installations.status_code == 200
    assert installations.json()["items"][0]["client_id"] == "managed-v2"

    credentials = client.get(
        "/admin/v1/clients/managed-v2/credentials",
        headers=_headers(ADMIN_KEY),
    )
    assert credentials.status_code == 200
    first_credential_id = credentials.json()["items"][0]["id"]
    cannot_revoke_last = client.delete(
        f"/admin/v1/clients/managed-v2/credentials/{first_credential_id}",
        headers=_headers(ADMIN_KEY),
    )
    assert cannot_revoke_last.status_code == 409

    rotated = client.post(
        "/admin/v1/clients/managed-v2/rotate-key",
        headers=_headers(ADMIN_KEY),
    )
    assert rotated.status_code == 200
    revoked = client.delete(
        f"/admin/v1/clients/managed-v2/credentials/{first_credential_id}",
        headers=_headers(ADMIN_KEY),
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None

    observed_at = datetime.now(UTC)
    imported = _import(
        client,
        [_item("reject-me", modified_at=observed_at)],
        version="reject-1",
        publish=False,
    )
    record_id = next(iter(imported["record_ids"].values()))
    rejected = client.post(
        f"/admin/v1/records/{record_id}/reject",
        headers=_headers(REVIEWER_KEY),
        json={"reason": "The source evidence did not meet the publication threshold."},
    )
    assert rejected.status_code == 200, rejected.text
    decisions = client.get(
        f"/admin/v1/records/{record_id}/decisions",
        headers=_headers(REVIEWER_KEY),
    )
    assert decisions.status_code == 200
    assert decisions.json()["items"][0]["decision"] == "rejected"


def test_failed_import_run_is_durable() -> None:
    app = create_publisher_app(
        PublisherSettings(
            environment="test",
            database_url="sqlite+pysqlite:///:memory:",
            auto_create_schema=True,
            admin_api_key=ADMIN_KEY,
            ingest_api_key=INGEST_KEY,
            reviewer_api_key=REVIEWER_KEY,
            cursor_secret=CURSOR_SECRET,
            signing_private_key=SIGNING_SEED,
            signing_key_id="publisher-v2-failed-run-key",
            allowed_hosts=["testserver"],
            allow_automatic_publish=False,
        )
    )
    with TestClient(app) as test_client:
        response = test_client.post(
            "/admin/v1/imports",
            headers=_headers(INGEST_KEY),
            json={
                "feed_id": "publisher-failed-run",
                "feed_version": "1",
                "generated_at": datetime.now(UTC).isoformat(),
                "idempotency_key": "publisher-failed-run-1",
                "publish": True,
                "items": [_item("failed-run", modified_at=datetime.now(UTC))],
            },
        )
        assert response.status_code == 409
        runs = test_client.get(
            "/admin/v1/imports",
            headers=_headers(ADMIN_KEY),
        )
        assert runs.status_code == 200
        assert runs.json()["items"][0]["status"] == "failed"
        assert runs.json()["items"][0]["error_code"] == "PublisherConflictError"


def test_production_rejects_legacy_v1_feed() -> None:
    with pytest.raises(ValueError):
        PublisherSettings(
            environment="production",
            surface="feed",
            database_url="postgresql+psycopg://publisher@localhost/traceless_publisher",
            auto_create_schema=False,
            cursor_secret=CURSOR_SECRET,
            signing_private_key=SIGNING_SEED,
            enable_legacy_v1_feed=True,
        )


def test_stale_import_run_is_recovered_with_same_idempotency_key(
    client: TestClient,
) -> None:
    from traceless_api.publisher.db_v2 import PublisherImportRunRow
    from traceless_api.publisher.models import PublisherImportBatch
    from traceless_api.publisher.service import _hash_json

    generated_at = datetime.now(UTC)
    payload = PublisherImportBatch.model_validate(
        {
            "feed_id": "publisher-v2-test",
            "feed_version": "lease-retry",
            "generated_at": generated_at.isoformat(),
            "idempotency_key": "publisher-v2-lease-retry",
            "publish": False,
            "items": [_item("lease-retry", modified_at=generated_at)],
        }
    )
    factory = client.app.state.publisher_session_factory
    with factory() as session:
        session.add(
            PublisherImportRunRow(
                feed_id=payload.feed_id,
                feed_version=payload.feed_version,
                generated_at=payload.generated_at,
                item_count=len(payload.items),
                manifest_sha256=_hash_json(payload.model_dump(mode="json")),
                idempotency_key_sha256=__import__("hashlib").sha256(
                    payload.idempotency_key.encode("utf-8")
                ).hexdigest(),
                status="running",
                actor="crashed-importer",
                heartbeat_at=generated_at - timedelta(hours=1),
                lease_expires_at=generated_at - timedelta(minutes=30),
                attempt_count=1,
            )
        )
        session.commit()

    response = client.post(
        "/admin/v1/imports",
        headers=_headers(INGEST_KEY),
        json=payload.model_dump(mode="json"),
    )
    assert response.status_code == 200, response.text
    runs = client.get("/admin/v1/imports", headers=_headers(ADMIN_KEY))
    assert runs.status_code == 200, runs.text
    recovered = next(
        item for item in runs.json()["items"] if item["feed_version"] == "lease-retry"
    )
    assert recovered["status"] == "completed"
    assert recovered["attempt_count"] == 2
    assert recovered["lease_expires_at"] is None


def test_revision_provenance_uses_separate_hashes_and_installation_metadata(
    client: TestClient,
) -> None:
    from sqlalchemy import select

    from traceless_api.publisher.db import PublisherRevisionRow

    observed_at = datetime.now(UTC)
    _import(
        client,
        [_item("hash-provenance", modified_at=observed_at)],
        version="hash-provenance",
        publish=False,
    )
    factory = client.app.state.publisher_session_factory
    with factory() as session:
        revision = session.scalar(
            select(PublisherRevisionRow).where(
                PublisherRevisionRow.feed_version == "hash-provenance"
            )
        )
        assert revision is not None
        assert revision.source_kind == "news"
        assert revision.record_type == "threat"
        assert len(revision.source_sha256) == 64
        assert len(revision.normalized_sha256) == 64
        assert len(revision.ai_analysis_sha256) == 64
        assert len(revision.payload_sha256) == 64

    created = client.post(
        "/admin/v1/clients",
        headers=_headers(ADMIN_KEY),
        json={"client_id": "installation-metadata", "name": "Installation metadata"},
    )
    assert created.status_code == 201, created.text
    installations = client.get("/admin/v1/installations", headers=_headers(ADMIN_KEY))
    installation = next(
        item
        for item in installations.json()["items"]
        if item["client_id"] == "installation-metadata"
    )
    assert installation["installation_key"] == "primary"
    assert installation["environment"] == "production"


def test_account_supports_multiple_independent_installations(client: TestClient) -> None:
    account = client.post(
        "/admin/v2/accounts",
        headers=_headers(ADMIN_KEY),
        json={"account_key": "multi-customer", "name": "Multi Customer"},
    )
    assert account.status_code == 201, account.text

    production = client.post(
        "/admin/v2/accounts/multi-customer/installations",
        headers=_headers(ADMIN_KEY),
        json={
            "client_id": "multi-customer-prod",
            "installation_key": "production",
            "name": "Production",
            "environment": "production",
            "region": "se-central",
            "max_tlp": "TLP:AMBER",
            "allowed_providers": ["central-analysis"],
        },
    )
    assert production.status_code == 201, production.text
    test_installation = client.post(
        "/admin/v2/accounts/multi-customer/installations",
        headers=_headers(ADMIN_KEY),
        json={
            "client_id": "multi-customer-test",
            "installation_key": "test",
            "name": "Test",
            "environment": "test",
            "max_tlp": "TLP:CLEAR",
            "allowed_providers": ["central-analysis"],
        },
    )
    assert test_installation.status_code == 201, test_installation.text
    assert production.json()["api_key"] != test_installation.json()["api_key"]

    observed_at = datetime.now(UTC)
    _import(
        client,
        [_item("multi-installation-record", modified_at=observed_at)],
        version="multi-installation",
        publish=True,
    )
    for response in (production, test_installation):
        feed = client.get(
            "/v2/datapoints",
            headers=_headers(response.json()["api_key"]),
        )
        assert feed.status_code == 200, feed.text
        assert feed.json()["items"][0]["record"]["external_id"] == "multi-installation-record"


def test_v4_installation_key_rotation_does_not_require_legacy_client(
    client: TestClient,
) -> None:
    account = client.post(
        "/admin/v2/accounts",
        headers=_headers(ADMIN_KEY),
        json={"account_key": "rotation-account", "name": "Rotation account"},
    )
    assert account.status_code == 201, account.text
    created = client.post(
        "/admin/v2/accounts/rotation-account/installations",
        headers=_headers(ADMIN_KEY),
        json={
            "client_id": "rotation-installation",
            "installation_key": "production",
            "name": "Rotation production",
        },
    )
    assert created.status_code == 201, created.text
    old_key = created.json()["api_key"]

    rotated = client.post(
        "/admin/v2/installations/rotation-installation/rotate-key",
        headers=_headers(ADMIN_KEY),
    )
    assert rotated.status_code == 200, rotated.text
    new_key = rotated.json()["api_key"]
    assert new_key != old_key
    assert client.get("/v2/datapoints", headers=_headers(old_key)).status_code == 200
    assert client.get("/v2/datapoints", headers=_headers(new_key)).status_code == 200
