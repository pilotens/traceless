import base64
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError

from traceless_api.publisher.app import create_publisher_app
from traceless_api.publisher.config import PublisherSettings

ADMIN_KEY = "publisher-v2-postgres-admin-" + "a" * 32
INGEST_KEY = "publisher-v2-postgres-ingest-" + "b" * 32
REVIEWER_KEY = "publisher-v2-postgres-review-" + "c" * 32
CURSOR_SECRET = "publisher-v2-postgres-cursor-" + "d" * 32
# This test shares the PostgreSQL database with the v1 publisher smoke test.
# Use distinct key material because one fingerprint must never be registered
# under two different key IDs.
SIGNING_SEED = base64.b64encode(bytes(reversed(range(32)))).decode("ascii")


def _role_url(database_url: str, username: str) -> str:
    return str(make_url(database_url).set(username=username, password=None))


def _settings(database_url: str, surface: str, **keys: str) -> PublisherSettings:
    return PublisherSettings(
        environment="test",
        surface=surface,
        database_url=database_url,
        auto_create_schema=False,
        cursor_secret=CURSOR_SECRET,
        signing_private_key=SIGNING_SEED,
        signing_key_id="publisher-v2-postgres-key",
        allowed_hosts=["testserver"],
        enable_legacy_v1_feed=False,
        **keys,
    )


def test_publisher_v2_postgres_roles_and_delta_delivery() -> None:
    owner_url = os.getenv("TRACELESS_TEST_PUBLISHER_POSTGRES_URL")
    if not owner_url:
        pytest.skip("TRACELESS_TEST_PUBLISHER_POSTGRES_URL is not configured")

    admin_app = create_publisher_app(
        _settings(
            _role_url(owner_url, "publisher_admin_api"),
            "admin",
            admin_api_key=ADMIN_KEY,
        )
    )
    ingest_app = create_publisher_app(
        _settings(
            _role_url(owner_url, "publisher_ingest_api"),
            "ingest",
            ingest_api_key=INGEST_KEY,
        )
    )
    review_app = create_publisher_app(
        _settings(
            _role_url(owner_url, "publisher_review_api"),
            "review",
            reviewer_api_key=REVIEWER_KEY,
        )
    )
    feed_url = _role_url(owner_url, "publisher_feed_api")
    feed_app = create_publisher_app(_settings(feed_url, "feed"))

    suffix = uuid4().hex[:12]
    observed_at = datetime.now(UTC).isoformat()
    with (
        TestClient(admin_app) as admin,
        TestClient(ingest_app) as ingest,
        TestClient(review_app) as review,
        TestClient(feed_app) as feed,
    ):
        created = admin.post(
            "/admin/v1/clients",
            headers={"Authorization": f"Bearer {ADMIN_KEY}"},
            json={"client_id": f"pg-v2-{suffix}", "name": "PostgreSQL v2 customer"},
        )
        assert created.status_code == 201, created.text
        client_key = created.json()["api_key"]

        imported = ingest.post(
            "/admin/v1/imports",
            headers={"Authorization": f"Bearer {INGEST_KEY}"},
            json={
                "feed_id": "publisher-v2-postgres",
                "feed_version": suffix,
                "generated_at": observed_at,
                "idempotency_key": f"publisher-v2-postgres-{suffix}",
                "items": [
                    {
                        "status": "active",
                        "record": {
                            "source_kind": "news",
                            "provider": "publisher-v2-postgres",
                            "external_id": f"article-{suffix}",
                            "record_type": "threat",
                            "title": "PostgreSQL v2 evidence",
                            "summary": "Normalized evidence for separated publisher roles.",
                            "modified_at": observed_at,
                            "retrieved_at": observed_at,
                            "markings": ["TLP:CLEAR"],
                            "revoked": False,
                            "raw_evidence": {"source_id": f"article-{suffix}"},
                        },
                    }
                ],
            },
        )
        assert imported.status_code == 200, imported.text
        record_id = next(iter(imported.json()["record_ids"].values()))
        published = review.post(
            f"/admin/v1/records/{record_id}/publish",
            headers={"Authorization": f"Bearer {REVIEWER_KEY}"},
            json={"reason": "PostgreSQL source evidence was independently reviewed."},
        )
        assert published.status_code == 200, published.text

        first = feed.get(
            "/v2/datapoints",
            headers={"Authorization": f"Bearer {client_key}"},
        )
        assert first.status_code == 200, first.text
        assert first.json()["mode"] == "full"
        assert first.headers["x-traceless-signature"]
        token = first.json()["next_sync_token"]
        delta = feed.get(
            "/v2/datapoints",
            params={"sync_token": token},
            headers={"Authorization": f"Bearer {client_key}"},
        )
        assert delta.status_code == 200, delta.text
        assert delta.json()["mode"] == "delta"
        assert delta.json()["items"] == []

    restricted_engine = create_engine(feed_url)
    try:
        with restricted_engine.connect() as connection:
            with pytest.raises(ProgrammingError):
                connection.execute(text("SELECT canonical_record FROM publisher_revisions"))
            connection.rollback()
            visible = connection.scalar(text("SELECT count(*) FROM publisher_current_projections"))
            assert visible is not None and visible >= 1
    finally:
        restricted_engine.dispose()
