import base64
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from traceless_api.publisher.app import create_publisher_app
from traceless_api.publisher.config import PublisherSettings

ADMIN_KEY = "publisher-postgres-admin-" + "a" * 32
CURSOR_SECRET = "publisher-postgres-cursor-" + "b" * 32
SIGNING_SEED = base64.b64encode(bytes(range(32))).decode("ascii")


def test_publisher_postgres_migrations_and_customer_pull() -> None:
    database_url = os.getenv("TRACELESS_TEST_PUBLISHER_POSTGRES_URL")
    if not database_url:
        pytest.skip("TRACELESS_TEST_PUBLISHER_POSTGRES_URL is not configured")

    suffix = uuid4().hex[:12]
    app = create_publisher_app(
        PublisherSettings(
            environment="test",
            database_url=database_url,
            auto_create_schema=False,
            admin_api_key=ADMIN_KEY,
            cursor_secret=CURSOR_SECRET,
            signing_private_key=SIGNING_SEED,
            signing_key_id="postgres-test-key",
            allowed_hosts=["testserver"],
        )
    )
    admin_headers = {
        "Authorization": f"Bearer {ADMIN_KEY}",
        "X-Actor": "postgres-publisher-test",
    }
    observed_at = datetime.now(UTC).isoformat()

    with TestClient(app) as client:
        assert client.get("/health/ready").status_code == 200
        created = client.post(
            "/admin/v1/clients",
            headers=admin_headers,
            json={
                "client_id": f"customer-{suffix}",
                "name": f"PostgreSQL customer {suffix}",
                "max_tlp": "TLP:CLEAR",
            },
        )
        assert created.status_code == 201, created.text
        api_key = created.json()["api_key"]

        imported = client.post(
            "/admin/v1/imports",
            headers=admin_headers,
            json={
                "feed_id": "postgres-publisher-smoke",
                "feed_version": suffix,
                "generated_at": observed_at,
                "publish": True,
                "items": [
                    {
                        "status": "active",
                        "status_changed_at": None,
                        "status_reason": None,
                        "record": {
                            "source_kind": "news",
                            "provider": "postgres-publisher-smoke",
                            "external_id": f"article-{suffix}",
                            "record_type": "threat",
                            "title": "Publisher PostgreSQL smoke record",
                            "summary": "Normalized source evidence for the publisher smoke test.",
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
        assert imported.json()["published"] == 1

        feed = client.get(
            "/v1/datapoints",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert feed.status_code == 200, feed.text
        assert feed.json()["items"][0]["record"]["external_id"] == f"article-{suffix}"
        assert feed.headers["x-traceless-signature"]
