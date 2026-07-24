import base64
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient
from pydantic import ValidationError

from traceless_api.publisher.app import create_publisher_app
from traceless_api.publisher.config import PublisherSettings
from traceless_api.publisher.service import PublisherCursorError, _decode_cursor

ADMIN_KEY = "publisher-admin-key-" + "a" * 32
CURSOR_SECRET = "publisher-cursor-secret-" + "b" * 32
SIGNING_SEED = base64.b64encode(bytes(range(32))).decode("ascii")


@pytest.fixture
def publisher_client() -> TestClient:
    app = create_publisher_app(
        PublisherSettings(
            environment="test",
            database_url="sqlite+pysqlite:///:memory:",
            auto_create_schema=True,
            admin_api_key=ADMIN_KEY,
            cursor_secret=CURSOR_SECRET,
            signing_private_key=SIGNING_SEED,
            signing_key_id="test-signing-key-1",
            allowed_hosts=["testserver"],
            max_page_size=1_000,
        )
    )
    with TestClient(app) as client:
        yield client


def _admin_headers(actor: str = "publisher-test") -> dict[str, str]:
    return {
        "Authorization": f"Bearer {ADMIN_KEY}",
        "X-Actor": actor,
    }


def _record(
    external_id: str,
    *,
    modified_at: datetime,
    tlp: str = "TLP:CLEAR",
    status: str = "active",
    source_kind: str = "news",
    title: str | None = None,
) -> dict[str, object]:
    revoked = status != "active"
    return {
        "status": status,
        "status_changed_at": modified_at.isoformat() if revoked else None,
        "status_reason": "Source was withdrawn." if revoked else None,
        "record": {
            "source_kind": source_kind,
            "provider": "central-analysis",
            "external_id": external_id,
            "record_type": "threat",
            "title": title or f"Threat intelligence {external_id}",
            "summary": "Normalized and source-grounded intelligence.",
            "source_url": None,
            "published_at": None,
            "modified_at": modified_at.isoformat(),
            "retrieved_at": modified_at.isoformat(),
            "severity": "high",
            "confidence": None,
            "cve_ids": [],
            "cpes": [],
            "affected_products": ["Example Gateway"],
            "mitre_attack_ids": ["T1190"],
            "indicators": [],
            "tags": ["initial-access"],
            "sectors": ["finance"],
            "regions": ["SE"],
            "markings": [tlp],
            "valid_from": None,
            "valid_until": None,
            "revoked": revoked,
            "raw_evidence": {"source_id": external_id},
            "ai_analysis": None,
            "vulnerability": None,
        },
    }


def _batch(
    items: list[dict[str, object]],
    *,
    version: str,
    publish: bool,
) -> dict[str, object]:
    return {
        "feed_id": "local-scrape-analysis",
        "feed_version": version,
        "generated_at": datetime.now(UTC).isoformat(),
        "publish": publish,
        "items": items,
    }


def _create_client(
    client: TestClient,
    client_id: str,
    *,
    max_tlp: str = "TLP:AMBER",
    allowed_providers: list[str] | None = None,
    allowed_source_kinds: list[str] | None = None,
) -> tuple[str, dict[str, object]]:
    response = client.post(
        "/admin/v1/clients",
        headers=_admin_headers(),
        json={
            "client_id": client_id,
            "name": f"Customer {client_id}",
            "max_tlp": max_tlp,
            "allowed_providers": allowed_providers or [],
            "allowed_source_kinds": allowed_source_kinds or [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["api_key"], response.json()["client"]


def test_staged_record_is_published_as_signed_customer_feed(
    publisher_client: TestClient,
) -> None:
    api_key, _ = _create_client(publisher_client, "customer-a", max_tlp="TLP:CLEAR")
    observed_at = datetime.now(UTC)
    imported = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers("scrape-worker"),
        json=_batch(
            [_record("article-0042", modified_at=observed_at)],
            version="1",
            publish=False,
        ),
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["staged"] == 1

    empty = publisher_client.get(
        "/v1/datapoints",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert empty.status_code == 200
    assert empty.json()["items"] == []

    record_id = next(iter(imported.json()["record_ids"].values()))
    published = publisher_client.post(
        f"/admin/v1/records/{record_id}/publish",
        headers=_admin_headers("reviewer"),
        json={"reason": "Reviewed source evidence and normalized content."},
    )
    assert published.status_code == 200, published.text
    assert published.json()["published"] is True
    assert published.json()["change_sequences"] == [1]

    repeated = publisher_client.post(
        f"/admin/v1/records/{record_id}/publish",
        headers=_admin_headers("reviewer"),
        json={"reason": "Reviewed source evidence and normalized content."},
    )
    assert repeated.status_code == 200
    assert repeated.json()["published"] is False

    feed = publisher_client.get(
        "/v1/datapoints",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert feed.status_code == 200, feed.text
    assert feed.json()["items"][0]["record"]["external_id"] == "article-0042"
    assert feed.headers["x-traceless-content-sha256"] == hashlib.sha256(
        feed.content
    ).hexdigest()
    key_document = publisher_client.get(
        "/.well-known/traceless-intelligence-signing-key"
    ).json()
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(key_document["public_key_base64"])
    )
    public_key.verify(
        base64.b64decode(feed.headers["x-traceless-signature"]),
        feed.content,
    )
    with pytest.raises(InvalidSignature):
        public_key.verify(
            base64.b64decode(feed.headers["x-traceless-signature"]),
            feed.content + b"x",
        )

    unchanged = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers("scrape-worker"),
        json=_batch(
            [_record("article-0042", modified_at=observed_at)],
            version="2",
            publish=False,
        ),
    )
    assert unchanged.status_code == 200
    assert unchanged.json()["unchanged"] == 1


def test_cursor_snapshot_is_stable_and_bound_to_entitlements(
    publisher_client: TestClient,
) -> None:
    api_key, _ = _create_client(publisher_client, "cursor-client", max_tlp="TLP:CLEAR")
    start = datetime.now(UTC)
    imported = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch(
            [
                _record("article-aa", modified_at=start),
                _record("article-bb", modified_at=start + timedelta(seconds=1)),
            ],
            version="1",
            publish=True,
        ),
    )
    assert imported.status_code == 200, imported.text

    first = publisher_client.get(
        "/v1/datapoints",
        params={"limit": 1},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert first.status_code == 200
    assert first.json()["has_more"] is True
    cursor = first.json()["next_cursor"]

    added_after_snapshot = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch(
            [_record("article-cc", modified_at=start + timedelta(seconds=2))],
            version="2",
            publish=True,
        ),
    )
    assert added_after_snapshot.status_code == 200

    second = publisher_client.get(
        "/v1/datapoints",
        params={"limit": 1, "cursor": cursor},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert second.status_code == 200, second.text
    assert second.json()["has_more"] is False
    delivered = {
        first.json()["items"][0]["record"]["external_id"],
        second.json()["items"][0]["record"]["external_id"],
    }
    assert delivered == {"article-aa", "article-bb"}

    updated = publisher_client.patch(
        "/admin/v1/clients/cursor-client",
        headers=_admin_headers(),
        json={"allowed_source_kinds": ["news"]},
    )
    assert updated.status_code == 200
    invalidated = publisher_client.get(
        "/v1/datapoints",
        params={"limit": 1, "cursor": cursor},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert invalidated.status_code == 400

    tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
    rejected = publisher_client.get(
        "/v1/datapoints",
        params={"limit": 1, "cursor": tampered},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert rejected.status_code == 400


def test_tlp_reclassification_creates_customer_specific_withdrawals(
    publisher_client: TestClient,
) -> None:
    low_key, _ = _create_client(
        publisher_client,
        "clear-client",
        max_tlp="TLP:CLEAR",
    )
    high_key, _ = _create_client(
        publisher_client,
        "amber-client",
        max_tlp="TLP:AMBER",
    )
    observed_at = datetime.now(UTC)
    first = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch(
            [_record("article-tlp", modified_at=observed_at)],
            version="1",
            publish=True,
        ),
    )
    assert first.status_code == 200

    amber = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch(
            [
                _record(
                    "article-tlp",
                    modified_at=observed_at + timedelta(minutes=1),
                    tlp="TLP:AMBER",
                )
            ],
            version="2",
            publish=True,
        ),
    )
    assert amber.status_code == 200, amber.text

    low = publisher_client.get(
        "/v1/datapoints",
        headers={"Authorization": f"Bearer {low_key}"},
    ).json()["items"][0]
    high = publisher_client.get(
        "/v1/datapoints",
        headers={"Authorization": f"Bearer {high_key}"},
    ).json()["items"][0]
    assert low["status"] == "deleted"
    assert low["record"]["revoked"] is True
    assert low["record"]["markings"] == ["TLP:CLEAR"]
    assert high["status"] == "active"
    assert high["record"]["markings"] == ["TLP:AMBER"]

    restricted = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch(
            [
                _record(
                    "article-tlp",
                    modified_at=observed_at + timedelta(minutes=2),
                    tlp="TLP:RED",
                )
            ],
            version="3",
            publish=True,
        ),
    )
    assert restricted.status_code == 200
    assert restricted.json()["restricted"] == 1
    record_id = next(iter(restricted.json()["record_ids"].values()))
    cannot_publish = publisher_client.post(
        f"/admin/v1/records/{record_id}/publish",
        headers=_admin_headers(),
        json={"reason": "Reviewed source evidence and normalized content."},
    )
    assert cannot_publish.status_code == 409
    high_after_red = publisher_client.get(
        "/v1/datapoints",
        headers={"Authorization": f"Bearer {high_key}"},
    ).json()["items"][0]
    assert high_after_red["status"] == "deleted"
    assert high_after_red["record"]["markings"] == ["TLP:AMBER"]


def test_client_administration_filters_and_key_rotation(
    publisher_client: TestClient,
) -> None:
    assert publisher_client.get("/admin/v1/clients").status_code == 401
    first_key, _ = _create_client(
        publisher_client,
        "filtered-client",
        allowed_providers=["central-analysis"],
        allowed_source_kinds=["news"],
    )
    duplicate = publisher_client.post(
        "/admin/v1/clients",
        headers=_admin_headers(),
        json={"client_id": "filtered-client", "name": "Duplicate"},
    )
    assert duplicate.status_code == 409

    updated = publisher_client.patch(
        "/admin/v1/clients/filtered-client",
        headers=_admin_headers(),
        json={"name": "Renamed customer", "max_tlp": "TLP:GREEN"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed customer"
    assert updated.json()["token_version"] == 2

    listed = publisher_client.get(
        "/admin/v1/clients",
        headers=_admin_headers(),
    )
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    rotated = publisher_client.post(
        "/admin/v1/clients/filtered-client/rotate-key",
        headers=_admin_headers(),
    )
    assert rotated.status_code == 200
    second_key = rotated.json()["api_key"]
    assert second_key != first_key
    assert publisher_client.get(
        "/v1/datapoints",
        headers={"Authorization": f"Bearer {first_key}"},
    ).status_code == 200
    assert publisher_client.get(
        "/v1/datapoints",
        headers={"Authorization": f"Bearer {second_key}"},
    ).status_code == 200

    missing = publisher_client.patch(
        "/admin/v1/clients/missing-client",
        headers=_admin_headers(),
        json={"enabled": False},
    )
    assert missing.status_code == 404


def test_revision_ordering_and_controlled_reclassification(
    publisher_client: TestClient,
) -> None:
    observed_at = datetime.now(UTC)
    first = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch(
            [_record("article-order", modified_at=observed_at)],
            version="2",
            publish=False,
        ),
    )
    assert first.status_code == 200

    older = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch(
            [
                _record(
                    "article-order",
                    modified_at=observed_at - timedelta(minutes=1),
                )
            ],
            version="1",
            publish=False,
        ),
    )
    assert older.status_code == 200
    assert older.json()["superseded"] == 1
    assert older.json()["warnings"]

    conflicting_time = _record("article-order", modified_at=observed_at)
    conflicting_time["record"]["title"] = "Different content at the same source time"
    conflict = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch([conflicting_time], version="3", publish=False),
    )
    assert conflict.status_code == 409

    changed_kind = publisher_client.post(
        "/admin/v1/imports",
        headers=_admin_headers(),
        json=_batch(
            [
                _record(
                    "article-order",
                    modified_at=observed_at + timedelta(minutes=1),
                    source_kind="misp",
                )
            ],
            version="4",
            publish=False,
        ),
    )
    assert changed_kind.status_code == 200
    assert changed_kind.json()["staged"] == 1
    record_id = changed_kind.json()["record_ids"]["central-analysis/article-order"]
    published = publisher_client.post(
        f"/admin/v1/records/{record_id}/publish",
        headers=_admin_headers(),
        json={"reason": "Reviewed and approved the corrected source classification."},
    )
    assert published.status_code == 200, published.text
    assert published.json()["record"]["source_kind"] == "misp"

    unknown_record = publisher_client.post(
        f"/admin/v1/records/{uuid4()}/publish",
        headers=_admin_headers(),
        json={"reason": "Reviewed source evidence and normalized content."},
    )
    assert unknown_record.status_code == 404


def test_configuration_and_cursor_validation_are_fail_closed() -> None:
    with pytest.raises(ValidationError):
        PublisherSettings(environment="production")
    with pytest.raises(ValidationError):
        PublisherSettings(
            environment="production",
            database_url="sqlite+pysqlite:///publisher.db",
            auto_create_schema=False,
            admin_api_key=ADMIN_KEY,
            cursor_secret=CURSOR_SECRET,
            signing_private_key=SIGNING_SEED,
        )
    with pytest.raises(ValidationError):
        PublisherSettings(allowed_hosts=["*"])
    with pytest.raises(ValidationError):
        PublisherSettings(admin_api_key="short")
    with pytest.raises(ValidationError):
        PublisherSettings(cursor_secret="short")
    with pytest.raises(ValidationError):
        PublisherSettings(signing_private_key="not-base64")

    secret = b"x" * 32
    for cursor in ("", "invalid", "a.b", "a" * 2_049):
        with pytest.raises(PublisherCursorError):
            _decode_cursor(cursor, secret=secret)
