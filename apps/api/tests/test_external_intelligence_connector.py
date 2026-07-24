import asyncio
import json
from collections.abc import Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from threading import Event
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from traceless_api.core.config import ExternalIntelligenceCredentialBinding, Settings
from traceless_api.db.models import (
    AuditEventRow,
    ExternalIntelligenceCheckpointRow,
    ExternalIntelligenceConnectorRow,
    ExternalIntelligenceSyncIdentityRow,
    ExternalIntelligenceSyncPageRow,
    ExternalIntelligenceSyncRunRow,
    GlobalIntelRecordRow,
    GlobalIntelRevisionRow,
)
from traceless_api.db.session import (
    create_database_engine,
    create_schema,
    create_session_factory,
)
from traceless_api.integrations.intelligence import (
    ExternalDatapointProvider,
    ExternalIntelligenceConnectorUpdate,
    IntelligencePayloadTooLarge,
    InvalidIntelligencePayload,
    parse_external_datapoint_page,
    validate_external_datapoint_endpoint,
)
from traceless_api.services.external_intelligence_pull import (
    ExternalSyncLeaseLostError,
    ExternalSyncRunClaim,
    _ExternalRunHeartbeat,
    _fail_owned_run,
    _finalize_owned_run,
    _persist_owned_page,
    get_external_sync_status,
    pull_external_intelligence,
    upsert_external_connector,
)
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalRepository,
)

ENDPOINT = "https://pipeline.example.test/v1/datapoints"
UPSTREAM_CREDENTIAL = token_urlsafe(32)
NOW = datetime(2026, 7, 21, 8, tzinfo=UTC)


def _credential(
    secret: str,
    *,
    origin: str = "https://pipeline.example.test",
) -> ExternalIntelligenceCredentialBinding:
    return ExternalIntelligenceCredentialBinding(secret=SecretStr(secret), origin=origin)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _record(
    external_id: str,
    *,
    modified_at: datetime = NOW,
    revoked: bool = False,
) -> dict[str, Any]:
    return {
        "source_kind": "news",
        "provider": "separate-scraper",
        "external_id": external_id,
        "record_type": "threat",
        "title": f"Threat report {external_id}",
        "summary": "A normalized source-grounded report from the external program.",
        "source_url": f"https://publisher.example/{external_id}",
        "published_at": (NOW - timedelta(hours=1)).isoformat(),
        "modified_at": modified_at.isoformat(),
        "retrieved_at": modified_at.isoformat(),
        "severity": "high",
        "confidence": 0.87,
        "cve_ids": ["CVE-2099-12345"],
        "cpes": [],
        "affected_products": ["Example Gateway"],
        "mitre_attack_ids": ["T1190"],
        "indicators": [],
        "tags": ["campaign"],
        "sectors": ["finance"],
        "regions": ["SE"],
        "markings": ["TLP:CLEAR"],
        "valid_from": NOW.isoformat(),
        "valid_until": None,
        "revoked": revoked,
        "raw_evidence": {
            "source_id": external_id,
            "source_excerpt": "Bounded original evidence",
        },
        "ai_analysis": {
            "model_name": "internal-classifier",
            "model_version": "2026-07-20",
            "prompt_version": "4",
            "taxonomy_version": "3",
            "analyzed_at": modified_at.isoformat(),
            "confidence": 0.87,
            "confidence_method": "calibrated classifier probability",
            "confidence_method_version": "2",
            "categories": ["initial-access"],
            "extracted_entities": {"products": ["Example Gateway"]},
            "rationale": "The source explicitly names the product and exploit path.",
        },
        "vulnerability": None,
    }


def _item(
    external_id: str,
    *,
    status: str = "active",
    modified_at: datetime = NOW,
) -> dict[str, Any]:
    retired = status != "active"
    return {
        "status": status,
        "status_changed_at": modified_at.isoformat() if retired else None,
        "status_reason": "Removed at the source" if retired else None,
        "record": _record(external_id, modified_at=modified_at, revoked=retired),
    }


def _page(
    items: list[dict[str, Any]],
    *,
    has_more: bool = False,
    next_cursor: str | None = None,
    feed_version: str = "snapshot-42",
    generated_at: datetime = NOW,
) -> bytes:
    return _json_bytes(
        {
            "schema_version": "1.0",
            "feed_id": "separate-cyber-pipeline",
            "feed_version": feed_version,
            "generated_at": generated_at.isoformat(),
            "items": items,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }
    )


@dataclass
class StubResponse:
    content: bytes
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    status_checked: bool = False

    def raise_for_status(self) -> None:
        self.status_checked = True

    async def aiter_bytes(self) -> Any:
        yield self.content


@dataclass
class ChunkedResponse:
    chunks: list[bytes]
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    chunks_read: int = 0

    def raise_for_status(self) -> None:
        return None

    async def aiter_bytes(self) -> Any:
        for chunk in self.chunks:
            self.chunks_read += 1
            yield chunk


class RecordingHttpClient:
    def __init__(self, responses: list[StubResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> StubResponse:
        self.requests.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
                "timeout": timeout,
                "follow_redirects": follow_redirects,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected external request")
        return self.responses.pop(0)

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> Any:
        assert method == "GET"
        yield await self.get(url, **kwargs)


def _settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "external_intelligence_url": ENDPOINT,
        "external_intelligence_token": SecretStr(UPSTREAM_CREDENTIAL),
        "intelligence_allowed_hosts": [
            "www.cisa.gov",
            "api.first.org",
            "services.nvd.nist.gov",
            "pipeline.example.test",
        ],
        "external_intelligence_page_size": 1,
        "external_intelligence_max_pages": 10,
        "external_intelligence_max_records": 10,
    }
    values.update(updates)
    return Settings(**values)


def _repository() -> tuple[object, object, OperationalRepository]:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    session = create_session_factory(engine)()
    return engine, session, OperationalRepository(session)


def test_provider_uses_fixed_url_auth_cursor_timeout_and_no_redirects() -> None:
    response = StubResponse(_page([_item("article-1")]))
    client = RecordingHttpClient([response])
    provider = ExternalDatapointProvider(
        client,
        ENDPOINT,
        token=UPSTREAM_CREDENTIAL,
        auth_scheme="X-API-Key",
        allowed_hosts={"pipeline.example.test"},
        page_size=1,
        timeout_seconds=7.5,
    )

    result = asyncio.run(provider.fetch_page("opaque:cursor/2"))

    assert result.page.items[0].record.external_id == "article-1"
    assert len(result.raw_payload_sha256) == 64
    assert response.status_checked is True
    assert client.requests == [
        {
            "url": ENDPOINT,
            "headers": {
                "Accept": "application/json",
                "X-API-Key": UPSTREAM_CREDENTIAL,
            },
            "params": {"limit": "1", "cursor": "opaque:cursor/2"},
            "timeout": 7.5,
            "follow_redirects": False,
        }
    ]
    assert UPSTREAM_CREDENTIAL not in result.model_dump_json()


def test_authenticated_api_route_pulls_without_exposing_upstream_secret(
    client: TestClient,
) -> None:
    external_client = RecordingHttpClient([StubResponse(_page([_item("article-route")]))])

    @asynccontextmanager
    async def external_client_context() -> Any:
        yield external_client

    client.app.state.settings = _settings()
    client.app.state.http_client_factory = external_client_context

    response = client.post(
        "/api/v1/operational/intelligence/sync/external",
        json={"cursor": None, "max_pages": 2},
        headers={"X-Actor": "external-feed-worker"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["created"] == 1
    assert response.json()["complete"] is True
    assert response.json()["correlation_jobs_queued"] == 0
    assert UPSTREAM_CREDENTIAL not in response.text
    listed = client.get("/api/v1/operational/intelligence/records")
    assert listed.json()["items"][0]["external_id"] == "article-route"
    assert listed.json()["items"][0]["review_status"] == "pending"


def test_viewer_role_cannot_trigger_external_pull(client: TestClient) -> None:
    external_client = RecordingHttpClient([])

    @asynccontextmanager
    async def external_client_context() -> Any:
        yield external_client

    api_key = "v" * 32
    client.app.state.settings = _settings(
        operational_api_key=SecretStr(api_key),
        operational_roles=["viewer"],
    )
    client.app.state.http_client_factory = external_client_context

    response = client.post(
        "/api/v1/operational/intelligence/sync/external",
        json={},
        headers={"Authorization": f"Bearer {api_key}"},
    )

    assert response.status_code == 403
    assert external_client.requests == []


def test_external_sync_history_is_paginated_and_never_exposes_secrets_or_cursors(
    client: TestClient,
) -> None:
    external_client = RecordingHttpClient(
        [
            StubResponse(_page([_item("history-1")], feed_version="history-1")),
            StubResponse(_page([_item("history-2")], feed_version="history-2")),
        ]
    )

    @asynccontextmanager
    async def external_client_context() -> Any:
        yield external_client

    client.app.state.settings = _settings()
    client.app.state.http_client_factory = external_client_context
    assert client.post("/api/v1/operational/intelligence/sync/external", json={}).status_code == 200
    assert client.post("/api/v1/operational/intelligence/sync/external", json={}).status_code == 200

    first_page = client.get(
        "/api/v1/operational/intelligence/sync/external/runs",
        params={"limit": 1, "offset": 0},
    )
    second_page = client.get(
        "/api/v1/operational/intelligence/sync/external/runs",
        params={"limit": 1, "offset": 1},
    )
    assert first_page.status_code == second_page.status_code == 200
    assert first_page.json()["total"] == second_page.json()["total"] == 2
    assert len(first_page.json()["items"]) == len(second_page.json()["items"]) == 1
    assert first_page.json()["items"][0]["id"] != second_page.json()["items"][0]["id"]
    serialized = first_page.text + second_page.text
    assert UPSTREAM_CREDENTIAL not in serialized
    assert '"next_cursor":' not in serialized
    assert '"start_cursor":' not in serialized


def test_tenant_connector_persists_only_a_credential_reference(
    client: TestClient,
) -> None:
    settings = _settings(
        external_intelligence_url=None,
        external_intelligence_token=None,
        external_intelligence_credentials={
            "local-traceless": {"tenant-feed-primary": _credential(UPSTREAM_CREDENTIAL)}
        },
    )
    client.app.state.settings = settings

    configured = client.put(
        "/api/v1/operational/intelligence/connectors/external",
        json={
            "endpoint": ENDPOINT,
            "auth_scheme": "Bearer",
            "credential_reference": "tenant-feed-primary",
            "enabled": True,
            "sync_interval_seconds": 300,
        },
    )

    assert configured.status_code == 200, configured.text
    assert configured.json()["credential_reference"] == "tenant-feed-primary"
    assert configured.json()["sync_interval_seconds"] == 300
    assert configured.json()["next_sync_at"] is not None
    assert UPSTREAM_CREDENTIAL not in configured.text
    disabled = client.put(
        "/api/v1/operational/intelligence/connectors/external",
        json={
            "endpoint": ENDPOINT,
            "auth_scheme": "Bearer",
            "credential_reference": "tenant-feed-primary",
            "enabled": False,
            "sync_interval_seconds": 300,
        },
    )
    assert disabled.status_code == 200
    assert disabled.json()["config_version"] == 1
    assert disabled.json()["enabled"] is False
    status_response = client.get("/api/v1/operational/intelligence/sync/external/status")
    assert status_response.status_code == 200
    assert status_response.json()["credential_available"] is True
    assert status_response.json()["enabled"] is False
    assert status_response.json()["schedule_state"] == "disabled"
    assert status_response.json()["sync_interval_seconds"] == 300
    assert status_response.json()["next_sync_at"] is None
    assert status_response.json()["checkpoint"] is None
    with client.app.state.session_factory() as session:
        row = session.scalar(select(ExternalIntelligenceConnectorRow))
        assert row is not None
        assert row.credential_reference == "tenant-feed-primary"
        assert UPSTREAM_CREDENTIAL not in json.dumps(
            {
                "endpoint": row.endpoint,
                "credential_reference": row.credential_reference,
            }
        )


def test_connector_configuration_is_isolated_per_organization() -> None:
    engine, session, repository_a = _repository()
    organization_b = uuid4()
    repository_b = OperationalRepository(
        session,
        organization_id=organization_b,
        organization_key=str(organization_b),
        organization_name="Organization B",
    )
    settings = _settings(
        external_intelligence_credentials={
            "local-traceless": {"tenant-a": _credential(token_urlsafe(32))},
            str(organization_b): {"tenant-b": _credential(token_urlsafe(32))},
        }
    )
    try:
        connector_a = upsert_external_connector(
            settings=settings,
            repository=repository_a,
            payload=ExternalIntelligenceConnectorUpdate(
                endpoint=ENDPOINT,
                credential_reference="tenant-a",
            ),
            actor="admin-a",
        )
        assert (
            get_external_sync_status(settings=settings, repository=repository_b).configured is False
        )
        with pytest.raises(OperationalConflictError, match="cannot be resolved"):
            upsert_external_connector(
                settings=settings,
                repository=repository_b,
                payload=ExternalIntelligenceConnectorUpdate(
                    endpoint=ENDPOINT,
                    credential_reference="tenant-a",
                ),
                actor="admin-b",
            )
        connector_b = upsert_external_connector(
            settings=settings,
            repository=repository_b,
            payload=ExternalIntelligenceConnectorUpdate(
                endpoint=ENDPOINT,
                credential_reference="tenant-b",
            ),
            actor="admin-b",
        )
        session.commit()

        assert connector_a.organization_id != connector_b.organization_id
        assert connector_a.credential_reference == "tenant-a"
        assert connector_b.credential_reference == "tenant-b"
        assert len(list(session.scalars(select(ExternalIntelligenceConnectorRow)))) == 2
    finally:
        session.close()
        engine.dispose()


def test_tenant_credential_is_rejected_for_a_different_recipient_origin() -> None:
    engine, session, repository = _repository()
    settings = _settings(
        external_intelligence_url=None,
        external_intelligence_token=None,
        intelligence_allowed_hosts=[
            "www.cisa.gov",
            "api.first.org",
            "services.nvd.nist.gov",
            "pipeline.example.test",
            "other.example.test",
        ],
        external_intelligence_credentials={
            "local-traceless": {
                "wrong-recipient": _credential(
                    token_urlsafe(32),
                    origin="https://other.example.test",
                )
            }
        },
    )
    try:
        with pytest.raises(OperationalConflictError, match="not bound to this endpoint origin"):
            upsert_external_connector(
                settings=settings,
                repository=repository,
                payload=ExternalIntelligenceConnectorUpdate(
                    endpoint=ENDPOINT,
                    credential_reference="wrong-recipient",
                ),
                actor="admin",
            )
        assert session.scalar(select(ExternalIntelligenceConnectorRow)) is None
    finally:
        session.close()
        engine.dispose()


def test_pull_paginates_imports_idempotently_and_preserves_deletion_tombstone() -> None:
    engine, session, repository = _repository()
    try:
        first_client = RecordingHttpClient(
            [
                StubResponse(_page([_item("article-1")], has_more=True, next_cursor="next-2")),
                StubResponse(_page([_item("article-2")])),
            ]
        )
        first = asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=first_client,
                actor="worker:external-intelligence",
            )
        )
        session.commit()

        assert first.model_dump(
            exclude={
                "run_id",
                "manifest_sha256",
                "warnings",
                "bytes_fetched",
                "batch_bytes_fetched",
                "correlation_jobs_queued",
            }
        ) == {
            "feed_id": "separate-cyber-pipeline",
            "feed_version": "snapshot-42",
            "pages_fetched": 2,
            "records_fetched": 2,
            "batch_pages_fetched": 2,
            "batch_records_fetched": 2,
            "created": 2,
            "updated": 0,
            "unchanged": 0,
            "quarantined": 0,
            "active": 2,
            "revoked": 0,
            "deleted": 0,
            "complete": True,
            "next_cursor": None,
        }
        assert first_client.requests[0]["params"] == {"limit": "1"}
        assert first_client.requests[1]["params"] == {
            "limit": "1",
            "cursor": "next-2",
        }

        deleted_at = NOW + timedelta(hours=2)
        deleted_payload = _page(
            [_item("article-1", status="deleted", modified_at=deleted_at)],
            feed_version="snapshot-43",
            generated_at=deleted_at,
        )
        deleted = asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=RecordingHttpClient([StubResponse(deleted_payload)]),
                actor="worker:external-intelligence",
            )
        )
        session.commit()
        assert deleted.updated == 1
        assert deleted.deleted == 1

        row = session.scalar(
            select(GlobalIntelRecordRow).where(GlobalIntelRecordRow.external_id == "article-1")
        )
        assert row is not None and row.revoked is True
        assert "traceless:source-status:deleted" in row.tags
        assert row.raw_evidence["source"] == {
            "source_id": "article-1",
            "source_excerpt": "Bounded original evidence",
        }
        lifecycle = row.raw_evidence["source_lifecycle"]
        assert lifecycle["status"] == "deleted"
        assert lifecycle["reason"] == "Removed at the source"
        assert len(lifecycle["source_raw_sha256"]) == 64
        assert row.ai_analysis["model_version"] == "2026-07-20"
        assert row.ai_analysis["confidence_method_version"] == "2"
        assert row.raw_evidence != row.ai_analysis

        replayed = asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=RecordingHttpClient([StubResponse(deleted_payload)]),
                actor="worker:external-intelligence",
            )
        )
        assert replayed.unchanged == 1
        assert replayed.created == replayed.updated == 0
        audits = list(
            session.scalars(
                select(AuditEventRow).where(
                    AuditEventRow.action == "intelligence.external_sync_completed"
                )
            )
        )
        assert audits
        assert UPSTREAM_CREDENTIAL not in json.dumps(audits[-1].details)
        assert "next_cursor" not in audits[-1].details
    finally:
        session.close()
        engine.dispose()


def test_page_budget_returns_continuation_cursor_for_next_pull() -> None:
    engine, session, repository = _repository()
    try:
        partial_client = RecordingHttpClient(
            [StubResponse(_page([_item("article-1")], has_more=True, next_cursor="resume-2"))]
        )
        partial = asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=partial_client,
                actor="worker",
                max_pages=1,
            )
        )
        assert partial.complete is False
        assert partial.next_cursor == "resume-2"
        assert partial.created == 1
        session.commit()
        checkpoint = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert checkpoint is not None
        assert checkpoint.cursor == "resume-2"
        assert checkpoint.feed_version == "snapshot-42"
        safe_status = get_external_sync_status(settings=_settings(), repository=repository)
        assert safe_status.checkpoint is not None
        assert "resume-2" not in safe_status.model_dump_json()
        wrong_cursor_client = RecordingHttpClient([])
        with pytest.raises(OperationalConflictError, match="does not match"):
            asyncio.run(
                pull_external_intelligence(
                    settings=_settings(),
                    repository=repository,
                    client=wrong_cursor_client,
                    actor="worker",
                    cursor="caller-controlled-cursor",
                )
            )
        assert wrong_cursor_client.requests == []
        with pytest.raises(OperationalConflictError, match="checkpoint is active"):
            upsert_external_connector(
                settings=_settings(
                    external_intelligence_credentials={
                        "local-traceless": {"rotated-feed": _credential(token_urlsafe(32))}
                    }
                ),
                repository=repository,
                payload=ExternalIntelligenceConnectorUpdate(
                    endpoint=ENDPOINT,
                    credential_reference="rotated-feed",
                ),
                actor="admin",
            )

        resumed_client = RecordingHttpClient([StubResponse(_page([_item("article-2")]))])
        resumed = asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=resumed_client,
                actor="worker",
                max_pages=1,
            )
        )
        assert resumed.complete is True
        assert resumed.created == 1
        assert resumed.pages_fetched == resumed.records_fetched == 2
        assert resumed.batch_pages_fetched == resumed.batch_records_fetched == 1
        assert resumed.manifest_sha256 != partial.manifest_sha256
        assert resumed_client.requests[0]["params"] == {
            "limit": "1",
            "cursor": "resume-2",
        }
        assert session.scalar(select(ExternalIntelligenceCheckpointRow)) is None
        resumed_run = session.get(ExternalIntelligenceSyncRunRow, resumed.run_id)
        assert resumed_run is not None
        assert resumed_run.pages_fetched == resumed_run.records_fetched == 2
        assert resumed_run.batch_pages_fetched == resumed_run.batch_records_fetched == 1
        assert resumed_run.manifest_sha256 == resumed.manifest_sha256
        assert resumed_run.claim_token_sha256 is None
    finally:
        session.close()
        engine.dispose()


def test_connector_change_is_fenced_before_first_checkpoint_and_resume_stays_bound() -> None:
    engine, session, repository = _repository()
    session_factory = create_session_factory(engine)
    credential_a = "a" * 32
    credential_b = "b" * 32
    endpoint_a = "https://pipeline.example.test/v1/feed-a"
    endpoint_b = "https://pipeline.example.test/v1/feed-b"
    settings = _settings(
        external_intelligence_url=None,
        external_intelligence_token=None,
        external_intelligence_credentials={
            "local-traceless": {
                "feed-a": _credential(credential_a),
                "feed-b": _credential(credential_b),
            }
        },
    )

    class ChangeBeforeFirstCheckpointClient(RecordingHttpClient):
        async def get(
            self,
            url: str,
            *,
            headers: Mapping[str, str] | None = None,
            params: Mapping[str, str] | None = None,
            timeout: float | None = None,
            follow_redirects: bool = False,
        ) -> StubResponse:
            with session_factory() as competing_session:
                competing_repository = OperationalRepository(competing_session)
                assert competing_session.scalar(
                    select(ExternalIntelligenceCheckpointRow)
                ) is None
                active_run = competing_session.scalar(
                    select(ExternalIntelligenceSyncRunRow).where(
                        ExternalIntelligenceSyncRunRow.status == "running"
                    )
                )
                assert active_run is not None
                with pytest.raises(OperationalConflictError, match="run is active"):
                    upsert_external_connector(
                        settings=settings,
                        repository=competing_repository,
                        payload=ExternalIntelligenceConnectorUpdate(
                            endpoint=endpoint_b,
                            credential_reference="feed-b",
                        ),
                        actor="competing-admin",
                    )
            return await super().get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )

    try:
        connector = upsert_external_connector(
            settings=settings,
            repository=repository,
            payload=ExternalIntelligenceConnectorUpdate(
                endpoint=endpoint_a,
                credential_reference="feed-a",
            ),
            actor="admin",
        )
        session.commit()

        partial_client = ChangeBeforeFirstCheckpointClient(
            [
                StubResponse(
                    _page(
                        [_item("article-config-fence-1")],
                        has_more=True,
                        next_cursor="cursor-from-feed-a",
                    )
                )
            ]
        )
        partial = asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=partial_client,
                actor="worker",
                max_pages=1,
            )
        )

        assert partial.complete is False
        assert partial_client.requests[0]["url"] == endpoint_a
        assert partial_client.requests[0]["headers"] == {
            "Accept": "application/json",
            "Authorization": f"Bearer {credential_a}",
        }
        current_connector = session.scalar(select(ExternalIntelligenceConnectorRow))
        checkpoint = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert current_connector is not None
        assert checkpoint is not None
        assert current_connector.id == connector.id
        assert current_connector.endpoint == endpoint_a
        assert current_connector.credential_reference == "feed-a"
        assert current_connector.config_version == 1
        assert checkpoint.connector_config_version == current_connector.config_version
        assert checkpoint.connector_identity_sha256 == current_connector.identity_sha256

        disabled = upsert_external_connector(
            settings=settings,
            repository=repository,
            payload=ExternalIntelligenceConnectorUpdate(
                endpoint=endpoint_a,
                credential_reference="feed-a",
                enabled=False,
            ),
            actor="admin",
        )
        session.commit()
        assert disabled.enabled is False
        assert disabled.config_version == 1
        preserved_checkpoint = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert preserved_checkpoint is not None
        assert preserved_checkpoint.id == checkpoint.id
        disabled_client = RecordingHttpClient([])
        with pytest.raises(OperationalConflictError, match="connector is disabled"):
            asyncio.run(
                pull_external_intelligence(
                    settings=settings,
                    repository=repository,
                    client=disabled_client,
                    actor="worker",
                )
            )
        assert disabled_client.requests == []

        reenabled = upsert_external_connector(
            settings=settings,
            repository=repository,
            payload=ExternalIntelligenceConnectorUpdate(
                endpoint=endpoint_a,
                credential_reference="feed-a",
                enabled=True,
            ),
            actor="admin",
        )
        session.commit()
        assert reenabled.enabled is True
        assert reenabled.config_version == 1
        assert session.scalar(select(ExternalIntelligenceCheckpointRow)) is not None

        resumed_client = RecordingHttpClient(
            [StubResponse(_page([_item("article-config-fence-2")]))]
        )
        resumed = asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=resumed_client,
                actor="worker",
                max_pages=1,
            )
        )

        assert resumed.complete is True
        assert resumed_client.requests == [
            {
                "url": endpoint_a,
                "headers": {
                    "Accept": "application/json",
                    "Authorization": f"Bearer {credential_a}",
                },
                "params": {"limit": "1", "cursor": "cursor-from-feed-a"},
                "timeout": settings.external_intelligence_timeout_seconds,
                "follow_redirects": False,
            }
        ]
        assert credential_b not in json.dumps(resumed_client.requests)
        assert endpoint_b not in json.dumps(resumed_client.requests)
    finally:
        session.close()
        engine.dispose()


def test_disabling_an_active_connector_fences_the_owned_run() -> None:
    engine, session, repository = _repository()
    session_factory = create_session_factory(engine)
    credential = "c" * 32
    endpoint = "https://pipeline.example.test/v1/emergency-disable"
    settings = _settings(
        external_intelligence_url=None,
        external_intelligence_token=None,
        external_intelligence_credentials={
            "local-traceless": {"emergency-feed": _credential(credential)}
        },
    )

    class DisableDuringRequestClient(RecordingHttpClient):
        async def get(
            self,
            url: str,
            *,
            headers: Mapping[str, str] | None = None,
            params: Mapping[str, str] | None = None,
            timeout: float | None = None,
            follow_redirects: bool = False,
        ) -> StubResponse:
            with session_factory() as competing_session:
                disabled = upsert_external_connector(
                    settings=settings,
                    repository=OperationalRepository(competing_session),
                    payload=ExternalIntelligenceConnectorUpdate(
                        endpoint=endpoint,
                        credential_reference="emergency-feed",
                        enabled=False,
                    ),
                    actor="emergency-admin",
                )
                competing_session.commit()
                assert disabled.enabled is False
                assert disabled.config_version == 1
            return await super().get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )

    try:
        upsert_external_connector(
            settings=settings,
            repository=repository,
            payload=ExternalIntelligenceConnectorUpdate(
                endpoint=endpoint,
                credential_reference="emergency-feed",
            ),
            actor="admin",
        )
        session.commit()

        with pytest.raises(ExternalSyncLeaseLostError, match="ownership changed"):
            asyncio.run(
                pull_external_intelligence(
                    settings=settings,
                    repository=repository,
                    client=DisableDuringRequestClient(
                        [StubResponse(_page([_item("article-disabled-run")]))]
                    ),
                    actor="worker",
                )
            )

        with session_factory() as verification_session:
            connector = verification_session.scalar(
                select(ExternalIntelligenceConnectorRow)
            )
            run = verification_session.scalar(select(ExternalIntelligenceSyncRunRow))
            assert connector is not None
            assert connector.enabled is False
            assert connector.config_version == 1
            assert run is not None
            assert run.status == "failed"
            assert run.error_code == "connector_disabled"
            assert run.claim_token_sha256 is None
            assert verification_session.scalar(
                select(ExternalIntelligenceSyncPageRow)
            ) is None
            assert verification_session.scalar(
                select(ExternalIntelligenceCheckpointRow)
            ) is None
    finally:
        session.close()
        engine.dispose()


def test_resume_rejects_identity_repeated_in_an_earlier_accepted_run() -> None:
    engine, session, repository = _repository()
    settings = _settings()
    try:
        partial = asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=RecordingHttpClient(
                    [
                        StubResponse(
                            _page(
                                [_item("article-duplicate")],
                                has_more=True,
                                next_cursor="resume-duplicate",
                            )
                        )
                    ]
                ),
                actor="worker",
                max_pages=1,
            )
        )
        assert partial.complete is False

        with pytest.raises(InvalidIntelligencePayload, match="persisted snapshot"):
            asyncio.run(
                pull_external_intelligence(
                    settings=settings,
                    repository=repository,
                    client=RecordingHttpClient([StubResponse(_page([_item("article-duplicate")]))]),
                    actor="worker",
                )
            )

        checkpoint = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert checkpoint is not None
        assert checkpoint.pages_completed == checkpoint.records_completed == 1
        accepted_identities = list(
            session.scalars(
                select(ExternalIntelligenceSyncIdentityRow)
                .join(ExternalIntelligenceSyncRunRow)
                .where(ExternalIntelligenceSyncRunRow.status == "partial")
            )
        )
        assert [row.external_id for row in accepted_identities] == ["article-duplicate"]
        failed = session.scalar(
            select(ExternalIntelligenceSyncRunRow)
            .where(ExternalIntelligenceSyncRunRow.status == "failed")
            .order_by(ExternalIntelligenceSyncRunRow.started_at.desc())
        )
        assert failed is not None
        assert failed.claim_token_sha256 is None
        assert failed.lease_expires_at is None
    finally:
        session.close()
        engine.dispose()


def test_failed_resume_provenance_does_not_advance_the_checkpoint() -> None:
    engine, session, repository = _repository()
    settings = _settings()
    try:
        first = asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=RecordingHttpClient(
                    [
                        StubResponse(
                            _page(
                                [_item("accepted-page-1")],
                                has_more=True,
                                next_cursor="retry-page-2",
                            )
                        )
                    ]
                ),
                actor="worker",
                max_pages=1,
            )
        )
        with pytest.raises(InvalidIntelligencePayload, match="persisted snapshot"):
            asyncio.run(
                pull_external_intelligence(
                    settings=settings,
                    repository=repository,
                    client=RecordingHttpClient(
                        [
                            StubResponse(
                                _page(
                                    [_item("retryable-page-2")],
                                    has_more=True,
                                    next_cursor="bad-page-3",
                                )
                            ),
                            StubResponse(_page([_item("retryable-page-2")])),
                        ]
                    ),
                    actor="worker",
                )
            )
        checkpoint = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert checkpoint is not None
        assert checkpoint.last_run_id == first.run_id
        assert checkpoint.pages_completed == checkpoint.records_completed == 1
        failed_run = session.scalar(
            select(ExternalIntelligenceSyncRunRow)
            .where(ExternalIntelligenceSyncRunRow.status == "failed")
            .order_by(ExternalIntelligenceSyncRunRow.started_at.desc())
        )
        assert failed_run is not None
        failed_identities = list(
            session.scalars(
                select(ExternalIntelligenceSyncIdentityRow).where(
                    ExternalIntelligenceSyncIdentityRow.run_id == failed_run.id
                )
            )
        )
        assert [row.external_id for row in failed_identities] == ["retryable-page-2"]

        retried = asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=RecordingHttpClient([StubResponse(_page([_item("retryable-page-2")]))]),
                actor="worker",
            )
        )
        assert retried.complete is True
        assert retried.pages_fetched == retried.records_fetched == 2
        assert retried.batch_pages_fetched == retried.batch_records_fetched == 1
        assert session.scalar(select(ExternalIntelligenceCheckpointRow)) is None
    finally:
        session.close()
        engine.dispose()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("records_completed", 2, "identity provenance"),
        ("page_manifest_sha256", "0" * 64, "page provenance manifest"),
        ("identity_manifest_sha256", "0" * 64, "identity manifest"),
    ],
)
def test_resume_fails_closed_when_checkpoint_provenance_is_tampered(
    field: str,
    value: object,
    message: str,
) -> None:
    engine, session, repository = _repository()
    settings = _settings()
    client = RecordingHttpClient([])
    try:
        asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=RecordingHttpClient(
                    [
                        StubResponse(
                            _page(
                                [_item("checkpoint-record")],
                                has_more=True,
                                next_cursor="checkpoint-next",
                            )
                        )
                    ]
                ),
                actor="worker",
                max_pages=1,
            )
        )
        checkpoint = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert checkpoint is not None
        setattr(checkpoint, field, value)
        session.commit()

        with pytest.raises(OperationalConflictError, match=message):
            asyncio.run(
                pull_external_intelligence(
                    settings=settings,
                    repository=repository,
                    client=client,
                    actor="worker",
                )
            )
        assert client.requests == []
    finally:
        session.close()
        engine.dispose()


@pytest.mark.parametrize(
    "limit_updates",
    [
        {"external_intelligence_max_pages": 2},
        {"external_intelligence_max_records": 2},
    ],
)
def test_resume_enforces_snapshot_limits_cumulatively(
    limit_updates: dict[str, int],
) -> None:
    engine, session, repository = _repository()
    settings = _settings(**limit_updates)
    try:
        first = asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=RecordingHttpClient(
                    [
                        StubResponse(
                            _page(
                                [_item("article-limit-1")],
                                has_more=True,
                                next_cursor="limit-page-2",
                            )
                        )
                    ]
                ),
                actor="worker",
                max_pages=1,
            )
        )
        assert first.complete is False

        with pytest.raises(InvalidIntelligencePayload, match="cumulative snapshot limits"):
            asyncio.run(
                pull_external_intelligence(
                    settings=settings,
                    repository=repository,
                    client=RecordingHttpClient(
                        [
                            StubResponse(
                                _page(
                                    [_item("article-limit-2")],
                                    has_more=True,
                                    next_cursor="limit-page-3",
                                )
                            )
                        ]
                    ),
                    actor="worker",
                )
            )

        checkpoint = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert checkpoint is not None
        assert checkpoint.pages_completed == checkpoint.records_completed == 1
        assert checkpoint.last_run_id == first.run_id
    finally:
        session.close()
        engine.dispose()


def test_resume_enforces_the_snapshot_byte_quota_across_processes() -> None:
    engine, session, repository = _repository()
    settings = _settings(
        external_intelligence_max_snapshot_bytes=1_048_576,
        external_intelligence_max_page_bytes=300_000,
    )

    def large_page(index: int, *, has_more: bool) -> bytes:
        value = json.loads(
            _page(
                [_item(f"article-bytes-{index}")],
                has_more=has_more,
                next_cursor=f"bytes-page-{index + 1}" if has_more else None,
            )
        )
        value["items"][0]["record"]["raw_evidence"] = {
            "source_id": f"article-bytes-{index}",
            "padding": "x" * 190_000,
        }
        return _json_bytes(value)

    try:
        first = asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=RecordingHttpClient(
                    [StubResponse(large_page(index, has_more=True)) for index in range(1, 6)]
                ),
                actor="worker",
                max_pages=5,
            )
        )
        assert first.complete is False
        assert first.bytes_fetched < settings.external_intelligence_max_snapshot_bytes
        checkpoint = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert checkpoint is not None
        assert checkpoint.bytes_completed == first.bytes_fetched

        with pytest.raises(InvalidIntelligencePayload, match="cumulative snapshot byte limit"):
            asyncio.run(
                pull_external_intelligence(
                    settings=settings,
                    repository=repository,
                    client=RecordingHttpClient(
                        [StubResponse(large_page(6, has_more=False))]
                    ),
                    actor="worker",
                )
            )
        session.expire_all()
        preserved = session.scalar(select(ExternalIntelligenceCheckpointRow))
        assert preserved is not None
        assert preserved.bytes_completed == first.bytes_fetched
        assert preserved.last_run_id == first.run_id
    finally:
        session.close()
        engine.dispose()


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value.update({"has_more": True, "next_cursor": None}),
            "schema validation",
        ),
        (
            lambda value: value["items"][0].update(
                {"status": "revoked", "status_changed_at": NOW.isoformat()}
            ),
            "schema validation",
        ),
        (
            lambda value: value["items"][0]["record"]["ai_analysis"].update(
                {"confidence_method_version": None}
            ),
            "schema validation",
        ),
        (
            lambda value: value["items"][0]["record"].update(
                {"ai_analysis": None, "confidence": 0.5}
            ),
            "schema validation",
        ),
    ],
)
def test_page_contract_fails_closed_for_ambiguous_lifecycle_or_confidence(
    mutate: Any,
    message: str,
) -> None:
    value = json.loads(_page([_item("article-1")]))
    mutate(value)

    with pytest.raises(InvalidIntelligencePayload, match=message):
        parse_external_datapoint_page(_json_bytes(value), page_size=1)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["items"][0]["record"].update({"revoked": True}),
        lambda value: value["items"][0]["record"].update({"confidence": 0.12}),
        lambda value: value["items"][0]["record"].update(
            {"source_url": (f"https://user:{UPSTREAM_CREDENTIAL}@publisher.example/article-1")}
        ),
        lambda value: value["items"][0]["record"]["tags"].append("traceless:source-status:active"),
    ],
)
def test_page_contract_rejects_conflicting_or_reserved_source_fields(
    mutate: Any,
) -> None:
    value = json.loads(_page([_item("article-1")]))
    mutate(value)
    with pytest.raises(InvalidIntelligencePayload, match="schema validation"):
        parse_external_datapoint_page(_json_bytes(value), page_size=1)


def test_page_contract_rejects_empty_intermediate_and_duplicate_page_identity() -> None:
    empty_intermediate = json.loads(_page([], has_more=True, next_cursor="next"))
    duplicate = json.loads(_page([_item("article-1"), _item("article-1")]))
    for value in (empty_intermediate, duplicate):
        with pytest.raises(InvalidIntelligencePayload, match="schema validation"):
            parse_external_datapoint_page(_json_bytes(value), page_size=2)

    with pytest.raises(ValueError, match="page_size"):
        parse_external_datapoint_page(_page([]), page_size=0)
    with pytest.raises(InvalidIntelligencePayload, match="more than the requested"):
        parse_external_datapoint_page(
            _page([_item("article-1"), _item("article-2")]),
            page_size=1,
        )


def test_pagination_rejects_an_unbound_caller_cursor_before_any_request() -> None:
    engine, session, repository = _repository()
    client = RecordingHttpClient(
        [StubResponse(_page([_item("article-1")], has_more=True, next_cursor="same"))]
    )
    try:
        with pytest.raises(OperationalConflictError, match="persisted checkpoint"):
            asyncio.run(
                pull_external_intelligence(
                    settings=_settings(),
                    repository=repository,
                    client=client,
                    actor="worker",
                    cursor="same",
                )
            )
        assert session.scalar(select(GlobalIntelRecordRow)) is None
        assert client.requests == []
    finally:
        session.close()
        engine.dispose()


def test_snapshot_change_and_duplicate_identity_across_pages_are_rejected() -> None:
    scenarios = [
        (
            _page([_item("article-2")], feed_version="changed"),
            "changed during pagination",
        ),
        (_page([_item("article-1")]), "repeated a record identity"),
    ]
    for second_page, message in scenarios:
        engine, session, repository = _repository()
        try:
            client = RecordingHttpClient(
                [
                    StubResponse(_page([_item("article-1")], has_more=True, next_cursor="next")),
                    StubResponse(second_page),
                ]
            )
            with pytest.raises(InvalidIntelligencePayload, match=message):
                asyncio.run(
                    pull_external_intelligence(
                        settings=_settings(),
                        repository=repository,
                        client=client,
                        actor="worker",
                    )
                )
            assert session.scalar(select(GlobalIntelRecordRow)) is None
            failed_run = session.scalar(
                select(ExternalIntelligenceSyncRunRow).order_by(
                    ExternalIntelligenceSyncRunRow.started_at.desc()
                )
            )
            assert failed_run is not None and failed_run.status == "failed"
        finally:
            session.close()
            engine.dispose()


def test_empty_final_page_and_configured_pull_limits_are_explicit() -> None:
    engine, session, repository = _repository()
    try:
        empty = asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=RecordingHttpClient([StubResponse(_page([]))]),
                actor="worker",
            )
        )
        assert empty.complete is True
        assert empty.records_fetched == empty.created == 0

        with pytest.raises(RuntimeError, match="not configured"):
            asyncio.run(
                pull_external_intelligence(
                    settings=Settings(environment="test"),
                    repository=repository,
                    client=RecordingHttpClient([]),
                    actor="worker",
                )
            )
        with pytest.raises(RuntimeError, match="page budget"):
            asyncio.run(
                pull_external_intelligence(
                    settings=_settings(),
                    repository=repository,
                    client=RecordingHttpClient([]),
                    actor="worker",
                    max_pages=11,
                )
            )

        two_records = RecordingHttpClient(
            [StubResponse(_page([_item("article-1"), _item("article-2")]))]
        )
        with pytest.raises(InvalidIntelligencePayload, match="record limit"):
            asyncio.run(
                pull_external_intelligence(
                    settings=_settings(
                        external_intelligence_page_size=2,
                        external_intelligence_max_records=1,
                    ),
                    repository=repository,
                    client=two_records,
                    actor="worker",
                )
            )

        with pytest.raises(InvalidIntelligencePayload, match="cumulative snapshot limits"):
            asyncio.run(
                pull_external_intelligence(
                    settings=_settings(external_intelligence_max_records=1),
                    repository=repository,
                    client=RecordingHttpClient(
                        [
                            StubResponse(
                                _page(
                                    [_item("article-limit")],
                                    has_more=True,
                                    next_cursor="limit-next",
                                )
                            )
                        ]
                    ),
                    actor="worker",
                )
            )
    finally:
        session.close()
        engine.dispose()


def test_response_and_endpoint_security_bounds() -> None:
    response = StubResponse(
        b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "2048"},
    )
    provider = ExternalDatapointProvider(
        RecordingHttpClient([response]),
        ENDPOINT,
        token=UPSTREAM_CREDENTIAL,
        allowed_hosts={"pipeline.example.test"},
        max_page_bytes=1_024,
    )
    with pytest.raises(IntelligencePayloadTooLarge):
        asyncio.run(provider.fetch_page())

    streamed = ChunkedResponse([b"x" * 800, b"y" * 300, b"z" * 800])
    streaming_provider = ExternalDatapointProvider(
        RecordingHttpClient([streamed]),  # type: ignore[list-item]
        ENDPOINT,
        token=UPSTREAM_CREDENTIAL,
        allowed_hosts={"pipeline.example.test"},
        max_page_bytes=1_024,
    )
    with pytest.raises(IntelligencePayloadTooLarge):
        asyncio.run(streaming_provider.fetch_page())
    # The third chunk is never consumed: the connector enforces its quota
    # while receiving decoded bytes instead of buffering the whole response.
    assert streamed.chunks_read == 2

    with pytest.raises(ValueError, match="allowlisted"):
        validate_external_datapoint_endpoint(
            "https://other.example/v1/datapoints",
            {"pipeline.example.test"},
        )
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        validate_external_datapoint_endpoint(
            f"https://user:{UPSTREAM_CREDENTIAL}@pipeline.example.test/v1/datapoints",
            {"pipeline.example.test"},
        )
    with pytest.raises(ValueError, match="explicit hostname allowlist"):
        validate_external_datapoint_endpoint(ENDPOINT, set())

    with pytest.raises(ValueError, match="token"):
        ExternalDatapointProvider(
            RecordingHttpClient([]),
            ENDPOINT,
            token="x" * 5,
            allowed_hosts={"pipeline.example.test"},
        )
    with pytest.raises(ValueError, match="auth_scheme"):
        ExternalDatapointProvider(
            RecordingHttpClient([]),
            ENDPOINT,
            token=UPSTREAM_CREDENTIAL,
            auth_scheme="Basic",  # type: ignore[arg-type]
            allowed_hosts={"pipeline.example.test"},
        )
    for cursor in ("", " leading", "line\nbreak"):
        with pytest.raises(ValueError, match="cursor"):
            asyncio.run(
                ExternalDatapointProvider(
                    RecordingHttpClient([]),
                    ENDPOINT,
                    token=UPSTREAM_CREDENTIAL,
                    allowed_hosts={"pipeline.example.test"},
                ).fetch_page(cursor)
            )


def test_provenance_wrapper_cannot_bypass_canonical_evidence_size_limit() -> None:
    value = json.loads(_page([_item("article-large")]))
    value["items"][0]["record"]["raw_evidence"] = {"blob": "x" * 262_000}
    parsed = parse_external_datapoint_page(_json_bytes(value), max_bytes=300_000, page_size=1)

    with pytest.raises(InvalidIntelligencePayload, match="provenance wrapping"):
        parsed.page.items[0].to_canonical_record()


def test_future_dated_revision_is_quarantined_without_overwriting_current_record() -> None:
    engine, session, repository = _repository()
    try:
        accepted = asyncio.run(
            pull_external_intelligence(
                settings=_settings(external_intelligence_clock_skew_seconds=60),
                repository=repository,
                client=RecordingHttpClient([StubResponse(_page([_item("article-clock")]))]),
                actor="worker",
            )
        )
        assert accepted.created == 1
        future = datetime.now(UTC) + timedelta(hours=2)
        quarantined = asyncio.run(
            pull_external_intelligence(
                settings=_settings(external_intelligence_clock_skew_seconds=60),
                repository=repository,
                client=RecordingHttpClient(
                    [
                        StubResponse(
                            _page(
                                [_item("article-clock", modified_at=future)],
                                feed_version="future-snapshot",
                                generated_at=future,
                            )
                        )
                    ]
                ),
                actor="worker",
            )
        )

        assert quarantined.quarantined == 1
        assert quarantined.created == quarantined.updated == quarantined.unchanged == 0
        current = session.scalar(
            select(GlobalIntelRecordRow).where(GlobalIntelRecordRow.external_id == "article-clock")
        )
        assert current is not None
        assert current.modified_at == NOW
        revisions = list(
            session.scalars(
                select(GlobalIntelRevisionRow)
                .where(GlobalIntelRevisionRow.external_id == "article-clock")
                .order_by(GlobalIntelRevisionRow.received_at)
            )
        )
        assert [revision.outcome for revision in revisions] == [
            "applied",
            "quarantined",
        ]
        assert revisions[0].raw_evidence == current.raw_evidence
        assert revisions[1].quarantine_reason is not None
        run = session.get(ExternalIntelligenceSyncRunRow, quarantined.run_id)
        assert run is not None and run.status == "quarantined"
    finally:
        session.close()
        engine.dispose()


def test_connector_serializes_runs_and_recovers_a_stale_execution() -> None:
    engine, session, repository = _repository()
    settings = _settings(external_intelligence_stale_run_seconds=60)
    try:
        asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=RecordingHttpClient([StubResponse(_page([]))]),
                actor="worker",
            )
        )
        connector = session.scalar(select(ExternalIntelligenceConnectorRow))
        assert connector is not None
        stale_snapshot_id = uuid4()
        active = ExternalIntelligenceSyncRunRow(
            organization_id=repository.organization_id,
            connector_id=connector.id,
            connector_config_version=connector.config_version,
            connector_identity_sha256=connector.identity_sha256,
            snapshot_id=stale_snapshot_id,
            status="running",
            started_by="crashed-worker",
            started_at=datetime.now(UTC),
            claim_token_sha256="a" * 64,
            lease_expires_at=datetime.now(UTC) + timedelta(seconds=60),
            heartbeat_at=datetime.now(UTC),
        )
        session.add(active)
        session.commit()
        stale_claim = ExternalSyncRunClaim(
            run_id=active.id,
            connector_id=connector.id,
            connector_config_version=connector.config_version,
            connector_identity_sha256=connector.identity_sha256,
            snapshot_id=stale_snapshot_id,
            token_sha256="a" * 64,
        )
        blocked_client = RecordingHttpClient([])

        with pytest.raises(OperationalConflictError, match="already running"):
            asyncio.run(
                pull_external_intelligence(
                    settings=settings,
                    repository=repository,
                    client=blocked_client,
                    actor="second-worker",
                )
            )
        assert blocked_client.requests == []

        active.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
        recovered = asyncio.run(
            pull_external_intelligence(
                settings=settings,
                repository=repository,
                client=RecordingHttpClient(
                    [StubResponse(_page([], feed_version="after-recovery"))]
                ),
                actor="second-worker",
            )
        )
        session.refresh(active)
        assert recovered.complete is True
        assert active.status == "failed"
        assert active.error_code == "stale_run_recovered"
        assert active.claim_token_sha256 is None
        assert active.lease_expires_at is None

        stale_payload = _page([_item("stale-write")])
        stale_page = parse_external_datapoint_page(
            stale_payload,
            page_size=1,
        )
        with pytest.raises(ExternalSyncLeaseLostError, match="ownership changed"):
            _persist_owned_page(
                settings=settings,
                repository=repository,
                connector=connector,
                claim=stale_claim,
                page_result=stale_page,
                page_number=1,
                request_cursor=None,
                local_pages_fetched=1,
                local_records_fetched=1,
                local_bytes_fetched=len(stale_payload),
                snapshot_pages_fetched=1,
                snapshot_records_fetched=1,
                snapshot_bytes_fetched=len(stale_payload),
            )
        assert (
            session.scalar(
                select(ExternalIntelligenceSyncPageRow).where(
                    ExternalIntelligenceSyncPageRow.run_id == stale_claim.run_id
                )
            )
            is None
        )
        assert (
            session.scalar(
                select(ExternalIntelligenceSyncIdentityRow).where(
                    ExternalIntelligenceSyncIdentityRow.run_id == stale_claim.run_id
                )
            )
            is None
        )
        with pytest.raises(ExternalSyncLeaseLostError, match="before commit"):
            _finalize_owned_run(
                repository=repository,
                claim=stale_claim,
                status="completed",
                next_cursor=None,
                created=1,
                updated=0,
                unchanged=0,
                quarantined=0,
                manifest_sha256="b" * 64,
            )
        session.rollback()
        assert (
            _fail_owned_run(
                repository=repository,
                claim=stale_claim,
                error=RuntimeError("stale failure"),
            )
            is False
        )
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_database_rejects_terminal_run_that_retains_its_claim_token() -> None:
    engine, session, repository = _repository()
    try:
        asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=RecordingHttpClient([StubResponse(_page([]))]),
                actor="worker",
            )
        )
        connector = session.scalar(select(ExternalIntelligenceConnectorRow))
        assert connector is not None
        now = datetime.now(UTC)
        run = ExternalIntelligenceSyncRunRow(
            organization_id=repository.organization_id,
            connector_id=connector.id,
            connector_config_version=connector.config_version,
            connector_identity_sha256=connector.identity_sha256,
            snapshot_id=uuid4(),
            status="running",
            started_by="constraint-test",
            started_at=now,
            claim_token_sha256="c" * 64,
            lease_expires_at=now + timedelta(minutes=5),
            heartbeat_at=now,
        )
        session.add(run)
        session.commit()

        run.status = "failed"
        run.completed_at = now
        run.lease_expires_at = None
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
    finally:
        session.close()
        engine.dispose()


def test_independent_run_heartbeat_renews_only_its_claim_token() -> None:
    engine, session, repository = _repository()
    try:
        asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=RecordingHttpClient([StubResponse(_page([]))]),
                actor="worker",
            )
        )
        connector = session.scalar(select(ExternalIntelligenceConnectorRow))
        assert connector is not None
        now = datetime.now(UTC)
        snapshot_id = uuid4()
        run = ExternalIntelligenceSyncRunRow(
            organization_id=repository.organization_id,
            connector_id=connector.id,
            connector_config_version=connector.config_version,
            connector_identity_sha256=connector.identity_sha256,
            snapshot_id=snapshot_id,
            status="running",
            started_by="heartbeat-test",
            started_at=now,
            claim_token_sha256="c" * 64,
            lease_expires_at=now + timedelta(minutes=5),
            heartbeat_at=now,
        )
        session.add(run)
        session.commit()
        claim = ExternalSyncRunClaim(
            run_id=run.id,
            connector_id=connector.id,
            connector_config_version=connector.config_version,
            connector_identity_sha256=connector.identity_sha256,
            snapshot_id=snapshot_id,
            token_sha256="c" * 64,
        )
        ownership_renewed = Event()
        heartbeat = _ExternalRunHeartbeat(
            settings=_settings(),
            repository=repository,
            claim=claim,
            ownership_heartbeat=ownership_renewed.set,
        )
        heartbeat._enabled = True
        heartbeat._interval_seconds = 0.01
        heartbeat.start()
        assert ownership_renewed.wait(timeout=1.0)
        heartbeat.stop()
        heartbeat.raise_if_lost()
        session.expire(run)
        assert run.heartbeat_at > now
        assert run.lease_expires_at is not None
        assert run.lease_expires_at > now + timedelta(minutes=5)

        run.claim_token_sha256 = "d" * 64
        session.commit()
        stale_heartbeat = _ExternalRunHeartbeat(
            settings=_settings(),
            repository=repository,
            claim=claim,
            ownership_heartbeat=None,
        )
        stale_heartbeat._enabled = True
        stale_heartbeat._interval_seconds = 0.01
        stale_heartbeat.start()
        assert stale_heartbeat._stop_event.wait(timeout=1.0)
        stale_heartbeat.stop()
        with pytest.raises(ExternalSyncLeaseLostError, match="heartbeat lost"):
            stale_heartbeat.raise_if_lost()

        session.expire(run)
        assert run.claim_token_sha256 == "d" * 64
        run.status = "failed"
        run.completed_at = datetime.now(UTC)
        run.claim_token_sha256 = None
        run.lease_expires_at = None
        session.commit()
    finally:
        session.close()
        engine.dispose()


def test_settings_require_paired_secret_and_exact_allowlist() -> None:
    with pytest.raises(ValidationError, match="configured together"):
        Settings(external_intelligence_url=ENDPOINT)
    with pytest.raises(ValidationError, match="explicitly allowlisted"):
        Settings(
            external_intelligence_url=ENDPOINT,
            external_intelligence_token=SecretStr(UPSTREAM_CREDENTIAL),
        )
    with pytest.raises(ValidationError):
        Settings(external_intelligence_credentials={"tenant:feed": SecretStr(UPSTREAM_CREDENTIAL)})
    with pytest.raises(ValidationError, match="case-insensitively unique"):
        Settings(
            external_intelligence_credentials={
                "Tenant": {"feed": _credential(UPSTREAM_CREDENTIAL)},
                "tenant": {"other": _credential(token_urlsafe(32))},
            },
            intelligence_allowed_hosts=[
                "www.cisa.gov",
                "api.first.org",
                "services.nvd.nist.gov",
                "pipeline.example.test",
            ],
        )
    with pytest.raises(ValidationError, match="HTTP timeout plus one heartbeat"):
        Settings(
            external_intelligence_timeout_seconds=50,
            external_intelligence_heartbeat_seconds=15,
            external_intelligence_stale_run_seconds=60,
        )
    with pytest.raises(ValidationError, match="case-insensitively unique"):
        Settings(
            external_intelligence_credentials={
                "tenant": {
                    "Feed": _credential(UPSTREAM_CREDENTIAL),
                    "feed": _credential(token_urlsafe(32)),
                }
            },
            intelligence_allowed_hosts=[
                "www.cisa.gov",
                "api.first.org",
                "services.nvd.nist.gov",
                "pipeline.example.test",
            ],
        )


def test_structured_credential_namespaces_do_not_collide_on_colons() -> None:
    engine, session, repository_a = _repository()
    organization_b = uuid4()
    repository_b = OperationalRepository(
        session,
        organization_id=organization_b,
        organization_key="tenant",
        organization_name="Tenant",
    )
    settings = _settings(
        external_intelligence_url=None,
        external_intelligence_token=None,
        external_intelligence_credentials={
            "tenant:blue": {"feed": _credential("a" * 32)},
            "tenant": {"blue:feed": _credential("b" * 32)},
        },
    )
    repository_a.organization_key = "tenant:blue"
    try:
        first = upsert_external_connector(
            settings=settings,
            repository=repository_a,
            payload=ExternalIntelligenceConnectorUpdate(
                endpoint=ENDPOINT,
                credential_reference="feed",
            ),
            actor="admin-a",
        )
        second = upsert_external_connector(
            settings=settings,
            repository=repository_b,
            payload=ExternalIntelligenceConnectorUpdate(
                endpoint=ENDPOINT,
                credential_reference="blue:feed",
            ),
            actor="admin-b",
        )
        assert first.credential_reference == "feed"
        assert second.credential_reference == "blue:feed"
    finally:
        session.close()
        engine.dispose()


def test_nested_credentials_parse_from_the_documented_json_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = token_urlsafe(32)
    monkeypatch.setenv(
        "TRACELESS_EXTERNAL_INTELLIGENCE_CREDENTIALS",
        json.dumps(
            {
                "tenant-id": {
                    "tenant-feed-primary": {
                        "secret": token,
                        "origin": "https://pipeline.example.test",
                    }
                }
            }
        ),
    )

    settings = Settings(
        _env_file=None,
        intelligence_allowed_hosts=[
            "www.cisa.gov",
            "api.first.org",
            "services.nvd.nist.gov",
            "pipeline.example.test",
        ],
    )

    assert (
        settings.external_intelligence_credentials["tenant-id"][
            "tenant-feed-primary"
        ].secret.get_secret_value()
        == token
    )


def test_full_snapshot_reconciliation_preserves_record_identity() -> None:
    from traceless_api.services.intelligence_hub import IntelligenceHubService

    engine, session, repository = _repository()
    try:
        external_client = RecordingHttpClient(
            [StubResponse(_page([_item("article-stable")]))]
        )
        result = asyncio.run(
            pull_external_intelligence(
                settings=_settings(),
                repository=repository,
                client=external_client,
                actor="snapshot-test",
            )
        )
        assert result.created == 1
        original = session.scalar(
            select(GlobalIntelRecordRow).where(
                GlobalIntelRecordRow.external_id == "article-stable"
            )
        )
        assert original is not None
        original_id = original.id
        original.review_status = "approved"
        original.reviewed_by = "analyst"
        original.reviewed_at = datetime.now(UTC)
        session.flush()

        withdrawn, manifest = IntelligenceHubService(repository).reconcile_full_snapshot(
            feed_id="separate-cyber-pipeline",
            feed_version="snapshot-43",
            feed_generated_at=NOW + timedelta(minutes=5),
            present_identities=set(),
            sync_run_id=result.run_id,
            actor="snapshot-test",
        )
        session.commit()

        current = session.get(GlobalIntelRecordRow, original_id)
        assert current is not None
        assert current.id == original_id
        assert current.revoked is True
        assert current.review_status == "pending"
        assert current.title == "Withdrawn publisher record"
        assert withdrawn == {original_id}
        assert manifest is not None and len(manifest) == 64
        revision = session.scalar(
            select(GlobalIntelRevisionRow)
            .where(GlobalIntelRevisionRow.record_id == original_id)
            .order_by(GlobalIntelRevisionRow.received_at.desc())
        )
        assert revision is not None
        assert revision.quarantine_reason == "publisher_snapshot_withdrawal"
    finally:
        session.close()
        engine.dispose()
