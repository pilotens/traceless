import asyncio
import json
from collections.abc import Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import select

from traceless_api.core.config import ExternalIntelligenceCredentialBinding, Settings
from traceless_api.db.models import (
    ExternalIntelligenceConnectorRow,
    ExternalIntelligenceSyncRunRow,
)
from traceless_api.db.session import (
    create_database_engine,
    create_schema,
    create_session_factory,
)
from traceless_api.external_intelligence_worker import (
    ScheduledClaimLostError,
    _claim_next_due_connector,
    _repository_for_claim,
    _require_schedule_claim_heartbeat,
    _reschedule_connector,
    create_external_intelligence_http_client,
    process_due_external_intelligence,
)
from traceless_api.integrations.intelligence import (
    ExternalIntelligenceConnectorUpdate,
)
from traceless_api.services.external_intelligence_pull import (
    get_external_sync_status,
    upsert_external_connector,
)
from traceless_api.services.operational_repository import OperationalRepository


def _page(*, feed_id: str, generated_at: datetime) -> bytes:
    return json.dumps(
        {
            "schema_version": "1.0",
            "feed_id": feed_id,
            "feed_version": "snapshot-1",
            "generated_at": generated_at.isoformat(),
            "items": [],
            "has_more": False,
            "next_cursor": None,
        },
        separators=(",", ":"),
    ).encode()


@dataclass
class StubResponse:
    content: bytes
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})

    def raise_for_status(self) -> None:
        return None

    async def aiter_bytes(self) -> Any:
        yield self.content


class RoutingHttpClient:
    def __init__(
        self,
        *,
        generated_at: datetime,
        failures: set[str] | None = None,
    ) -> None:
        self.generated_at = generated_at
        self.failures = failures or set()
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
        if url in self.failures:
            raise httpx.ConnectError(
                "upstream unavailable",
                request=httpx.Request("GET", url),
            )
        feed_id = url.rsplit("/", maxsplit=1)[-1]
        return StubResponse(_page(feed_id=feed_id, generated_at=self.generated_at))

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> Any:
        assert method == "GET"
        yield await self.get(url, **kwargs)


def _settings(credentials: dict[str, dict[str, str]]) -> Settings:
    return Settings(
        environment="test",
        external_intelligence_credentials={
            organization_key: {
                reference: ExternalIntelligenceCredentialBinding(
                    secret=SecretStr(value),
                    origin="https://pipeline.example.test",
                )
                for reference, value in organization_credentials.items()
            }
            for organization_key, organization_credentials in credentials.items()
        },
        intelligence_allowed_hosts=[
            "www.cisa.gov",
            "api.first.org",
            "services.nvd.nist.gov",
            "pipeline.example.test",
        ],
        external_intelligence_page_size=10,
        external_intelligence_max_pages=2,
        external_intelligence_max_records=10,
    )


def _configure_connector(
    session: Any,
    *,
    settings: Settings,
    organization_id: UUID,
    organization_key: str,
    endpoint_key: str,
    credential_reference: str,
    enabled: bool = True,
    sync_interval_seconds: int | None = 60,
    next_sync_at: datetime | None = None,
) -> ExternalIntelligenceConnectorRow:
    repository = OperationalRepository(
        session,
        organization_id=organization_id,
        organization_key=organization_key,
        organization_name=f"Organization {organization_key}",
    )
    view = upsert_external_connector(
        settings=settings,
        repository=repository,
        payload=ExternalIntelligenceConnectorUpdate(
            endpoint=f"https://pipeline.example.test/v1/{endpoint_key}",
            credential_reference=credential_reference,
            enabled=enabled,
            sync_interval_seconds=sync_interval_seconds,
        ),
        actor="admin",
    )
    row = session.get(ExternalIntelligenceConnectorRow, view.id)
    assert row is not None
    if next_sync_at is not None:
        row.next_sync_at = next_sync_at
    session.commit()
    return row


def test_scheduler_processes_only_due_enabled_non_manual_connectors() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    session_factory = create_session_factory(engine)
    now = datetime.now(UTC)
    credentials = {
        "due": {"feed": "d" * 32},
        "manual": {"feed": "m" * 32},
        "disabled": {"feed": "x" * 32},
        "future": {"feed": "f" * 32},
    }
    settings = _settings(credentials)
    try:
        with session_factory() as session:
            due = _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="due",
                endpoint_key="due",
                credential_reference="feed",
                next_sync_at=now - timedelta(seconds=1),
            )
            _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="manual",
                endpoint_key="manual",
                credential_reference="feed",
                sync_interval_seconds=None,
            )
            _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="disabled",
                endpoint_key="disabled",
                credential_reference="feed",
                enabled=False,
            )
            _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="future",
                endpoint_key="future",
                credential_reference="feed",
                next_sync_at=now + timedelta(minutes=5),
            )
            due_id = due.id

        client = RoutingHttpClient(generated_at=now)

        @asynccontextmanager
        async def client_factory() -> Any:
            yield client

        result = asyncio.run(
            process_due_external_intelligence(
                settings=settings,
                session_factory=session_factory,
                client_factory=client_factory,
                due_at=now,
            )
        )

        assert result.processed == result.completed == 1
        assert result.failed == result.partial == 0
        assert result.outcomes[0].connector_id == due_id
        assert [request["url"] for request in client.requests] == [
            "https://pipeline.example.test/v1/due"
        ]
        with session_factory() as session:
            connectors = list(session.scalars(select(ExternalIntelligenceConnectorRow)))
            states = {}
            for key, interval, enabled in [
                ("manual", None, True),
                ("disabled", 60, False),
                ("future", 60, True),
            ]:
                connector = next(item for item in connectors if item.endpoint.endswith(f"/{key}"))
                repository = OperationalRepository(
                    session,
                    organization_id=connector.organization_id,
                    organization_key=key,
                    organization_name=f"Organization {key}",
                )
                status = get_external_sync_status(
                    settings=settings,
                    repository=repository,
                )
                states[key] = status.schedule_state
                assert connector.sync_interval_seconds == interval
                assert connector.enabled is enabled
            assert states == {
                "manual": "manual",
                "disabled": "disabled",
                "future": "scheduled",
            }
            due_row = session.get(ExternalIntelligenceConnectorRow, due_id)
            due_run = session.scalar(
                select(ExternalIntelligenceSyncRunRow).where(
                    ExternalIntelligenceSyncRunRow.connector_id == due_id
                )
            )
            assert due_row is not None and due_run is not None
            assert due_run.completed_at is not None
            assert due_row.next_sync_at == due_run.completed_at + timedelta(seconds=60)
    finally:
        engine.dispose()


def test_scheduler_resolves_credentials_within_each_tenant() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    session_factory = create_session_factory(engine)
    now = datetime.now(UTC)
    settings = _settings({"alpha": {"feed": "a" * 32}, "beta": {"feed": "b" * 32}})
    try:
        with session_factory() as session:
            alpha = _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="alpha",
                endpoint_key="alpha",
                credential_reference="feed",
                next_sync_at=now - timedelta(seconds=2),
            )
            beta = _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="beta",
                endpoint_key="beta",
                credential_reference="feed",
                next_sync_at=now - timedelta(seconds=1),
            )
            expected_pairs = {
                (alpha.organization_id, alpha.id),
                (beta.organization_id, beta.id),
            }

        client = RoutingHttpClient(generated_at=now)

        @asynccontextmanager
        async def client_factory() -> Any:
            yield client

        result = asyncio.run(
            process_due_external_intelligence(
                settings=settings,
                session_factory=session_factory,
                client_factory=client_factory,
                due_at=now,
            )
        )

        assert result.completed == 2
        assert {
            (outcome.organization_id, outcome.connector_id) for outcome in result.outcomes
        } == expected_pairs
        auth_by_endpoint = {str(request["url"]): request["headers"] for request in client.requests}
        assert (
            auth_by_endpoint["https://pipeline.example.test/v1/alpha"]["Authorization"]
            == "Bearer " + "a" * 32
        )
        assert (
            auth_by_endpoint["https://pipeline.example.test/v1/beta"]["Authorization"]
            == "Bearer " + "b" * 32
        )
        with session_factory() as session:
            assert {
                (run.organization_id, run.connector_id)
                for run in session.scalars(select(ExternalIntelligenceSyncRunRow))
            } == expected_pairs
    finally:
        engine.dispose()


def test_scheduler_continues_after_one_tenant_fails() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    session_factory = create_session_factory(engine)
    now = datetime.now(UTC)
    settings = _settings({"broken": {"feed": "z" * 32}, "healthy": {"feed": "h" * 32}})
    broken_endpoint = "https://pipeline.example.test/v1/broken"
    try:
        with session_factory() as session:
            broken = _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="broken",
                endpoint_key="broken",
                credential_reference="feed",
                next_sync_at=now - timedelta(seconds=2),
            )
            healthy = _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="healthy",
                endpoint_key="healthy",
                credential_reference="feed",
                next_sync_at=now - timedelta(seconds=1),
            )

        client = RoutingHttpClient(generated_at=now, failures={broken_endpoint})

        @asynccontextmanager
        async def client_factory() -> Any:
            yield client

        result = asyncio.run(
            process_due_external_intelligence(
                settings=settings,
                session_factory=session_factory,
                client_factory=client_factory,
                due_at=now,
            )
        )

        assert result.processed == 2
        assert result.failed == result.completed == 1
        assert [request["url"] for request in client.requests] == [
            broken_endpoint,
            "https://pipeline.example.test/v1/healthy",
        ]
        outcomes = {outcome.connector_id: outcome for outcome in result.outcomes}
        assert outcomes[broken.id].status == "failed"
        assert outcomes[healthy.id].status == "completed"
        with session_factory() as session:
            runs = {
                run.connector_id: run
                for run in session.scalars(select(ExternalIntelligenceSyncRunRow))
            }
            assert runs[broken.id].status == "failed"
            assert runs[healthy.id].status == "completed"
    finally:
        engine.dispose()


def test_expired_schedule_claim_is_reclaimed_and_success_uses_tenant_interval() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    session_factory = create_session_factory(engine)
    now = datetime.now(UTC)
    settings = _settings({"recover": {"feed": "r" * 32}})
    try:
        with session_factory() as session:
            connector = _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="recover",
                endpoint_key="recover",
                credential_reference="feed",
                sync_interval_seconds=600,
                next_sync_at=now - timedelta(seconds=1),
            )
            connector_id = connector.id

        abandoned_claim = _claim_next_due_connector(
            session_factory,
            due_at=now,
            excluded_connector_ids=set(),
            claim_seconds=30,
        )
        assert abandoned_claim is not None
        with session_factory() as session:
            claimed = session.get(ExternalIntelligenceConnectorRow, connector_id)
            assert claimed is not None
            assert claimed.next_sync_at == now + timedelta(seconds=30)
            assert session.scalar(select(ExternalIntelligenceSyncRunRow)) is None

        client = RoutingHttpClient(generated_at=now)

        @asynccontextmanager
        async def client_factory() -> Any:
            yield client

        before_expiry = asyncio.run(
            process_due_external_intelligence(
                settings=settings,
                session_factory=session_factory,
                client_factory=client_factory,
                due_at=now + timedelta(seconds=29),
            )
        )
        assert before_expiry.processed == 0

        recovered = asyncio.run(
            process_due_external_intelligence(
                settings=settings,
                session_factory=session_factory,
                client_factory=client_factory,
                due_at=now + timedelta(seconds=31),
            )
        )
        assert recovered.completed == 1
        with session_factory() as session:
            row = session.get(ExternalIntelligenceConnectorRow, connector_id)
            run = session.scalar(
                select(ExternalIntelligenceSyncRunRow).where(
                    ExternalIntelligenceSyncRunRow.connector_id == connector_id
                )
            )
            assert row is not None and run is not None and run.completed_at is not None
            assert row.next_sync_at == run.completed_at + timedelta(seconds=600)
    finally:
        engine.dispose()


def test_reclaimed_schedule_claim_fences_the_stale_scheduler() -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    session_factory = create_session_factory(engine)
    now = datetime.now(UTC)
    settings = _settings({"fenced": {"feed": "f" * 32}})
    try:
        with session_factory() as session:
            connector = _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="fenced",
                endpoint_key="fenced",
                credential_reference="feed",
                next_sync_at=now - timedelta(seconds=1),
            )

        first = _claim_next_due_connector(
            session_factory,
            due_at=now,
            excluded_connector_ids=set(),
            claim_seconds=30,
            worker_id="worker-one",
        )
        assert first is not None
        second = _claim_next_due_connector(
            session_factory,
            due_at=now + timedelta(seconds=31),
            excluded_connector_ids=set(),
            claim_seconds=30,
            worker_id="worker-one",
        )
        assert second is not None
        assert first.connector_id == second.connector_id == connector.id
        assert first.claim_token_sha256 != second.claim_token_sha256
        with pytest.raises(ScheduledClaimLostError, match="heartbeat"):
            _require_schedule_claim_heartbeat(
                session_factory,
                first,
                lease_seconds=120,
            )

        with session_factory() as session:
            with pytest.raises(RuntimeError, match="valid tenant boundary"):
                _repository_for_claim(session, first)
            assert (
                _reschedule_connector(
                    session,
                    first,
                    next_sync_at=now + timedelta(days=30),
                )
                is False
            )
            session.commit()

        with session_factory() as session:
            current = session.get(ExternalIntelligenceConnectorRow, connector.id)
            assert current is not None
            assert current.schedule_claim_token_sha256 == second.claim_token_sha256
            assert current.schedule_claimed_by == "worker-one"
            assert current.next_sync_at == now + timedelta(seconds=61)
            assert (
                _reschedule_connector(
                    session,
                    second,
                    next_sync_at=now + timedelta(minutes=5),
                )
                is True
            )
            session.commit()

        with session_factory() as session:
            current = session.get(ExternalIntelligenceConnectorRow, connector.id)
            assert current is not None
            assert current.next_sync_at == now + timedelta(minutes=5)
            assert current.schedule_claim_token_sha256 is None
            assert current.schedule_claim_expires_at is None
    finally:
        engine.dispose()


def test_scheduler_reports_a_lost_heartbeat_as_fenced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    session_factory = create_session_factory(engine)
    now = datetime.now(UTC)
    settings = _settings({"lost": {"feed": "l" * 32}})
    try:
        with session_factory() as session:
            connector = _configure_connector(
                session,
                settings=settings,
                organization_id=uuid4(),
                organization_key="lost",
                endpoint_key="lost",
                credential_reference="feed",
                next_sync_at=now - timedelta(seconds=1),
            )

        def lose_claim(*args: object, **kwargs: object) -> None:
            raise ScheduledClaimLostError("newer scheduler owns this connector")

        monkeypatch.setattr(
            "traceless_api.external_intelligence_worker._require_schedule_claim_heartbeat",
            lose_claim,
        )
        client = RoutingHttpClient(generated_at=now)

        @asynccontextmanager
        async def client_factory() -> Any:
            yield client

        result = asyncio.run(
            process_due_external_intelligence(
                settings=settings,
                session_factory=session_factory,
                client_factory=client_factory,
                due_at=now,
            )
        )

        assert result.processed == result.fenced == 1
        assert result.failed == result.completed == result.partial == 0
        assert result.outcomes[0].connector_id == connector.id
        assert result.outcomes[0].error_code == "ScheduledClaimLostError"
        assert client.requests == []
        with session_factory() as session:
            run = session.scalar(select(ExternalIntelligenceSyncRunRow))
            assert run is not None and run.status == "failed"
            assert run.claim_token_sha256 is None
            assert run.lease_expires_at is None
    finally:
        engine.dispose()


def test_schedule_bounds_and_worker_http_client_hardening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 60"):
        ExternalIntelligenceConnectorUpdate(
            endpoint="https://pipeline.example.test/v1/feed",
            credential_reference="feed",
            sync_interval_seconds=59,
        )
    with pytest.raises(ValidationError, match="less than or equal to 2592000"):
        ExternalIntelligenceConnectorUpdate(
            endpoint="https://pipeline.example.test/v1/feed",
            credential_reference="feed",
            sync_interval_seconds=2_592_001,
        )

    captured: dict[str, object] = {}

    def fake_async_client(**kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(
        "traceless_api.external_intelligence_worker.httpx.AsyncClient",
        fake_async_client,
    )
    create_external_intelligence_http_client()

    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False
