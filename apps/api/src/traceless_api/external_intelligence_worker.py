"""Tenant-safe scheduler for the pull-only external intelligence connector.

This worker never scrapes. It only invokes the same bounded, normalized pull
service as the authenticated API after atomically claiming a due connector.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from typing import Literal
from uuid import UUID

import httpx
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session, sessionmaker

from traceless_api import __version__
from traceless_api.core.config import Settings
from traceless_api.db.models import (
    ExternalIntelligenceConnectorRow,
    ExternalIntelligenceSyncRunRow,
    OrganizationRow,
)
from traceless_api.db.session import (
    apply_tenant_rls_scope,
    create_database_engine,
    create_schema,
    create_session_factory,
)
from traceless_api.integrations.intelligence.external_datapoints import (
    ExternalDatapointHttpClient,
)
from traceless_api.services.external_intelligence_pull import (
    pull_external_intelligence,
)
from traceless_api.services.operational_repository import OperationalRepository

logger = logging.getLogger(__name__)

ExternalClientFactory = Callable[[], AbstractAsyncContextManager[ExternalDatapointHttpClient]]


class ScheduledClaimLostError(RuntimeError):
    """A newer scheduler owns the connector; the stale worker is fenced out."""


@dataclass(frozen=True, slots=True)
class ScheduledConnectorClaim:
    connector_id: UUID
    organization_id: UUID
    config_version: int
    sync_interval_seconds: int
    claim_token_sha256: str


@dataclass(frozen=True, slots=True)
class ScheduledSyncOutcome:
    connector_id: UUID
    organization_id: UUID
    status: Literal["completed", "partial", "failed", "fenced"]
    run_id: UUID | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class ScheduledSyncBatchResult:
    outcomes: tuple[ScheduledSyncOutcome, ...]

    @property
    def processed(self) -> int:
        return len(self.outcomes)

    @property
    def completed(self) -> int:
        return sum(outcome.status == "completed" for outcome in self.outcomes)

    @property
    def partial(self) -> int:
        return sum(outcome.status == "partial" for outcome in self.outcomes)

    @property
    def failed(self) -> int:
        return sum(outcome.status == "failed" for outcome in self.outcomes)

    @property
    def fenced(self) -> int:
        return sum(outcome.status == "fenced" for outcome in self.outcomes)


def create_external_intelligence_http_client() -> httpx.AsyncClient:
    """Create a proxy-independent client that refuses redirects."""

    return httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": f"traceless-external-intelligence-worker/{__version__}"},
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
    )


async def process_due_external_intelligence(
    *,
    settings: Settings,
    session_factory: sessionmaker[Session],
    client_factory: ExternalClientFactory = create_external_intelligence_http_client,
    limit: int | None = None,
    due_at: datetime | None = None,
) -> ScheduledSyncBatchResult:
    """Claim and process one bounded pass of due tenant connectors.

    Each claim advances its next due time before network I/O. The existing
    synchronization lock then serializes the actual pull and recovers stale
    runs. A failed tenant is recorded in the result and never aborts the pass.
    """

    batch_limit = settings.external_intelligence_scheduler_batch_size if limit is None else limit
    if not 1 <= batch_limit <= 500:
        raise ValueError("scheduled connector batch limit must be between 1 and 500")
    effective_due_at = _as_aware(due_at or datetime.now(UTC))
    worker_id = f"{settings.external_intelligence_worker_id}:{os.getpid()}"[:160]
    actor = f"external-sync-worker:{worker_id}"[:160]
    outcomes: list[ScheduledSyncOutcome] = []
    claimed_ids: set[UUID] = set()

    async with client_factory() as client:
        while len(outcomes) < batch_limit:
            claim = _claim_next_due_connector(
                session_factory,
                due_at=effective_due_at,
                excluded_connector_ids=claimed_ids,
                claim_seconds=settings.external_intelligence_schedule_claim_seconds,
                worker_id=worker_id,
            )
            if claim is None:
                break
            claimed_ids.add(claim.connector_id)
            try:
                with session_factory() as session:
                    repository = _repository_for_claim(session, claim)
                    result = await pull_external_intelligence(
                        settings=settings,
                        repository=repository,
                        client=client,
                        actor=actor,
                        ownership_heartbeat=lambda claim=claim: _require_schedule_claim_heartbeat(
                            session_factory,
                            claim,
                            lease_seconds=max(
                                settings.external_intelligence_schedule_claim_seconds,
                                settings.external_intelligence_stale_run_seconds,
                            ),
                        ),
                    )
                    next_sync_at = (
                        _completed_run_time(session, claim, result.run_id)
                        + timedelta(seconds=claim.sync_interval_seconds)
                        if result.complete
                        else datetime.now(UTC)
                    )
                    rescheduled = _reschedule_connector(session, claim, next_sync_at=next_sync_at)
                    session.commit()
                    if not rescheduled:
                        raise ScheduledClaimLostError(
                            "Scheduled connector claim changed before rescheduling"
                        )
                    outcomes.append(
                        ScheduledSyncOutcome(
                            connector_id=claim.connector_id,
                            organization_id=claim.organization_id,
                            status="completed" if result.complete else "partial",
                            run_id=result.run_id,
                        )
                    )
            except ScheduledClaimLostError as error:
                logger.warning(
                    "Scheduled external intelligence worker was fenced for connector %s",
                    claim.connector_id,
                )
                outcomes.append(
                    ScheduledSyncOutcome(
                        connector_id=claim.connector_id,
                        organization_id=claim.organization_id,
                        status="fenced",
                        error_code=type(error).__name__[:100],
                    )
                )
            except Exception as error:
                retained_claim = False
                try:
                    with session_factory() as retry_session:
                        retained_claim = _reschedule_connector(
                            retry_session,
                            claim,
                            next_sync_at=datetime.now(UTC)
                            + timedelta(
                                seconds=settings.external_intelligence_schedule_retry_seconds
                            ),
                        )
                        retry_session.commit()
                except Exception:
                    logger.exception(
                        "Could not persist retry time for scheduled connector %s",
                        claim.connector_id,
                    )
                logger.exception(
                    "Scheduled external intelligence sync failed for connector %s "
                    "in organization %s",
                    claim.connector_id,
                    claim.organization_id,
                )
                outcomes.append(
                    ScheduledSyncOutcome(
                        connector_id=claim.connector_id,
                        organization_id=claim.organization_id,
                        status="failed" if retained_claim else "fenced",
                        error_code=(
                            type(error).__name__[:100]
                            if retained_claim
                            else "ScheduledClaimLostError"
                        ),
                    )
                )

    return ScheduledSyncBatchResult(outcomes=tuple(outcomes))


def _claim_next_due_connector(
    session_factory: sessionmaker[Session],
    *,
    due_at: datetime,
    excluded_connector_ids: set[UUID],
    claim_seconds: int,
    worker_id: str = "external-intelligence-scheduler",
) -> ScheduledConnectorClaim | None:
    with session_factory() as session:
        if session.get_bind().dialect.name == "postgresql":
            dispatch = session.execute(
                text(
                    "SELECT connector_id, organization_id, config_version, "
                    "sync_interval_seconds FROM public.traceless_dispatch_due_connector("
                    "CAST(:excluded_connector_ids AS uuid[]))"
                ),
                {
                    "excluded_connector_ids": sorted(excluded_connector_ids, key=str),
                },
            ).one_or_none()
        else:
            statement = (
                select(
                    ExternalIntelligenceConnectorRow.id.label("connector_id"),
                    ExternalIntelligenceConnectorRow.organization_id,
                    ExternalIntelligenceConnectorRow.config_version,
                    ExternalIntelligenceConnectorRow.sync_interval_seconds,
                )
                .where(
                    ExternalIntelligenceConnectorRow.enabled.is_(True),
                    ExternalIntelligenceConnectorRow.sync_interval_seconds.is_not(None),
                    ExternalIntelligenceConnectorRow.next_sync_at.is_not(None),
                    ExternalIntelligenceConnectorRow.next_sync_at <= due_at,
                )
                .order_by(
                    ExternalIntelligenceConnectorRow.next_sync_at,
                    ExternalIntelligenceConnectorRow.id,
                )
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if excluded_connector_ids:
                statement = statement.where(
                    ExternalIntelligenceConnectorRow.id.not_in(excluded_connector_ids)
                )
            dispatch = session.execute(statement).one_or_none()
        if dispatch is None:
            return None
        assert dispatch.sync_interval_seconds is not None
        apply_tenant_rls_scope(session, dispatch.organization_id)
        claim_token_sha256 = sha256(token_urlsafe(32).encode()).hexdigest()
        claim_expires_at = due_at + timedelta(seconds=claim_seconds)
        claimed = session.execute(
            update(ExternalIntelligenceConnectorRow)
            .where(
                ExternalIntelligenceConnectorRow.id == dispatch.connector_id,
                ExternalIntelligenceConnectorRow.organization_id
                == dispatch.organization_id,
                ExternalIntelligenceConnectorRow.config_version
                == dispatch.config_version,
            )
            .values(
                next_sync_at=claim_expires_at,
                schedule_claim_token_sha256=claim_token_sha256,
                schedule_claimed_by=worker_id[:160],
                schedule_claimed_at=due_at,
                schedule_claim_expires_at=claim_expires_at,
                schedule_heartbeat_at=due_at,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:  # pragma: no cover - the dispatcher row is locked
            session.rollback()
            return None
        claim = ScheduledConnectorClaim(
            connector_id=dispatch.connector_id,
            organization_id=dispatch.organization_id,
            config_version=dispatch.config_version,
            sync_interval_seconds=dispatch.sync_interval_seconds,
            claim_token_sha256=claim_token_sha256,
        )
        session.commit()
        return claim


def _repository_for_claim(
    session: Session,
    claim: ScheduledConnectorClaim,
) -> OperationalRepository:
    apply_tenant_rls_scope(session, claim.organization_id)
    connector = session.scalar(
        select(ExternalIntelligenceConnectorRow).where(
            ExternalIntelligenceConnectorRow.id == claim.connector_id,
            ExternalIntelligenceConnectorRow.organization_id == claim.organization_id,
            ExternalIntelligenceConnectorRow.config_version == claim.config_version,
            ExternalIntelligenceConnectorRow.schedule_claim_token_sha256
            == claim.claim_token_sha256,
            ExternalIntelligenceConnectorRow.schedule_claim_expires_at > datetime.now(UTC),
        )
    )
    organization = session.get(OrganizationRow, claim.organization_id)
    if connector is None or organization is None:
        raise RuntimeError("Scheduled connector no longer has a valid tenant boundary")
    return OperationalRepository(
        session,
        organization_id=organization.id,
        organization_key=organization.external_key,
        organization_name=organization.name,
    )


def _require_schedule_claim_heartbeat(
    session_factory: sessionmaker[Session],
    claim: ScheduledConnectorClaim,
    *,
    lease_seconds: int,
) -> None:
    """Renew only the current random schedule token or fail as a fenced worker."""

    now = datetime.now(UTC)
    with session_factory() as session:
        apply_tenant_rls_scope(session, claim.organization_id)
        result = session.execute(
            update(ExternalIntelligenceConnectorRow)
            .where(
                ExternalIntelligenceConnectorRow.id == claim.connector_id,
                ExternalIntelligenceConnectorRow.organization_id == claim.organization_id,
                ExternalIntelligenceConnectorRow.config_version == claim.config_version,
                ExternalIntelligenceConnectorRow.schedule_claim_token_sha256
                == claim.claim_token_sha256,
                ExternalIntelligenceConnectorRow.schedule_claim_expires_at > now,
                ExternalIntelligenceConnectorRow.enabled.is_(True),
                ExternalIntelligenceConnectorRow.sync_interval_seconds.is_not(None),
            )
            .values(
                next_sync_at=now + timedelta(seconds=lease_seconds),
                schedule_claim_expires_at=now + timedelta(seconds=lease_seconds),
                schedule_heartbeat_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            session.rollback()
            raise ScheduledClaimLostError("Scheduled connector claim changed before heartbeat")
        session.commit()


def _reschedule_connector(
    session: Session,
    claim: ScheduledConnectorClaim,
    *,
    next_sync_at: datetime,
) -> bool:
    apply_tenant_rls_scope(session, claim.organization_id)
    result = session.execute(
        update(ExternalIntelligenceConnectorRow)
        .where(
            ExternalIntelligenceConnectorRow.id == claim.connector_id,
            ExternalIntelligenceConnectorRow.organization_id == claim.organization_id,
            ExternalIntelligenceConnectorRow.config_version == claim.config_version,
            ExternalIntelligenceConnectorRow.schedule_claim_token_sha256
            == claim.claim_token_sha256,
            ExternalIntelligenceConnectorRow.schedule_claim_expires_at > datetime.now(UTC),
            ExternalIntelligenceConnectorRow.enabled.is_(True),
            ExternalIntelligenceConnectorRow.sync_interval_seconds.is_not(None),
        )
        .values(
            next_sync_at=_as_aware(next_sync_at),
            schedule_claim_token_sha256=None,
            schedule_claimed_by=None,
            schedule_claimed_at=None,
            schedule_claim_expires_at=None,
            schedule_heartbeat_at=None,
        )
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def _completed_run_time(
    session: Session,
    claim: ScheduledConnectorClaim,
    run_id: UUID,
) -> datetime:
    run = session.scalar(
        select(ExternalIntelligenceSyncRunRow).where(
            ExternalIntelligenceSyncRunRow.id == run_id,
            ExternalIntelligenceSyncRunRow.connector_id == claim.connector_id,
            ExternalIntelligenceSyncRunRow.organization_id == claim.organization_id,
        )
    )
    if run is None or run.completed_at is None:
        raise RuntimeError("Scheduled synchronization has no completed tenant run")
    return _as_aware(run.completed_at)


def _as_aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def _run_worker(args: argparse.Namespace) -> None:
    settings = Settings()
    engine = create_database_engine(settings.database_url)
    if settings.auto_create_schema:
        create_schema(engine)
    session_factory = create_session_factory(engine)
    try:
        while True:
            await process_due_external_intelligence(
                settings=settings,
                session_factory=session_factory,
                limit=args.batch_size,
            )
            if args.once:
                break
            # A partial cursor is due immediately, but every pass is rate-limited
            # so a large snapshot cannot create a tight upstream polling loop.
            await asyncio.sleep(max(0.2, args.poll_seconds))
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pull due normalized intelligence feeds without performing scraping"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Process one due batch and exit")
    mode.add_argument(
        "--poll",
        action="store_true",
        help="Continuously poll for due connectors (the default)",
    )
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--batch-size", type=int, default=None)
    args = parser.parse_args()
    if args.poll_seconds <= 0:
        parser.error("--poll-seconds must be positive")
    if args.batch_size is not None and not 1 <= args.batch_size <= 500:
        parser.error("--batch-size must be between 1 and 500")
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_run_worker(args))


if __name__ == "__main__":
    main()
