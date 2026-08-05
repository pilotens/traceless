"""Durable, tenant-scoped orchestration for an external normalized-datapoint API.

Traceless never scrapes in this boundary. It only pulls bounded, normalized pages
from a separately operated service. Credentials remain in the operator secret
store; the database contains a tenant-owned reference and append-only provenance.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from threading import Event, Thread
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.sql.selectable import Exists

from traceless_api.core.config import ExternalIntelligenceCredentialBinding, Settings
from traceless_api.db.external_intelligence_v2 import (
    ExternalIntelligenceSubscriptionStateRow,
)
from traceless_api.db.models import (
    ExternalIntelligenceCheckpointRow,
    ExternalIntelligenceConnectorRow,
    ExternalIntelligenceSyncIdentityRow,
    ExternalIntelligenceSyncPageRow,
    ExternalIntelligenceSyncRunRow,
)
from traceless_api.db.session import apply_tenant_rls_scope
from traceless_api.integrations.intelligence.errors import InvalidIntelligencePayload
from traceless_api.integrations.intelligence.external_datapoints import (
    ExternalDatapointHttpClient,
    ExternalDatapointPageResult,
    ExternalDatapointProvider,
    ExternalIntelligenceConnectorUpdate,
    ExternalIntelligenceConnectorView,
    ExternalIntelligencePullResult,
    ExternalIntelligenceSyncRunList,
    ExternalIntelligenceSyncRunView,
    ExternalIntelligenceSyncStatus,
    ScheduleState,
    validate_cursor,
    validate_external_datapoint_endpoint,
)
from traceless_api.models.intelligence_hub import CanonicalIntelFeed
from traceless_api.services.intelligence_correlation_jobs import (
    enqueue_tenant_correlation_jobs,
)
from traceless_api.services.intelligence_hub import IntelligenceHubService
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalRepository,
)

CONNECTOR_NAME = "external-datapoints"
LEGACY_CREDENTIAL_REFERENCE = "legacy:external-intelligence-token"


class ExternalSyncLeaseLostError(OperationalConflictError):
    """The current process no longer owns the durable synchronization lease."""


@dataclass(frozen=True, slots=True)
class ExternalSyncRunClaim:
    run_id: UUID
    connector_id: UUID
    connector_config_version: int
    connector_identity_sha256: str
    snapshot_id: UUID
    token_sha256: str


class _ExternalRunHeartbeat:
    """Renew a claimed run independently while network/import work is in flight."""

    def __init__(
        self,
        *,
        settings: Settings,
        repository: OperationalRepository,
        claim: ExternalSyncRunClaim,
        ownership_heartbeat: Callable[[], None] | None,
    ) -> None:
        bind = repository.session.get_bind()
        self._enabled = bind.dialect.name != "sqlite"
        self._session_factory = sessionmaker(
            bind=bind,
            autoflush=False,
            expire_on_commit=False,
        )
        self._organization_id = repository.organization_id
        self._claim = claim
        self._lease_seconds = settings.external_intelligence_stale_run_seconds
        self._interval_seconds = settings.external_intelligence_heartbeat_seconds
        self._ownership_heartbeat = ownership_heartbeat
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._error: Exception | None = None

    def start(self) -> None:
        if not self._enabled:
            return
        self._thread = Thread(
            target=self._run,
            name=f"external-intel-heartbeat-{self._claim.run_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=10.0)
            if self._thread.is_alive() and self._error is None:
                self._error = ExternalSyncLeaseLostError(
                    "External intelligence heartbeat did not stop before finalization"
                )

    def raise_if_lost(self) -> None:
        if self._error is not None:
            raise self._error

    def _run(self) -> None:
        while not self._stop_event.wait(self._interval_seconds):
            try:
                if not _renew_run_lease_with_factory(
                    session_factory=self._session_factory,
                    organization_id=self._organization_id,
                    claim=self._claim,
                    lease_seconds=self._lease_seconds,
                ):
                    raise ExternalSyncLeaseLostError(
                        "External intelligence synchronization heartbeat lost its lease"
                    )
                if self._ownership_heartbeat is not None:
                    self._ownership_heartbeat()
            except Exception as error:
                self._error = error
                self._stop_event.set()
                return


def upsert_external_connector(
    *,
    settings: Settings,
    repository: OperationalRepository,
    payload: ExternalIntelligenceConnectorUpdate,
    actor: str,
) -> ExternalIntelligenceConnectorView:
    """Create or rotate one tenant connector without accepting a credential value."""

    organization = repository.ensure_organization()
    endpoint = validate_external_datapoint_endpoint(
        payload.endpoint, settings.intelligence_allowed_hosts
    )
    _resolve_credential(
        settings,
        repository,
        payload.credential_reference,
        endpoint=endpoint,
    )
    row = _connector_row(repository, for_update=True)
    identity_sha256 = _connector_identity_sha256(
        organization_id=organization.id,
        name=CONNECTOR_NAME,
        endpoint=endpoint,
        auth_scheme=payload.auth_scheme,
        credential_reference=payload.credential_reference,
    )
    if row is not None:
        _require_connector_identity_integrity(row)
    identity_changed = row is None or any(
        (
            row.endpoint != endpoint,
            row.auth_scheme != payload.auth_scheme,
            row.credential_reference != payload.credential_reference,
        )
    )
    changed = identity_changed or row is None or any(
        (
            row.enabled != payload.enabled,
            row.sync_interval_seconds != payload.sync_interval_seconds,
        )
    )
    if row is not None and not changed:
        return ExternalIntelligenceConnectorView.model_validate(row)

    checkpoint = _checkpoint_row(repository, row.id) if row is not None else None
    active_run = (
        repository.session.scalar(
            select(ExternalIntelligenceSyncRunRow)
            .where(
                ExternalIntelligenceSyncRunRow.organization_id
                == repository.organization_id,
                ExternalIntelligenceSyncRunRow.connector_id == row.id,
                ExternalIntelligenceSyncRunRow.status == "running",
            )
            .limit(1)
        )
        if row is not None
        else None
    )
    if identity_changed and active_run is not None:
        raise OperationalConflictError(
            "Connector identity cannot change while a synchronization run is active"
        )
    if identity_changed and row is not None and checkpoint is not None:
        raise OperationalConflictError(
            "Connector identity cannot change while a snapshot checkpoint is active"
        )
    now = datetime.now(UTC)
    if row is None:
        next_sync_at = (
            now + timedelta(seconds=payload.sync_interval_seconds)
            if payload.enabled and payload.sync_interval_seconds is not None
            else None
        )
        row = ExternalIntelligenceConnectorRow(
            organization_id=organization.id,
            name=CONNECTOR_NAME,
            endpoint=endpoint,
            auth_scheme=payload.auth_scheme,
            credential_reference=payload.credential_reference,
            enabled=payload.enabled,
            sync_interval_seconds=payload.sync_interval_seconds,
            next_sync_at=next_sync_at,
            config_version=1,
            identity_sha256=identity_sha256,
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        repository.session.add(row)
        action = "intelligence.external_connector_created"
    else:
        prior_enabled = row.enabled
        prior_interval = row.sync_interval_seconds
        if prior_enabled and not payload.enabled and active_run is not None:
            repository.session.execute(
                update(ExternalIntelligenceSyncRunRow)
                .where(
                    ExternalIntelligenceSyncRunRow.id == active_run.id,
                    ExternalIntelligenceSyncRunRow.organization_id
                    == repository.organization_id,
                    ExternalIntelligenceSyncRunRow.connector_id == row.id,
                    ExternalIntelligenceSyncRunRow.connector_config_version
                    == row.config_version,
                    ExternalIntelligenceSyncRunRow.connector_identity_sha256
                    == row.identity_sha256,
                    ExternalIntelligenceSyncRunRow.status == "running",
                    ExternalIntelligenceSyncRunRow.claim_token_sha256
                    == active_run.claim_token_sha256,
                )
                .values(
                    status="failed",
                    completed_at=now,
                    claim_token_sha256=None,
                    heartbeat_at=now,
                    lease_expires_at=None,
                    error_code="connector_disabled",
                    error_message="The connector was disabled by an administrator.",
                )
                .execution_options(synchronize_session=False)
            )
        row.endpoint = endpoint
        row.auth_scheme = payload.auth_scheme
        row.credential_reference = payload.credential_reference
        row.identity_sha256 = identity_sha256
        row.enabled = payload.enabled
        row.sync_interval_seconds = payload.sync_interval_seconds
        row.schedule_claim_token_sha256 = None
        row.schedule_claimed_by = None
        row.schedule_claimed_at = None
        row.schedule_claim_expires_at = None
        row.schedule_heartbeat_at = None
        if not payload.enabled or payload.sync_interval_seconds is None:
            row.next_sync_at = None
        elif (
            not prior_enabled
            or prior_interval != payload.sync_interval_seconds
            or row.next_sync_at is None
        ):
            row.next_sync_at = now + timedelta(seconds=payload.sync_interval_seconds)
        if identity_changed:
            row.config_version += 1
        row.updated_at = now
        action = "intelligence.external_connector_updated"
    repository.session.flush()
    repository.audit(
        actor,
        action,
        "external_intelligence_connector",
        row.id,
        {
            "endpoint": endpoint,
            "auth_scheme": payload.auth_scheme,
            "credential_reference_sha256": sha256(
                payload.credential_reference.encode()
            ).hexdigest(),
            "enabled": payload.enabled,
            "sync_interval_seconds": payload.sync_interval_seconds,
            "next_sync_at": row.next_sync_at.isoformat() if row.next_sync_at is not None else None,
            "config_version": row.config_version,
            "identity_sha256": row.identity_sha256,
        },
    )
    return ExternalIntelligenceConnectorView.model_validate(row)


def get_external_connector(
    *, repository: OperationalRepository
) -> ExternalIntelligenceConnectorView:
    row = _connector_row(repository)
    if row is None:
        raise OperationalConflictError(
            "An external intelligence connector is not configured for this organization"
        )
    _require_connector_identity_integrity(row)
    return ExternalIntelligenceConnectorView.model_validate(row)


def get_external_sync_status(
    *, settings: Settings, repository: OperationalRepository
) -> ExternalIntelligenceSyncStatus:
    """Return safe connector health; opaque cursors and credentials are never exposed."""

    row = _connector_row(repository)
    if row is None:
        return ExternalIntelligenceSyncStatus(configured=False)
    _require_connector_identity_integrity(row)
    checkpoint = _checkpoint_row(repository, row.id)
    latest_run = repository.session.scalar(
        select(ExternalIntelligenceSyncRunRow)
        .where(
            ExternalIntelligenceSyncRunRow.organization_id == repository.organization_id,
            ExternalIntelligenceSyncRunRow.connector_id == row.id,
        )
        .order_by(ExternalIntelligenceSyncRunRow.started_at.desc())
        .limit(1)
    )
    try:
        _resolve_credential(
            settings,
            repository,
            row.credential_reference,
            endpoint=row.endpoint,
        )
        credential_available = True
    except OperationalConflictError:
        credential_available = False
    return ExternalIntelligenceSyncStatus(
        configured=True,
        connector_id=row.id,
        endpoint=row.endpoint,
        enabled=row.enabled,
        schedule_state=_schedule_state(row),
        sync_interval_seconds=row.sync_interval_seconds,
        next_sync_at=row.next_sync_at,
        config_version=row.config_version,
        credential_available=credential_available,
        checkpoint=checkpoint,
        latest_run=latest_run,
    )


def list_external_sync_runs(
    *,
    repository: OperationalRepository,
    limit: int,
    offset: int,
) -> ExternalIntelligenceSyncRunList:
    """Return tenant-scoped connector execution history without secrets/cursors."""

    connector = _connector_row(repository)
    if connector is None:
        return ExternalIntelligenceSyncRunList(
            items=[],
            total=0,
            limit=limit,
            offset=offset,
        )
    total = int(
        repository.session.scalar(
            select(func.count())
            .select_from(ExternalIntelligenceSyncRunRow)
            .where(
                ExternalIntelligenceSyncRunRow.organization_id
                == repository.organization_id,
                ExternalIntelligenceSyncRunRow.connector_id == connector.id,
            )
        )
        or 0
    )
    rows = list(
        repository.session.scalars(
            select(ExternalIntelligenceSyncRunRow)
            .where(
                ExternalIntelligenceSyncRunRow.organization_id
                == repository.organization_id,
                ExternalIntelligenceSyncRunRow.connector_id == connector.id,
            )
            .order_by(
                ExternalIntelligenceSyncRunRow.started_at.desc(),
                ExternalIntelligenceSyncRunRow.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )
    )
    return ExternalIntelligenceSyncRunList(
        items=[ExternalIntelligenceSyncRunView.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


async def pull_external_intelligence(
    *,
    settings: Settings,
    repository: OperationalRepository,
    client: ExternalDatapointHttpClient,
    actor: str,
    cursor: str | None = None,
    max_pages: int | None = None,
    ownership_heartbeat: Callable[[], None] | None = None,
) -> ExternalIntelligencePullResult:
    """Fetch and atomically import a bounded page set with a durable checkpoint."""

    repository.ensure_organization()
    page_budget = settings.external_intelligence_max_pages if max_pages is None else max_pages
    if not 1 <= page_budget <= settings.external_intelligence_max_pages:
        raise OperationalConflictError(
            "Requested page budget must be positive and not exceed the configured maximum"
        )
    try:
        connector = _configured_connector(settings, repository, actor)
        connector = _lock_connector_for_sync(
            settings=settings,
            repository=repository,
            connector_id=connector.id,
            actor=actor,
        )
        if not connector.enabled:
            raise OperationalConflictError("The external intelligence connector is disabled")
        credential_binding = _resolve_credential_binding(
            settings,
            repository,
            connector.credential_reference,
            endpoint=connector.endpoint,
        )
        configured_token = credential_binding.secret.get_secret_value()
        checkpoint = _checkpoint_row(repository, connector.id)
        subscription = _subscription_state_row(repository, connector.id)
        supplied_cursor = validate_cursor(cursor)
        if checkpoint is None:
            if supplied_cursor is not None:
                raise OperationalConflictError(
                    "A continuation cursor is accepted only from a persisted checkpoint"
                )
            start_cursor = None
            expected_snapshot: tuple[str, str, datetime] | None = None
            snapshot_id = uuid4()
            prior_pages = 0
            prior_records = 0
            prior_bytes = 0
            prior_page_provenance: list[tuple[int, str]] = []
            seen_identities: set[tuple[str, str]] = set()
            start_sync_token = (
                subscription.next_sync_token if subscription is not None else None
            )
        else:
            if supplied_cursor is not None and supplied_cursor != checkpoint.cursor:
                raise OperationalConflictError(
                    "The supplied cursor does not match the persisted snapshot checkpoint"
                )
            (
                prior_page_provenance,
                seen_identities,
            ) = _validate_checkpoint_provenance(
                repository=repository,
                connector=connector,
                checkpoint=checkpoint,
            )
            start_cursor = checkpoint.cursor
            expected_snapshot = (
                checkpoint.feed_id,
                checkpoint.feed_version,
                _as_aware(checkpoint.feed_generated_at),
            )
            snapshot_id = checkpoint.snapshot_id
            prior_pages = checkpoint.pages_completed
            prior_records = checkpoint.records_completed
            prior_bytes = checkpoint.bytes_completed
            start_sync_token = None

        if prior_pages >= settings.external_intelligence_max_pages:
            raise OperationalConflictError(
                "Persisted snapshot already reached the configured cumulative page limit"
            )
        if prior_records >= settings.external_intelligence_max_records:
            raise OperationalConflictError(
                "Persisted snapshot already reached the configured cumulative record limit"
            )
        if prior_bytes >= settings.external_intelligence_max_snapshot_bytes:
            raise OperationalConflictError(
                "Persisted snapshot already reached the configured cumulative byte limit"
            )
        effective_page_budget = min(
            page_budget,
            settings.external_intelligence_max_pages - prior_pages,
        )
        run_claim = _create_sync_run(
            settings=settings,
            repository=repository,
            connector=connector,
            actor=actor,
            snapshot_id=snapshot_id,
            start_cursor=start_cursor,
            expected_snapshot=expected_snapshot,
        )
        # The connector lock, stale-run recovery and new lease are committed
        # atomically before network I/O. Every later write is fenced by this token.
        repository.session.commit()
    except Exception:
        repository.session.rollback()
        raise

    provider = ExternalDatapointProvider(
        client,
        connector.endpoint,
        token=configured_token,
        auth_scheme=connector.auth_scheme,  # type: ignore[arg-type]
        allowed_hosts=settings.intelligence_allowed_hosts,
        page_size=settings.external_intelligence_page_size,
        max_page_bytes=settings.external_intelligence_max_page_bytes,
        timeout_seconds=settings.external_intelligence_timeout_seconds,
        trusted_signing_keys=credential_binding.signing_keys,
        require_signature=credential_binding.require_signature,
    )
    fetched_pages: list[ExternalDatapointPageResult] = []
    page_cursor = start_cursor
    seen_cursors = {start_cursor} if start_cursor is not None else set()
    record_count = 0
    byte_count = 0
    complete = False
    continuation_cursor: str | None = None
    expected_delivery: tuple[int, str, bool, int, int] | None = None
    signing_key_ids: set[str] = set()
    run_heartbeat = _ExternalRunHeartbeat(
        settings=settings,
        repository=repository,
        claim=run_claim,
        ownership_heartbeat=ownership_heartbeat,
    )

    try:
        if ownership_heartbeat is not None:
            ownership_heartbeat()
        run_heartbeat.start()
        for local_page_number in range(1, effective_page_budget + 1):
            request_cursor = page_cursor
            page_result = await provider.fetch_page(
                request_cursor,
                sync_token=(
                    start_sync_token
                    if local_page_number == 1 and request_cursor is None
                    else None
                ),
            )
            page = page_result.page
            snapshot_page_number = prior_pages + local_page_number
            snapshot = (
                page.feed_id,
                page.feed_version,
                _as_aware(page.generated_at),
            )
            if expected_snapshot is None:
                expected_snapshot = snapshot
            elif snapshot != expected_snapshot:
                raise InvalidIntelligencePayload(
                    "External feed identity or generation time changed during pagination"
                )
            if page.schema_version == "2.0":
                if not page_result.signature_verified or page_result.signing_key_id is None:
                    raise InvalidIntelligencePayload(
                        "Version 2 external feed pages require a trusted signature"
                    )
                signing_key_ids.add(page_result.signing_key_id)
                if len(signing_key_ids) != 1:
                    raise InvalidIntelligencePayload(
                        "External feed signing key changed during one snapshot"
                    )
                assert page.feed_epoch is not None
                assert page.mode is not None
                assert page.from_sequence is not None
                assert page.through_sequence is not None
                delivery = (
                    page.feed_epoch,
                    page.mode,
                    page.reset_required,
                    page.from_sequence,
                    page.through_sequence,
                )
                if expected_delivery is None:
                    expected_delivery = delivery
                elif delivery != expected_delivery:
                    raise InvalidIntelligencePayload(
                        "External feed delivery metadata changed during pagination"
                    )

            identities = {
                (item.record.provider.casefold(), item.record.external_id) for item in page.items
            }
            if seen_identities.intersection(identities):
                raise InvalidIntelligencePayload(
                    "External feed repeated a record identity across the persisted snapshot"
                )
            cumulative_records = prior_records + record_count + len(page.items)
            if cumulative_records > settings.external_intelligence_max_records:
                raise InvalidIntelligencePayload(
                    "External feed exceeds the configured cumulative snapshot record limit"
                )
            cumulative_bytes = prior_bytes + byte_count + page_result.raw_payload_bytes
            if cumulative_bytes > settings.external_intelligence_max_snapshot_bytes:
                raise InvalidIntelligencePayload(
                    "External feed exceeds the configured cumulative snapshot byte limit"
                )
            if page.has_more and (
                snapshot_page_number >= settings.external_intelligence_max_pages
                or cumulative_records >= settings.external_intelligence_max_records
                or cumulative_bytes >= settings.external_intelligence_max_snapshot_bytes
            ):
                raise InvalidIntelligencePayload(
                    "External feed cannot be completed within the configured cumulative "
                    "snapshot limits"
                )
            seen_identities.update(identities)
            record_count += len(page.items)
            byte_count += page_result.raw_payload_bytes
            fetched_pages.append(page_result)
            _persist_owned_page(
                settings=settings,
                repository=repository,
                connector=connector,
                claim=run_claim,
                page_result=page_result,
                page_number=snapshot_page_number,
                request_cursor=request_cursor,
                local_pages_fetched=local_page_number,
                local_records_fetched=record_count,
                local_bytes_fetched=byte_count,
                snapshot_pages_fetched=snapshot_page_number,
                snapshot_records_fetched=cumulative_records,
                snapshot_bytes_fetched=cumulative_bytes,
            )
            if ownership_heartbeat is not None:
                ownership_heartbeat()

            if not page.has_more:
                complete = True
                continuation_cursor = None
                break
            assert page.next_cursor is not None
            if page.next_cursor in seen_cursors:
                raise InvalidIntelligencePayload("External feed returned a repeated cursor")
            seen_cursors.add(page.next_cursor)
            continuation_cursor = page.next_cursor
            page_cursor = page.next_cursor

        assert expected_snapshot is not None
        feed_id, feed_version, generated_at = expected_snapshot
        _heartbeat_owned_run(
            settings=settings,
            repository=repository,
            claim=run_claim,
        )
        if ownership_heartbeat is not None:
            ownership_heartbeat()
        hub = IntelligenceHubService(repository)
        first_page = fetched_pages[0].page
        reset_requested = bool(
            first_page.schema_version == "2.0" and first_page.reset_required
        )
        reset_applied = False
        created = updated = unchanged = quarantined = 0
        recorrelation_record_ids: set[UUID] = set()
        recorrelation_manifests: set[str] = set()
        warnings: list[str] = []
        status_counts: Counter[str] = Counter()
        for page_result in fetched_pages:
            page = page_result.page
            status_counts.update(item.status for item in page.items)
            if not page.items:
                continue
            outcome = hub.import_feed(
                CanonicalIntelFeed(
                    feed_id=page.feed_id,
                    feed_version=page.feed_version,
                    generated_at=page.generated_at,
                    items=[item.to_canonical_record() for item in page.items],
                ),
                actor,
                sync_run_id=run_claim.run_id,
                max_future_skew_seconds=settings.external_intelligence_clock_skew_seconds,
            )
            created += outcome.created
            updated += outcome.updated
            unchanged += outcome.unchanged
            quarantined += outcome.quarantined
            recorrelation_record_ids.update(outcome._records_requiring_recorrelation)
            if outcome._recorrelation_manifest_sha256 is not None:
                recorrelation_manifests.add(outcome._recorrelation_manifest_sha256)
            warnings.extend(outcome.warnings)

        if complete and reset_requested:
            present_identities = set(
                repository.session.execute(
                    select(
                        ExternalIntelligenceSyncIdentityRow.provider_key,
                        ExternalIntelligenceSyncIdentityRow.external_id,
                    ).where(
                        ExternalIntelligenceSyncIdentityRow.organization_id
                        == repository.organization_id,
                        ExternalIntelligenceSyncIdentityRow.connector_id == connector.id,
                        ExternalIntelligenceSyncIdentityRow.snapshot_id
                        == run_claim.snapshot_id,
                    )
                ).all()
            )
            withdrawn_ids, withdrawal_manifest = hub.reconcile_full_snapshot(
                feed_id=feed_id,
                feed_version=feed_version,
                feed_generated_at=generated_at,
                present_identities=present_identities,
                sync_run_id=run_claim.run_id,
                actor=actor,
            )
            recorrelation_record_ids.update(withdrawn_ids)
            if withdrawal_manifest is not None:
                recorrelation_manifests.add(withdrawal_manifest)
            reset_applied = True

        run_heartbeat.stop()
        run_heartbeat.raise_if_lost()
        current_page_provenance = [
            (prior_pages + index, page.raw_payload_sha256)
            for index, page in enumerate(fetched_pages, start=1)
        ]
        cumulative_page_provenance = prior_page_provenance + current_page_provenance
        manifest_sha256 = _page_manifest(cumulative_page_provenance)
        terminal_status = (
            "partial"
            if not complete
            else "quarantined"
            if record_count > 0 and quarantined == record_count
            else "completed"
        )
        if complete:
            repository.session.execute(
                delete(ExternalIntelligenceCheckpointRow).where(
                    ExternalIntelligenceCheckpointRow.organization_id == repository.organization_id,
                    ExternalIntelligenceCheckpointRow.connector_id == connector.id,
                )
            )
        else:
            assert continuation_cursor is not None
            cumulative_page_manifest = _page_manifest(cumulative_page_provenance)
            cumulative_identity_manifest = _identity_manifest(seen_identities)
            if checkpoint is None:
                checkpoint = ExternalIntelligenceCheckpointRow(
                    organization_id=repository.organization_id,
                    connector_id=connector.id,
                    last_run_id=run_claim.run_id,
                    connector_config_version=run_claim.connector_config_version,
                    connector_identity_sha256=run_claim.connector_identity_sha256,
                    snapshot_id=run_claim.snapshot_id,
                    cursor=continuation_cursor,
                    cursor_sha256=_cursor_digest(continuation_cursor),
                    feed_id=feed_id,
                    feed_version=feed_version,
                    feed_generated_at=generated_at,
                    pages_completed=prior_pages + len(fetched_pages),
                    records_completed=prior_records + record_count,
                    bytes_completed=prior_bytes + byte_count,
                    page_manifest_sha256=cumulative_page_manifest,
                    identity_manifest_sha256=cumulative_identity_manifest,
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                )
                repository.session.add(checkpoint)
            else:
                checkpoint.last_run_id = run_claim.run_id
                checkpoint.connector_config_version = run_claim.connector_config_version
                checkpoint.connector_identity_sha256 = run_claim.connector_identity_sha256
                checkpoint.cursor = continuation_cursor
                checkpoint.cursor_sha256 = _cursor_digest(continuation_cursor)
                checkpoint.pages_completed = prior_pages + len(fetched_pages)
                checkpoint.records_completed = prior_records + record_count
                checkpoint.bytes_completed = prior_bytes + byte_count
                checkpoint.page_manifest_sha256 = cumulative_page_manifest
                checkpoint.identity_manifest_sha256 = cumulative_identity_manifest
                checkpoint.updated_at = datetime.now(UTC)

        final_page = fetched_pages[-1].page
        final_page_result = fetched_pages[-1]
        if complete and final_page.schema_version == "2.0":
            if final_page.next_sync_token is None or final_page_result.signing_key_id is None:
                raise InvalidIntelligencePayload(
                    "Complete version 2 feeds require a verified next_sync_token"
                )
            assert final_page.feed_epoch is not None
            assert final_page.through_sequence is not None
            state = subscription
            now_state = datetime.now(UTC)
            if state is None:
                state = ExternalIntelligenceSubscriptionStateRow(
                    connector_id=connector.id,
                    organization_id=repository.organization_id,
                    feed_id=final_page.feed_id,
                    feed_epoch=final_page.feed_epoch,
                    next_sync_token=final_page.next_sync_token,
                    next_sync_token_sha256=sha256(
                        final_page.next_sync_token.encode("utf-8")
                    ).hexdigest(),
                    through_sequence=final_page.through_sequence,
                    entitlement_epoch=None,
                    reset_generation=None,
                    last_full_snapshot_at=(
                        now_state if final_page.mode == "full" else None
                    ),
                    signing_key_id=final_page_result.signing_key_id,
                    signature_verified_at=now_state,
                    created_at=now_state,
                    updated_at=now_state,
                )
                repository.session.add(state)
            else:
                state.feed_id = final_page.feed_id
                state.feed_epoch = final_page.feed_epoch
                state.next_sync_token = final_page.next_sync_token
                state.next_sync_token_sha256 = sha256(
                    final_page.next_sync_token.encode("utf-8")
                ).hexdigest()
                state.through_sequence = final_page.through_sequence
                if final_page.mode == "full":
                    state.last_full_snapshot_at = now_state
                state.signing_key_id = final_page_result.signing_key_id
                state.signature_verified_at = now_state
                state.updated_at = now_state

        repository.audit(
            actor,
            "intelligence.external_sync_completed",
            "external_intelligence_sync_run",
            run_claim.run_id,
            {
                "feed_id": feed_id,
                "feed_version": feed_version,
                "pages_fetched": len(fetched_pages),
                "records_fetched": record_count,
                "bytes_fetched": byte_count,
                "complete": complete,
                "start_cursor_sha256": _cursor_digest(start_cursor),
                "next_cursor_sha256": _cursor_digest(continuation_cursor),
                "manifest_sha256": manifest_sha256,
                "source_status_counts": dict(status_counts),
                "quarantined": quarantined,
                "reset_applied": reset_applied,
                "signed_pages": sum(page.signature_verified for page in fetched_pages),
                "signing_key_ids": sorted(signing_key_ids),
                "through_sequence": (
                    fetched_pages[-1].page.through_sequence
                    if fetched_pages[-1].page.schema_version == "2.0"
                    else None
                ),
            },
        )
        _finalize_owned_run(
            repository=repository,
            claim=run_claim,
            status=terminal_status,
            next_cursor=continuation_cursor,
            created=created,
            updated=updated,
            unchanged=unchanged,
            quarantined=quarantined,
            manifest_sha256=manifest_sha256,
        )
        correlation_job_ids: list[UUID] = []
        if recorrelation_record_ids:
            recorrelation_manifest = sha256(
                "\0".join(sorted(recorrelation_manifests)).encode("utf-8")
            ).hexdigest()
            correlation_job_ids = enqueue_tenant_correlation_jobs(
                settings=settings,
                repository=repository,
                trigger_type="intel_superseded",
                trigger_id=min(recorrelation_record_ids, key=str),
                manifest_sha256=recorrelation_manifest,
                actor=actor,
            )
        # The conditional finalization holds the run-row lock through this flush
        # and commit. A reclaimer cannot interleave a checkpoint or canonical write.
        repository.session.flush()
        repository.session.commit()
        return ExternalIntelligencePullResult(
            run_id=run_claim.run_id,
            feed_id=feed_id,
            feed_version=feed_version,
            pages_fetched=prior_pages + len(fetched_pages),
            records_fetched=prior_records + record_count,
            bytes_fetched=prior_bytes + byte_count,
            batch_pages_fetched=len(fetched_pages),
            batch_records_fetched=record_count,
            batch_bytes_fetched=byte_count,
            created=created,
            updated=updated,
            unchanged=unchanged,
            quarantined=quarantined,
            active=status_counts["active"],
            revoked=status_counts["revoked"],
            deleted=status_counts["deleted"],
            # New records stay pending. A replacement of a previously
            # materializable identity queues fail-closed de-correlation while
            # its new content remains unavailable until analyst approval.
            correlation_jobs_queued=len(correlation_job_ids),
            complete=complete,
            next_cursor=continuation_cursor,
            manifest_sha256=manifest_sha256,
            warnings=warnings[:100],
        )
    except Exception as error:
        run_heartbeat.stop()
        repository.session.rollback()
        if _fail_owned_run(
            repository=repository,
            claim=run_claim,
            error=error,
        ):
            repository.audit(
                actor,
                "intelligence.external_sync_failed",
                "external_intelligence_sync_run",
                run_claim.run_id,
                {"error_code": type(error).__name__[:100]},
            )
            repository.session.flush()
            repository.session.commit()
        raise


def _configured_connector(
    settings: Settings,
    repository: OperationalRepository,
    actor: str,
) -> ExternalIntelligenceConnectorRow:
    row = _connector_row(repository)
    if row is not None:
        return row
    # Compatibility is intentionally limited to non-production environments.
    # The materialized row is still tenant-owned; production must use a named
    # credential reference and an explicit connector configuration.
    if (
        settings.environment == "production"
        or settings.external_intelligence_url is None
        or settings.external_intelligence_token is None
    ):
        raise OperationalConflictError(
            "An external intelligence connector is not configured for this organization"
        )
    validate_external_datapoint_endpoint(
        settings.external_intelligence_url, settings.intelligence_allowed_hosts
    )
    row = ExternalIntelligenceConnectorRow(
        organization_id=repository.organization_id,
        name=CONNECTOR_NAME,
        endpoint=settings.external_intelligence_url,
        auth_scheme=settings.external_intelligence_auth_scheme,
        credential_reference=LEGACY_CREDENTIAL_REFERENCE,
        enabled=True,
        sync_interval_seconds=None,
        next_sync_at=None,
        config_version=1,
        identity_sha256=_connector_identity_sha256(
            organization_id=repository.organization_id,
            name=CONNECTOR_NAME,
            endpoint=settings.external_intelligence_url,
            auth_scheme=settings.external_intelligence_auth_scheme,
            credential_reference=LEGACY_CREDENTIAL_REFERENCE,
        ),
        created_by=actor,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    repository.session.add(row)
    repository.session.flush()
    repository.audit(
        actor,
        "intelligence.external_connector_materialized",
        "external_intelligence_connector",
        row.id,
        {"development_compatibility": True},
    )
    return row


def _connector_row(
    repository: OperationalRepository,
    *,
    for_update: bool = False,
) -> ExternalIntelligenceConnectorRow | None:
    if repository.organization_id is None:
        raise OperationalConflictError("An organization scope is required")
    statement = select(ExternalIntelligenceConnectorRow).where(
        ExternalIntelligenceConnectorRow.organization_id == repository.organization_id,
        ExternalIntelligenceConnectorRow.name == CONNECTOR_NAME,
    )
    if for_update:
        statement = statement.execution_options(populate_existing=True).with_for_update()
    return repository.session.scalar(statement)


def _lock_connector_for_sync(
    *,
    settings: Settings,
    repository: OperationalRepository,
    connector_id: UUID,
    actor: str,
) -> ExternalIntelligenceConnectorRow:
    connector = repository.session.scalar(
        select(ExternalIntelligenceConnectorRow)
        .where(
            ExternalIntelligenceConnectorRow.id == connector_id,
            ExternalIntelligenceConnectorRow.organization_id == repository.organization_id,
        )
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    if connector is None:
        raise OperationalConflictError("The external intelligence connector is not available")
    _require_connector_identity_integrity(connector)
    active_run = repository.session.scalar(
        select(ExternalIntelligenceSyncRunRow)
        .where(
            ExternalIntelligenceSyncRunRow.organization_id == repository.organization_id,
            ExternalIntelligenceSyncRunRow.connector_id == connector_id,
            ExternalIntelligenceSyncRunRow.status == "running",
        )
        .order_by(ExternalIntelligenceSyncRunRow.started_at.desc())
        .limit(1)
    )
    if active_run is None:
        return connector
    now = datetime.now(UTC)
    if active_run.lease_expires_at is not None and _as_aware(active_run.lease_expires_at) > now:
        raise OperationalConflictError(
            "An external intelligence synchronization is already running"
        )
    reclaimed = repository.session.execute(
        update(ExternalIntelligenceSyncRunRow)
        .where(
            ExternalIntelligenceSyncRunRow.id == active_run.id,
            ExternalIntelligenceSyncRunRow.organization_id == repository.organization_id,
            ExternalIntelligenceSyncRunRow.connector_id == connector_id,
            ExternalIntelligenceSyncRunRow.connector_config_version
            == connector.config_version,
            ExternalIntelligenceSyncRunRow.connector_identity_sha256
            == connector.identity_sha256,
            ExternalIntelligenceSyncRunRow.status == "running",
            ExternalIntelligenceSyncRunRow.claim_token_sha256 == active_run.claim_token_sha256,
            ExternalIntelligenceSyncRunRow.lease_expires_at <= now,
        )
        .values(
            status="failed",
            completed_at=now,
            claim_token_sha256=None,
            lease_expires_at=None,
            error_code="stale_run_recovered",
            error_message="The previous synchronization lease expired.",
        )
        .execution_options(synchronize_session=False)
    )
    if reclaimed.rowcount != 1:
        raise OperationalConflictError(
            "The external intelligence synchronization lease changed during recovery"
        )
    repository.audit(
        actor,
        "intelligence.external_sync_stale_recovered",
        "external_intelligence_sync_run",
        active_run.id,
        {"connector_id": str(connector_id)},
    )
    repository.session.flush()
    return connector


def _create_sync_run(
    *,
    settings: Settings,
    repository: OperationalRepository,
    connector: ExternalIntelligenceConnectorRow,
    actor: str,
    snapshot_id: UUID,
    start_cursor: str | None,
    expected_snapshot: tuple[str, str, datetime] | None,
) -> ExternalSyncRunClaim:
    _require_connector_identity_integrity(connector)
    now = datetime.now(UTC)
    claim_token = token_urlsafe(32)
    claim_token_sha256 = sha256(claim_token.encode()).hexdigest()
    run = ExternalIntelligenceSyncRunRow(
        organization_id=repository.organization_id,
        connector_id=connector.id,
        connector_config_version=connector.config_version,
        connector_identity_sha256=connector.identity_sha256,
        snapshot_id=snapshot_id,
        status="running",
        started_by=actor,
        started_at=now,
        claim_token_sha256=claim_token_sha256,
        lease_expires_at=now + timedelta(seconds=settings.external_intelligence_stale_run_seconds),
        heartbeat_at=now,
        start_cursor_sha256=_cursor_digest(start_cursor),
        feed_id=expected_snapshot[0] if expected_snapshot is not None else None,
        feed_version=expected_snapshot[1] if expected_snapshot is not None else None,
        feed_generated_at=expected_snapshot[2] if expected_snapshot is not None else None,
    )
    repository.session.add(run)
    repository.session.flush()
    repository.audit(
        actor,
        "intelligence.external_sync_started",
        "external_intelligence_sync_run",
        run.id,
        {
            "connector_id": str(connector.id),
            "config_version": connector.config_version,
            "connector_identity_sha256": connector.identity_sha256,
            "snapshot_id": str(snapshot_id),
            "start_cursor_sha256": run.start_cursor_sha256,
        },
    )
    return ExternalSyncRunClaim(
        run_id=run.id,
        connector_id=connector.id,
        connector_config_version=connector.config_version,
        connector_identity_sha256=connector.identity_sha256,
        snapshot_id=snapshot_id,
        token_sha256=claim_token_sha256,
    )


def _validate_checkpoint_provenance(
    *,
    repository: OperationalRepository,
    connector: ExternalIntelligenceConnectorRow,
    checkpoint: ExternalIntelligenceCheckpointRow,
) -> tuple[list[tuple[int, str]], set[tuple[str, str]]]:
    """Fail closed unless checkpoint counts and manifests match accepted prior runs."""

    _require_connector_identity_integrity(connector)
    if (
        checkpoint.connector_config_version != connector.config_version
        or checkpoint.connector_identity_sha256 != connector.identity_sha256
    ):
        raise OperationalConflictError(
            "Persisted snapshot checkpoint belongs to a different connector configuration"
        )
    if checkpoint.cursor_sha256 != _cursor_digest(checkpoint.cursor):
        raise OperationalConflictError("Persisted snapshot cursor integrity check failed")
    last_run = repository.session.scalar(
        select(ExternalIntelligenceSyncRunRow).where(
            ExternalIntelligenceSyncRunRow.id == checkpoint.last_run_id,
            ExternalIntelligenceSyncRunRow.organization_id == repository.organization_id,
            ExternalIntelligenceSyncRunRow.connector_id == connector.id,
            ExternalIntelligenceSyncRunRow.connector_config_version
            == connector.config_version,
            ExternalIntelligenceSyncRunRow.connector_identity_sha256
            == connector.identity_sha256,
            ExternalIntelligenceSyncRunRow.snapshot_id == checkpoint.snapshot_id,
            ExternalIntelligenceSyncRunRow.status == "partial",
        )
    )
    if last_run is None:
        raise OperationalConflictError(
            "Persisted snapshot checkpoint does not reference an accepted partial run"
        )

    pages = list(
        repository.session.scalars(
            select(ExternalIntelligenceSyncPageRow)
            .join(
                ExternalIntelligenceSyncRunRow,
                ExternalIntelligenceSyncRunRow.id == ExternalIntelligenceSyncPageRow.run_id,
            )
            .where(
                ExternalIntelligenceSyncPageRow.organization_id == repository.organization_id,
                ExternalIntelligenceSyncPageRow.connector_config_version
                == connector.config_version,
                ExternalIntelligenceSyncPageRow.connector_identity_sha256
                == connector.identity_sha256,
                ExternalIntelligenceSyncPageRow.snapshot_id == checkpoint.snapshot_id,
                ExternalIntelligenceSyncRunRow.connector_id == connector.id,
                ExternalIntelligenceSyncRunRow.connector_config_version
                == connector.config_version,
                ExternalIntelligenceSyncRunRow.connector_identity_sha256
                == connector.identity_sha256,
                ExternalIntelligenceSyncRunRow.status == "partial",
            )
            .order_by(ExternalIntelligenceSyncPageRow.page_number)
        )
    )
    page_provenance = [(page.page_number, page.raw_payload_sha256) for page in pages]
    if [number for number, _ in page_provenance] != list(range(1, checkpoint.pages_completed + 1)):
        raise OperationalConflictError(
            "Persisted snapshot page provenance does not match checkpoint counts"
        )
    if sum(page.raw_payload_bytes for page in pages) != checkpoint.bytes_completed:
        raise OperationalConflictError(
            "Persisted snapshot byte provenance does not match checkpoint counts"
        )
    expected_snapshot = (
        checkpoint.feed_id,
        checkpoint.feed_version,
        _as_aware(checkpoint.feed_generated_at),
    )
    if any(
        (
            page.feed_id,
            page.feed_version,
            _as_aware(page.feed_generated_at),
        )
        != expected_snapshot
        for page in pages
    ):
        raise OperationalConflictError("Persisted snapshot page provenance changed feed identity")
    if _page_manifest(page_provenance) != checkpoint.page_manifest_sha256:
        raise OperationalConflictError(
            "Persisted snapshot page provenance manifest does not match checkpoint"
        )

    identity_rows = list(
        repository.session.scalars(
            select(ExternalIntelligenceSyncIdentityRow)
            .join(
                ExternalIntelligenceSyncRunRow,
                ExternalIntelligenceSyncRunRow.id == ExternalIntelligenceSyncIdentityRow.run_id,
            )
            .where(
                ExternalIntelligenceSyncIdentityRow.organization_id == repository.organization_id,
                ExternalIntelligenceSyncIdentityRow.connector_id == connector.id,
                ExternalIntelligenceSyncIdentityRow.connector_config_version
                == connector.config_version,
                ExternalIntelligenceSyncIdentityRow.connector_identity_sha256
                == connector.identity_sha256,
                ExternalIntelligenceSyncIdentityRow.snapshot_id == checkpoint.snapshot_id,
                ExternalIntelligenceSyncRunRow.connector_config_version
                == connector.config_version,
                ExternalIntelligenceSyncRunRow.connector_identity_sha256
                == connector.identity_sha256,
                ExternalIntelligenceSyncRunRow.status == "partial",
            )
        )
    )
    identities = {(identity.provider_key, identity.external_id) for identity in identity_rows}
    if len(identity_rows) != len(identities) or len(identities) != checkpoint.records_completed:
        raise OperationalConflictError(
            "Persisted snapshot identity provenance does not match checkpoint counts"
        )
    if any(identity.page_number > checkpoint.pages_completed for identity in identity_rows):
        raise OperationalConflictError(
            "Persisted snapshot identity references an uncheckpointed page"
        )
    if _identity_manifest(identities) != checkpoint.identity_manifest_sha256:
        raise OperationalConflictError(
            "Persisted snapshot identity manifest does not match checkpoint"
        )
    return page_provenance, identities


def _persist_owned_page(
    *,
    settings: Settings,
    repository: OperationalRepository,
    connector: ExternalIntelligenceConnectorRow,
    claim: ExternalSyncRunClaim,
    page_result: ExternalDatapointPageResult,
    page_number: int,
    request_cursor: str | None,
    local_pages_fetched: int,
    local_records_fetched: int,
    local_bytes_fetched: int,
    snapshot_pages_fetched: int,
    snapshot_records_fetched: int,
    snapshot_bytes_fetched: int,
) -> None:
    """Persist page provenance only while atomically renewing this run's lease."""

    _require_connector_identity_integrity(connector)
    if (
        connector.id != claim.connector_id
        or connector.config_version != claim.connector_config_version
        or connector.identity_sha256 != claim.connector_identity_sha256
    ):
        raise ExternalSyncLeaseLostError(
            "External intelligence page belongs to a different connector configuration"
        )
    now = datetime.now(UTC)
    page = page_result.page
    repository.session.add(
        ExternalIntelligenceSyncPageRow(
            organization_id=repository.organization_id,
            run_id=claim.run_id,
            connector_config_version=claim.connector_config_version,
            connector_identity_sha256=claim.connector_identity_sha256,
            snapshot_id=claim.snapshot_id,
            page_number=page_number,
            request_cursor_sha256=_cursor_digest(request_cursor),
            raw_payload_sha256=page_result.raw_payload_sha256,
            raw_payload_bytes=page_result.raw_payload_bytes,
            feed_id=page.feed_id,
            feed_version=page.feed_version,
            feed_generated_at=page.generated_at,
            item_count=len(page.items),
            received_at=now,
        )
    )
    for item in page.items:
        repository.session.add(
            ExternalIntelligenceSyncIdentityRow(
                organization_id=repository.organization_id,
                connector_id=connector.id,
                run_id=claim.run_id,
                connector_config_version=claim.connector_config_version,
                connector_identity_sha256=claim.connector_identity_sha256,
                snapshot_id=claim.snapshot_id,
                page_number=page_number,
                provider_key=item.record.provider.casefold(),
                external_id=item.record.external_id,
                received_at=now,
            )
        )
    if not _update_owned_run(
        repository=repository,
        claim=claim,
        now=now,
        values={
            "heartbeat_at": now,
            "lease_expires_at": now
            + timedelta(seconds=settings.external_intelligence_stale_run_seconds),
            "pages_fetched": snapshot_pages_fetched,
            "records_fetched": snapshot_records_fetched,
            "bytes_fetched": snapshot_bytes_fetched,
            "batch_pages_fetched": local_pages_fetched,
            "batch_records_fetched": local_records_fetched,
            "batch_bytes_fetched": local_bytes_fetched,
            "feed_id": page.feed_id,
            "feed_version": page.feed_version,
            "feed_generated_at": page.generated_at,
        },
    ):
        repository.session.rollback()
        raise ExternalSyncLeaseLostError(
            "External intelligence synchronization lease ownership changed"
        )
    repository.session.flush()
    repository.session.commit()


def _heartbeat_owned_run(
    *,
    settings: Settings,
    repository: OperationalRepository,
    claim: ExternalSyncRunClaim,
) -> None:
    now = datetime.now(UTC)
    if not _update_owned_run(
        repository=repository,
        claim=claim,
        now=now,
        values={
            "heartbeat_at": now,
            "lease_expires_at": now
            + timedelta(seconds=settings.external_intelligence_stale_run_seconds),
        },
    ):
        repository.session.rollback()
        raise ExternalSyncLeaseLostError(
            "External intelligence synchronization lease ownership changed"
        )
    repository.session.commit()


def _finalize_owned_run(
    *,
    repository: OperationalRepository,
    claim: ExternalSyncRunClaim,
    status: str,
    next_cursor: str | None,
    created: int,
    updated: int,
    unchanged: int,
    quarantined: int,
    manifest_sha256: str,
) -> None:
    now = datetime.now(UTC)
    if not _update_owned_run(
        repository=repository,
        claim=claim,
        now=now,
        values={
            "status": status,
            "completed_at": now,
            "claim_token_sha256": None,
            "heartbeat_at": now,
            "lease_expires_at": None,
            "next_cursor_sha256": _cursor_digest(next_cursor),
            "created_count": created,
            "updated_count": updated,
            "unchanged_count": unchanged,
            "quarantined_count": quarantined,
            "manifest_sha256": manifest_sha256,
        },
    ):
        raise ExternalSyncLeaseLostError(
            "External intelligence synchronization lease ownership changed before commit"
        )


def _fail_owned_run(
    *,
    repository: OperationalRepository,
    claim: ExternalSyncRunClaim,
    error: Exception,
) -> bool:
    now = datetime.now(UTC)
    return _update_owned_run(
        repository=repository,
        claim=claim,
        now=now,
        values={
            "status": "failed",
            "completed_at": now,
            "claim_token_sha256": None,
            "heartbeat_at": now,
            "lease_expires_at": None,
            "error_code": type(error).__name__[:100],
            "error_message": str(error)[:2_000],
        },
    )


def _update_owned_run(
    *,
    repository: OperationalRepository,
    claim: ExternalSyncRunClaim,
    now: datetime,
    values: dict[str, object],
) -> bool:
    result = repository.session.execute(
        update(ExternalIntelligenceSyncRunRow)
        .where(
            ExternalIntelligenceSyncRunRow.id == claim.run_id,
            ExternalIntelligenceSyncRunRow.organization_id == repository.organization_id,
            ExternalIntelligenceSyncRunRow.connector_id == claim.connector_id,
            ExternalIntelligenceSyncRunRow.connector_config_version
            == claim.connector_config_version,
            ExternalIntelligenceSyncRunRow.connector_identity_sha256
            == claim.connector_identity_sha256,
            ExternalIntelligenceSyncRunRow.snapshot_id == claim.snapshot_id,
            ExternalIntelligenceSyncRunRow.status == "running",
            ExternalIntelligenceSyncRunRow.claim_token_sha256 == claim.token_sha256,
            ExternalIntelligenceSyncRunRow.lease_expires_at > now,
            _current_connector_claim_exists(
                organization_id=repository.organization_id,
                claim=claim,
            ),
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def _renew_run_lease_with_factory(
    *,
    session_factory: sessionmaker[Session],
    organization_id: UUID,
    claim: ExternalSyncRunClaim,
    lease_seconds: int,
) -> bool:
    """Heartbeat helper for the independent PostgreSQL lease-renewal thread."""

    now = datetime.now(UTC)
    with session_factory() as session:
        apply_tenant_rls_scope(session, organization_id)
        result = session.execute(
            update(ExternalIntelligenceSyncRunRow)
            .where(
                ExternalIntelligenceSyncRunRow.id == claim.run_id,
                ExternalIntelligenceSyncRunRow.organization_id == organization_id,
                ExternalIntelligenceSyncRunRow.connector_id == claim.connector_id,
                ExternalIntelligenceSyncRunRow.connector_config_version
                == claim.connector_config_version,
                ExternalIntelligenceSyncRunRow.connector_identity_sha256
                == claim.connector_identity_sha256,
                ExternalIntelligenceSyncRunRow.snapshot_id == claim.snapshot_id,
                ExternalIntelligenceSyncRunRow.status == "running",
                ExternalIntelligenceSyncRunRow.claim_token_sha256 == claim.token_sha256,
                ExternalIntelligenceSyncRunRow.lease_expires_at > now,
                _current_connector_claim_exists(
                    organization_id=organization_id,
                    claim=claim,
                ),
            )
            .values(
                heartbeat_at=now,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            session.rollback()
            return False
        session.commit()
        return True


def _page_manifest(pages: list[tuple[int, str]]) -> str:
    digest = sha256()
    for page_number, raw_sha256 in pages:
        digest.update(page_number.to_bytes(8, "big", signed=False))
        digest.update(bytes.fromhex(raw_sha256))
    return digest.hexdigest()


def _identity_manifest(identities: set[tuple[str, str]]) -> str:
    digest = sha256()
    for provider_key, external_id in sorted(identities):
        for value in (provider_key, external_id):
            encoded = value.encode()
            digest.update(len(encoded).to_bytes(4, "big", signed=False))
            digest.update(encoded)
    return digest.hexdigest()


def _connector_identity_sha256(
    *,
    organization_id: UUID,
    name: str,
    endpoint: str,
    auth_scheme: str,
    credential_reference: str,
) -> str:
    """Hash the exact tenant/provider/auth boundary used by one pull."""

    canonical = json.dumps(
        {
            "schema_version": 1,
            "organization_id": str(organization_id),
            "provider": name,
            "endpoint": endpoint,
            "auth_scheme": auth_scheme,
            "credential_reference": credential_reference,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def _require_connector_identity_integrity(
    connector: ExternalIntelligenceConnectorRow,
) -> None:
    expected = _connector_identity_sha256(
        organization_id=connector.organization_id,
        name=connector.name,
        endpoint=connector.endpoint,
        auth_scheme=connector.auth_scheme,
        credential_reference=connector.credential_reference,
    )
    if connector.identity_sha256 != expected:
        raise OperationalConflictError(
            "Persisted external connector identity failed its integrity check"
        )


def _current_connector_claim_exists(
    *,
    organization_id: UUID,
    claim: ExternalSyncRunClaim,
) -> Exists:
    """Correlate every run write with the still-current connector configuration."""

    return (
        select(ExternalIntelligenceConnectorRow.id)
        .where(
            ExternalIntelligenceConnectorRow.id == claim.connector_id,
            ExternalIntelligenceConnectorRow.organization_id == organization_id,
            ExternalIntelligenceConnectorRow.name == CONNECTOR_NAME,
            ExternalIntelligenceConnectorRow.config_version
            == claim.connector_config_version,
            ExternalIntelligenceConnectorRow.identity_sha256
            == claim.connector_identity_sha256,
            ExternalIntelligenceConnectorRow.enabled.is_(True),
        )
        .exists()
    )


def _checkpoint_row(
    repository: OperationalRepository,
    connector_id: UUID,
) -> ExternalIntelligenceCheckpointRow | None:
    return repository.session.scalar(
        select(ExternalIntelligenceCheckpointRow).where(
            ExternalIntelligenceCheckpointRow.organization_id == repository.organization_id,
            ExternalIntelligenceCheckpointRow.connector_id == connector_id,
        )
    )


def _subscription_state_row(
    repository: OperationalRepository,
    connector_id: UUID,
) -> ExternalIntelligenceSubscriptionStateRow | None:
    return repository.session.scalar(
        select(ExternalIntelligenceSubscriptionStateRow).where(
            ExternalIntelligenceSubscriptionStateRow.organization_id
            == repository.organization_id,
            ExternalIntelligenceSubscriptionStateRow.connector_id == connector_id,
        )
    )


def _resolve_credential(
    settings: Settings,
    repository: OperationalRepository,
    reference: str,
    *,
    endpoint: str,
) -> str:
    return _resolve_credential_binding(
        settings,
        repository,
        reference,
        endpoint=endpoint,
    ).secret.get_secret_value()


def _resolve_credential_binding(
    settings: Settings,
    repository: OperationalRepository,
    reference: str,
    *,
    endpoint: str,
) -> ExternalIntelligenceCredentialBinding:
    if reference == LEGACY_CREDENTIAL_REFERENCE:
        if settings.environment != "production" and settings.external_intelligence_token:
            return ExternalIntelligenceCredentialBinding(
                secret=settings.external_intelligence_token,
                origin=_endpoint_origin(endpoint),
                require_signature=False,
            )
        raise OperationalConflictError(
            "The external intelligence connector credential is not configured"
        )
    if not repository.organization_key:
        raise OperationalConflictError("The organization has no credential namespace")
    tenant_credentials = settings.external_intelligence_credentials.get(repository.organization_key)
    binding = tenant_credentials.get(reference) if tenant_credentials is not None else None
    if binding is None:
        raise OperationalConflictError(
            "The external intelligence credential reference cannot be resolved"
        )
    if binding.origin != _endpoint_origin(endpoint):
        raise OperationalConflictError(
            "The external intelligence credential is not bound to this endpoint origin"
        )
    return binding


def _endpoint_origin(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError as error:
        raise OperationalConflictError("The external endpoint origin is invalid") from error
    host = parsed.hostname.rstrip(".").casefold() if parsed.hostname else ""
    if parsed.scheme.casefold() != "https" or not host:
        raise OperationalConflictError("The external endpoint origin is invalid")
    rendered_host = f"[{host}]" if ":" in host else host
    rendered_port = f":{port}" if port not in {None, 443} else ""
    return f"https://{rendered_host}{rendered_port}"


def _cursor_digest(cursor: str | None) -> str | None:
    return sha256(cursor.encode()).hexdigest() if cursor is not None else None


def _as_aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _schedule_state(connector: ExternalIntelligenceConnectorRow) -> ScheduleState:
    if not connector.enabled:
        return "disabled"
    if connector.sync_interval_seconds is None or connector.next_sync_at is None:
        return "manual"
    if _as_aware(connector.next_sync_at) <= datetime.now(UTC):
        return "due"
    return "scheduled"
