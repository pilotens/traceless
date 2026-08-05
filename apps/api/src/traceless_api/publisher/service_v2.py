"""Production-oriented publisher workflows layered over the v1 contracts."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from traceless_api.integrations.intelligence.external_datapoints import ExternalDatapoint
from traceless_api.publisher.auth import PublisherAuthenticatedClient, PublisherPrincipal
from traceless_api.publisher.config import PublisherSettings
from traceless_api.publisher.db import (
    PublisherChangeRow,
    PublisherClientRow,
    PublisherRecordRow,
    PublisherRevisionRow,
    utc_now,
)
from traceless_api.publisher.db_v2 import (
    PublisherAccountRow,
    PublisherClientCredentialRow,
    PublisherCurrentProjectionRow,
    PublisherEntitlementRow,
    PublisherImportRunRow,
    PublisherInstallationRow,
    PublisherPublicationDecisionRow,
    PublisherSigningKeyRow,
)
from traceless_api.publisher.models import (
    PublisherClientCreate,
    PublisherClientCredential,
    PublisherClientPage,
    PublisherClientUpdate,
    PublisherClientView,
    PublisherImportBatch,
    PublisherImportResult,
    PublisherPublishResult,
    PublisherRecordPage,
)
from traceless_api.publisher.models_v2 import (
    PublisherAccountCreate,
    PublisherAccountPage,
    PublisherAccountView,
    PublisherCredentialMetadata,
    PublisherCredentialPage,
    PublisherFeedPageV2,
    PublisherImportRunPage,
    PublisherImportRunView,
    PublisherInstallationCreate,
    PublisherInstallationCredential,
    PublisherInstallationPage,
    PublisherInstallationView,
    PublisherPublicationDecisionPage,
    PublisherPublicationDecisionView,
    PublisherPublicationRequest,
    PublisherRejectionRequest,
    PublisherSigningKeyItem,
    PublisherSigningKeySetView,
)
from traceless_api.publisher.service import (
    PublisherConflictError,
    PublisherCursorError,
    PublisherNotFoundError,
    PublisherService,
    _decode_cursor,
    _encode_cursor,
    _hash_json,
    _new_client_token,
    api_key_sha256,
    signing_public_key_base64,
)

_TLP_RANK = {
    "TLP:CLEAR": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}


class PublisherPlatformService:
    """Keep v1 compatibility while enforcing normalized v2 state and delivery."""

    def __init__(self, session: Session, settings: PublisherSettings) -> None:
        self.session = session
        self.settings = settings
        self.legacy = PublisherService(session, settings)

    def create_client(
        self,
        payload: PublisherClientCreate,
        principal: PublisherPrincipal,
    ) -> PublisherClientCredential:
        result = self.legacy.create_client(payload, principal.actor)
        client = self._legacy_client(payload.client_id)
        installation = self._create_installation(client)
        self._replace_entitlements(installation, client)
        self._create_credential(
            installation=installation,
            token=result.api_key,
            token_version=client.token_version,
            actor=principal.actor,
        )
        return result

    def list_clients(self, *, limit: int, offset: int) -> PublisherClientPage:
        return self.legacy.list_clients(limit=limit, offset=offset)

    def create_account(
        self,
        payload: PublisherAccountCreate,
        principal: PublisherPrincipal,
    ) -> PublisherAccountView:
        if self.session.scalar(
            select(PublisherAccountRow.id).where(
                PublisherAccountRow.account_key == payload.account_key
            )
        ) is not None:
            raise PublisherConflictError("Publisher account_key already exists")
        account = PublisherAccountRow(
            account_key=payload.account_key,
            name=payload.name,
            enabled=payload.enabled,
        )
        self.session.add(account)
        self.session.flush()
        self.legacy._audit(  # noqa: SLF001
            principal.actor,
            "publisher.account_created",
            "publisher_account",
            account.id,
            {"account_key": account.account_key, "enabled": account.enabled},
        )
        return PublisherAccountView.model_validate(account)

    def list_accounts(self, *, limit: int, offset: int) -> PublisherAccountPage:
        total = int(
            self.session.scalar(select(func.count()).select_from(PublisherAccountRow)) or 0
        )
        rows = list(
            self.session.scalars(
                select(PublisherAccountRow)
                .order_by(PublisherAccountRow.created_at, PublisherAccountRow.account_key)
                .offset(offset)
                .limit(limit)
            )
        )
        return PublisherAccountPage(
            items=[PublisherAccountView.model_validate(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def create_account_installation(
        self,
        account_key: str,
        payload: PublisherInstallationCreate,
        principal: PublisherPrincipal,
    ) -> PublisherInstallationCredential:
        account = self.session.scalar(
            select(PublisherAccountRow)
            .where(PublisherAccountRow.account_key == account_key)
            .with_for_update()
        )
        if account is None:
            raise PublisherNotFoundError("Publisher account was not found")
        if self.session.scalar(
            select(PublisherInstallationRow.id).where(
                or_(
                    PublisherInstallationRow.client_id == payload.client_id,
                    (
                        (PublisherInstallationRow.account_id == account.id)
                        & (PublisherInstallationRow.installation_key == payload.installation_key)
                    ),
                )
            )
        ) is not None:
            raise PublisherConflictError("Publisher installation identity already exists")
        if self.session.scalar(
            select(PublisherClientRow.id).where(
                PublisherClientRow.client_id == payload.client_id
            )
        ) is not None:
            raise PublisherConflictError("Publisher client_id is reserved by a legacy client")
        installation = PublisherInstallationRow(
            account_id=account.id,
            client_id=payload.client_id,
            installation_key=payload.installation_key,
            environment=payload.environment,
            region=payload.region,
            name=payload.name,
            enabled=payload.enabled,
            max_tlp=payload.max_tlp,
        )
        self.session.add(installation)
        self.session.flush()
        self._replace_installation_entitlements(
            installation,
            providers=payload.allowed_providers,
            source_kinds=payload.allowed_source_kinds,
        )
        token = _new_client_token(payload.client_id)
        self._create_credential(
            installation=installation,
            token=token,
            token_version=1,
            actor=principal.actor,
        )
        self.legacy._audit(  # noqa: SLF001
            principal.actor,
            "publisher.installation_created",
            "publisher_installation",
            installation.id,
            {
                "account_key": account.account_key,
                "client_id": installation.client_id,
                "installation_key": installation.installation_key,
                "environment": installation.environment,
            },
        )
        return PublisherInstallationCredential(
            installation=PublisherInstallationView.model_validate(installation),
            api_key=token,
        )

    def rotate_installation_key(
        self,
        client_id: str,
        principal: PublisherPrincipal,
    ) -> PublisherInstallationCredential:
        installation = self._installation(client_id, for_update=True)
        now = utc_now()
        active_credentials = list(
            self.session.scalars(
                select(PublisherClientCredentialRow).where(
                    PublisherClientCredentialRow.installation_id == installation.id,
                    PublisherClientCredentialRow.revoked_at.is_(None),
                    or_(
                        PublisherClientCredentialRow.expires_at.is_(None),
                        PublisherClientCredentialRow.expires_at > now,
                    ),
                )
            )
        )
        overlap_until = now + timedelta(seconds=self.settings.credential_overlap_seconds)
        for credential in active_credentials:
            if credential.expires_at is None or credential.expires_at > overlap_until:
                credential.expires_at = overlap_until
        next_version = max((item.token_version for item in active_credentials), default=0) + 1
        token = _new_client_token(client_id)
        self._create_credential(
            installation=installation,
            token=token,
            token_version=next_version,
            actor=principal.actor,
        )
        self.legacy._audit(  # noqa: SLF001
            principal.actor,
            "publisher.installation_key_rotated",
            "publisher_installation",
            installation.id,
            {"client_id": client_id, "token_version": next_version},
        )
        return PublisherInstallationCredential(
            installation=PublisherInstallationView.model_validate(installation),
            api_key=token,
        )

    def list_installations(
        self,
        *,
        limit: int,
        offset: int,
    ) -> PublisherInstallationPage:
        total = int(
            self.session.scalar(
                select(func.count()).select_from(PublisherInstallationRow)
            )
            or 0
        )
        rows = list(
            self.session.scalars(
                select(PublisherInstallationRow)
                .order_by(
                    PublisherInstallationRow.updated_at.desc(),
                    PublisherInstallationRow.id,
                )
                .offset(offset)
                .limit(limit)
            )
        )
        return PublisherInstallationPage(
            items=[PublisherInstallationView.model_validate(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def list_credentials(
        self,
        client_id: str,
        *,
        limit: int,
        offset: int,
    ) -> PublisherCredentialPage:
        installation = self._installation(client_id)
        filters = (
            PublisherClientCredentialRow.installation_id == installation.id,
        )
        total = int(
            self.session.scalar(
                select(func.count())
                .select_from(PublisherClientCredentialRow)
                .where(*filters)
            )
            or 0
        )
        rows = list(
            self.session.scalars(
                select(PublisherClientCredentialRow)
                .where(*filters)
                .order_by(
                    PublisherClientCredentialRow.created_at.desc(),
                    PublisherClientCredentialRow.id,
                )
                .offset(offset)
                .limit(limit)
            )
        )
        return PublisherCredentialPage(
            items=[PublisherCredentialMetadata.model_validate(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def revoke_credential(
        self,
        client_id: str,
        credential_id: UUID,
        principal: PublisherPrincipal,
    ) -> PublisherCredentialMetadata:
        installation = self._installation(client_id, for_update=True)
        credential = self.session.scalar(
            select(PublisherClientCredentialRow)
            .where(
                PublisherClientCredentialRow.id == credential_id,
                PublisherClientCredentialRow.installation_id == installation.id,
            )
            .with_for_update()
        )
        if credential is None:
            raise PublisherNotFoundError("Publisher credential was not found")
        if credential.revoked_at is not None:
            return PublisherCredentialMetadata.model_validate(credential)
        now = utc_now()
        remaining = int(
            self.session.scalar(
                select(func.count())
                .select_from(PublisherClientCredentialRow)
                .where(
                    PublisherClientCredentialRow.installation_id == installation.id,
                    PublisherClientCredentialRow.id != credential.id,
                    PublisherClientCredentialRow.not_before <= now,
                    PublisherClientCredentialRow.revoked_at.is_(None),
                    or_(
                        PublisherClientCredentialRow.expires_at.is_(None),
                        PublisherClientCredentialRow.expires_at > now,
                    ),
                )
            )
            or 0
        )
        if installation.enabled and remaining == 0:
            raise PublisherConflictError(
                "An enabled installation must retain at least one active credential"
            )
        credential.revoked_at = now
        self.legacy._audit(  # noqa: SLF001 - shared publisher audit boundary
            principal.actor,
            "publisher.credential_revoked",
            "publisher_client_credential",
            credential.id,
            {"client_id": client_id, "token_version": credential.token_version},
        )
        self.session.flush()
        return PublisherCredentialMetadata.model_validate(credential)

    def update_client(
        self,
        client_id: str,
        payload: PublisherClientUpdate,
        principal: PublisherPrincipal,
    ) -> PublisherClientView:
        client = self._legacy_client(client_id, for_update=True)
        installation = self._installation(client_id, for_update=True)
        old_max_tlp = client.max_tlp
        old_providers = set(client.allowed_providers)
        old_source_kinds = set(client.allowed_source_kinds)
        result = self.legacy.update_client(client_id, payload, principal.actor)
        self.session.flush()
        client = self._legacy_client(client_id, for_update=True)
        entitlement_changed = any(
            (
                old_max_tlp != client.max_tlp,
                old_providers != set(client.allowed_providers),
                old_source_kinds != set(client.allowed_source_kinds),
            )
        )
        narrowed = (
            _TLP_RANK[client.max_tlp] < _TLP_RANK[old_max_tlp]
            or _scope_narrowed(old_providers, set(client.allowed_providers))
            or _scope_narrowed(old_source_kinds, set(client.allowed_source_kinds))
        )
        installation.name = client.name
        installation.enabled = client.enabled
        installation.max_tlp = client.max_tlp
        if entitlement_changed:
            installation.entitlement_epoch += 1
            if narrowed:
                installation.reset_generation += 1
            self._replace_entitlements(installation, client)
        installation.updated_at = utc_now()
        return result

    def rotate_client_key(
        self,
        client_id: str,
        principal: PublisherPrincipal,
    ) -> PublisherClientCredential:
        client = self._legacy_client(client_id, for_update=True)
        installation = self._installation(client_id, for_update=True)
        now = utc_now()
        active_credentials = list(
            self.session.scalars(
                select(PublisherClientCredentialRow).where(
                    PublisherClientCredentialRow.installation_id == installation.id,
                    PublisherClientCredentialRow.revoked_at.is_(None),
                    or_(
                        PublisherClientCredentialRow.expires_at.is_(None),
                        PublisherClientCredentialRow.expires_at > now,
                    ),
                )
            )
        )
        result = self.legacy.rotate_client_key(client_id, principal.actor)
        self.session.flush()
        client = self._legacy_client(client_id, for_update=True)
        overlap_until = now + timedelta(seconds=self.settings.credential_overlap_seconds)
        for credential in active_credentials:
            if credential.expires_at is None or credential.expires_at > overlap_until:
                credential.expires_at = overlap_until
        self._create_credential(
            installation=installation,
            token=result.api_key,
            token_version=client.token_version,
            actor=principal.actor,
        )
        return result

    def import_batch(
        self,
        payload: PublisherImportBatch,
        principal: PublisherPrincipal,
    ) -> PublisherImportResult:
        now = utc_now()
        self._abandon_stale_import_runs(now)
        manifest = _hash_json(payload.model_dump(mode="json"))
        idempotency_hash = _optional_idempotency_hash(payload)
        if idempotency_hash is not None:
            prior = self.session.scalar(
                select(PublisherImportRunRow).where(
                    PublisherImportRunRow.idempotency_key_sha256 == idempotency_hash
                )
            )
            if prior is not None:
                if prior.manifest_sha256 != manifest:
                    raise PublisherConflictError(
                        "Publisher import idempotency key was reused with different content"
                    )
                if prior.status == "completed" and prior.result is not None:
                    return PublisherImportResult.model_validate(prior.result)
                if prior.status in {"failed", "abandoned"}:
                    prior.status = "running"
                    prior.actor = principal.actor
                    prior.error_code = None
                    prior.result = None
                    prior.completed_at = None
                    prior.heartbeat_at = now
                    prior.lease_expires_at = now + timedelta(
                        seconds=self.settings.import_lease_seconds
                    )
                    prior.attempt_count += 1
                    run = prior
                else:
                    raise PublisherConflictError(
                        "Publisher import idempotency key is already in use"
                    )
            else:
                run = PublisherImportRunRow(
                    feed_id=payload.feed_id,
                    feed_version=payload.feed_version,
                    generated_at=payload.generated_at,
                    item_count=len(payload.items),
                    manifest_sha256=manifest,
                    idempotency_key_sha256=idempotency_hash,
                    actor=principal.actor,
                    status="running",
                    heartbeat_at=now,
                    lease_expires_at=now
                    + timedelta(seconds=self.settings.import_lease_seconds),
                )
                self.session.add(run)
        else:
            run = PublisherImportRunRow(
                feed_id=payload.feed_id,
                feed_version=payload.feed_version,
                generated_at=payload.generated_at,
                item_count=len(payload.items),
                manifest_sha256=manifest,
                idempotency_key_sha256=None,
                actor=principal.actor,
                status="running",
                heartbeat_at=now,
                lease_expires_at=now
                + timedelta(seconds=self.settings.import_lease_seconds),
            )
            self.session.add(run)
        self.session.flush()
        run_id = run.id
        # Persist the execution record before processing so failures survive the
        # request transaction rollback and remain visible to operations.
        self.session.commit()

        try:
            providers = {item.record.provider.casefold() for item in payload.items}
            automatic = bool(payload.publish) and self.settings.automatic_publish_enabled(
                feed_id=payload.feed_id,
                providers=providers,
            )
            if payload.publish and not automatic:
                raise PublisherConflictError(
                    "Automatic publisher release is disabled for this feed/provider set"
                )
            effective = payload.model_copy(update={"publish": automatic})
            result = self.legacy.import_batch(effective, principal.actor)
            self.session.flush()

            for item in payload.items:
                record = self.session.scalar(
                    select(PublisherRecordRow).where(
                        PublisherRecordRow.provider_key
                        == item.record.provider.casefold(),
                        PublisherRecordRow.external_id == item.record.external_id,
                    )
                )
                if record is None:
                    continue
                revision = self._current_revision(record.id)
                if revision is None:
                    continue
                if item.status != "active" and revision.publication_status == "staged":
                    published = self.legacy.publish_record(record.id, principal.actor)
                    if published.published:
                        self._decision(
                            record_id=record.id,
                            revision_id=revision.id,
                            decision="emergency_withdrawal",
                            actor=principal.actor,
                            reason=(
                                "Source lifecycle changed to revoked/deleted; "
                                "stale delivery was withdrawn."
                            ),
                        )
                elif automatic and revision.publication_status == "published":
                    self._decision(
                        record_id=record.id,
                        revision_id=revision.id,
                        decision="automatic",
                        actor=principal.actor,
                        reason=(
                            "Server-configured automatic publication policy matched "
                            "the feed and providers."
                        ),
                    )
                self._sync_current_projection(record.id)

            completed = self.session.get(PublisherImportRunRow, run_id)
            if completed is None:
                raise PublisherConflictError("Publisher import run disappeared")
            completed.status = "completed"
            completed.result = result.model_dump(mode="json")
            completed.heartbeat_at = utc_now()
            completed.lease_expires_at = None
            completed.completed_at = completed.heartbeat_at
            self.session.flush()
            self.session.commit()
            return result
        except Exception as error:
            self.session.rollback()
            failed = self.session.get(PublisherImportRunRow, run_id)
            if failed is not None and failed.status == "running":
                failed.status = "failed"
                failed.error_code = type(error).__name__[:120]
                failed.result = {"error_code": failed.error_code}
                failed.heartbeat_at = utc_now()
                failed.lease_expires_at = None
                failed.completed_at = failed.heartbeat_at
                self.session.commit()
            raise

    def _abandon_stale_import_runs(self, now: datetime) -> None:
        stale = list(
            self.session.scalars(
                select(PublisherImportRunRow)
                .where(
                    PublisherImportRunRow.status == "running",
                    PublisherImportRunRow.lease_expires_at.is_not(None),
                    PublisherImportRunRow.lease_expires_at <= now,
                )
                .with_for_update()
            )
        )
        for run in stale:
            run.status = "abandoned"
            run.error_code = "PublisherImportLeaseExpired"
            run.result = {"error_code": run.error_code}
            run.heartbeat_at = now
            run.lease_expires_at = None
            run.completed_at = now

    def list_import_runs(
        self,
        *,
        limit: int,
        offset: int,
    ) -> PublisherImportRunPage:
        total = int(
            self.session.scalar(
                select(func.count()).select_from(PublisherImportRunRow)
            )
            or 0
        )
        rows = list(
            self.session.scalars(
                select(PublisherImportRunRow)
                .order_by(PublisherImportRunRow.created_at.desc(), PublisherImportRunRow.id)
                .offset(offset)
                .limit(limit)
            )
        )
        return PublisherImportRunPage(
            items=[PublisherImportRunView.model_validate(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def list_publication_decisions(
        self,
        record_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> PublisherPublicationDecisionPage:
        if self.session.get(PublisherRecordRow, record_id) is None:
            raise PublisherNotFoundError("Publisher record was not found")
        filters = (PublisherPublicationDecisionRow.record_id == record_id,)
        total = int(
            self.session.scalar(
                select(func.count())
                .select_from(PublisherPublicationDecisionRow)
                .where(*filters)
            )
            or 0
        )
        rows = list(
            self.session.scalars(
                select(PublisherPublicationDecisionRow)
                .where(*filters)
                .order_by(
                    PublisherPublicationDecisionRow.created_at.desc(),
                    PublisherPublicationDecisionRow.id,
                )
                .offset(offset)
                .limit(limit)
            )
        )
        return PublisherPublicationDecisionPage(
            items=[
                PublisherPublicationDecisionView.model_validate(row) for row in rows
            ],
            total=total,
            limit=limit,
            offset=offset,
        )

    def list_records(self, *, limit: int, offset: int) -> PublisherRecordPage:
        return self.legacy.list_records(limit=limit, offset=offset)

    def publish_record(
        self,
        record_id: UUID,
        payload: PublisherPublicationRequest,
        principal: PublisherPrincipal,
    ) -> PublisherPublishResult:
        result = self.legacy.publish_record(record_id, principal.actor)
        revision = self._current_revision(record_id, for_update=True)
        if revision is None:
            raise PublisherConflictError("Publisher record has no current revision")
        if result.published:
            self._decision(
                record_id=record_id,
                revision_id=revision.id,
                decision="published",
                actor=principal.actor,
                reason=payload.reason,
            )
        self._sync_current_projection(record_id)
        return result

    def reject_record(
        self,
        record_id: UUID,
        payload: PublisherRejectionRequest,
        principal: PublisherPrincipal,
    ) -> PublisherPublishResult:
        record = self.session.scalar(
            select(PublisherRecordRow).where(PublisherRecordRow.id == record_id)
        )
        if record is None:
            raise PublisherNotFoundError("Publisher record was not found")
        revision = self._current_revision(record_id)
        if revision is None:
            raise PublisherConflictError("Publisher record has no current revision")
        if revision.publication_status == "rejected":
            return PublisherPublishResult(
                record=self.legacy._record_view(record),  # noqa: SLF001
                published=False,
                change_sequences=[],
                warnings=["The current revision was already rejected."],
            )
        if revision.publication_status != "staged":
            raise PublisherConflictError("Only the current staged revision can be rejected")
        revision.publication_status = "rejected"
        self._decision(
            record_id=record_id,
            revision_id=revision.id,
            decision="rejected",
            actor=principal.actor,
            reason=payload.reason,
        )
        self.legacy._audit(  # noqa: SLF001
            principal.actor,
            "publisher.record_rejected",
            "publisher_record",
            record_id,
            {"revision": revision.revision_number},
        )
        self.session.flush()
        return PublisherPublishResult(
            record=self.legacy._record_view(record),  # noqa: SLF001
            published=False,
            change_sequences=[],
        )

    def build_feed_page_v2(
        self,
        authenticated: PublisherAuthenticatedClient,
        *,
        limit: int,
        cursor: str | None,
        sync_token: str | None,
    ) -> PublisherFeedPageV2:
        if not 1 <= limit <= self.settings.max_page_size:
            raise PublisherCursorError("limit exceeds the publisher page-size policy")
        installation = authenticated.installation
        now = utc_now()
        entitlement = self._entitlement_sha256(installation)

        if cursor is not None and sync_token is not None:
            raise PublisherCursorError("cursor and sync_token cannot be supplied together")

        if cursor is not None:
            state = _decode_cursor(cursor, secret=self.settings.cursor_secret_bytes())
            self._validate_delivery_state(
                state,
                kind="page-v2",
                installation=installation,
                entitlement=entitlement,
                now=now,
            )
            mode = _delivery_mode(state.get("mode"))
            generated_at = _cursor_datetime(state.get("generated_at"), "generated_at")
            snapshot_max = _cursor_integer(state.get("snapshot_max"), "snapshot_max")
            from_sequence = _cursor_integer(state.get("from_sequence"), "from_sequence")
            after_sequence = _cursor_integer(state.get("after_sequence"), "after_sequence")
            reset_required = bool(state.get("reset_required"))
        else:
            sync_state: dict[str, Any] | None = None
            if sync_token is not None:
                sync_state = _decode_cursor(
                    sync_token,
                    secret=self.settings.cursor_secret_bytes(),
                )
                self._validate_delivery_state(
                    sync_state,
                    kind="sync-v2",
                    installation=installation,
                    entitlement=None,
                    now=now,
                    allow_stale_entitlement=True,
                )
            token_epoch = _optional_cursor_integer(sync_state, "feed_epoch")
            token_entitlement_epoch = _optional_cursor_integer(
                sync_state,
                "entitlement_epoch",
            )
            token_reset_generation = _optional_cursor_integer(
                sync_state,
                "reset_generation",
            )
            token_sequence = _optional_cursor_integer(sync_state, "through_sequence") or 0
            reset_required = sync_state is not None and (
                token_epoch != self.settings.feed_epoch
                or token_entitlement_epoch != installation.entitlement_epoch
                or token_reset_generation != installation.reset_generation
            )
            mode = "full" if sync_state is None or reset_required else "delta"
            from_sequence = 0 if mode == "full" else token_sequence
            after_sequence = 0 if mode == "full" else from_sequence
            snapshot_max = int(
                self.session.scalar(select(func.max(PublisherChangeRow.sequence))) or 0
            )
            generated_at = now

        if after_sequence > snapshot_max or from_sequence > snapshot_max:
            raise PublisherCursorError("Publisher delivery sequence is inconsistent")

        allowed_tlps, providers, source_kinds = self._entitlement_scope(installation)
        if mode == "full":
            statement = select(PublisherCurrentProjectionRow).where(
                PublisherCurrentProjectionRow.sequence <= snapshot_max,
                PublisherCurrentProjectionRow.sequence > after_sequence,
                PublisherCurrentProjectionRow.distribution_tlp.in_(allowed_tlps),
            )
            if providers:
                statement = statement.where(
                    PublisherCurrentProjectionRow.provider_key.in_(providers)
                )
            if source_kinds:
                statement = statement.where(
                    PublisherCurrentProjectionRow.source_kind.in_(source_kinds)
                )
            rows = list(
                self.session.scalars(
                    statement.order_by(PublisherCurrentProjectionRow.sequence).limit(limit + 1)
                )
            )
        else:
            filters: list[Any] = [
                PublisherChangeRow.sequence > from_sequence,
                PublisherChangeRow.sequence <= snapshot_max,
                PublisherChangeRow.distribution_tlp.in_(allowed_tlps),
            ]
            if providers:
                filters.append(PublisherChangeRow.provider_key.in_(providers))
            if source_kinds:
                filters.append(PublisherChangeRow.source_kind.in_(source_kinds))
            latest = (
                select(
                    PublisherChangeRow.provider_key.label("provider_key"),
                    PublisherChangeRow.external_id.label("external_id"),
                    func.max(PublisherChangeRow.sequence).label("sequence"),
                )
                .where(*filters)
                .group_by(
                    PublisherChangeRow.provider_key,
                    PublisherChangeRow.external_id,
                )
                .subquery()
            )
            statement = (
                select(PublisherChangeRow)
                .join(latest, PublisherChangeRow.sequence == latest.c.sequence)
                .where(PublisherChangeRow.sequence > after_sequence)
                .order_by(PublisherChangeRow.sequence)
                .limit(limit + 1)
            )
            rows = list(self.session.scalars(statement))

        has_more = len(rows) > limit
        selected = rows[:limit]
        next_cursor = None
        next_sync_token = None
        last_sequence = selected[-1].sequence if selected else snapshot_max
        if has_more:
            next_cursor = _encode_cursor(
                self._delivery_cursor_payload(
                    kind="page-v2",
                    installation=installation,
                    entitlement=entitlement,
                    mode=mode,
                    generated_at=generated_at,
                    snapshot_max=snapshot_max,
                    from_sequence=from_sequence,
                    after_sequence=last_sequence,
                    reset_required=reset_required,
                    now=now,
                ),
                secret=self.settings.cursor_secret_bytes(),
            )
        else:
            next_sync_token = _encode_cursor(
                {
                    "v": 2,
                    "kind": "sync-v2",
                    "installation_id": str(installation.id),
                    "client_id": installation.client_id,
                    "feed_epoch": self.settings.feed_epoch,
                    "entitlement_epoch": installation.entitlement_epoch,
                    "reset_generation": installation.reset_generation,
                    "through_sequence": snapshot_max,
                    "generated_at": generated_at.isoformat(),
                    "expires_at": (
                        now + timedelta(seconds=self.settings.cursor_max_age_seconds)
                    ).isoformat(),
                },
                secret=self.settings.cursor_secret_bytes(),
            )

        items = [
            ExternalDatapoint.model_validate(
                {
                    "status": row.lifecycle_status,
                    "status_changed_at": row.status_changed_at,
                    "status_reason": row.status_reason,
                    "record": row.canonical_record,
                }
            )
            for row in selected
        ]
        page_manifest = _hash_json(
            [
                {
                    "sequence": row.sequence,
                    "provider": row.provider_key,
                    "external_id": row.external_id,
                    "payload": row.canonical_record,
                }
                for row in selected
            ]
        )
        feed_version = (
            f"v2-e{self.settings.feed_epoch}-{mode}-{snapshot_max:x}-"
            f"{installation.entitlement_epoch}-{installation.reset_generation}"
        )
        return PublisherFeedPageV2(
            feed_id=self.settings.feed_id,
            feed_version=feed_version,
            feed_epoch=self.settings.feed_epoch,
            generated_at=generated_at,
            mode=mode,
            reset_required=reset_required,
            from_sequence=from_sequence,
            through_sequence=snapshot_max,
            items=items,
            has_more=has_more,
            next_cursor=next_cursor,
            next_sync_token=next_sync_token,
            manifest_sha256=page_manifest,
        )

    def _delivery_cursor_payload(
        self,
        *,
        kind: str,
        installation: PublisherInstallationRow,
        entitlement: str,
        mode: str,
        generated_at: datetime,
        snapshot_max: int,
        from_sequence: int,
        after_sequence: int,
        reset_required: bool,
        now: datetime,
    ) -> dict[str, Any]:
        return {
            "v": 2,
            "kind": kind,
            "installation_id": str(installation.id),
            "client_id": installation.client_id,
            "feed_epoch": self.settings.feed_epoch,
            "entitlement_epoch": installation.entitlement_epoch,
            "reset_generation": installation.reset_generation,
            "entitlement": entitlement,
            "mode": mode,
            "generated_at": generated_at.isoformat(),
            "snapshot_max": snapshot_max,
            "from_sequence": from_sequence,
            "after_sequence": after_sequence,
            "reset_required": reset_required,
            "expires_at": (
                now + timedelta(seconds=self.settings.cursor_max_age_seconds)
            ).isoformat(),
        }

    def _validate_delivery_state(
        self,
        state: dict[str, Any],
        *,
        kind: str,
        installation: PublisherInstallationRow,
        entitlement: str | None,
        now: datetime,
        allow_stale_entitlement: bool = False,
    ) -> None:
        if state.get("v") != 2 or state.get("kind") != kind:
            raise PublisherCursorError("Unsupported publisher delivery token")
        if state.get("installation_id") != str(installation.id):
            raise PublisherCursorError("Publisher delivery token belongs to another installation")
        if state.get("client_id") != installation.client_id:
            raise PublisherCursorError("Publisher delivery token belongs to another client")
        expires_at = _cursor_datetime(state.get("expires_at"), "expires_at")
        if expires_at <= now:
            raise PublisherCursorError("Publisher delivery token has expired")
        if not allow_stale_entitlement:
            if state.get("feed_epoch") != self.settings.feed_epoch:
                raise PublisherCursorError("Publisher feed epoch has changed")
            if state.get("entitlement_epoch") != installation.entitlement_epoch:
                raise PublisherCursorError("Publisher entitlements changed during pagination")
            if state.get("reset_generation") != installation.reset_generation:
                raise PublisherCursorError("Publisher reset generation changed during pagination")
            if entitlement is not None and state.get("entitlement") != entitlement:
                raise PublisherCursorError("Publisher entitlement digest changed")

    def _create_installation(
        self,
        client: PublisherClientRow,
    ) -> PublisherInstallationRow:
        account = PublisherAccountRow(
            account_key=client.client_id,
            name=client.name,
            enabled=client.enabled,
        )
        self.session.add(account)
        self.session.flush()
        installation = PublisherInstallationRow(
            account_id=account.id,
            client_id=client.client_id,
            name=client.name,
            enabled=client.enabled,
            max_tlp=client.max_tlp,
        )
        self.session.add(installation)
        self.session.flush()
        return installation

    def _create_credential(
        self,
        *,
        installation: PublisherInstallationRow,
        token: str,
        token_version: int,
        actor: str,
    ) -> PublisherClientCredentialRow:
        now = utc_now()
        credential = PublisherClientCredentialRow(
            installation_id=installation.id,
            key_sha256=api_key_sha256(token),
            token_version=token_version,
            not_before=now,
            expires_at=now + timedelta(seconds=self.settings.credential_ttl_seconds),
            created_by=actor,
        )
        self.session.add(credential)
        self.session.flush()
        return credential

    def _replace_entitlements(
        self,
        installation: PublisherInstallationRow,
        client: PublisherClientRow,
    ) -> None:
        self._replace_installation_entitlements(
            installation,
            providers=client.allowed_providers,
            source_kinds=client.allowed_source_kinds,
        )

    def _replace_installation_entitlements(
        self,
        installation: PublisherInstallationRow,
        *,
        providers: list[str],
        source_kinds: list[str],
    ) -> None:
        self.session.execute(
            delete(PublisherEntitlementRow).where(
                PublisherEntitlementRow.installation_id == installation.id
            )
        )
        self.session.add_all(
            [
                PublisherEntitlementRow(
                    installation_id=installation.id,
                    scope_type="provider",
                    scope_value=value.casefold(),
                )
                for value in providers
            ]
            + [
                PublisherEntitlementRow(
                    installation_id=installation.id,
                    scope_type="source_kind",
                    scope_value=value,
                )
                for value in source_kinds
            ]
        )

    def _entitlement_scope(
        self,
        installation: PublisherInstallationRow,
    ) -> tuple[list[str], set[str], set[str]]:
        rows = list(
            self.session.scalars(
                select(PublisherEntitlementRow).where(
                    PublisherEntitlementRow.installation_id == installation.id
                )
            )
        )
        providers = {
            row.scope_value for row in rows if row.scope_type == "provider"
        }
        source_kinds = {
            row.scope_value for row in rows if row.scope_type == "source_kind"
        }
        allowed_tlps = [
            value
            for value, rank in _TLP_RANK.items()
            if value != "TLP:RED" and rank <= _TLP_RANK[installation.max_tlp]
        ]
        return allowed_tlps, providers, source_kinds

    def _entitlement_sha256(self, installation: PublisherInstallationRow) -> str:
        _, providers, source_kinds = self._entitlement_scope(installation)
        return _hash_json(
            {
                "installation_id": str(installation.id),
                "enabled": installation.enabled,
                "max_tlp": installation.max_tlp,
                "providers": sorted(providers),
                "source_kinds": sorted(source_kinds),
                "entitlement_epoch": installation.entitlement_epoch,
                "reset_generation": installation.reset_generation,
            }
        )

    def _sync_current_projection(self, record_id: UUID) -> None:
        latest = self.session.scalar(
            select(PublisherChangeRow)
            .where(PublisherChangeRow.record_id == record_id)
            .order_by(PublisherChangeRow.sequence.desc())
            .limit(1)
        )
        current = self.session.get(PublisherCurrentProjectionRow, record_id)
        if latest is None or latest.projection != "canonical":
            if current is not None:
                self.session.delete(current)
            return
        values = {
            "revision_id": latest.revision_id,
            "sequence": latest.sequence,
            "provider": latest.provider,
            "provider_key": latest.provider_key,
            "external_id": latest.external_id,
            "source_kind": latest.source_kind,
            "record_type": latest.record_type,
            "distribution_tlp": latest.distribution_tlp,
            "lifecycle_status": latest.lifecycle_status,
            "status_changed_at": latest.status_changed_at,
            "status_reason": latest.status_reason,
            "canonical_record": latest.canonical_record,
            "updated_at": utc_now(),
        }
        if current is None:
            self.session.add(PublisherCurrentProjectionRow(record_id=record_id, **values))
        else:
            for key, value in values.items():
                setattr(current, key, value)

    def _decision(
        self,
        *,
        record_id: UUID,
        revision_id: UUID,
        decision: str,
        actor: str,
        reason: str,
    ) -> None:
        self.session.add(
            PublisherPublicationDecisionRow(
                record_id=record_id,
                revision_id=revision_id,
                decision=decision,
                actor=actor,
                reason=reason,
            )
        )

    def _current_revision(
        self,
        record_id: UUID,
        *,
        for_update: bool = False,
    ) -> PublisherRevisionRow | None:
        statement = (
            select(PublisherRevisionRow)
            .where(
                PublisherRevisionRow.record_id == record_id,
                PublisherRevisionRow.publication_status != "superseded",
            )
            .order_by(
                PublisherRevisionRow.modified_at.desc(),
                PublisherRevisionRow.revision_number.desc(),
            )
            .limit(1)
        )
        if for_update:
            statement = statement.with_for_update()
        return self.session.scalar(statement)

    def _legacy_client(
        self,
        client_id: str,
        *,
        for_update: bool = False,
    ) -> PublisherClientRow:
        statement = select(PublisherClientRow).where(
            PublisherClientRow.client_id == client_id
        )
        if for_update:
            statement = statement.with_for_update()
        row = self.session.scalar(statement)
        if row is None:
            raise PublisherNotFoundError("Publisher client was not found")
        return row

    def _installation(
        self,
        client_id: str,
        *,
        for_update: bool = False,
    ) -> PublisherInstallationRow:
        statement = select(PublisherInstallationRow).where(
            PublisherInstallationRow.client_id == client_id
        )
        if for_update:
            statement = statement.with_for_update()
        row = self.session.scalar(statement)
        if row is None:
            raise PublisherNotFoundError("Publisher installation was not found")
        return row


def synchronize_signing_key_registry(
    session: Session,
    settings: PublisherSettings,
) -> None:
    current_public = signing_public_key_base64(settings)
    keys = {
        settings.signing_key_id: (current_public, "active"),
        **{
            key_id: (public_key, "retiring")
            for key_id, public_key in settings.previous_signing_public_keys.items()
        },
    }
    for key_id, (public_key, status) in keys.items():
        raw = base64.b64decode(public_key)
        fingerprint = hashlib.sha256(raw).hexdigest()
        row = session.get(PublisherSigningKeyRow, key_id)
        if row is None:
            session.add(
                PublisherSigningKeyRow(
                    key_id=key_id,
                    public_key_base64=public_key,
                    fingerprint_sha256=fingerprint,
                    status=status,
                )
            )
        else:
            if row.fingerprint_sha256 != fingerprint:
                raise PublisherConflictError(
                    "A publisher signing key ID cannot be rebound to different key material"
                )
            row.status = status
    configured = set(keys)
    for row in session.scalars(select(PublisherSigningKeyRow)):
        if row.key_id not in configured and row.status != "retired":
            row.status = "retired"
            row.not_after = utc_now()


def signing_key_set(
    session: Session,
    settings: PublisherSettings,
) -> PublisherSigningKeySetView:
    rows = list(
        session.scalars(
            select(PublisherSigningKeyRow).order_by(
                PublisherSigningKeyRow.status,
                PublisherSigningKeyRow.not_before.desc(),
            )
        )
    )
    return PublisherSigningKeySetView(
        generated_at=utc_now(),
        active_key_id=settings.signing_key_id,
        keys=[PublisherSigningKeyItem.model_validate(row) for row in rows],
    )


def _scope_narrowed(old: set[str], new: set[str]) -> bool:
    if not old:
        return bool(new)
    if not new:
        return False
    return not old.issubset(new)


def _optional_idempotency_hash(payload: PublisherImportBatch) -> str | None:
    value = getattr(payload, "idempotency_key", None)
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _delivery_mode(value: Any) -> str:
    if value not in {"full", "delta"}:
        raise PublisherCursorError("Publisher cursor mode is invalid")
    return str(value)


def _cursor_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise PublisherCursorError(f"Publisher cursor {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PublisherCursorError(f"Publisher cursor {field} is invalid") from error
    if parsed.tzinfo is None:
        raise PublisherCursorError(f"Publisher cursor {field} must be timezone-aware")
    return parsed.astimezone(UTC)


def _cursor_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PublisherCursorError(f"Publisher cursor {field} is invalid")
    return value


def _optional_cursor_integer(state: dict[str, Any] | None, field: str) -> int | None:
    if state is None:
        return None
    value = state.get(field)
    if value is None:
        return None
    return _cursor_integer(value, field)
