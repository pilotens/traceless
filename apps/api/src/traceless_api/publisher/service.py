"""Publisher workflows for staging, publication, entitlement and feed snapshots."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from traceless_api.core.markings import tlp_marking
from traceless_api.integrations.intelligence.external_datapoints import (
    ExternalDatapoint,
    ExternalDatapointPage,
)
from traceless_api.publisher.config import PublisherSettings
from traceless_api.publisher.db import (
    PublisherAuditRow,
    PublisherChangeRow,
    PublisherClientRow,
    PublisherRecordRow,
    PublisherRevisionRow,
    utc_now,
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
    PublisherRecordView,
)

_TLP_RANK = {
    "TLP:CLEAR": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}


class PublisherNotFoundError(LookupError):
    pass


class PublisherConflictError(RuntimeError):
    pass


class PublisherCursorError(ValueError):
    pass


def api_key_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def client_entitlement_sha256(client: PublisherClientRow) -> str:
    return _hash_json(
        {
            "client_id": client.client_id,
            "enabled": client.enabled,
            "max_tlp": client.max_tlp,
            "allowed_providers": sorted(item.casefold() for item in client.allowed_providers),
            "allowed_source_kinds": sorted(client.allowed_source_kinds),
            "token_version": client.token_version,
        }
    )


def signing_public_key_base64(settings: PublisherSettings) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(settings.signing_private_key_bytes())
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def sign_payload(settings: PublisherSettings, payload: bytes) -> dict[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(settings.signing_private_key_bytes())
    signature = private_key.sign(payload)
    return {
        "X-Traceless-Content-SHA256": hashlib.sha256(payload).hexdigest(),
        "X-Traceless-Key-Id": settings.signing_key_id,
        "X-Traceless-Signature": base64.b64encode(signature).decode("ascii"),
    }


class PublisherService:
    def __init__(self, session: Session, settings: PublisherSettings) -> None:
        self.session = session
        self.settings = settings

    def create_client(
        self,
        payload: PublisherClientCreate,
        actor: str,
    ) -> PublisherClientCredential:
        if self.session.scalar(
            select(PublisherClientRow.id).where(
                PublisherClientRow.client_id == payload.client_id
            )
        ) is not None:
            raise PublisherConflictError("Publisher client_id already exists")
        token = _new_client_token(payload.client_id)
        row = PublisherClientRow(
            client_id=payload.client_id,
            name=payload.name,
            api_key_sha256=api_key_sha256(token),
            enabled=payload.enabled,
            max_tlp=payload.max_tlp,
            allowed_providers=payload.allowed_providers,
            allowed_source_kinds=list(payload.allowed_source_kinds),
        )
        self.session.add(row)
        self.session.flush()
        self._audit(
            actor,
            "publisher.client_created",
            "publisher_client",
            row.id,
            {
                "client_id": row.client_id,
                "max_tlp": row.max_tlp,
                "enabled": row.enabled,
            },
        )
        return PublisherClientCredential(
            client=PublisherClientView.model_validate(row),
            api_key=token,
        )

    def list_clients(self, *, limit: int, offset: int) -> PublisherClientPage:
        total = int(
            self.session.scalar(select(func.count()).select_from(PublisherClientRow)) or 0
        )
        rows = list(
            self.session.scalars(
                select(PublisherClientRow)
                .order_by(PublisherClientRow.created_at, PublisherClientRow.client_id)
                .offset(offset)
                .limit(limit)
            )
        )
        return PublisherClientPage(
            items=[PublisherClientView.model_validate(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def update_client(
        self,
        client_id: str,
        payload: PublisherClientUpdate,
        actor: str,
    ) -> PublisherClientView:
        row = self._client(client_id, for_update=True)
        entitlement_changed = False
        if payload.name is not None:
            row.name = payload.name
        if payload.enabled is not None and payload.enabled != row.enabled:
            row.enabled = payload.enabled
            entitlement_changed = True
        if payload.max_tlp is not None and payload.max_tlp != row.max_tlp:
            row.max_tlp = payload.max_tlp
            entitlement_changed = True
        if (
            payload.allowed_providers is not None
            and payload.allowed_providers != row.allowed_providers
        ):
            row.allowed_providers = payload.allowed_providers
            entitlement_changed = True
        if (
            payload.allowed_source_kinds is not None
            and list(payload.allowed_source_kinds) != row.allowed_source_kinds
        ):
            row.allowed_source_kinds = list(payload.allowed_source_kinds)
            entitlement_changed = True
        if entitlement_changed:
            row.token_version += 1
        row.updated_at = utc_now()
        self.session.flush()
        self._audit(
            actor,
            "publisher.client_updated",
            "publisher_client",
            row.id,
            {
                "client_id": row.client_id,
                "max_tlp": row.max_tlp,
                "enabled": row.enabled,
                "token_version": row.token_version,
            },
        )
        return PublisherClientView.model_validate(row)

    def rotate_client_key(
        self,
        client_id: str,
        actor: str,
    ) -> PublisherClientCredential:
        row = self._client(client_id, for_update=True)
        token = _new_client_token(row.client_id)
        row.api_key_sha256 = api_key_sha256(token)
        row.token_version += 1
        row.updated_at = utc_now()
        self.session.flush()
        self._audit(
            actor,
            "publisher.client_key_rotated",
            "publisher_client",
            row.id,
            {"client_id": row.client_id, "token_version": row.token_version},
        )
        return PublisherClientCredential(
            client=PublisherClientView.model_validate(row),
            api_key=token,
        )

    def import_batch(
        self,
        payload: PublisherImportBatch,
        actor: str,
    ) -> PublisherImportResult:
        if len(payload.items) > self.settings.max_import_items:
            raise PublisherConflictError("Publisher import exceeds the configured item limit")
        if self.session.get_bind().dialect.name == "postgresql":
            self.session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext('traceless-publisher-import'))")
            )

        created = staged = published = unchanged = superseded = restricted = 0
        record_ids: dict[str, UUID] = {}
        warnings: list[str] = []

        for item in payload.items:
            record = item.record
            identity = (record.provider.casefold(), record.external_id)
            identity_label = f"{record.provider}/{record.external_id}"
            row = self.session.scalar(
                select(PublisherRecordRow)
                .where(
                    PublisherRecordRow.provider_key == identity[0],
                    PublisherRecordRow.external_id == identity[1],
                )
                .with_for_update()
            )
            if row is None:
                row = PublisherRecordRow(
                    provider=record.provider,
                    provider_key=identity[0],
                    external_id=record.external_id,
                    source_kind=record.source_kind,
                    record_type=record.record_type,
                    title=record.title,
                )
                self.session.add(row)
                self.session.flush()
                created += 1

            record_ids[identity_label] = row.id
            current = self._current_revision(row.id)
            canonical_record = record.model_dump(mode="json")
            payload_envelope = {
                "status": item.status,
                "status_changed_at": (
                    item.status_changed_at.isoformat()
                    if item.status_changed_at is not None
                    else None
                ),
                "status_reason": item.status_reason,
                "record": canonical_record,
            }
            source_sha256 = _hash_json(record.raw_evidence)
            analysis_sha256 = _hash_json(
                {
                    key: value
                    for key, value in canonical_record.items()
                    if key != "raw_evidence"
                }
            )
            normalized_sha256 = _hash_json(
                {
                    key: value
                    for key, value in canonical_record.items()
                    if key not in {"raw_evidence", "ai_analysis"}
                }
            )
            ai_analysis_sha256 = _hash_json(canonical_record.get("ai_analysis"))
            payload_sha256 = _hash_json(payload_envelope)
            distribution_tlp = tlp_marking(record.markings)

            if current is not None and record.modified_at < current.modified_at:
                revision = self._add_revision(
                    row=row,
                    item=item,
                    payload=payload,
                    canonical_record=canonical_record,
                    source_sha256=source_sha256,
                    analysis_sha256=analysis_sha256,
                    normalized_sha256=normalized_sha256,
                    ai_analysis_sha256=ai_analysis_sha256,
                    payload_sha256=payload_sha256,
                    distribution_tlp=distribution_tlp,
                    publication_status="superseded",
                    actor=actor,
                )
                superseded += 1
                warnings.append(
                    f"Stored older revision {revision.revision_number} for {identity_label} "
                    "without replacing the current source state."
                )
                continue

            if current is not None and record.modified_at == current.modified_at:
                if current.payload_sha256 == payload_sha256:
                    unchanged += 1
                    continue
                raise PublisherConflictError(
                    "Publisher source reused modified_at with different content"
                )

            if current is not None and current.publication_status in {
                "staged",
                "restricted",
            }:
                current.publication_status = "superseded"

            target_status = (
                "restricted"
                if distribution_tlp == "TLP:RED"
                else "published"
                if payload.publish
                else "staged"
            )
            revision = self._add_revision(
                row=row,
                item=item,
                payload=payload,
                canonical_record=canonical_record,
                source_sha256=source_sha256,
                analysis_sha256=analysis_sha256,
                normalized_sha256=normalized_sha256,
                ai_analysis_sha256=ai_analysis_sha256,
                payload_sha256=payload_sha256,
                distribution_tlp=distribution_tlp,
                publication_status=target_status,
                actor=actor,
            )
            row.provider = record.provider
            row.title = record.title
            row.updated_at = utc_now()

            if target_status == "restricted":
                restricted += 1
                self._withdraw_for_restricted_revision(row, revision)
            elif target_status == "published":
                published += 1
                self._publish_revision(row, revision)
            else:
                staged += 1

        self.session.flush()
        self._audit(
            actor,
            "publisher.import_completed",
            "publisher_import",
            payload.feed_version,
            {
                "feed_id": payload.feed_id,
                "feed_version": payload.feed_version,
                "records": len(payload.items),
                "publish": payload.publish,
            },
        )
        return PublisherImportResult(
            imported=len(payload.items),
            created=created,
            staged=staged,
            published=published,
            unchanged=unchanged,
            superseded=superseded,
            restricted=restricted,
            record_ids=record_ids,
            warnings=warnings,
        )

    def list_records(self, *, limit: int, offset: int) -> PublisherRecordPage:
        total = int(
            self.session.scalar(select(func.count()).select_from(PublisherRecordRow)) or 0
        )
        rows = list(
            self.session.scalars(
                select(PublisherRecordRow)
                .order_by(PublisherRecordRow.updated_at.desc(), PublisherRecordRow.id)
                .offset(offset)
                .limit(limit)
            )
        )
        return PublisherRecordPage(
            items=[self._record_view(row) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def publish_record(self, record_id: UUID, actor: str) -> PublisherPublishResult:
        row = self.session.scalar(
            select(PublisherRecordRow).where(PublisherRecordRow.id == record_id)
        )
        if row is None:
            raise PublisherNotFoundError("Publisher record was not found")
        revision = self._current_revision(row.id, for_update=True)
        if revision is None:
            raise PublisherConflictError("Publisher record has no current revision")
        if revision.publication_status == "restricted":
            raise PublisherConflictError("TLP:RED revisions cannot be published")
        if revision.publication_status == "published":
            return PublisherPublishResult(
                record=self._record_view(row),
                published=False,
                change_sequences=[],
            )
        if revision.publication_status != "staged":
            raise PublisherConflictError("Only the current staged revision can be published")
        sequences = self._publish_revision(row, revision)
        self._audit(
            actor,
            "publisher.record_published",
            "publisher_record",
            row.id,
            {
                "revision": revision.revision_number,
                "change_sequences": sequences,
            },
        )
        return PublisherPublishResult(
            record=self._record_view(row),
            published=True,
            change_sequences=sequences,
        )

    def build_feed_page(
        self,
        client: PublisherClientRow,
        *,
        limit: int,
        cursor: str | None,
    ) -> ExternalDatapointPage:
        if not 1 <= limit <= self.settings.max_page_size:
            raise PublisherCursorError("limit exceeds the publisher page-size policy")
        entitlement = client_entitlement_sha256(client)
        now = utc_now()
        if cursor is None:
            snapshot_max = int(
                self.session.scalar(select(func.max(PublisherChangeRow.sequence))) or 0
            )
            after_sequence = 0
            generated_at = now
        else:
            payload = _decode_cursor(
                cursor,
                secret=self.settings.cursor_secret_bytes(),
            )
            if payload.get("v") != 1 or payload.get("kind") != "page":
                raise PublisherCursorError("Unsupported publisher cursor")
            if payload.get("client_id") != client.client_id:
                raise PublisherCursorError("Publisher cursor belongs to another client")
            if payload.get("entitlement") != entitlement:
                raise PublisherCursorError("Publisher cursor entitlement has changed")
            if payload.get("token_version") != client.token_version:
                raise PublisherCursorError("Publisher cursor credential version has changed")
            expires_at = _cursor_datetime(payload.get("expires_at"), "expires_at")
            if expires_at <= now:
                raise PublisherCursorError("Publisher cursor has expired")
            generated_at = _cursor_datetime(payload.get("generated_at"), "generated_at")
            snapshot_max = _cursor_integer(payload.get("snapshot_max"), "snapshot_max")
            after_sequence = _cursor_integer(
                payload.get("after_sequence"),
                "after_sequence",
            )
            if after_sequence > snapshot_max:
                raise PublisherCursorError("Publisher cursor sequence is inconsistent")

        allowed_tlps = [
            value
            for value, rank in _TLP_RANK.items()
            if rank <= _TLP_RANK[client.max_tlp] and value != "TLP:RED"
        ]
        filters: list[Any] = [
            PublisherChangeRow.sequence <= snapshot_max,
            PublisherChangeRow.distribution_tlp.in_(allowed_tlps),
        ]
        if client.allowed_providers:
            filters.append(
                PublisherChangeRow.provider_key.in_(
                    [value.casefold() for value in client.allowed_providers]
                )
            )
        if client.allowed_source_kinds:
            filters.append(
                PublisherChangeRow.source_kind.in_(client.allowed_source_kinds)
            )

        latest = (
            select(
                PublisherChangeRow.provider_key.label("provider_key"),
                PublisherChangeRow.external_id.label("external_id"),
                func.max(PublisherChangeRow.sequence).label("sequence"),
            )
            .where(*filters)
            .group_by(PublisherChangeRow.provider_key, PublisherChangeRow.external_id)
            .subquery()
        )
        rows = list(
            self.session.scalars(
                select(PublisherChangeRow)
                .join(latest, PublisherChangeRow.sequence == latest.c.sequence)
                .where(PublisherChangeRow.sequence > after_sequence)
                .order_by(PublisherChangeRow.sequence)
                .limit(limit + 1)
            )
        )
        has_more = len(rows) > limit
        selected = rows[:limit]
        next_cursor = None
        if has_more:
            next_cursor = _encode_cursor(
                {
                    "v": 1,
                    "kind": "page",
                    "client_id": client.client_id,
                    "token_version": client.token_version,
                    "entitlement": entitlement,
                    "snapshot_max": snapshot_max,
                    "after_sequence": selected[-1].sequence,
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
        feed_version = (
            f"snapshot-{snapshot_max:x}-{client.token_version}-{entitlement[:16]}"
        )
        self._audit(
            f"client:{client.client_id}",
            "publisher.feed_page_served",
            "publisher_client",
            client.id,
            {
                "feed_version": feed_version,
                "snapshot_max": snapshot_max,
                "after_sequence": after_sequence,
                "returned": len(items),
                "has_more": has_more,
                "entitlement_sha256": entitlement,
            },
        )
        return ExternalDatapointPage(
            feed_id=self.settings.feed_id,
            feed_version=feed_version,
            generated_at=generated_at,
            items=items,
            has_more=has_more,
            next_cursor=next_cursor,
        )

    def _client(self, client_id: str, *, for_update: bool = False) -> PublisherClientRow:
        statement = select(PublisherClientRow).where(
            PublisherClientRow.client_id == client_id
        )
        if for_update:
            statement = statement.with_for_update()
        row = self.session.scalar(statement)
        if row is None:
            raise PublisherNotFoundError("Publisher client was not found")
        return row

    def _add_revision(
        self,
        *,
        row: PublisherRecordRow,
        item: ExternalDatapoint,
        payload: PublisherImportBatch,
        canonical_record: dict[str, Any],
        source_sha256: str,
        analysis_sha256: str,
        normalized_sha256: str,
        ai_analysis_sha256: str,
        payload_sha256: str,
        distribution_tlp: str,
        publication_status: str,
        actor: str,
    ) -> PublisherRevisionRow:
        revision_number = int(
            self.session.scalar(
                select(func.max(PublisherRevisionRow.revision_number)).where(
                    PublisherRevisionRow.record_id == row.id
                )
            )
            or 0
        ) + 1
        revision = PublisherRevisionRow(
            record_id=row.id,
            revision_number=revision_number,
            lifecycle_status=item.status,
            source_kind=item.record.source_kind,
            record_type=item.record.record_type,
            status_changed_at=item.status_changed_at,
            status_reason=item.status_reason,
            distribution_tlp=distribution_tlp,
            modified_at=item.record.modified_at,
            feed_id=payload.feed_id,
            feed_version=payload.feed_version,
            feed_generated_at=payload.generated_at,
            canonical_record=canonical_record,
            source_sha256=source_sha256,
            analysis_sha256=analysis_sha256,
            normalized_sha256=normalized_sha256,
            ai_analysis_sha256=ai_analysis_sha256,
            payload_sha256=payload_sha256,
            publication_status=publication_status,
            imported_by=actor,
        )
        self.session.add(revision)
        self.session.flush()
        return revision

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

    def _previous_published_revision(
        self,
        record_id: UUID,
        current_revision_id: UUID,
    ) -> PublisherRevisionRow | None:
        return self.session.scalar(
            select(PublisherRevisionRow)
            .where(
                PublisherRevisionRow.record_id == record_id,
                PublisherRevisionRow.id != current_revision_id,
                PublisherRevisionRow.publication_status == "published",
            )
            .order_by(
                PublisherRevisionRow.modified_at.desc(),
                PublisherRevisionRow.revision_number.desc(),
            )
            .limit(1)
        )

    def _publish_revision(
        self,
        row: PublisherRecordRow,
        revision: PublisherRevisionRow,
    ) -> list[int]:
        if revision.distribution_tlp == "TLP:RED":
            raise PublisherConflictError("TLP:RED revisions cannot be published")
        previous = self._previous_published_revision(row.id, revision.id)
        changes: list[PublisherChangeRow] = []
        if previous is not None and _TLP_RANK[revision.distribution_tlp] > _TLP_RANK[
            previous.distribution_tlp
        ]:
            changes.append(self._withdrawal_change(row, revision, previous))
        row.source_kind = revision.source_kind
        row.record_type = revision.record_type
        changes.append(
            PublisherChangeRow(
                record_id=row.id,
                revision_id=revision.id,
                projection="canonical",
                provider=row.provider,
                provider_key=row.provider_key,
                external_id=row.external_id,
                source_kind=revision.source_kind,
                record_type=revision.record_type,
                distribution_tlp=revision.distribution_tlp,
                lifecycle_status=revision.lifecycle_status,
                status_changed_at=revision.status_changed_at,
                status_reason=revision.status_reason,
                canonical_record=revision.canonical_record,
            )
        )
        self.session.add_all(changes)
        revision.publication_status = "published"
        revision.published_at = utc_now()
        self._supersede_older_revisions(row.id, revision.id)
        self.session.flush()
        return [change.sequence for change in changes]

    def _withdraw_for_restricted_revision(
        self,
        row: PublisherRecordRow,
        revision: PublisherRevisionRow,
    ) -> list[int]:
        previous = self._previous_published_revision(row.id, revision.id)
        if previous is None:
            return []
        change = self._withdrawal_change(row, revision, previous)
        self.session.add(change)
        self._supersede_older_revisions(row.id, revision.id)
        self.session.flush()
        return [change.sequence]

    def _withdrawal_change(
        self,
        row: PublisherRecordRow,
        revision: PublisherRevisionRow,
        previous: PublisherRevisionRow,
    ) -> PublisherChangeRow:
        canonical = dict(previous.canonical_record)
        revision_time = revision.modified_at.astimezone(UTC)
        canonical["revoked"] = True
        canonical["modified_at"] = revision_time.isoformat()
        canonical["retrieved_at"] = revision_time.isoformat()
        canonical["valid_until"] = revision_time.isoformat()
        canonical["markings"] = [previous.distribution_tlp]
        return PublisherChangeRow(
            record_id=row.id,
            revision_id=revision.id,
            projection="withdrawal",
            provider=row.provider,
            provider_key=row.provider_key,
            external_id=row.external_id,
            source_kind=previous.source_kind,
            record_type=previous.record_type,
            distribution_tlp=previous.distribution_tlp,
            lifecycle_status="deleted",
            status_changed_at=revision.modified_at,
            status_reason="A newer source revision is no longer distributable at this TLP.",
            canonical_record=canonical,
        )

    def _supersede_older_revisions(
        self,
        record_id: UUID,
        current_revision_id: UUID,
    ) -> None:
        rows = list(
            self.session.scalars(
                select(PublisherRevisionRow).where(
                    PublisherRevisionRow.record_id == record_id,
                    PublisherRevisionRow.id != current_revision_id,
                    PublisherRevisionRow.publication_status.in_(("published", "staged")),
                )
            )
        )
        for row in rows:
            row.publication_status = "superseded"

    def _record_view(self, row: PublisherRecordRow) -> PublisherRecordView:
        revision = self._current_revision(row.id)
        if revision is None:
            revision = self.session.scalar(
                select(PublisherRevisionRow)
                .where(PublisherRevisionRow.record_id == row.id)
                .order_by(PublisherRevisionRow.revision_number.desc())
                .limit(1)
            )
        if revision is None:
            raise PublisherConflictError("Publisher record has no revision")
        return PublisherRecordView(
            id=row.id,
            provider=row.provider,
            external_id=row.external_id,
            source_kind=row.source_kind,  # type: ignore[arg-type]
            record_type=row.record_type,
            title=row.title,
            latest_revision=revision.revision_number,
            latest_modified_at=revision.modified_at,
            latest_status=revision.lifecycle_status,  # type: ignore[arg-type]
            latest_tlp=revision.distribution_tlp,
            publication_status=revision.publication_status,  # type: ignore[arg-type]
            payload_sha256=revision.payload_sha256,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _audit(
        self,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: UUID | str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.session.add(
            PublisherAuditRow(
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=str(resource_id),
                details=details or {},
            )
        )


def _new_client_token(client_id: str) -> str:
    return f"traceless.{client_id}.{token_urlsafe(32)}"


def _hash_json(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _encode_cursor(payload: dict[str, Any], *, secret: bytes) -> str:
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    encoded = _base64url(raw)
    signature = _base64url(hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def _decode_cursor(value: str, *, secret: bytes) -> dict[str, Any]:
    if not isinstance(value, str) or not 1 <= len(value) <= 2_048:
        raise PublisherCursorError("Publisher cursor has an invalid length")
    encoded, separator, signature = value.partition(".")
    if not separator or not encoded or not signature:
        raise PublisherCursorError("Publisher cursor has an invalid shape")
    expected = _base64url(hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        raise PublisherCursorError("Publisher cursor signature is invalid")
    try:
        decoded = base64.urlsafe_b64decode(_restore_padding(encoded)).decode("utf-8")
        payload = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublisherCursorError("Publisher cursor payload is invalid") from error
    if not isinstance(payload, dict):
        raise PublisherCursorError("Publisher cursor payload must be an object")
    return payload


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _restore_padding(value: str) -> str:
    return value + "=" * (-len(value) % 4)


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
