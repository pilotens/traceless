"""Normalized publisher v2 persistence and delivery state."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from traceless_api.publisher.db import PublisherBase, PublisherUTCDateTime, utc_now

_TLP_CHECK = (
    "max_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT')"
)
_DISTRIBUTION_TLP_CHECK = (
    "distribution_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', "
    "'TLP:AMBER+STRICT', 'TLP:RED')"
)


class PublisherAccountRow(PublisherBase):
    __tablename__ = "publisher_accounts"
    __table_args__ = (
        Index("ix_publisher_account_enabled", "enabled", "account_key"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    account_key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        PublisherUTCDateTime(), default=utc_now, onupdate=utc_now
    )


class PublisherInstallationRow(PublisherBase):
    __tablename__ = "publisher_installations"
    __table_args__ = (
        CheckConstraint(_TLP_CHECK, name="ck_publisher_installation_max_tlp"),
        CheckConstraint(
            "entitlement_epoch >= 1 AND reset_generation >= 1",
            name="ck_publisher_installation_epochs",
        ),
        CheckConstraint(
            "environment IN ('production', 'test', 'development', 'disaster_recovery')",
            name="ck_publisher_installation_environment",
        ),
        UniqueConstraint(
            "account_id",
            "installation_key",
            name="uq_publisher_installation_account_key",
        ),
        Index("ix_publisher_installation_account", "account_id", "enabled"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    account_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("publisher_accounts.id", ondelete="RESTRICT"),
        nullable=False,
    )
    client_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    installation_key: Mapped[str] = mapped_column(String(80), nullable=False, default="primary")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="production")
    region: Mapped[str | None] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_tlp: Mapped[str] = mapped_column(String(24), default="TLP:AMBER", nullable=False)
    entitlement_epoch: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    reset_generation: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        PublisherUTCDateTime(), default=utc_now, onupdate=utc_now
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())


class PublisherClientCredentialRow(PublisherBase):
    __tablename__ = "publisher_client_credentials"
    __table_args__ = (
        CheckConstraint("token_version >= 1", name="ck_publisher_credential_version"),
        CheckConstraint(
            "length(key_sha256) = 64",
            name="ck_publisher_credential_key_hash",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > not_before",
            name="ck_publisher_credential_expiry",
        ),
        Index(
            "ix_publisher_credential_installation_active",
            "installation_id",
            "revoked_at",
            "expires_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    installation_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("publisher_installations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    key_sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False)
    not_before: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    expires_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)


class PublisherEntitlementRow(PublisherBase):
    __tablename__ = "publisher_entitlements"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('provider', 'source_kind')",
            name="ck_publisher_entitlement_scope_type",
        ),
        UniqueConstraint(
            "installation_id",
            "scope_type",
            "scope_value",
            name="uq_publisher_entitlement_scope",
        ),
        Index(
            "ix_publisher_entitlement_lookup",
            "installation_id",
            "scope_type",
            "scope_value",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    installation_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("publisher_installations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    scope_type: Mapped[str] = mapped_column(String(24), nullable=False)
    scope_value: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)


class PublisherImportRunRow(PublisherBase):
    __tablename__ = "publisher_import_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'abandoned')",
            name="ck_publisher_import_run_status",
        ),
        CheckConstraint("item_count >= 0", name="ck_publisher_import_run_item_count"),
        CheckConstraint("attempt_count >= 1", name="ck_publisher_import_run_attempt_count"),
        CheckConstraint(
            "length(manifest_sha256) = 64",
            name="ck_publisher_import_run_manifest",
        ),
        Index("ix_publisher_import_run_created", "created_at", "id"),
        Index("ix_publisher_import_run_lease", "status", "lease_expires_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    feed_id: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_version: Mapped[str] = mapped_column(String(120), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key_sha256: Mapped[str | None] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    lease_expires_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())
    attempt_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(120))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())


class PublisherPublicationDecisionRow(PublisherBase):
    __tablename__ = "publisher_publication_decisions"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('published', 'rejected', 'emergency_withdrawal', 'automatic')",
            name="ck_publisher_publication_decision",
        ),
        Index("ix_publisher_decision_record_created", "record_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    record_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("publisher_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    revision_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("publisher_revisions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)


class PublisherCurrentProjectionRow(PublisherBase):
    __tablename__ = "publisher_current_projections"
    __table_args__ = (
        CheckConstraint(
            _DISTRIBUTION_TLP_CHECK,
            name="ck_publisher_current_projection_tlp",
        ),
        CheckConstraint(
            "lifecycle_status IN ('active', 'revoked', 'deleted')",
            name="ck_publisher_current_projection_lifecycle",
        ),
        Index(
            "ix_publisher_current_projection_feed",
            "distribution_tlp",
            "source_kind",
            "provider_key",
            "sequence",
        ),
    )

    record_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("publisher_records.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    revision_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("publisher_revisions.id", ondelete="RESTRICT"),
        unique=True,
        nullable=False,
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(100), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    record_type: Mapped[str] = mapped_column(String(32), nullable=False)
    distribution_tlp: Mapped[str] = mapped_column(String(24), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(20), nullable=False)
    status_changed_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())
    status_reason: Mapped[str | None] = mapped_column(Text)
    canonical_record: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)



class PublisherSigningKeyRow(PublisherBase):
    __tablename__ = "publisher_signing_keys"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'retiring', 'retired')",
            name="ck_publisher_signing_key_status",
        ),
        CheckConstraint(
            "length(fingerprint_sha256) = 64",
            name="ck_publisher_signing_key_fingerprint",
        ),
        Index("ix_publisher_signing_key_status", "status", "not_before"),
    )

    key_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    public_key_base64: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    not_before: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    not_after: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
