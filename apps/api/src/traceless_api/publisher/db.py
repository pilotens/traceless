"""Independent persistence for the central intelligence publisher."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import Request
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Engine,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator


class PublisherBase(DeclarativeBase):
    """Declarative base kept separate from customer-side Traceless tables."""


def utc_now() -> datetime:
    return datetime.now(UTC)


class PublisherUTCDateTime(TypeDecorator[datetime]):
    """Persist UTC values and restore timezone information for SQLite."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Naive datetimes are not permitted")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


_TLP_CHECK = (
    "max_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT')"
)
_DISTRIBUTION_TLP_CHECK = (
    "distribution_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', "
    "'TLP:AMBER+STRICT', 'TLP:RED')"
)


class PublisherClientRow(PublisherBase):
    __tablename__ = "publisher_clients"
    __table_args__ = (
        CheckConstraint(_TLP_CHECK, name="ck_publisher_client_max_tlp"),
        CheckConstraint("token_version >= 1", name="ck_publisher_client_token_version"),
        CheckConstraint("length(api_key_sha256) = 64", name="ck_publisher_client_key_hash"),
        Index("ix_publisher_client_enabled", "enabled", "client_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    client_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    api_key_sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_tlp: Mapped[str] = mapped_column(String(24), default="TLP:AMBER", nullable=False)
    allowed_providers: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    allowed_source_kinds: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        PublisherUTCDateTime(),
        default=utc_now,
        onupdate=utc_now,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())


class PublisherRecordRow(PublisherBase):
    __tablename__ = "publisher_records"
    __table_args__ = (
        UniqueConstraint(
            "provider_key",
            "external_id",
            name="uq_publisher_record_provider_external_id",
        ),
        Index("ix_publisher_record_updated", "updated_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(100), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    record_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        PublisherUTCDateTime(),
        default=utc_now,
        onupdate=utc_now,
    )


class PublisherRevisionRow(PublisherBase):
    __tablename__ = "publisher_revisions"
    __table_args__ = (
        UniqueConstraint(
            "record_id",
            "revision_number",
            name="uq_publisher_revision_number",
        ),
        CheckConstraint(
            "revision_number >= 1",
            name="ck_publisher_revision_number",
        ),
        CheckConstraint(
            "lifecycle_status IN ('active', 'revoked', 'deleted')",
            name="ck_publisher_revision_lifecycle_status",
        ),
        CheckConstraint(
            "publication_status IN ('staged', 'published', 'restricted', 'superseded', 'rejected')",
            name="ck_publisher_revision_publication_status",
        ),
        CheckConstraint(
            _DISTRIBUTION_TLP_CHECK,
            name="ck_publisher_revision_distribution_tlp",
        ),
        CheckConstraint(
            "length(source_sha256) = 64 AND length(analysis_sha256) = 64 "
            "AND length(normalized_sha256) = 64 AND length(ai_analysis_sha256) = 64 "
            "AND length(payload_sha256) = 64",
            name="ck_publisher_revision_hashes",
        ),
        Index("ix_publisher_revision_record_created", "record_id", "revision_number"),
        Index("ix_publisher_revision_publication", "publication_status", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    record_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("publisher_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(20), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    record_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status_changed_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())
    status_reason: Mapped[str | None] = mapped_column(Text)
    distribution_tlp: Mapped[str] = mapped_column(String(24), nullable=False)
    modified_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), nullable=False)
    feed_id: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_version: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_generated_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), nullable=False)
    canonical_record: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # Legacy digest retained for migration compatibility. New code should use the
    # normalized and AI-specific digests below.
    analysis_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ai_analysis_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    publication_status: Mapped[str] = mapped_column(String(20), nullable=False)
    imported_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)
    published_at: Mapped[datetime | None] = mapped_column(PublisherUTCDateTime())


class PublisherChangeRow(PublisherBase):
    """Immutable projection consumed by customer snapshots."""

    __tablename__ = "publisher_changes"
    __table_args__ = (
        UniqueConstraint(
            "revision_id",
            "projection",
            "distribution_tlp",
            name="uq_publisher_change_revision_projection_tlp",
        ),
        CheckConstraint(
            "projection IN ('canonical', 'withdrawal')",
            name="ck_publisher_change_projection",
        ),
        CheckConstraint(
            "lifecycle_status IN ('active', 'revoked', 'deleted')",
            name="ck_publisher_change_lifecycle_status",
        ),
        CheckConstraint(
            _DISTRIBUTION_TLP_CHECK,
            name="ck_publisher_change_distribution_tlp",
        ),
        Index(
            "ix_publisher_change_identity_sequence",
            "provider_key",
            "external_id",
            "sequence",
        ),
        Index("ix_publisher_change_published", "published_at", "sequence"),
    )

    sequence: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
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
    projection: Mapped[str] = mapped_column(String(20), nullable=False)
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
    published_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)


class PublisherAuditRow(PublisherBase):
    __tablename__ = "publisher_audit_events"
    __table_args__ = (Index("ix_publisher_audit_created", "created_at", "id"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(160), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(PublisherUTCDateTime(), default=utc_now)


def create_publisher_engine(database_url: str) -> Engine:
    kwargs: dict[str, object] = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, **kwargs)
    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    return engine


def create_publisher_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_publisher_schema(engine: Engine) -> None:
    PublisherBase.metadata.create_all(engine)


def get_publisher_session(request: Request) -> Iterator[Session]:
    factory: sessionmaker[Session] = request.app.state.publisher_session_factory
    with factory() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
