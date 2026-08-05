"""Durable signed-feed delta state for customer-local intelligence pulls."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
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

from traceless_api.db.base import Base
from traceless_api.db.models import UTCDateTime, utc_now


class ExternalIntelligenceSubscriptionStateRow(Base):
    __tablename__ = "external_intelligence_subscription_state"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "connector_id",
            name="uq_external_intel_subscription_org_connector",
        ),
        CheckConstraint("feed_epoch >= 1", name="ck_external_intel_subscription_epoch"),
        CheckConstraint(
            "through_sequence >= 0",
            name="ck_external_intel_subscription_sequence",
        ),
        CheckConstraint(
            "length(next_sync_token_sha256) = 64",
            name="ck_external_intel_subscription_token_hash",
        ),
        Index(
            "ix_external_intel_subscription_org_updated",
            "organization_id",
            "updated_at",
        ),
    )

    connector_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("external_intelligence_connectors.id", ondelete="CASCADE"),
        primary_key=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    feed_id: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_epoch: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    next_sync_token: Mapped[str] = mapped_column(Text, nullable=False)
    next_sync_token_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    through_sequence: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    entitlement_epoch: Mapped[int | None] = mapped_column(Integer)
    reset_generation: Mapped[int | None] = mapped_column(Integer)
    last_full_snapshot_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    signing_key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    signature_verified_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utc_now, onupdate=utc_now
    )
