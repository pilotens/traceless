"""Tenant-scoped persistence for reachable attack-chain analyses."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from traceless_api.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class _UTCDateTime(TypeDecorator[datetime]):
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


class AttackChainAnalysisRow(Base):
    __tablename__ = "attack_chain_analyses"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "input_sha256",
            name="uq_attack_chain_analysis_org_input",
        ),
        Index(
            "ix_attack_chain_analysis_org_created",
            "organization_id",
            "created_at",
        ),
        Index(
            "ix_attack_chain_analysis_source_record",
            "source_record_id",
            "created_at",
        ),
        CheckConstraint(
            "status IN ('reachable', 'unreachable')",
            name="ck_attack_chain_analysis_status",
        ),
        CheckConstraint(
            "distribution_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', "
            "'TLP:AMBER+STRICT')",
            name="ck_attack_chain_analysis_distribution_tlp",
        ),
        CheckConstraint(
            "repair_rounds >= 0 AND repair_rounds <= 2",
            name="ck_attack_chain_analysis_repair_rounds",
        ),
        CheckConstraint(
            "unit_count >= 0 AND path_count >= 0 AND issue_count >= 0",
            name="ck_attack_chain_analysis_counts",
        ),
        CheckConstraint(
            "length(input_sha256) = 64 AND length(source_sha256) = 64",
            name="ck_attack_chain_analysis_hashes",
        ),
        CheckConstraint(
            "(source_text_retained AND source_text IS NOT NULL) OR "
            "(NOT source_text_retained AND source_text IS NULL)",
            name="ck_attack_chain_analysis_source_retention",
        ),
        CheckConstraint(
            "(status = 'reachable' AND reachable AND path_count >= 1) OR "
            "(status = 'unreachable' AND NOT reachable AND path_count = 0)",
            name="ck_attack_chain_analysis_reachability",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_record_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("global_intel_records.id", ondelete="SET NULL"),
    )
    source_title: Mapped[str] = mapped_column(String(500), nullable=False)
    distribution_tlp: Mapped[str] = mapped_column(String(24), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_text: Mapped[str | None] = mapped_column(Text)
    source_text_retained: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    pipeline_version: Mapped[str] = mapped_column(String(120), nullable=False)
    vocabulary_version: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    reachable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    unit_count: Mapped[int] = mapped_column(Integer, nullable=False)
    path_count: Mapped[int] = mapped_column(Integer, nullable=False)
    issue_count: Mapped[int] = mapped_column(Integer, nullable=False)
    repair_rounds: Mapped[int] = mapped_column(Integer, nullable=False)
    analysis: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(_UTCDateTime(), default=_utc_now, nullable=False)
