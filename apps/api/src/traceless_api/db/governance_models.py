"""Persistent closed-loop risk governance records."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from traceless_api.db.base import Base
from traceless_api.db.models import UTCDateTime, utc_now


class SystemContextVersionRow(Base):
    __tablename__ = "system_context_versions"
    __table_args__ = (
        UniqueConstraint("system_id", "version", name="uq_system_context_system_version"),
        Index("ix_system_context_system_created", "system_id", "created_at"),
        Index(
            "ux_system_context_one_published",
            "system_id",
            unique=True,
            postgresql_where=text("status = 'published'"),
            sqlite_where=text("status = 'published'"),
        ),
        CheckConstraint(
            "status IN ('draft', 'published', 'superseded')",
            name="ck_system_context_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="draft", nullable=False)
    business_owner: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    processes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    data_categories: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    regulations: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    recovery_time_objective_hours: Mapped[float | None] = mapped_column(Float)
    recovery_point_objective_hours: Mapped[float | None] = mapped_column(Float)
    impact_profile: Mapped[dict[str, int]] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    published_by: Mapped[str | None] = mapped_column(String(160))
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class RiskEvidenceLinkRow(Base):
    __tablename__ = "risk_evidence_links"
    __table_args__ = (
        UniqueConstraint(
            "risk_id", "evidence_type", "evidence_id", name="uq_risk_evidence_identity"
        ),
        Index("ix_risk_evidence_risk", "risk_id"),
        CheckConstraint(
            "evidence_type IN ('finding', 'threat', 'architecture', 'control', "
            "'attack_chain', 'manual')",
            name="ck_risk_evidence_type",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    risk_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("risks_operational.id", ondelete="CASCADE"), nullable=False
    )
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(240), nullable=False)
    label: Mapped[str] = mapped_column(String(500), nullable=False)
    source_version: Mapped[str | None] = mapped_column(String(200))
    metadata_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class RiskTreatmentRow(Base):
    __tablename__ = "risk_treatments"
    __table_args__ = (
        Index("ix_risk_treatments_system_status", "system_id", "status"),
        Index("ix_risk_treatments_risk", "risk_id"),
        Index("ix_risk_treatments_due", "due_at"),
        CheckConstraint(
            "strategy IN ('mitigate', 'avoid', 'transfer', 'accept')",
            name="ck_risk_treatment_strategy",
        ),
        CheckConstraint(
            "status IN ('proposed', 'approved', 'in_progress', 'verification', "
            "'closed', 'cancelled')",
            name="ck_risk_treatment_status",
        ),
        CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="ck_risk_treatment_priority",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    risk_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("risks_operational.id", ondelete="CASCADE"), nullable=False
    )
    strategy: Mapped[str] = mapped_column(String(24), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner: Mapped[str] = mapped_column(String(160), nullable=False)
    approver: Mapped[str | None] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(24), default="proposed", nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False)
    due_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    sla_days: Mapped[int | None] = mapped_column(Integer)
    verification_criteria: Mapped[str] = mapped_column(Text, default="", nullable=False)
    decision_note: Mapped[str] = mapped_column(Text, default="", nullable=False)
    external_system: Mapped[str | None] = mapped_column(String(80))
    external_key: Mapped[str | None] = mapped_column(String(160))
    external_url: Mapped[str | None] = mapped_column(String(2000))
    residual_likelihood: Mapped[int | None] = mapped_column(Integer)
    residual_impact: Mapped[int | None] = mapped_column(Integer)
    residual_score: Mapped[int | None] = mapped_column(Integer)
    residual_level: Mapped[str | None] = mapped_column(String(20))
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)
    approved_by: Mapped[str | None] = mapped_column(String(160))
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    verified_by: Mapped[str | None] = mapped_column(String(160))
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class ControlRow(Base):
    __tablename__ = "controls_operational"
    __table_args__ = (
        UniqueConstraint("system_id", "control_key", name="uq_control_system_key"),
        Index("ix_controls_system_status", "system_id", "status"),
        CheckConstraint(
            "status IN ('planned', 'implemented', 'retired')",
            name="ck_control_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    control_key: Mapped[str] = mapped_column(String(160), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    framework: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    owner: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="planned", nullable=False)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class ControlAssessmentRow(Base):
    __tablename__ = "control_assessments"
    __table_args__ = (
        Index("ix_control_assessments_control_assessed", "control_id", "assessed_at"),
        CheckConstraint(
            "design_effectiveness >= 0 AND design_effectiveness <= 1",
            name="ck_control_assessment_design",
        ),
        CheckConstraint(
            "operating_effectiveness >= 0 AND operating_effectiveness <= 1",
            name="ck_control_assessment_operating",
        ),
        CheckConstraint(
            "result IN ('effective', 'partial', 'ineffective', 'not_tested')",
            name="ck_control_assessment_result",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    control_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("controls_operational.id", ondelete="CASCADE"), nullable=False
    )
    design_effectiveness: Mapped[float] = mapped_column(Float, nullable=False)
    operating_effectiveness: Mapped[float] = mapped_column(Float, nullable=False)
    result: Mapped[str] = mapped_column(String(24), nullable=False)
    evidence_reference: Mapped[str] = mapped_column(Text, nullable=False)
    assessed_by: Mapped[str] = mapped_column(String(160), nullable=False)
    assessed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    valid_until: Mapped[datetime | None] = mapped_column(UTCDateTime())


class AnalysisManifestRow(Base):
    __tablename__ = "analysis_manifests"
    __table_args__ = (
        Index("ix_analysis_manifests_system_created", "system_id", "created_at"),
        UniqueConstraint(
            "system_id", "purpose", "source_fingerprint", name="uq_analysis_manifest_source"
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(80), nullable=False)
    architecture_snapshot_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("architecture_snapshots.id", ondelete="SET NULL")
    )
    system_context_version_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("system_context_versions.id", ondelete="SET NULL")
    )
    scan_job_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    risk_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    components: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
