"""Persistent records for the first operational Traceless pipeline."""

from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
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
from sqlalchemy.types import TypeDecorator

from traceless_api.db.base import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Persist UTC values and restore tzinfo on SQLite result rows."""

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


class OrganizationRow(Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    external_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class ProjectRow(Base):
    __tablename__ = "projects"
    __table_args__ = (Index("ix_projects_organization", "organization_id"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class SystemRow(Base):
    __tablename__ = "systems_operational"
    __table_args__ = (Index("ix_systems_project", "project_id"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner: Mapped[str] = mapped_column(String(160), nullable=False)
    criticality: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class ScanAuthorizationRow(Base):
    __tablename__ = "scan_authorizations"
    __table_args__ = (Index("ix_scan_authorizations_system", "system_id"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    targets: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    profile: Mapped[str] = mapped_column(String(40), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(160), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    scope_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class ScanJobRow(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_system_requested", "system_id", "requested_at"),
        Index("ix_scan_jobs_organization", "organization_id"),
        Index("ix_scan_jobs_status", "status"),
        Index("ix_scan_jobs_lease", "status", "lease_expires_at"),
        CheckConstraint("attempt_count >= 0", name="ck_scan_job_attempt_count"),
        CheckConstraint(
            "max_attempts >= 1 AND max_attempts <= 10", name="ck_scan_job_max_attempts"
        ),
        CheckConstraint(
            "source_time_status IN ('trusted', 'missing', 'stale', 'quarantined')",
            name="ck_scan_source_time_status",
        ),
        CheckConstraint(
            "completeness IN ('complete', 'partial', 'discovery')",
            name="ck_scan_completeness",
        ),
        CheckConstraint(
            "inventory_role IN ('authoritative', 'supplemental', 'historical')",
            name="ck_scan_inventory_role",
        ),
        Index(
            "ix_scan_jobs_current_inventory",
            "system_id",
            "is_current_inventory",
            "source_observed_at",
        ),
        Index(
            "ux_scan_jobs_one_current_inventory",
            "system_id",
            unique=True,
            postgresql_where=text("is_current_inventory"),
            sqlite_where=text("is_current_inventory = 1"),
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    authorization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("scan_authorizations.id", ondelete="RESTRICT"), nullable=False
    )
    scanner: Mapped[str] = mapped_column(String(40), default="nmap", nullable=False)
    mode: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    claimed_by: Mapped[str | None] = mapped_column(String(160))
    lease_token: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    raw_evidence_sha256: Mapped[str | None] = mapped_column(String(64))
    raw_evidence: Mapped[str | None] = mapped_column(Text)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_message: Mapped[str | None] = mapped_column(Text)
    source_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    source_completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    source_observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    source_time_status: Mapped[str] = mapped_column(
        String(20), default="missing", nullable=False
    )
    scope_targets: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    scope_sha256: Mapped[str | None] = mapped_column(String(64))
    scan_profile: Mapped[str] = mapped_column(
        String(40), default="unknown", nullable=False
    )
    completeness: Mapped[str] = mapped_column(
        String(20), default="partial", nullable=False
    )
    inventory_role: Mapped[str] = mapped_column(
        String(20), default="supplemental", nullable=False
    )
    is_current_inventory: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )


class AssetRow(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("system_id", "stable_key", name="uq_asset_system_stable_key"),
        Index("ix_assets_system_last_seen", "system_id", "last_seen_at"),
        CheckConstraint(
            "inventory_status IN ('current', 'unobserved', 'stale')",
            name="ck_asset_inventory_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    source_scan_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("scan_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    stable_key: Mapped[str] = mapped_column(String(255), nullable=False)
    primary_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(20), default="up", nullable=False)
    os_family: Mapped[str | None] = mapped_column(String(120))
    os_accuracy: Mapped[int | None] = mapped_column(Integer)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    observation_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    inventory_status: Mapped[str] = mapped_column(
        String(20), default="stale", nullable=False
    )


class AssetAliasRow(Base):
    """Stable identity aliases kept independently from mutable asset presentation."""

    __tablename__ = "asset_aliases"
    __table_args__ = (
        UniqueConstraint(
            "system_id",
            "kind",
            "value_normalized",
            name="uq_asset_alias_system_kind_value",
        ),
        Index("ix_asset_alias_asset", "asset_id"),
        CheckConstraint(
            "kind IN ('ip', 'mac', 'hostname')", name="ck_asset_alias_kind"
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    value_normalized: Mapped[str] = mapped_column(String(500), nullable=False)
    value_display: Mapped[str] = mapped_column(String(500), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class AssetObservationRow(Base):
    """Immutable asset presentation captured in one scanner generation."""

    __tablename__ = "asset_observations"
    __table_args__ = (
        UniqueConstraint(
            "scan_job_id",
            "observation_key",
            name="uq_asset_observation_scan_key",
        ),
        Index("ix_asset_observations_system_observed", "system_id", "observed_at"),
        Index("ix_asset_observations_asset_observed", "asset_id", "observed_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    observation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    primary_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    os_family: Mapped[str | None] = mapped_column(String(120))
    os_accuracy: Mapped[int | None] = mapped_column(Integer)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class ServiceRow(Base):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint(
            "scan_job_id", "asset_id", "protocol", "port", name="uq_service_scan_endpoint"
        ),
        Index("ix_services_asset", "asset_id"),
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_service_valid_port"),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_service_valid_confidence",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    asset_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(12), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(100))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(120))
    cpes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)


class ArchitectureSnapshotRow(Base):
    __tablename__ = "architecture_snapshots"
    __table_args__ = (
        UniqueConstraint("system_id", "version", name="uq_architecture_system_version"),
        Index("ix_architecture_system_created", "system_id", "created_at"),
        CheckConstraint(
            "source_type IN ('scan', 'manual', 'import')",
            name="ck_architecture_source_type",
        ),
        CheckConstraint(
            "layer IN ('manual', 'observed', 'proposal')",
            name="ck_architecture_layer",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    source_scan_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("scan_jobs.id", ondelete="RESTRICT")
    )
    base_snapshot_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("architecture_snapshots.id", ondelete="SET NULL")
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="draft", nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), default="scan", nullable=False)
    layer: Mapped[str] = mapped_column(String(20), default="observed", nullable=False)
    title: Mapped[str] = mapped_column(
        String(160), default="Skanningshärlett arkitekturutkast", nullable=False
    )
    change_note: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_by: Mapped[str] = mapped_column(String(160), default="system", nullable=False)
    graph: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class VulnerabilityScanImportRow(Base):
    """One immutable vendor report import; raw evidence is represented by its digest."""

    __tablename__ = "vulnerability_scan_imports"
    __table_args__ = (
        UniqueConstraint("system_id", "raw_sha256", name="uq_vuln_import_system_digest"),
        Index("ix_vuln_import_system_imported", "system_id", "imported_at"),
        CheckConstraint(
            "provider IN ('nessus', 'qualys', 'greenbone', 'rapid7', 'defender_vm', 'generic')",
            name="ck_vuln_import_provider",
        ),
        CheckConstraint(
            "observation_count >= 0 AND asset_count >= 0 AND matched_asset_count >= 0 "
            "AND promoted_finding_count >= 0",
            name="ck_vuln_import_counts",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    source_format: Mapped[str] = mapped_column(String(40), nullable=False)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scanner_version: Mapped[str | None] = mapped_column(String(120))
    scan_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    scan_completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    imported_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    imported_by: Mapped[str] = mapped_column(String(160), nullable=False)
    raw_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    report_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    observation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    asset_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    matched_asset_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    promoted_finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class VulnerabilityObservationRow(Base):
    """Normalized scanner observation, including records not yet correlated to an asset."""

    __tablename__ = "vulnerability_observations"
    __table_args__ = (
        UniqueConstraint("import_id", "observation_key", name="uq_vuln_observation_import_key"),
        Index("ix_vuln_observation_system_severity", "system_id", "severity"),
        Index("ix_vuln_observation_import", "import_id"),
        CheckConstraint(
            "port IS NULL OR (port >= 0 AND port <= 65535)",
            name="ck_vuln_observation_port",
        ),
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_vuln_observation_cvss",
        ),
        CheckConstraint(
            "match_confidence IS NULL OR (match_confidence >= 0 AND match_confidence <= 1)",
            name="ck_vuln_observation_confidence",
        ),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_vuln_observation_severity",
        ),
        CheckConstraint(
            "state IN ('open', 'fixed', 'reopened', 'accepted', "
            "'false_positive', 'out_of_scope', 'unknown')",
            name="ck_vuln_observation_state",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    import_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("vulnerability_scan_imports.id", ondelete="CASCADE"), nullable=False
    )
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    observation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_finding_id: Mapped[str] = mapped_column(String(160), nullable=False)
    asset_identifier: Mapped[str] = mapped_column(String(500), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(20))
    service_name: Mapped[str | None] = mapped_column(String(100))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(120))
    cpes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    solution: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(160))
    state: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    exploitable: Mapped[bool | None] = mapped_column(Boolean)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    matched_asset_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("assets.id", ondelete="SET NULL")
    )
    matched_service_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("services.id", ondelete="SET NULL")
    )
    match_confidence: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class ThreatRow(Base):
    __tablename__ = "threats_operational"
    __table_args__ = (
        UniqueConstraint("system_id", "source", "external_id", name="uq_threat_source_id"),
        Index("ix_threats_system", "system_id"),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_threat_valid_confidence",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    attack_patterns: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    matched_asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    modified_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class FindingRow(Base):
    __tablename__ = "findings_operational"
    __table_args__ = (
        UniqueConstraint("system_id", "stable_key", name="uq_finding_system_stable_key"),
        Index("ix_findings_system", "system_id"),
        Index("ix_findings_cve", "cve_id"),
        Index("ix_findings_system_lifecycle", "system_id", "lifecycle_status"),
        CheckConstraint(
            "match_confidence >= 0 AND match_confidence <= 1",
            name="ck_finding_valid_confidence",
        ),
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_finding_valid_cvss",
        ),
        CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name="ck_finding_valid_epss",
        ),
        CheckConstraint(
            "lifecycle_status IN ('open', 'fixed', 'accepted', 'false_positive', "
            "'out_of_scope', 'reopened')",
            name="ck_finding_lifecycle_status",
        ),
        CheckConstraint(
            "finding_type IN ('vulnerability', 'misconfiguration', 'informational')",
            name="ck_finding_type",
        ),
        CheckConstraint(
            "primary_evidence_strength >= 0 AND primary_evidence_strength <= 100",
            name="ck_finding_evidence_strength",
        ),
        CheckConstraint("occurrence_count >= 1", name="ck_finding_occurrence_count"),
        CheckConstraint(
            "inventory_status IN ('current', 'unobserved', 'stale', 'unknown')",
            name="ck_finding_inventory_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    asset_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("assets.id", ondelete="SET NULL")
    )
    service_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("services.id", ondelete="SET NULL")
    )
    stable_key: Mapped[str] = mapped_column(String(500), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(32), default="vulnerability", nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="candidate", nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(24), default="open", nullable=False)
    match_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    match_reason: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(160))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    sources: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    primary_evidence_strength: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    status_updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    inventory_status: Mapped[str] = mapped_column(
        String(20), default="current", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class FindingEvidenceRow(Base):
    """Current source-specific evidence state with immutable observations behind it."""

    __tablename__ = "finding_evidence"
    __table_args__ = (
        UniqueConstraint("finding_id", "evidence_key", name="uq_finding_evidence_key"),
        Index("ix_finding_evidence_finding", "finding_id"),
        CheckConstraint(
            "lifecycle_status IN ('open', 'fixed', 'accepted', 'false_positive', "
            "'out_of_scope', 'reopened')",
            name="ck_finding_evidence_lifecycle",
        ),
        CheckConstraint("strength >= 0 AND strength <= 100", name="ck_evidence_strength"),
        CheckConstraint("observation_count >= 1", name="ck_evidence_observation_count"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("findings_operational.id", ondelete="CASCADE"), nullable=False
    )
    observation_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("vulnerability_observations.id", ondelete="SET NULL")
    )
    evidence_key: Mapped[str] = mapped_column(String(500), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    source_name: Mapped[str] = mapped_column(String(120), nullable=False)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(24), nullable=False)
    strength: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    observation_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class RiskRow(Base):
    __tablename__ = "risks_operational"
    __table_args__ = (
        Index("ix_risks_system", "system_id"),
        CheckConstraint(
            "(finding_id IS NOT NULL AND threat_id IS NULL) OR "
            "(finding_id IS NULL AND threat_id IS NOT NULL)",
            name="ck_risk_exactly_one_source",
        ),
        CheckConstraint("likelihood >= 1 AND likelihood <= 5", name="ck_risk_likelihood"),
        CheckConstraint("impact >= 1 AND impact <= 5", name="ck_risk_impact"),
        CheckConstraint("score = likelihood * impact", name="ck_risk_score_product"),
        CheckConstraint(
            "evidence_status IN ('current', 'unobserved', 'stale', 'unknown')",
            name="ck_risk_evidence_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("findings_operational.id", ondelete="CASCADE")
    )
    threat_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("threats_operational.id", ondelete="CASCADE")
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    impact: Mapped[int] = mapped_column(Integer, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="open", nullable=False)
    rationale: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    evidence_status: Mapped[str] = mapped_column(
        String(20), default="current", nullable=False
    )


class IntelligenceCacheRow(Base):
    __tablename__ = "intelligence_cache"
    __table_args__ = (
        UniqueConstraint("provider", "external_id", name="uq_intelligence_provider_id"),
        Index("ix_intelligence_provider", "provider"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class IntelligenceSyncStateRow(Base):
    """Monotonic per-system watermark for authoritative provider snapshots."""

    __tablename__ = "intelligence_sync_states"
    __table_args__ = (
        UniqueConstraint(
            "system_id", "provider", "scope_key", name="uq_intel_sync_state_scope"
        ),
        Index("ix_intel_sync_state_system_provider", "system_id", "provider"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(500), nullable=False)
    source_updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    source_version: Mapped[str] = mapped_column(String(200), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=utc_now, onupdate=utc_now
    )


class GlobalIntelRecordRow(Base):
    """Deduplicated source record scoped to one authenticated organization."""

    __tablename__ = "global_intel_records"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "provider_key",
            "external_id",
            name="uq_global_intel_org_provider_id",
        ),
        Index("ix_global_intel_organization", "organization_id"),
        Index("ix_global_intel_modified", "modified_at"),
        Index("ix_global_intel_type_source", "record_type", "source_kind"),
        Index("ix_global_intel_source_modified", "source_kind", "modified_at"),
        Index(
            "ix_global_intel_org_review",
            "organization_id",
            "review_status",
            "modified_at",
        ),
        Index("ix_global_intel_distribution_tlp", "distribution_tlp"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="ck_global_intel_confidence",
        ),
        CheckConstraint(
            "distribution_tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', "
            "'TLP:AMBER+STRICT', 'TLP:RED')",
            name="ck_global_intel_distribution_tlp",
        ),
        CheckConstraint(
            "review_status IN ('pending', 'approved', 'rejected')",
            name="ck_global_intel_review_status",
        ),
        CheckConstraint(
            "(review_status = 'pending' AND reviewed_by IS NULL AND reviewed_at IS NULL) OR "
            "(review_status IN ('approved', 'rejected') AND reviewed_by IS NOT NULL "
            "AND reviewed_at IS NOT NULL)",
            name="ck_global_intel_review_state",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    source_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(100), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    record_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2_000))
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    modified_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    retrieved_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(20))
    confidence: Mapped[float | None] = mapped_column(Float)
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    cpes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_attack_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    indicators: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list, nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    sectors: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    regions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    markings: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    distribution_tlp: Mapped[str] = mapped_column(
        String(24), default="TLP:AMBER", nullable=False
    )
    review_status: Mapped[str] = mapped_column(
        String(20), default="pending", nullable=False
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(160))
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    review_note: Mapped[str | None] = mapped_column(Text)
    valid_from: Mapped[datetime | None] = mapped_column(UTCDateTime())
    valid_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    raw_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    raw_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ai_analysis: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    analysis_sha256: Mapped[str | None] = mapped_column(String(64))
    vulnerability: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    feed_id: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_version: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_generated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    first_ingested_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    last_ingested_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class GlobalIntelObservableRow(Base):
    """Indexed join keys used to avoid scanning the global intelligence table."""

    __tablename__ = "global_intel_observables"
    __table_args__ = (
        UniqueConstraint(
            "record_id", "kind", "value_normalized", name="uq_global_intel_observable"
        ),
        Index("ix_global_intel_observable_lookup", "kind", "value_normalized"),
        Index("ix_global_intel_observable_record", "record_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    record_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("global_intel_records.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    value_normalized: Mapped[str] = mapped_column(String(500), nullable=False)
    value_display: Mapped[str] = mapped_column(String(500), nullable=False)


class ExternalIntelligenceConnectorRow(Base):
    """Tenant-owned pull-only connector configuration without stored credentials."""

    __tablename__ = "external_intelligence_connectors"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_external_intel_connector_org_name"),
        Index("ix_external_intel_connector_organization", "organization_id"),
        Index(
            "ix_external_intel_connector_due",
            "enabled",
            "next_sync_at",
        ),
        Index(
            "ux_external_intel_connector_schedule_claim",
            "schedule_claim_token_sha256",
            unique=True,
        ),
        CheckConstraint(
            "auth_scheme IN ('Bearer', 'X-API-Key')",
            name="ck_external_intel_connector_auth_scheme",
        ),
        CheckConstraint("config_version >= 1", name="ck_external_intel_connector_config_version"),
        CheckConstraint(
            "length(identity_sha256) = 64",
            name="ck_external_intel_connector_identity_sha256",
        ),
        CheckConstraint(
            "sync_interval_seconds IS NULL OR "
            "(sync_interval_seconds >= 60 AND sync_interval_seconds <= 2592000)",
            name="ck_external_intel_connector_sync_interval",
        ),
        CheckConstraint(
            "next_sync_at IS NULL OR (enabled AND sync_interval_seconds IS NOT NULL)",
            name="ck_external_intel_connector_next_sync",
        ),
        CheckConstraint(
            "(schedule_claim_token_sha256 IS NULL AND schedule_claimed_by IS NULL "
            "AND schedule_claimed_at IS NULL AND schedule_claim_expires_at IS NULL "
            "AND schedule_heartbeat_at IS NULL) OR "
            "(schedule_claim_token_sha256 IS NOT NULL AND schedule_claimed_by IS NOT NULL "
            "AND schedule_claimed_at IS NOT NULL AND schedule_claim_expires_at IS NOT NULL "
            "AND schedule_heartbeat_at IS NOT NULL)",
            name="ck_external_intel_connector_schedule_claim",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(80), default="external-datapoints", nullable=False)
    endpoint: Mapped[str] = mapped_column(String(2_000), nullable=False)
    auth_scheme: Mapped[str] = mapped_column(String(20), nullable=False)
    credential_reference: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sync_interval_seconds: Mapped[int | None] = mapped_column(Integer)
    next_sync_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    schedule_claim_token_sha256: Mapped[str | None] = mapped_column(String(64))
    schedule_claimed_by: Mapped[str | None] = mapped_column(String(160))
    schedule_claimed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    schedule_claim_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    schedule_heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    config_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class ExternalIntelligenceSyncRunRow(Base):
    """Durable execution record for one bounded external pull."""

    __tablename__ = "external_intelligence_sync_runs"
    __table_args__ = (
        Index("ix_external_intel_sync_org_started", "organization_id", "started_at"),
        Index("ix_external_intel_sync_connector_started", "connector_id", "started_at"),
        Index("ix_external_intel_sync_lease", "status", "lease_expires_at"),
        Index("ix_external_intel_sync_snapshot", "connector_id", "snapshot_id"),
        Index(
            "ux_external_intel_sync_running_connector",
            "connector_id",
            unique=True,
            postgresql_where=text("status = 'running'"),
            sqlite_where=text("status = 'running'"),
        ),
        Index(
            "ux_external_intel_sync_claim_token",
            "claim_token_sha256",
            unique=True,
        ),
        CheckConstraint(
            "status IN ('running', 'partial', 'completed', 'failed', 'quarantined')",
            name="ck_external_intel_sync_status",
        ),
        CheckConstraint(
            "pages_fetched >= 0 AND records_fetched >= 0 AND created_count >= 0 "
            "AND bytes_fetched >= 0 AND batch_pages_fetched >= 0 "
            "AND batch_records_fetched >= 0 AND batch_bytes_fetched >= 0 "
            "AND updated_count >= 0 AND unchanged_count >= 0 AND quarantined_count >= 0",
            name="ck_external_intel_sync_counts",
        ),
        CheckConstraint(
            "connector_config_version >= 1",
            name="ck_external_intel_sync_config_version",
        ),
        CheckConstraint(
            "length(connector_identity_sha256) = 64",
            name="ck_external_intel_sync_identity_sha256",
        ),
        CheckConstraint(
            "(status = 'running' AND completed_at IS NULL AND claim_token_sha256 IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND heartbeat_at IS NOT NULL) OR "
            "(status <> 'running' AND completed_at IS NOT NULL "
            "AND claim_token_sha256 IS NULL AND lease_expires_at IS NULL)",
            name="ck_external_intel_sync_lease_state",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("external_intelligence_connectors.id", ondelete="RESTRICT"),
        nullable=False,
    )
    connector_config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    connector_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="running", nullable=False)
    started_by: Mapped[str] = mapped_column(String(160), nullable=False)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    claim_token_sha256: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    heartbeat_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    start_cursor_sha256: Mapped[str | None] = mapped_column(String(64))
    next_cursor_sha256: Mapped[str | None] = mapped_column(String(64))
    feed_id: Mapped[str | None] = mapped_column(String(120))
    feed_version: Mapped[str | None] = mapped_column(String(120))
    feed_generated_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    pages_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    batch_pages_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    batch_records_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    batch_bytes_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unchanged_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    quarantined_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64))
    error_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)


class ExternalIntelligenceSyncPageRow(Base):
    """Append-only digest provenance for every successfully fetched source page."""

    __tablename__ = "external_intelligence_sync_pages"
    __table_args__ = (
        UniqueConstraint("run_id", "page_number", name="uq_external_intel_sync_page"),
        Index("ix_external_intel_sync_page_org", "organization_id"),
        Index(
            "ix_external_intel_sync_page_snapshot",
            "snapshot_id",
            "page_number",
        ),
        CheckConstraint("page_number >= 1", name="ck_external_intel_page_number"),
        CheckConstraint("item_count >= 0", name="ck_external_intel_page_item_count"),
        CheckConstraint("raw_payload_bytes >= 1", name="ck_external_intel_page_payload_bytes"),
        CheckConstraint(
            "connector_config_version >= 1",
            name="ck_external_intel_page_config_version",
        ),
        CheckConstraint(
            "length(connector_identity_sha256) = 64",
            name="ck_external_intel_page_identity_sha256",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("external_intelligence_sync_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    connector_config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    connector_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    page_number: Mapped[int] = mapped_column(Integer, nullable=False)
    request_cursor_sha256: Mapped[str | None] = mapped_column(String(64))
    raw_payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_payload_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    feed_id: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_version: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_generated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class ExternalIntelligenceSyncIdentityRow(Base):
    """Provider identity provenance for cross-run snapshot deduplication."""

    __tablename__ = "external_intelligence_sync_identities"
    __table_args__ = (
        Index(
            "ix_external_intel_sync_identity_snapshot",
            "snapshot_id",
            "provider_key",
            "external_id",
        ),
        Index("ix_external_intel_sync_identity_run", "run_id"),
        CheckConstraint("page_number >= 1", name="ck_external_intel_identity_page"),
        CheckConstraint(
            "connector_config_version >= 1",
            name="ck_external_intel_identity_config_version",
        ),
        CheckConstraint(
            "length(connector_identity_sha256) = 64",
            name="ck_external_intel_identity_identity_sha256",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("external_intelligence_connectors.id", ondelete="CASCADE"),
        nullable=False,
    )
    run_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("external_intelligence_sync_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    connector_config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    connector_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    page_number: Mapped[int] = mapped_column(Integer, nullable=False)
    provider_key: Mapped[str] = mapped_column(String(100), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class ExternalIntelligenceCheckpointRow(Base):
    """The only accepted continuation cursor, bound to one immutable feed snapshot."""

    __tablename__ = "external_intelligence_checkpoints"
    __table_args__ = (
        UniqueConstraint("connector_id", name="uq_external_intel_checkpoint_connector"),
        Index("ix_external_intel_checkpoint_org", "organization_id"),
        CheckConstraint(
            "pages_completed >= 1 AND records_completed >= 0 AND bytes_completed >= 1",
            name="ck_external_intel_checkpoint_counts",
        ),
        CheckConstraint(
            "connector_config_version >= 1",
            name="ck_external_intel_checkpoint_config_version",
        ),
        CheckConstraint(
            "length(connector_identity_sha256) = 64",
            name="ck_external_intel_checkpoint_identity_sha256",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("external_intelligence_connectors.id", ondelete="CASCADE"),
        nullable=False,
    )
    last_run_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("external_intelligence_sync_runs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    connector_config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    connector_identity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    cursor: Mapped[str] = mapped_column(String(2_048), nullable=False)
    cursor_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    feed_id: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_version: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_generated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    pages_completed: Mapped[int] = mapped_column(Integer, nullable=False)
    records_completed: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes_completed: Mapped[int] = mapped_column(Integer, nullable=False)
    page_manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class GlobalIntelRevisionRow(Base):
    """Append-only source and analysis revision received by one organization."""

    __tablename__ = "global_intel_revisions"
    __table_args__ = (
        Index(
            "ix_global_intel_revision_identity",
            "organization_id",
            "provider_key",
            "external_id",
            "received_at",
        ),
        Index("ix_global_intel_revision_record", "record_id"),
        Index("ix_global_intel_revision_run", "sync_run_id"),
        CheckConstraint(
            "outcome IN ('applied', 'unchanged', 'superseded', 'quarantined')",
            name="ck_global_intel_revision_outcome",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    record_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("global_intel_records.id", ondelete="SET NULL")
    )
    sync_run_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("external_intelligence_sync_runs.id", ondelete="SET NULL")
    )
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(100), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    feed_id: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_version: Mapped[str] = mapped_column(String(120), nullable=False)
    feed_generated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    source_modified_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    source_retrieved_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    quarantine_reason: Mapped[str | None] = mapped_column(String(200))
    canonical_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    raw_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    raw_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    analysis_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class AssetSourceSnapshotRow(Base):
    """Immutable, unreviewed inventory evidence from an external asset source."""

    __tablename__ = "asset_source_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "system_id",
            "provider",
            "manifest_sha256",
            name="uq_asset_source_snapshot_manifest",
        ),
        Index(
            "ix_asset_source_snapshots_system_created",
            "system_id",
            "created_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    source_base_url: Mapped[str] = mapped_column(String(2_000), nullable=False)
    approval_state: Mapped[str] = mapped_column(String(40), nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    page_count: Mapped[int] = mapped_column(Integer, nullable=False)
    record_counts: Mapped[dict[str, int]] = mapped_column(JSON, nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class ReportRow(Base):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_system_created", "system_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    format: Mapped[str] = mapped_column(String(12), nullable=False)
    report_type: Mapped[str] = mapped_column(String(40), nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    content: Mapped[bytes] = mapped_column(nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class BackgroundJobRow(Base):
    """Tenant-owned durable work item with an integrity-bound immutable payload."""

    __tablename__ = "background_jobs"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "idempotency_key_sha256",
            name="uq_background_job_org_idempotency",
        ),
        Index(
            "ix_background_jobs_status_available",
            "status",
            "available_at",
            "requested_at",
        ),
        Index(
            "ix_background_jobs_org_requested",
            "organization_id",
            "requested_at",
        ),
        Index(
            "ix_background_jobs_system_requested",
            "system_id",
            "requested_at",
        ),
        Index("ix_background_jobs_lease", "status", "lease_expires_at"),
        CheckConstraint(
            "job_type IN ('intelligence_correlation', "
            "'normalized_vulnerability_import', 'report_generation')",
            name="ck_background_job_type",
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_background_job_status",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_background_job_attempt_count"),
        CheckConstraint(
            "max_attempts >= 1 AND max_attempts <= 10",
            name="ck_background_job_max_attempts",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    system_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("systems_operational.id", ondelete="CASCADE"), nullable=False
    )
    job_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    payload_schema_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(160), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    available_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    claimed_by: Mapped[str | None] = mapped_column(String(160))
    # Internal fencing token. A fresh cryptographically-random value is issued
    # for every claim, including reclaim by the same worker identity.
    lease_token: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_resource_type: Mapped[str | None] = mapped_column(String(80))
    result_resource_id: Mapped[str | None] = mapped_column(String(160))
    error_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_resource_created", "resource_type", "created_at"),
        Index("ix_audit_events_organization", "organization_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(160), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
