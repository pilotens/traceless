"""HTTP contracts for the persistent end-to-end pipeline."""

import json
import re
from datetime import date
from ipaddress import ip_address
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from traceless_api.models.common import StrictModel

Criticality = Literal["low", "medium", "high", "critical"]
ScanProfile = Literal["discovery", "service_inventory"]
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


class ProjectCreate(StrictModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=4_000)


class ProjectView(ProjectCreate):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(max_length=4_000)
    id: UUID
    created_at: AwareDatetime
    updated_at: AwareDatetime


class OperationalSystemCreate(StrictModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=4_000)
    owner: str = Field(min_length=2, max_length=160)
    criticality: Criticality = "medium"


class OperationalSystemView(OperationalSystemCreate):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(max_length=4_000)
    owner: str = Field(min_length=2, max_length=160)
    criticality: Criticality
    id: UUID
    project_id: UUID
    created_at: AwareDatetime
    updated_at: AwareDatetime


class ScanAuthorizationCreate(StrictModel):
    targets: list[str] = Field(min_length=1, max_length=64)
    profile: ScanProfile = "discovery"
    approved_by: str = Field(min_length=2, max_length=160)
    purpose: str = Field(min_length=10, max_length=2_000)
    expires_at: AwareDatetime
    confirmation: Literal["Jag bekräftar att jag har tillstånd att skanna angivna mål."]

    @field_validator("targets")
    @classmethod
    def targets_are_unique(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("targets must be unique")
        return normalized


class ScanAuthorizationView(StrictModel):
    id: UUID
    system_id: UUID
    targets: list[str]
    profile: ScanProfile
    approved_by: str
    purpose: str
    expires_at: AwareDatetime
    scope_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["active", "expired", "revoked"]
    created_at: AwareDatetime


class LiveScanCreate(StrictModel):
    authorization_id: UUID
    scanner: Literal["nmap"] = "nmap"


class ScanJobView(StrictModel):
    id: UUID
    system_id: UUID
    authorization_id: UUID
    scanner: str
    mode: Literal["live", "import"]
    status: ScanStatus
    requested_at: AwareDatetime
    started_at: AwareDatetime | None
    completed_at: AwareDatetime | None
    claimed_by: str | None
    lease_expires_at: AwareDatetime | None
    heartbeat_at: AwareDatetime | None
    attempt_count: int = Field(ge=0)
    max_attempts: int = Field(ge=1, le=10)
    cancel_requested_at: AwareDatetime | None
    raw_evidence_sha256: str | None
    result_summary: dict[str, Any]
    error_code: str | None
    error_message: str | None


class AssetView(StrictModel):
    id: UUID
    system_id: UUID
    source_scan_id: UUID
    primary_ip: str
    hostname: str | None
    mac_address: str | None
    state: str
    os_family: str | None
    os_accuracy: int | None
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    observation_count: int = Field(ge=1)
    inventory_status: Literal["current", "unobserved", "stale"]


class ServiceView(StrictModel):
    id: UUID
    asset_id: UUID
    scan_job_id: UUID
    port: int = Field(ge=1, le=65535)
    protocol: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    cpes: list[str]
    confidence: float = Field(ge=0, le=1)


class ArchitectureSnapshotView(StrictModel):
    id: UUID
    system_id: UUID
    source_scan_id: UUID | None
    base_snapshot_id: UUID | None
    version: int = Field(ge=1)
    status: Literal["draft", "published", "superseded"]
    source_type: Literal["scan", "manual", "import"]
    layer: Literal["manual", "observed", "proposal"]
    title: str
    change_note: str
    created_by: str
    graph: dict[str, Any]
    created_at: AwareDatetime


class ArchitecturePosition(StrictModel):
    x: float = Field(ge=-100_000, le=100_000)
    y: float = Field(ge=-100_000, le=100_000)


class ArchitectureNodeInput(StrictModel):
    id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9:._/-]+$")
    name: str = Field(min_length=1, max_length=160)
    kind: Literal[
        "asset",
        "service",
        "server",
        "database",
        "user",
        "security_control",
        "gateway",
        "queue",
        "application",
        "cloud",
        "network",
        "other",
    ]
    position: ArchitecturePosition
    zone_id: str | None = Field(default=None, max_length=120, pattern=r"^[A-Za-z0-9:._/-]+$")
    properties: dict[str, Any] = Field(default_factory=dict)
    provenance: Literal["manual", "observed", "imported"] = "manual"


class ArchitectureEdgeInput(StrictModel):
    id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9:._/-]+$")
    source: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=1, max_length=120)
    label: str | None = Field(default=None, max_length=160)
    protocol: str | None = Field(default=None, max_length=40)
    encrypted: bool | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class ArchitectureZoneInput(StrictModel):
    id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9:._/-]+$")
    name: str = Field(min_length=1, max_length=160)
    trust_boundary: Literal["unconfirmed", "external", "untrusted", "restricted", "trusted"] = (
        "unconfirmed"
    )


class ArchitectureRiskContextInput(StrictModel):
    """Analyst-verified environmental context used by the risk policy."""

    asset_id: UUID
    service_id: UUID | None = None
    exposure: Literal["external", "internal", "isolated", "unknown"] = "unknown"
    reachable: bool | None = None
    control_effectiveness: float | None = Field(default=None, ge=0, le=1)
    evidence_reference: str = Field(min_length=2, max_length=1_000)

    @model_validator(mode="after")
    def contains_a_context_signal(self) -> "ArchitectureRiskContextInput":
        if (
            self.exposure == "unknown"
            and self.reachable is None
            and self.control_effectiveness is None
        ):
            raise ValueError("risk context must contain at least one verified signal")
        return self


class ArchitectureBusinessImpactInput(StrictModel):
    confidentiality: int = Field(default=3, ge=1, le=5)
    integrity: int = Field(default=3, ge=1, le=5)
    availability: int = Field(default=3, ge=1, le=5)
    financial: int = Field(default=3, ge=1, le=5)
    regulatory: int = Field(default=3, ge=1, le=5)
    reputation: int = Field(default=3, ge=1, le=5)
    safety: int = Field(default=1, ge=1, le=5)


class ArchitectureBusinessContextInput(StrictModel):
    business_owner: str = Field(default="", max_length=160)
    capabilities: list[str] = Field(default_factory=list, max_length=50)
    processes: list[str] = Field(default_factory=list, max_length=50)
    data_categories: list[str] = Field(default_factory=list, max_length=50)
    regulations: list[str] = Field(default_factory=list, max_length=50)
    recovery_time_objective_hours: float | None = Field(default=None, ge=0, le=8_760)
    recovery_point_objective_hours: float | None = Field(default=None, ge=0, le=8_760)
    impact: ArchitectureBusinessImpactInput = Field(default_factory=ArchitectureBusinessImpactInput)

    @field_validator(
        "capabilities",
        "processes",
        "data_categories",
        "regulations",
    )
    @classmethod
    def values_are_normalized_and_unique(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if any(len(value) > 160 for value in normalized):
            raise ValueError("business context values may not exceed 160 characters")
        if len(normalized) != len(set(normalized)):
            raise ValueError("business context values must be unique")
        return normalized


class ArchitectureGraphInput(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    publication_state: Literal["draft"] = "draft"
    warning: str = Field(
        default=(
            "Manually edited architecture. Components, trust boundaries and data flows "
            "require review before the model is published."
        ),
        max_length=1_000,
    )
    business_context: ArchitectureBusinessContextInput = Field(
        default_factory=ArchitectureBusinessContextInput
    )
    zones: list[ArchitectureZoneInput] = Field(default_factory=list, max_length=100)
    nodes: list[ArchitectureNodeInput] = Field(default_factory=list, max_length=500)
    edges: list[ArchitectureEdgeInput] = Field(default_factory=list, max_length=2_000)
    risk_contexts: list[ArchitectureRiskContextInput] = Field(
        default_factory=list,
        max_length=500,
    )

    @model_validator(mode="after")
    def graph_is_consistent_and_bounded(self) -> "ArchitectureGraphInput":
        node_ids = [node.id for node in self.nodes]
        zone_ids = [zone.id for zone in self.zones]
        edge_ids = [edge.id for edge in self.edges]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("architecture node ids must be unique")
        if len(zone_ids) != len(set(zone_ids)):
            raise ValueError("architecture zone ids must be unique")
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("architecture edge ids must be unique")
        context_keys = [(context.asset_id, context.service_id) for context in self.risk_contexts]
        if len(context_keys) != len(set(context_keys)):
            raise ValueError("architecture risk contexts must be unique per asset/service")
        known_nodes = set(node_ids)
        known_zones = set(zone_ids)
        for node in self.nodes:
            if node.zone_id is not None and node.zone_id not in known_zones:
                raise ValueError(f"architecture node {node.id} references an unknown zone")
        for edge in self.edges:
            if edge.source not in known_nodes or edge.target not in known_nodes:
                raise ValueError(f"architecture edge {edge.id} references an unknown node")
            if edge.source == edge.target:
                raise ValueError(f"architecture edge {edge.id} cannot reference itself")
        if len(json.dumps(self.model_dump(mode="json"), separators=(",", ":"))) > 1_000_000:
            raise ValueError("architecture graph exceeds the 1 MB normalized limit")
        return self


class ArchitectureVersionCreate(StrictModel):
    title: str = Field(min_length=2, max_length=160)
    change_note: str = Field(default="", max_length=2_000)
    base_snapshot_id: UUID | None = None
    graph: ArchitectureGraphInput


VulnerabilityProvider = Literal["nessus", "qualys", "greenbone", "rapid7", "defender_vm", "generic"]
VulnerabilitySeverity = Literal["info", "low", "medium", "high", "critical"]


class VulnerabilityObservationInput(StrictModel):
    provider_finding_id: str = Field(min_length=1, max_length=160)
    asset_identifier: str = Field(min_length=1, max_length=500)
    ip_address: str | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    port: int | None = Field(default=None, ge=0, le=65_535)
    protocol: str | None = Field(default=None, min_length=1, max_length=20)
    service_name: str | None = Field(default=None, max_length=100)
    product: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=120)
    cpes: list[str] = Field(default_factory=list, max_length=100)
    cve_ids: list[str] = Field(default_factory=list, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=50_000)
    solution: str = Field(default="", max_length=50_000)
    severity: VulnerabilitySeverity
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=160)
    state: Literal[
        "open",
        "fixed",
        "reopened",
        "accepted",
        "false_positive",
        "out_of_scope",
        "unknown",
    ] = "open"
    exploitable: bool | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    observed_at: AwareDatetime | None = None

    @field_validator("ip_address")
    @classmethod
    def ip_address_is_valid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(ip_address(value))

    @field_validator("cve_ids")
    @classmethod
    def cves_are_normalized_and_unique(cls, values: list[str]) -> list[str]:
        normalized = [value.upper() for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("cve_ids must be unique")
        for value in normalized:
            if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value):
                raise ValueError(f"invalid CVE identifier: {value}")
        return normalized

    @model_validator(mode="after")
    def observation_is_consistent_and_bounded(self) -> "VulnerabilityObservationInput":
        if self.cvss_vector and self.cvss_score is None:
            raise ValueError("cvss_vector requires cvss_score")
        if self.protocol is not None and self.port is None:
            raise ValueError("protocol requires port")
        if self.ip_address is None and self.hostname is None and not self.asset_identifier:
            raise ValueError("an asset identifier is required")
        if len(json.dumps(self.evidence, separators=(",", ":"))) > 64_000:
            raise ValueError("observation evidence exceeds the 64 KB normalized limit")
        return self


class VulnerabilityScanImportCreate(StrictModel):
    provider: VulnerabilityProvider
    source_format: Literal["normalized-json"] = "normalized-json"
    source_name: str = Field(min_length=1, max_length=255)
    scanner_version: str | None = Field(default=None, max_length=120)
    scan_started_at: AwareDatetime | None = None
    scan_completed_at: AwareDatetime | None = None
    report_metadata: dict[str, Any] = Field(default_factory=dict)
    observations: list[VulnerabilityObservationInput] = Field(max_length=50_000)

    @model_validator(mode="after")
    def report_is_chronological_and_bounded(self) -> "VulnerabilityScanImportCreate":
        if (
            self.scan_started_at is not None
            and self.scan_completed_at is not None
            and self.scan_completed_at < self.scan_started_at
        ):
            raise ValueError("scan_completed_at cannot precede scan_started_at")
        if len(json.dumps(self.report_metadata, separators=(",", ":"))) > 64_000:
            raise ValueError("report_metadata exceeds the 64 KB normalized limit")
        complete_snapshot = self.report_metadata.get("snapshot_complete") is True
        series_id = self.report_metadata.get("snapshot_series_id")
        if (
            complete_snapshot
            and self.provider == "nessus"
            and not (isinstance(series_id, str) and 1 <= len(series_id.strip()) <= 500)
        ):
            raise ValueError("a complete Nessus snapshot requires a stable snapshot_series_id")
        if not self.observations and self.provider != "nessus":
            raise ValueError(
                "an empty import is valid only for a Nessus report; absence resolution "
                "still requires an explicitly complete stable snapshot"
            )
        return self


class VulnerabilityScanImportView(StrictModel):
    id: UUID
    system_id: UUID
    provider: VulnerabilityProvider
    source_format: str
    source_name: str
    scanner_version: str | None
    scan_started_at: AwareDatetime | None
    scan_completed_at: AwareDatetime | None
    imported_at: AwareDatetime
    imported_by: str
    raw_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    report_metadata: dict[str, Any]
    observation_count: int = Field(ge=0)
    asset_count: int = Field(ge=0)
    matched_asset_count: int = Field(ge=0)
    promoted_finding_count: int = Field(ge=0)


class VulnerabilityObservationView(VulnerabilityObservationInput):
    id: UUID
    import_id: UUID
    system_id: UUID
    observation_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    matched_asset_id: UUID | None
    matched_service_id: UUID | None
    match_confidence: float | None = Field(default=None, ge=0, le=1)
    created_at: AwareDatetime


class VulnerabilityImportResult(StrictModel):
    import_record: VulnerabilityScanImportView
    imported: int = Field(ge=0)
    matched_assets: int = Field(ge=0)
    matched_services: int = Field(ge=0)
    promoted_findings: int = Field(ge=0)
    idempotent_replay: bool = False
    warnings: list[str] = Field(default_factory=list)


class CveEnrichmentItem(StrictModel):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    title: str = Field(min_length=3, max_length=500)
    affected_cpes: list[str] = Field(min_length=1, max_length=100)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=160)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    epss_percentile: float | None = Field(default=None, ge=0, le=1)
    # KEV membership is accepted only from the configured CISA provider. A
    # generic/manual enrichment feed cannot self-assert known exploitation.
    is_kev: Literal[False] = False
    kev_due_date: None = None
    source: str = Field(min_length=2, max_length=120)
    source_record_url: str | None = Field(default=None, max_length=2_000)
    source_updated_at: AwareDatetime

    @model_validator(mode="after")
    def vector_requires_score(self) -> "CveEnrichmentItem":
        if self.cvss_vector and self.cvss_score is None:
            raise ValueError("cvss_vector requires cvss_score")
        for cpe in self.affected_cpes:
            _validate_affected_cpe(cpe)
        return self


class CveEnrichmentImport(StrictModel):
    feed_name: str = Field(min_length=2, max_length=120)
    feed_version: str = Field(min_length=1, max_length=120)
    generated_at: AwareDatetime
    items: list[CveEnrichmentItem] = Field(min_length=1, max_length=10_000)


class ThreatImportItem(StrictModel):
    external_id: str = Field(min_length=2, max_length=160)
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(min_length=3, max_length=10_000)
    severity: Criticality
    confidence: float = Field(ge=0, le=1)
    attack_patterns: list[str] = Field(default_factory=list, max_length=100)
    affected_products: list[str] = Field(default_factory=list, max_length=100)
    modified_at: AwareDatetime

    @field_validator("affected_products")
    @classmethod
    def affected_products_are_specific(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values]
        if any(not value for value in normalized):
            raise ValueError("affected_products must not contain empty match patterns")
        if len(set(value.casefold() for value in normalized)) != len(normalized):
            raise ValueError("affected_products must be unique")
        return normalized


class ThreatFeedImport(StrictModel):
    source: str = Field(min_length=2, max_length=120)
    source_url: str | None = Field(default=None, max_length=2_000)
    feed_version: str = Field(min_length=1, max_length=120)
    generated_at: AwareDatetime
    items: list[ThreatImportItem] = Field(min_length=1, max_length=10_000)


class FindingView(StrictModel):
    id: UUID
    system_id: UUID
    scan_job_id: UUID | None
    asset_id: UUID | None
    service_id: UUID | None
    stable_key: str
    finding_type: Literal["vulnerability", "misconfiguration", "informational"]
    cve_id: str | None
    title: str
    status: Literal["candidate", "likely", "confirmed", "false_positive"]
    lifecycle_status: Literal[
        "open", "fixed", "accepted", "false_positive", "out_of_scope", "reopened"
    ]
    match_confidence: float = Field(ge=0, le=1)
    match_reason: str
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    is_kev: bool
    kev_due_date: date | None
    sources: list[dict[str, Any]]
    primary_evidence_strength: int = Field(ge=0, le=100)
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    status_updated_at: AwareDatetime
    resolved_at: AwareDatetime | None
    occurrence_count: int = Field(ge=1)
    inventory_status: Literal["current", "unobserved", "stale", "unknown"]
    created_at: AwareDatetime


class FindingLifecycleUpdate(StrictModel):
    lifecycle_status: Literal[
        "open", "fixed", "accepted", "false_positive", "out_of_scope", "reopened"
    ]
    reason: str = Field(min_length=3, max_length=2_000)


class FindingEvidenceView(StrictModel):
    id: UUID
    finding_id: UUID
    observation_id: UUID | None
    evidence_key: str
    source_kind: str
    source_name: str
    external_id: str
    lifecycle_status: Literal[
        "open", "fixed", "accepted", "false_positive", "out_of_scope", "reopened"
    ]
    strength: int = Field(ge=0, le=100)
    payload: dict[str, Any]
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    observation_count: int = Field(ge=1)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class ThreatView(StrictModel):
    id: UUID
    system_id: UUID
    source: str
    external_id: str
    title: str
    description: str
    severity: Criticality
    confidence: float
    attack_patterns: list[str]
    affected_products: list[str]
    matched_asset_ids: list[str]
    provenance: dict[str, Any]
    modified_at: AwareDatetime
    ingested_at: AwareDatetime


class RiskView(StrictModel):
    id: UUID
    system_id: UUID
    finding_id: UUID | None
    threat_id: UUID | None
    title: str
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    score: int = Field(ge=1, le=25)
    level: Criticality
    status: Literal["open", "closed"]
    rationale: dict[str, Any]
    created_at: AwareDatetime
    updated_at: AwareDatetime
    closed_at: AwareDatetime | None
    evidence_status: Literal["current", "unobserved", "stale", "unknown"]


RiskGraphNodeKind = Literal[
    "business_capability",
    "regulation",
    "system",
    "architecture_component",
    "asset",
    "service",
    "finding",
    "threat",
    "risk",
    "action",
]


class RiskGraphNode(StrictModel):
    id: str = Field(min_length=1, max_length=240)
    kind: RiskGraphNodeKind
    label: str = Field(min_length=1, max_length=500)
    severity: Criticality | None = None
    status: str | None = Field(default=None, max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskGraphEdge(StrictModel):
    id: str = Field(min_length=1, max_length=300)
    source: str = Field(min_length=1, max_length=240)
    target: str = Field(min_length=1, max_length=240)
    relationship: str = Field(min_length=1, max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CisoRiskSummary(StrictModel):
    security_score: int = Field(ge=0, le=100)
    critical_risks: int = Field(ge=0)
    high_risks: int = Field(ge=0)
    open_findings: int = Field(ge=0)
    kev_findings: int = Field(ge=0)
    active_threats: int = Field(ge=0)
    external_assets: int = Field(ge=0)
    recommended_actions: list[str] = Field(default_factory=list, max_length=10)


class CyberRiskGraphView(StrictModel):
    system_id: UUID
    business_context: ArchitectureBusinessContextInput
    summary: CisoRiskSummary
    nodes: list[RiskGraphNode]
    edges: list[RiskGraphEdge]
    truncated: bool = False


class PipelineCollectionTotals(StrictModel):
    assets: int = Field(ge=0)
    services: int = Field(ge=0)
    findings: int = Field(ge=0)
    threats: int = Field(ge=0)
    risks: int = Field(ge=0)


class PipelineOverview(StrictModel):
    system: OperationalSystemView
    latest_scan: ScanJobView | None
    latest_architecture: ArchitectureSnapshotView | None
    assets: list[AssetView]
    services: list[ServiceView]
    findings: list[FindingView]
    threats: list[ThreatView]
    risks: list[RiskView]
    collection_totals: PipelineCollectionTotals
    collection_limit: int = Field(ge=1, le=200)
    collections_truncated: bool


class ImportResult(StrictModel):
    imported: int = Field(ge=0)
    matched: int = Field(ge=0)
    created: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)


class IntelligenceSyncResult(StrictModel):
    provider: str
    fetched: int = Field(ge=0)
    matched: int = Field(ge=0)
    updated: int = Field(ge=0)
    feed_version: str
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    warnings: list[str] = Field(default_factory=list)


class AssetSourceSnapshotSummary(StrictModel):
    id: UUID
    system_id: UUID
    provider: str
    source_base_url: str
    approval_state: Literal["unreviewed_source_snapshot"]
    manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_count: int = Field(ge=0)
    page_count: int = Field(ge=0)
    record_counts: dict[str, int]
    started_at: AwareDatetime
    completed_at: AwareDatetime
    created_at: AwareDatetime


class AssetSourceSnapshotDetail(AssetSourceSnapshotSummary):
    records: list[dict[str, Any]]
    pages: list[dict[str, Any]]
    warning: str = "Source observations are unreviewed and do not modify an approved architecture."


ReportSection = Literal[
    "executive_summary",
    "scope_methodology",
    "architecture",
    "assets_services",
    "findings",
    "threats",
    "risks",
    "vulnerability_observations",
    "limitations",
]


class ReportCreate(StrictModel):
    format: Literal["pdf", "json", "csv"] = "pdf"
    report_type: Literal["management", "technical", "risk_register"] = "management"
    sections: list[ReportSection] | None = Field(default=None, min_length=1, max_length=9)

    @field_validator("sections")
    @classmethod
    def sections_are_unique(cls, values: list[ReportSection] | None) -> list[ReportSection] | None:
        if values is not None and len(values) != len(set(values)):
            raise ValueError("report sections must be unique")
        return values


class ReportView(StrictModel):
    id: UUID
    system_id: UUID
    format: Literal["pdf", "json", "csv"]
    report_type: Literal["management", "technical", "risk_register"]
    sha256: str
    distribution_tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
    export_status: Literal["available", "withdrawn"]
    withdrawal_reason: str | None = None
    created_at: AwareDatetime


def _validate_affected_cpe(value: str) -> None:
    """Reject universal/ambiguous CPE patterns in manually supplied enrichment."""

    if not 13 <= len(value) <= 2_048 or not value.startswith("cpe:2.3:"):
        raise ValueError("affected_cpes must use CPE 2.3 formatted strings")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("affected_cpes must not contain control characters")

    components: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value[len("cpe:2.3:") :]:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            components.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        raise ValueError("affected_cpes contain an incomplete escape sequence")
    components.append("".join(current))
    if len(components) != 11 or any(not component for component in components):
        raise ValueError("affected_cpes must contain all eleven CPE 2.3 components")
    part, vendor, product = components[:3]
    if part not in {"a", "h", "o"} or vendor in {"*", "-"} or product in {"*", "-"}:
        raise ValueError("affected_cpes require a concrete part, vendor, and product")
