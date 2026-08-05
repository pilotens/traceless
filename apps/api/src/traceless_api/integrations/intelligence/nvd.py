"""NVD CVE API 2.0 query, parser, and provider.

NVD applicability statements are retained as logical configuration trees with
their original CPE criteria and version bounds. This module deliberately does
not implement product-version matching or claim that a returned CVE applies to
an asset; that decision belongs to a separately tested match engine.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AnyUrl,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from traceless_api.integrations.intelligence._json import (
    decode_bounded_json,
    validated_json_response_body,
)
from traceless_api.integrations.intelligence._support import (
    Clock,
    digest_payload,
    utc_now,
    validate_http_endpoint,
    validate_retrieved_at,
)
from traceless_api.integrations.intelligence.errors import InvalidIntelligencePayload
from traceless_api.integrations.intelligence.models import (
    CveId,
    CvssMetric,
    IntelligenceBatch,
    SourceProvenance,
)
from traceless_api.integrations.intelligence.protocols import AsyncHttpClient
from traceless_api.models.common import StrictModel

NVD_API_DISCLAIMER = "This product uses the NVD API but is not endorsed or certified by the NVD."
DEFAULT_MAX_NVD_BYTES = 50_000_000
DEFAULT_MAX_NVD_RECORDS = 2_000
MAX_NVD_WINDOW = timedelta(days=120)

Cpe23 = Annotated[str, StringConstraints(min_length=13, max_length=2_048)]
VersionBoundary = Annotated[str, StringConstraints(min_length=1, max_length=1_024)]


def _split_cpe23(value: str) -> tuple[str, ...]:
    if not value.startswith("cpe:2.3:"):
        raise ValueError("CPE name must use the CPE 2.3 formatted-string binding")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("CPE name must not contain control characters")

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
        raise ValueError("CPE name contains an incomplete escape sequence")
    components.append("".join(current))

    if len(components) != 11:
        raise ValueError("CPE 2.3 formatted strings must contain exactly 11 components")
    if any(not component for component in components):
        raise ValueError("CPE 2.3 components must not be empty")
    if components[0] not in {"a", "h", "o", "*", "-"}:
        raise ValueError("CPE part must be application, hardware, operating system, any, or NA")
    return tuple(components)


def _validate_cpe23(value: str, *, concrete_product: bool) -> str:
    components = _split_cpe23(value)
    if concrete_product:
        part, vendor, product, version = components[:4]
        if part not in {"a", "h", "o"}:
            raise ValueError("NVD cpeName queries require a concrete part")
        if any(component == "*" for component in (vendor, product, version)):
            raise ValueError(
                "NVD cpeName queries require concrete vendor, product, and version components"
            )
    return value


def _format_nvd_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds")


def _as_nvd_utc(value: datetime) -> datetime:
    """NVD response examples omit an offset; those timestamps are emitted as UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class NvdQuery(StrictModel):
    """Bounded NVD query supporting exact CPE names and incremental sync windows."""

    model_config = ConfigDict(frozen=True)

    cpe_name: Cpe23 | None = None
    last_modified_start: AwareDatetime | None = None
    last_modified_end: AwareDatetime | None = None
    results_per_page: Annotated[int, Field(ge=1, le=2_000)] = 2_000
    start_index: Annotated[int, Field(ge=0)] = 0

    @field_validator("cpe_name")
    @classmethod
    def validate_cpe_name(cls, value: str | None) -> str | None:
        return None if value is None else _validate_cpe23(value, concrete_product=True)

    @model_validator(mode="after")
    def validate_filter_and_window(self) -> NvdQuery:
        has_start = self.last_modified_start is not None
        has_end = self.last_modified_end is not None
        if has_start != has_end:
            raise ValueError("NVD modified queries require both start and end timestamps")
        if self.cpe_name is None and not has_start:
            raise ValueError("NVD query requires a cpe_name or a modified window")
        if has_start and has_end:
            assert self.last_modified_start is not None
            assert self.last_modified_end is not None
            if self.last_modified_end < self.last_modified_start:
                raise ValueError("NVD modified window end cannot be earlier than start")
            if self.last_modified_end - self.last_modified_start > MAX_NVD_WINDOW:
                raise ValueError("NVD modified window cannot exceed 120 consecutive days")
        return self

    def as_params(self) -> dict[str, str]:
        """Return values for the HTTP client's parameter encoder, never a hand-built URL."""

        params = {
            "resultsPerPage": str(self.results_per_page),
            "startIndex": str(self.start_index),
        }
        if self.cpe_name is not None:
            params["cpeName"] = self.cpe_name
        if self.last_modified_start is not None and self.last_modified_end is not None:
            params["lastModStartDate"] = _format_nvd_timestamp(self.last_modified_start)
            params["lastModEndDate"] = _format_nvd_timestamp(self.last_modified_end)
        return params


class NvdLocalizedText(StrictModel):
    language: Annotated[str, StringConstraints(min_length=2, max_length=35)]
    value: Annotated[str, StringConstraints(min_length=1, max_length=20_000)]


class NvdCveTag(StrictModel):
    source_identifier: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    tags: tuple[Annotated[str, StringConstraints(min_length=1, max_length=100)], ...] = Field(
        min_length=1,
        max_length=50,
    )


class NvdWeakness(StrictModel):
    source: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    metric_type: Literal["Primary", "Secondary"]
    descriptions: tuple[NvdLocalizedText, ...] = Field(min_length=1, max_length=50)


class NvdReference(StrictModel):
    url: AnyUrl
    source: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    tags: tuple[Annotated[str, StringConstraints(min_length=1, max_length=100)], ...] = Field(
        default_factory=tuple,
        max_length=50,
    )


class NvdCpeMatch(StrictModel):
    """Uninterpreted NVD CPE match criteria and lexical version boundaries."""

    vulnerable: bool
    criteria: Cpe23
    match_criteria_id: UUID
    version_start_including: VersionBoundary | None = None
    version_start_excluding: VersionBoundary | None = None
    version_end_including: VersionBoundary | None = None
    version_end_excluding: VersionBoundary | None = None

    @field_validator("criteria")
    @classmethod
    def validate_criteria(cls, value: str) -> str:
        return _validate_cpe23(value, concrete_product=False)

    @model_validator(mode="after")
    def validate_boundary_pairs(self) -> NvdCpeMatch:
        if self.version_start_including is not None and self.version_start_excluding is not None:
            raise ValueError("CPE criteria cannot have two start boundaries")
        if self.version_end_including is not None and self.version_end_excluding is not None:
            raise ValueError("CPE criteria cannot have two end boundaries")
        return self


class NvdConfigurationNode(StrictModel):
    operator: Literal["AND", "OR"]
    negate: bool = False
    cpe_matches: tuple[NvdCpeMatch, ...] = Field(default_factory=tuple, max_length=1_000)
    children: tuple[NvdConfigurationNode, ...] = Field(default_factory=tuple, max_length=100)

    @model_validator(mode="after")
    def contains_applicability_input(self) -> NvdConfigurationNode:
        if not self.cpe_matches and not self.children:
            raise ValueError("NVD configuration node requires CPE matches or child nodes")
        return self


class NvdConfiguration(StrictModel):
    """Logical applicability tree retained for a future CPE/version match engine."""

    nodes: tuple[NvdConfigurationNode, ...] = Field(min_length=1, max_length=1_000)
    operator: Literal["AND", "OR"] | None = None
    negate: bool | None = None


class NvdCveEnrichment(StrictModel):
    """Provider-attributed NVD enrichment, not an assertion of asset applicability."""

    cve_id: CveId
    source_identifier: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    published_at: AwareDatetime
    last_modified_at: AwareDatetime
    vulnerability_status: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    descriptions: tuple[NvdLocalizedText, ...] = Field(min_length=1, max_length=100)
    cve_tags: tuple[NvdCveTag, ...] = Field(default_factory=tuple, max_length=100)
    cvss_metrics: tuple[CvssMetric, ...] = Field(default_factory=tuple, max_length=100)
    has_legacy_cvss_v2: bool = False
    weaknesses: tuple[NvdWeakness, ...] = Field(default_factory=tuple, max_length=100)
    references: tuple[NvdReference, ...] = Field(default_factory=tuple, max_length=1_000)
    applicability_configurations: tuple[NvdConfiguration, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
        description=(
            "Uninterpreted NVD applicability logic. Presence does not by itself prove that "
            "the CVE applies to an asset."
        ),
    )
    evaluator_comment: Annotated[str, StringConstraints(max_length=20_000)] | None = None
    evaluator_impact: Annotated[str, StringConstraints(max_length=20_000)] | None = None
    evaluator_solution: Annotated[str, StringConstraints(max_length=20_000)] | None = None
    provenance: SourceProvenance

    @model_validator(mode="after")
    def validate_record_consistency(self) -> NvdCveEnrichment:
        if self.last_modified_at < self.published_at:
            raise ValueError("NVD lastModified cannot be earlier than published")
        if any(metric.cve_id != self.cve_id for metric in self.cvss_metrics):
            raise ValueError("NVD CVSS metrics must reference their containing CVE")
        return self


class NvdCveBatch(IntelligenceBatch[NvdCveEnrichment]):
    results_per_page: Annotated[int, Field(ge=0, le=2_000)]
    start_index: Annotated[int, Field(ge=0)]
    total_results: Annotated[int, Field(ge=0)]
    query: NvdQuery | None = None
    disclaimer: Literal[
        "This product uses the NVD API but is not endorsed or certified by the NVD."
    ] = NVD_API_DISCLAIMER

    @property
    def next_start_index(self) -> int | None:
        candidate = self.start_index + len(self.records)
        return candidate if self.records and candidate < self.total_results else None

    @model_validator(mode="after")
    def validate_pagination(self) -> NvdCveBatch:
        if len(self.records) > self.results_per_page:
            raise ValueError("NVD records exceed resultsPerPage")
        if len(self.records) > self.total_results:
            raise ValueError("NVD records exceed totalResults")
        if self.records and self.start_index + len(self.records) > self.total_results:
            raise ValueError("NVD response page extends beyond totalResults")
        return self


class _NvdCvssDataPayload(BaseModel):
    """Validated CVSS identity fields; the full vector remains the canonical detail."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    version: Literal["3.0", "3.1", "4.0"]
    vector_string: Annotated[
        str,
        Field(alias="vectorString", min_length=1, max_length=300),
    ]
    base_score: Annotated[Decimal, Field(alias="baseScore", ge=0, le=10)]
    base_severity: Annotated[
        Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
        Field(alias="baseSeverity"),
    ] = None


class _NvdCvssMetricPayload(StrictModel):
    source: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    type: Literal["Primary", "Secondary"]
    cvss_data: Annotated[_NvdCvssDataPayload, Field(alias="cvssData")]
    exploitability_score: Annotated[
        Decimal | None,
        Field(alias="exploitabilityScore", ge=0, le=10),
    ] = None
    impact_score: Annotated[
        Decimal | None,
        Field(alias="impactScore", ge=0, le=10),
    ] = None
    base_severity: Annotated[
        Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
        Field(alias="baseSeverity"),
    ] = None


class _NvdMetricsPayload(StrictModel):
    cvss_metric_v40: tuple[_NvdCvssMetricPayload, ...] = Field(
        default_factory=tuple,
        alias="cvssMetricV40",
        max_length=100,
    )
    cvss_metric_v31: tuple[_NvdCvssMetricPayload, ...] = Field(
        default_factory=tuple,
        alias="cvssMetricV31",
        max_length=100,
    )
    cvss_metric_v30: tuple[_NvdCvssMetricPayload, ...] = Field(
        default_factory=tuple,
        alias="cvssMetricV30",
        max_length=100,
    )
    cvss_metric_v2: tuple[dict[str, JsonValue], ...] = Field(
        default_factory=tuple,
        alias="cvssMetricV2",
        max_length=100,
    )


class _NvdLocalizedTextPayload(StrictModel):
    lang: Annotated[str, StringConstraints(min_length=2, max_length=35)]
    value: Annotated[str, StringConstraints(min_length=1, max_length=20_000)]


class _NvdCveTagPayload(StrictModel):
    source_identifier: Annotated[
        str,
        Field(alias="sourceIdentifier", min_length=1, max_length=300),
    ]
    tags: tuple[Annotated[str, StringConstraints(min_length=1, max_length=100)], ...] = Field(
        min_length=1,
        max_length=50,
    )


class _NvdWeaknessPayload(StrictModel):
    source: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    type: Literal["Primary", "Secondary"]
    description: tuple[_NvdLocalizedTextPayload, ...] = Field(min_length=1, max_length=50)


class _NvdReferencePayload(StrictModel):
    url: Annotated[str, StringConstraints(min_length=1, max_length=4_000)]
    source: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    tags: tuple[Annotated[str, StringConstraints(min_length=1, max_length=100)], ...] = Field(
        default_factory=tuple,
        max_length=50,
    )


class _NvdCpeMatchPayload(StrictModel):
    vulnerable: bool
    criteria: Cpe23
    match_criteria_id: Annotated[UUID, Field(alias="matchCriteriaId")]
    version_start_including: Annotated[
        VersionBoundary | None,
        Field(alias="versionStartIncluding"),
    ] = None
    version_start_excluding: Annotated[
        VersionBoundary | None,
        Field(alias="versionStartExcluding"),
    ] = None
    version_end_including: Annotated[
        VersionBoundary | None,
        Field(alias="versionEndIncluding"),
    ] = None
    version_end_excluding: Annotated[
        VersionBoundary | None,
        Field(alias="versionEndExcluding"),
    ] = None

    @field_validator("criteria")
    @classmethod
    def validate_criteria(cls, value: str) -> str:
        return _validate_cpe23(value, concrete_product=False)

    @model_validator(mode="after")
    def validate_boundary_pairs(self) -> _NvdCpeMatchPayload:
        if self.version_start_including is not None and self.version_start_excluding is not None:
            raise ValueError("CPE criteria cannot have two start boundaries")
        if self.version_end_including is not None and self.version_end_excluding is not None:
            raise ValueError("CPE criteria cannot have two end boundaries")
        return self


class _NvdConfigurationNodePayload(StrictModel):
    operator: Literal["AND", "OR"]
    negate: bool = False
    cpe_match: tuple[_NvdCpeMatchPayload, ...] = Field(
        default_factory=tuple,
        alias="cpeMatch",
        max_length=1_000,
    )
    children: tuple[_NvdConfigurationNodePayload, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )

    @model_validator(mode="after")
    def contains_applicability_input(self) -> _NvdConfigurationNodePayload:
        if not self.cpe_match and not self.children:
            raise ValueError("NVD configuration node requires CPE matches or child nodes")
        return self


class _NvdConfigurationPayload(StrictModel):
    nodes: tuple[_NvdConfigurationNodePayload, ...] = Field(min_length=1, max_length=1_000)
    operator: Literal["AND", "OR"] | None = None
    negate: bool | None = None


class _NvdVendorCommentPayload(StrictModel):
    organization: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    comment: Annotated[str, StringConstraints(min_length=1, max_length=20_000)]
    last_modified: Annotated[datetime, Field(alias="lastModified")]


class _NvdCvePayload(StrictModel):
    id: CveId
    source_identifier: Annotated[
        str,
        Field(alias="sourceIdentifier", min_length=1, max_length=300),
    ]
    published: datetime
    last_modified: Annotated[datetime, Field(alias="lastModified")]
    vuln_status: Annotated[
        str,
        Field(alias="vulnStatus", min_length=1, max_length=100),
    ]
    cve_tags: tuple[_NvdCveTagPayload, ...] = Field(
        default_factory=tuple,
        alias="cveTags",
        max_length=100,
    )
    descriptions: tuple[_NvdLocalizedTextPayload, ...] = Field(min_length=1, max_length=100)
    metrics: _NvdMetricsPayload = Field(default_factory=_NvdMetricsPayload)
    weaknesses: tuple[_NvdWeaknessPayload, ...] = Field(default_factory=tuple, max_length=100)
    configurations: tuple[_NvdConfigurationPayload, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    references: tuple[_NvdReferencePayload, ...] = Field(max_length=1_000)
    evaluator_comment: Annotated[
        str | None,
        Field(alias="evaluatorComment", max_length=20_000),
    ] = None
    evaluator_impact: Annotated[
        str | None,
        Field(alias="evaluatorImpact", max_length=20_000),
    ] = None
    evaluator_solution: Annotated[
        str | None,
        Field(alias="evaluatorSolution", max_length=20_000),
    ] = None
    cisa_exploit_add: Annotated[date | None, Field(alias="cisaExploitAdd")] = None
    cisa_action_due: Annotated[date | None, Field(alias="cisaActionDue")] = None
    cisa_required_action: Annotated[
        str | None,
        Field(alias="cisaRequiredAction", max_length=4_000),
    ] = None
    cisa_vulnerability_name: Annotated[
        str | None,
        Field(alias="cisaVulnerabilityName", max_length=500),
    ] = None
    vendor_comments: tuple[_NvdVendorCommentPayload, ...] = Field(
        default_factory=tuple,
        alias="vendorComments",
        max_length=100,
    )
    ssvc_v203: tuple[dict[str, JsonValue], ...] = Field(
        default_factory=tuple,
        alias="ssvcV203",
        max_length=100,
    )
    affected: tuple[dict[str, JsonValue], ...] = Field(default_factory=tuple, max_length=100)


class _NvdVulnerabilityPayload(StrictModel):
    cve: _NvdCvePayload


class _NvdResponsePayload(StrictModel):
    results_per_page: Annotated[int, Field(alias="resultsPerPage", ge=0, le=2_000)]
    start_index: Annotated[int, Field(alias="startIndex", ge=0)]
    total_results: Annotated[int, Field(alias="totalResults", ge=0)]
    format: Literal["NVD_CVE"]
    version: Literal["2.0"]
    timestamp: datetime
    vulnerabilities: tuple[_NvdVulnerabilityPayload, ...] = Field(
        max_length=DEFAULT_MAX_NVD_RECORDS
    )

    @model_validator(mode="after")
    def validate_pagination(self) -> _NvdResponsePayload:
        count = len(self.vulnerabilities)
        if count > self.results_per_page:
            raise ValueError("NVD vulnerabilities exceed resultsPerPage")
        if count > self.total_results:
            raise ValueError("NVD vulnerabilities exceed totalResults")
        if count and self.start_index + count > self.total_results:
            raise ValueError("NVD response page extends beyond totalResults")
        return self


def _normalize_cvss_metrics(
    source: _NvdCvePayload,
    *,
    feed_provenance: SourceProvenance,
    last_modified_at: datetime,
) -> tuple[CvssMetric, ...]:
    families: tuple[tuple[str, tuple[_NvdCvssMetricPayload, ...]], ...] = (
        ("4.0", source.metrics.cvss_metric_v40),
        ("3.1", source.metrics.cvss_metric_v31),
        ("3.0", source.metrics.cvss_metric_v30),
    )
    normalized: list[CvssMetric] = []
    for expected_version, metrics in families:
        for index, metric in enumerate(metrics):
            if metric.cvss_data.version != expected_version:
                raise InvalidIntelligencePayload(
                    f"NVD CVSS {expected_version} collection contains another version"
                )
            metric_record_id = f"{source.id}#cvss-{expected_version}-{index}"
            normalized.append(
                CvssMetric(
                    cve_id=source.id,
                    version=expected_version,
                    score=metric.cvss_data.base_score,
                    vector=metric.cvss_data.vector_string,
                    metric_source=metric.source,
                    metric_type=metric.type,
                    base_severity=metric.cvss_data.base_severity or metric.base_severity,
                    exploitability_score=metric.exploitability_score,
                    impact_score=metric.impact_score,
                    provenance=feed_provenance.for_record(
                        metric_record_id,
                        source_updated_at=last_modified_at,
                    ),
                )
            )
    return tuple(normalized)


def _normalize_configuration_node(
    source: _NvdConfigurationNodePayload,
) -> NvdConfigurationNode:
    return NvdConfigurationNode(
        operator=source.operator,
        negate=source.negate,
        cpe_matches=tuple(
            NvdCpeMatch(
                vulnerable=match.vulnerable,
                criteria=match.criteria,
                match_criteria_id=match.match_criteria_id,
                version_start_including=match.version_start_including,
                version_start_excluding=match.version_start_excluding,
                version_end_including=match.version_end_including,
                version_end_excluding=match.version_end_excluding,
            )
            for match in source.cpe_match
        ),
        children=tuple(_normalize_configuration_node(child) for child in source.children),
    )


def _normalize_nvd_cve(
    source: _NvdCvePayload,
    *,
    feed_provenance: SourceProvenance,
) -> NvdCveEnrichment:
    published_at = _as_nvd_utc(source.published)
    last_modified_at = _as_nvd_utc(source.last_modified)
    record_provenance = feed_provenance.for_record(
        source.id,
        source_updated_at=last_modified_at,
    )
    return NvdCveEnrichment(
        cve_id=source.id,
        source_identifier=source.source_identifier,
        published_at=published_at,
        last_modified_at=last_modified_at,
        vulnerability_status=source.vuln_status,
        descriptions=tuple(
            NvdLocalizedText(language=item.lang, value=item.value) for item in source.descriptions
        ),
        cve_tags=tuple(
            NvdCveTag(source_identifier=item.source_identifier, tags=item.tags)
            for item in source.cve_tags
        ),
        cvss_metrics=_normalize_cvss_metrics(
            source,
            feed_provenance=feed_provenance,
            last_modified_at=last_modified_at,
        ),
        has_legacy_cvss_v2=bool(source.metrics.cvss_metric_v2),
        weaknesses=tuple(
            NvdWeakness(
                source=weakness.source,
                metric_type=weakness.type,
                descriptions=tuple(
                    NvdLocalizedText(language=item.lang, value=item.value)
                    for item in weakness.description
                ),
            )
            for weakness in source.weaknesses
        ),
        references=tuple(
            NvdReference(url=reference.url, source=reference.source, tags=reference.tags)
            for reference in source.references
        ),
        applicability_configurations=tuple(
            NvdConfiguration(
                nodes=tuple(_normalize_configuration_node(node) for node in configuration.nodes),
                operator=configuration.operator,
                negate=configuration.negate,
            )
            for configuration in source.configurations
        ),
        evaluator_comment=source.evaluator_comment,
        evaluator_impact=source.evaluator_impact,
        evaluator_solution=source.evaluator_solution,
        provenance=record_provenance,
    )


def parse_nvd_cves(
    payload: bytes,
    *,
    source_url: str,
    query: NvdQuery | None = None,
    retrieved_at: datetime | None = None,
    max_bytes: int = DEFAULT_MAX_NVD_BYTES,
    max_records: int = DEFAULT_MAX_NVD_RECORDS,
) -> NvdCveBatch:
    """Validate and normalize one page from the NVD CVE API 2.0."""

    endpoint = validate_http_endpoint(source_url)
    retrieved = validate_retrieved_at(retrieved_at or utc_now())
    decoded = decode_bounded_json(
        payload,
        max_bytes=max_bytes,
        max_depth=48,
        max_nodes=1_000_000,
    )
    try:
        source = _NvdResponsePayload.model_validate(decoded)
    except ValidationError as exc:
        raise InvalidIntelligencePayload("NVD CVE payload failed schema validation") from exc
    if len(source.vulnerabilities) > max_records:
        raise InvalidIntelligencePayload(f"NVD CVE payload exceeds the {max_records}-record limit")

    identities = [item.cve.id for item in source.vulnerabilities]
    if len(identities) != len(set(identities)):
        raise InvalidIntelligencePayload("NVD CVE payload contains duplicate CVE records")

    response_timestamp = _as_nvd_utc(source.timestamp)
    feed_provenance = SourceProvenance(
        provider=NvdCveProvider.provider_name,
        source_url=endpoint,
        source_feed_id="nvd-cve-api",
        source_version=source.version,
        source_updated_at=response_timestamp,
        retrieved_at=retrieved,
        payload_sha256=digest_payload(payload),
    )
    try:
        records = tuple(
            _normalize_nvd_cve(item.cve, feed_provenance=feed_provenance)
            for item in source.vulnerabilities
        )
        return NvdCveBatch(
            provenance=feed_provenance,
            records=records,
            results_per_page=source.results_per_page,
            start_index=source.start_index,
            total_results=source.total_results,
            query=query,
        )
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, InvalidIntelligencePayload):
            raise
        raise InvalidIntelligencePayload("NVD CVE normalization failed validation") from exc


parse_nvd_cve_json = parse_nvd_cves


class NvdCveProvider:
    """Fetch one bounded NVD CVE API page with an injected HTTP client."""

    provider_name = "nvd"

    def __init__(
        self,
        client: AsyncHttpClient,
        endpoint: str,
        query: NvdQuery,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
        max_payload_bytes: int = DEFAULT_MAX_NVD_BYTES,
        max_records: int = DEFAULT_MAX_NVD_RECORDS,
        clock: Clock = utc_now,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_payload_bytes <= 0 or max_records <= 0:
            raise ValueError("payload and record limits must be positive")
        if query.results_per_page > max_records:
            raise ValueError("query results_per_page cannot exceed the provider record limit")
        if api_key is not None:
            if not api_key or len(api_key) > 512:
                raise ValueError("api_key must be non-empty and at most 512 characters")
            if any(ord(character) < 32 or ord(character) == 127 for character in api_key):
                raise ValueError("api_key must not contain control characters")

        self._client = client
        self._endpoint = validate_http_endpoint(endpoint)
        self._query = query
        self._api_key = api_key
        self._timeout = timeout
        self._max_payload_bytes = max_payload_bytes
        self._max_records = max_records
        self._clock = clock

    async def fetch(self) -> NvdCveBatch:
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key is not None:
            headers["apiKey"] = self._api_key
        response = await self._client.get(
            self._endpoint,
            headers=headers,
            params=self._query.as_params(),
            timeout=self._timeout,
        )
        body = validated_json_response_body(
            response,
            max_bytes=self._max_payload_bytes,
        )
        return parse_nvd_cves(
            body,
            source_url=self._endpoint,
            query=self._query,
            retrieved_at=self._clock(),
            max_bytes=self._max_payload_bytes,
            max_records=self._max_records,
        )
