"""Normalized, source-preserving intelligence contracts.

CVSS, EPSS, and KEV intentionally use different models. They represent technical
severity, dated exploitation probability, and catalogue membership respectively;
none of them is a Traceless risk score.
"""

from datetime import date
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AnyHttpUrl,
    AwareDatetime,
    Field,
    StringConstraints,
    model_validator,
)

from traceless_api.models.common import StrictModel

ProviderName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    ),
]
SourceIdentifier = Annotated[str, StringConstraints(min_length=1, max_length=500)]
SourceVersion = Annotated[str, StringConstraints(min_length=1, max_length=200)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
CveId = Annotated[str, StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]
StixId = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^[a-z][a-z0-9-]{0,249}--[0-9a-f]{8}-[0-9a-f]{4}-"
            r"[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
    ),
]


class SourceProvenance(StrictModel):
    """Lineage retained for a feed snapshot or one normalized source record."""

    provider: ProviderName
    source_url: AnyHttpUrl
    source_feed_id: SourceIdentifier | None = None
    source_record_id: SourceIdentifier | None = None
    source_version: SourceVersion
    source_updated_at: AwareDatetime | None = None
    retrieved_at: AwareDatetime
    payload_sha256: Sha256

    def for_record(
        self,
        source_record_id: str,
        *,
        source_updated_at: AwareDatetime | None = None,
    ) -> Self:
        """Create validated record lineage from validated feed lineage."""

        values = self.model_dump()
        values["source_record_id"] = source_record_id
        if source_updated_at is not None:
            values["source_updated_at"] = source_updated_at
        return type(self).model_validate(values)


class IntelligenceBatch[RecordT](StrictModel):
    """One validated, immutable-by-convention provider snapshot."""

    provenance: SourceProvenance
    records: tuple[RecordT, ...] = Field(max_length=10_000)


class CvssMetric(StrictModel):
    """A provider-attributed CVSS metric, kept separate from probability and KEV."""

    cve_id: CveId
    version: Literal["3.0", "3.1", "4.0"]
    score: Annotated[Decimal, Field(ge=0, le=10)]
    vector: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    metric_source: Annotated[str, StringConstraints(min_length=1, max_length=300)] | None = None
    metric_type: Literal["Primary", "Secondary"] | None = None
    base_severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    exploitability_score: Annotated[Decimal, Field(ge=0, le=10)] | None = None
    impact_score: Annotated[Decimal, Field(ge=0, le=10)] | None = None
    provenance: SourceProvenance

    @model_validator(mode="after")
    def vector_matches_version(self) -> "CvssMetric":
        if not self.vector.startswith(f"CVSS:{self.version}/"):
            raise ValueError("CVSS vector must identify the declared CVSS version")
        return self


class EpssMetric(StrictModel):
    """FIRST EPSS probability and percentile for one CVE on one model date."""

    cve_id: CveId
    probability: Annotated[Decimal, Field(ge=0, le=1)]
    percentile: Annotated[Decimal, Field(ge=0, le=1)]
    model_date: date
    provenance: SourceProvenance


class KnownRansomwareUse(StrEnum):
    known = "known"
    unknown = "unknown"


class KevCatalogEntry(StrictModel):
    """One CISA KEV catalogue membership record; deliberately has no score."""

    cve_id: CveId
    vendor_project: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    product: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    vulnerability_name: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    date_added: date
    short_description: Annotated[str, StringConstraints(min_length=1, max_length=4_000)]
    required_action: Annotated[str, StringConstraints(min_length=1, max_length=4_000)]
    due_date: Annotated[
        date,
        Field(
            description=(
                "CISA BOD 22-01 deadline for US federal civilian agencies; "
                "not a general remediation SLA."
            )
        ),
    ]
    known_ransomware_campaign_use: KnownRansomwareUse
    notes: Annotated[str, StringConstraints(max_length=4_000)] = ""
    cwes: tuple[Annotated[str, StringConstraints(min_length=1, max_length=40)], ...] = Field(
        default_factory=tuple, max_length=50
    )
    provenance: SourceProvenance


class ThreatObjectType(StrEnum):
    indicator = "indicator"
    threat_actor = "threat-actor"
    malware = "malware"
    attack_pattern = "attack-pattern"
    vulnerability = "vulnerability"
    campaign = "campaign"
    tool = "tool"
    report = "report"
    relationship = "relationship"


class ExternalReference(StrictModel):
    source_name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    external_id: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None
    url: AnyHttpUrl | None = None
    description: Annotated[str, StringConstraints(max_length=1_000)] = ""

    @model_validator(mode="after")
    def contains_reference_detail(self) -> "ExternalReference":
        if self.external_id is None and self.url is None and not self.description:
            raise ValueError("External reference requires an id, URL, or description")
        return self


class ThreatIntelligenceObject(StrictModel):
    """Bounded internal STIX-like object normalized from the internal feed."""

    type: ThreatObjectType
    spec_version: Literal["2.1"] = "2.1"
    id: StixId
    created: AwareDatetime
    modified: AwareDatetime
    name: Annotated[str, StringConstraints(min_length=1, max_length=300)] | None = None
    description: Annotated[str, StringConstraints(max_length=10_000)] = ""
    confidence: Annotated[int, Field(ge=0, le=100)] | None = None
    labels: tuple[Annotated[str, StringConstraints(min_length=1, max_length=100)], ...] = Field(
        default_factory=tuple, max_length=50
    )
    object_marking_refs: tuple[StixId, ...] = Field(default_factory=tuple, max_length=50)
    external_references: tuple[ExternalReference, ...] = Field(
        default_factory=tuple,
        max_length=50,
    )
    cve_ids: tuple[CveId, ...] = Field(default_factory=tuple, max_length=100)
    mitre_attack_ids: tuple[
        Annotated[str, StringConstraints(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")], ...
    ] = Field(default_factory=tuple, max_length=100)
    relationship_type: Annotated[str, StringConstraints(min_length=1, max_length=100)] | None = None
    source_ref: StixId | None = None
    target_ref: StixId | None = None
    pattern: Annotated[str, StringConstraints(min_length=1, max_length=10_000)] | None = None
    pattern_type: Annotated[str, StringConstraints(min_length=1, max_length=50)] | None = None
    valid_from: AwareDatetime | None = None
    valid_until: AwareDatetime | None = None
    revoked: bool = False
    provenance: SourceProvenance

    @model_validator(mode="after")
    def validate_stix_shape(self) -> "ThreatIntelligenceObject":
        identifier_type = self.id.split("--", maxsplit=1)[0]
        if identifier_type != self.type.value:
            raise ValueError("Object id prefix must match object type")
        if self.modified < self.created:
            raise ValueError("modified cannot be earlier than created")
        if self.valid_until is not None:
            if self.valid_from is None:
                raise ValueError("valid_until requires valid_from")
            if self.valid_until < self.valid_from:
                raise ValueError("valid_until cannot be earlier than valid_from")

        relationship_fields = (
            self.relationship_type,
            self.source_ref,
            self.target_ref,
        )
        if self.type == ThreatObjectType.relationship:
            if any(field is None for field in relationship_fields):
                raise ValueError("Relationship objects require type, source_ref, and target_ref")
        elif any(field is not None for field in relationship_fields):
            raise ValueError("Relationship fields are only valid on relationship objects")

        if self.type == ThreatObjectType.indicator:
            if self.pattern is None or self.pattern_type is None or self.valid_from is None:
                raise ValueError("Indicator objects require pattern, pattern_type, and valid_from")
        elif self.pattern is not None or self.pattern_type is not None:
            raise ValueError("Pattern fields are only valid on indicator objects")

        if self.provenance.source_record_id != self.id:
            raise ValueError("Object provenance must identify the normalized source record")
        return self
