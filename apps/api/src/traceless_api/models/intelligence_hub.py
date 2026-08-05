"""Canonical contracts for globally ingested cyber-intelligence records."""

import json
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AwareDatetime, Field, HttpUrl, PrivateAttr, field_validator, model_validator

from traceless_api.core.markings import normalize_markings
from traceless_api.models.common import StrictModel
from traceless_api.models.operational import Criticality

IntelSourceKind = Literal["news", "misp", "vulnerability", "other"]
IntelRecordType = Literal[
    "report",
    "threat",
    "vulnerability",
    "indicator",
    "campaign",
    "malware",
    "threat_actor",
]
IndicatorType = Literal["ipv4", "ipv6", "domain", "url", "file_sha256", "email"]
IndicatorRole = Literal["unknown", "source", "destination", "host", "callback", "artifact"]
IntelReviewStatus = Literal["pending", "approved", "rejected"]
DistributionTlp = Literal[
    "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"
]


def _unique(values: list[str], field_name: str) -> list[str]:
    normalized = [value.strip() for value in values]
    if any(not value for value in normalized):
        raise ValueError(f"{field_name} must not contain empty values")
    if len({value.casefold() for value in normalized}) != len(normalized):
        raise ValueError(f"{field_name} must contain unique values")
    return normalized


def _validate_cpe(value: str) -> str:
    parts = value.split(":")
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        raise ValueError("CPE values must be concrete CPE 2.3 names")
    if parts[2] not in {"a", "o", "h"} or parts[3] in {"", "*", "-"}:
        raise ValueError("CPE values require a concrete part and vendor")
    if parts[4] in {"", "*", "-"}:
        raise ValueError("CPE values require a concrete product")
    return value


class AiAnalysis(StrictModel):
    """Derived AI output. It is versioned and never replaces source evidence."""

    model_name: str = Field(min_length=2, max_length=200)
    model_version: str | None = Field(default=None, max_length=120)
    prompt_version: str = Field(min_length=1, max_length=120)
    taxonomy_version: str = Field(min_length=1, max_length=120)
    analyzed_at: AwareDatetime
    confidence: float = Field(ge=0, le=1)
    confidence_method: str | None = Field(default=None, min_length=2, max_length=200)
    confidence_method_version: str | None = Field(default=None, min_length=1, max_length=120)
    categories: list[str] = Field(default_factory=list, max_length=50)
    extracted_entities: dict[str, list[str]] = Field(default_factory=dict)
    rationale: str | None = Field(default=None, max_length=4_000)

    @field_validator("categories")
    @classmethod
    def categories_are_unique(cls, values: list[str]) -> list[str]:
        return _unique(values, "categories")

    @field_validator("extracted_entities")
    @classmethod
    def entities_are_bounded(cls, values: dict[str, list[str]]) -> dict[str, list[str]]:
        if len(values) > 50:
            raise ValueError("extracted_entities supports at most 50 entity types")
        normalized: dict[str, list[str]] = {}
        for key, items in values.items():
            clean_key = key.strip()
            if not clean_key or len(clean_key) > 80:
                raise ValueError("entity type names must contain 1-80 characters")
            if len(items) > 200 or any(len(item) > 500 for item in items):
                raise ValueError("entity values exceed the supported bounds")
            normalized[clean_key] = _unique(items, f"extracted_entities.{clean_key}")
        return normalized


class VulnerabilitySignals(StrictModel):
    affected_cpes: list[str] = Field(min_length=1, max_length=100)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=160)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    epss_percentile: float | None = Field(default=None, ge=0, le=1)
    cwe_ids: list[str] = Field(default_factory=list, max_length=100)
    exploit_status: Literal["unknown", "poc", "active"] = "unknown"

    @field_validator("affected_cpes")
    @classmethod
    def affected_cpes_are_valid(cls, values: list[str]) -> list[str]:
        normalized = _unique(values, "affected_cpes")
        for cpe in normalized:
            _validate_cpe(cpe)
        return normalized

    @field_validator("cwe_ids")
    @classmethod
    def cwe_ids_are_valid(cls, values: list[str]) -> list[str]:
        normalized = _unique(values, "cwe_ids")
        for cwe_id in normalized:
            if not cwe_id.startswith("CWE-") or not cwe_id[4:].isdigit():
                raise ValueError("cwe_ids must use CWE-<number>")
        return normalized

    @model_validator(mode="after")
    def validate_signals(self) -> "VulnerabilitySignals":
        if self.cvss_vector and self.cvss_score is None:
            raise ValueError("cvss_vector requires cvss_score")
        return self


class IndicatorObservable(StrictModel):
    type: IndicatorType
    value: str = Field(min_length=1, max_length=2_000)
    role: IndicatorRole = "unknown"

    @model_validator(mode="after")
    def validate_value(self) -> "IndicatorObservable":
        if self.type in {"ipv4", "ipv6"}:
            parsed = ip_address(self.value)
            expected_version = 4 if self.type == "ipv4" else 6
            if parsed.version != expected_version:
                raise ValueError(f"{self.type} does not match the supplied address family")
        elif self.type == "domain":
            _validate_domain(self.value)
        elif self.type == "url":
            parsed_url = urlsplit(self.value)
            if parsed_url.scheme.casefold() not in {"http", "https"} or not parsed_url.hostname:
                raise ValueError("url indicators require an absolute HTTP(S) URL")
        elif self.type == "file_sha256":
            if len(self.value) != 64 or any(
                character not in "0123456789abcdefABCDEF" for character in self.value
            ):
                raise ValueError("file_sha256 indicators require 64 hexadecimal characters")
        elif self.type == "email":
            local, separator, domain = self.value.rpartition("@")
            if not separator or not local or len(local) > 64:
                raise ValueError("email indicators require a valid address shape")
            _validate_domain(domain)
        return self


def _validate_domain(value: str) -> None:
    domain = value.rstrip(".")
    if len(domain) > 253 or "." not in domain:
        raise ValueError("domain indicators require a concrete fully qualified domain")
    for label in domain.split("."):
        if (
            not label
            or len(label) > 63
            or label[0] == "-"
            or label[-1] == "-"
            or any(not (character.isalnum() or character == "-") for character in label)
        ):
            raise ValueError("domain indicator contains an invalid label")


class CanonicalIntelRecord(StrictModel):
    """One normalized record from a scraper, MISP or vulnerability pipeline."""

    source_kind: IntelSourceKind
    provider: str = Field(min_length=2, max_length=100)
    external_id: str = Field(min_length=2, max_length=160)
    record_type: IntelRecordType
    title: str = Field(min_length=3, max_length=500)
    summary: str = Field(min_length=3, max_length=20_000)
    source_url: HttpUrl | None = None
    published_at: AwareDatetime | None = None
    modified_at: AwareDatetime
    retrieved_at: AwareDatetime
    severity: Criticality | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    cve_ids: list[str] = Field(default_factory=list, max_length=100)
    cpes: list[str] = Field(default_factory=list, max_length=100)
    affected_products: list[str] = Field(default_factory=list, max_length=100)
    mitre_attack_ids: list[str] = Field(default_factory=list, max_length=100)
    indicators: list[IndicatorObservable] = Field(default_factory=list, max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=100)
    sectors: list[str] = Field(default_factory=list, max_length=100)
    regions: list[str] = Field(default_factory=list, max_length=100)
    markings: list[str] = Field(default_factory=lambda: ["TLP:AMBER"], max_length=50)
    valid_from: AwareDatetime | None = None
    valid_until: AwareDatetime | None = None
    revoked: bool = False
    raw_evidence: dict[str, Any]
    ai_analysis: AiAnalysis | None = None
    vulnerability: VulnerabilitySignals | None = None

    @field_validator(
        "cve_ids",
        "cpes",
        "affected_products",
        "mitre_attack_ids",
        "tags",
        "sectors",
        "regions",
    )
    @classmethod
    def lists_are_unique(cls, values: list[str], info: Any) -> list[str]:
        return _unique(values, info.field_name)

    @field_validator("markings")
    @classmethod
    def markings_follow_dissemination_policy(cls, values: list[str]) -> list[str]:
        return normalize_markings(values)

    @model_validator(mode="after")
    def validate_record(self) -> "CanonicalIntelRecord":
        for cve_id in self.cve_ids:
            parts = cve_id.split("-")
            if len(parts) != 3 or parts[0] != "CVE" or len(parts[1]) != 4 or not all(
                part.isdigit() for part in parts[1:]
            ) or len(parts[2]) < 4:
                raise ValueError("cve_ids must use CVE-YYYY-NNNN format")
        for cpe in self.cpes:
            _validate_cpe(cpe)
        for attack_id in self.mitre_attack_ids:
            prefix, separator, number = attack_id.partition(".")
            if len(prefix) != 5 or not prefix.startswith("T") or not prefix[1:].isdigit() or (
                separator and (len(number) != 3 or not number.isdigit())
            ):
                raise ValueError("mitre_attack_ids must use T#### or T####.### format")
        indicator_identities = [
            (indicator.type, indicator.value.casefold()) for indicator in self.indicators
        ]
        if len(set(indicator_identities)) != len(indicator_identities):
            raise ValueError("indicators must have unique type/value identities")
        if self.published_at and self.modified_at < self.published_at:
            raise ValueError("modified_at must not precede published_at")
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        if self.record_type == "vulnerability":
            if not self.cve_ids or self.vulnerability is None:
                raise ValueError("vulnerability records require cve_ids and vulnerability signals")
        elif self.vulnerability is not None:
            raise ValueError("vulnerability signals are only valid for vulnerability records")
        try:
            raw_bytes = json.dumps(
                self.raw_evidence,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        except (TypeError, ValueError) as error:
            raise ValueError("raw_evidence must contain finite JSON values") from error
        if len(raw_bytes) > 262_144:
            raise ValueError("raw_evidence exceeds 256 KiB; store the source object externally")
        return self


class CanonicalIntelFeed(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    feed_id: str = Field(min_length=2, max_length=120)
    feed_version: str = Field(min_length=1, max_length=120)
    generated_at: AwareDatetime
    items: list[CanonicalIntelRecord] = Field(min_length=1, max_length=1_000)

    @field_validator("items")
    @classmethod
    def identities_are_unique(
        cls, values: list[CanonicalIntelRecord]
    ) -> list[CanonicalIntelRecord]:
        identities = [(item.provider.casefold(), item.external_id) for item in values]
        if len(set(identities)) != len(identities):
            raise ValueError("items must have unique provider/external_id identities")
        return values


class GlobalIntelRecordView(StrictModel):
    id: UUID
    source_kind: IntelSourceKind
    provider: str
    external_id: str
    record_type: IntelRecordType
    title: str
    summary: str
    source_url: str | None
    published_at: AwareDatetime | None
    modified_at: AwareDatetime
    retrieved_at: AwareDatetime
    severity: Criticality | None
    confidence: float | None
    cve_ids: list[str]
    cpes: list[str]
    affected_products: list[str]
    mitre_attack_ids: list[str]
    indicators: list[dict[str, str]]
    tags: list[str]
    sectors: list[str]
    regions: list[str]
    markings: list[str]
    distribution_tlp: DistributionTlp
    review_status: IntelReviewStatus
    reviewed_by: str | None
    reviewed_at: AwareDatetime | None
    review_note: str | None
    valid_from: AwareDatetime | None
    valid_until: AwareDatetime | None
    revoked: bool
    raw_evidence: dict[str, Any]
    raw_sha256: str
    ai_analysis: dict[str, Any] | None
    analysis_sha256: str | None
    vulnerability: dict[str, Any] | None
    feed_id: str
    feed_version: str
    feed_generated_at: AwareDatetime
    first_ingested_at: AwareDatetime
    last_ingested_at: AwareDatetime


class GlobalIntelPage(StrictModel):
    items: list[GlobalIntelRecordView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class IntelReviewRequest(StrictModel):
    decision: Literal["approved", "rejected"]
    note: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def rejection_requires_a_reason(self) -> "IntelReviewRequest":
        if self.decision == "rejected" and (self.note is None or len(self.note.strip()) < 3):
            raise ValueError("rejected intelligence requires a review note")
        return self


class IntelReviewResult(StrictModel):
    record: GlobalIntelRecordView
    correlation_job_ids: list[UUID] = Field(default_factory=list)


class IntelImportResult(StrictModel):
    imported: int = Field(ge=0)
    created: int = Field(ge=0)
    updated: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    quarantined: int = Field(default=0, ge=0)
    warnings: list[str] = Field(default_factory=list)
    # Internal hand-off to the durable correlation queue. These values are not
    # part of the public response contract and never expose source identities.
    _records_requiring_recorrelation: tuple[UUID, ...] = PrivateAttr(default=())
    _recorrelation_manifest_sha256: str | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def validate_counts(self) -> "IntelImportResult":
        if self.imported != self.created + self.updated + self.unchanged + self.quarantined:
            raise ValueError("import outcome counts must equal imported")
        return self


class IntelCorrelationResult(StrictModel):
    system_id: UUID
    scan_id: UUID
    records_considered: int = Field(ge=0)
    vulnerability_records_applied: int = Field(ge=0)
    finding_matches: int = Field(ge=0)
    findings_created: int = Field(ge=0)
    threat_records_matched: int = Field(ge=0)
    threats_created: int = Field(ge=0)
    risks_created: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)


def is_active(record: CanonicalIntelRecord | GlobalIntelRecordView, now: datetime) -> bool:
    return (
        not record.revoked
        and (record.valid_from is None or record.valid_from <= now)
        and (record.valid_until is None or record.valid_until > now)
    )
