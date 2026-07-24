"""Public and administrative contracts for the intelligence publisher."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from traceless_api.integrations.intelligence.external_datapoints import ExternalDatapoint
from traceless_api.models.common import StrictModel

PublisherTlp = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"]
PublisherSourceKind = Literal["news", "misp", "vulnerability", "other"]


def _normalized_unique(values: list[str], *, casefold: bool = True) -> list[str]:
    cleaned = [value.strip() for value in values]
    if any(not value for value in cleaned):
        raise ValueError("values must not be empty")
    identities = [value.casefold() if casefold else value for value in cleaned]
    if len(identities) != len(set(identities)):
        raise ValueError("values must be unique")
    return cleaned


class PublisherImportBatch(StrictModel):
    """Normalized output pushed from the separately operated scrape/analysis process."""

    feed_id: str = Field(min_length=2, max_length=120)
    feed_version: str = Field(min_length=1, max_length=120)
    generated_at: AwareDatetime
    items: list[ExternalDatapoint] = Field(min_length=1, max_length=1_000)
    publish: bool = False
    idempotency_key: str | None = Field(
        default=None,
        min_length=8,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )

    @field_validator("items")
    @classmethod
    def identities_are_unique(cls, values: list[ExternalDatapoint]) -> list[ExternalDatapoint]:
        identities = [
            (item.record.provider.casefold(), item.record.external_id) for item in values
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("items must have unique provider/external_id identities")
        return values


class PublisherImportResult(StrictModel):
    imported: int = Field(ge=0)
    created: int = Field(ge=0)
    staged: int = Field(ge=0)
    published: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    superseded: int = Field(ge=0)
    restricted: int = Field(ge=0)
    record_ids: dict[str, UUID]
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def counters_match(self) -> PublisherImportResult:
        if self.imported != (
            self.staged
            + self.published
            + self.unchanged
            + self.superseded
            + self.restricted
        ):
            raise ValueError("import counters must sum to imported")
        return self


class PublisherClientCreate(StrictModel):
    client_id: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    name: str = Field(min_length=2, max_length=160)
    enabled: bool = True
    max_tlp: PublisherTlp = "TLP:AMBER"
    allowed_providers: list[str] = Field(default_factory=list, max_length=200)
    allowed_source_kinds: list[PublisherSourceKind] = Field(
        default_factory=list,
        max_length=4,
    )

    @field_validator("allowed_providers")
    @classmethod
    def providers_are_unique(cls, values: list[str]) -> list[str]:
        return _normalized_unique(values)

    @field_validator("allowed_source_kinds")
    @classmethod
    def source_kinds_are_unique(
        cls,
        values: list[PublisherSourceKind],
    ) -> list[PublisherSourceKind]:
        normalized = _normalized_unique(list(values), casefold=False)
        return [value for value in normalized]  # type: ignore[return-value]


class PublisherClientUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    enabled: bool | None = None
    max_tlp: PublisherTlp | None = None
    allowed_providers: list[str] | None = Field(default=None, max_length=200)
    allowed_source_kinds: list[PublisherSourceKind] | None = Field(
        default=None,
        max_length=4,
    )

    @field_validator("allowed_providers")
    @classmethod
    def providers_are_unique(cls, values: list[str] | None) -> list[str] | None:
        return _normalized_unique(values) if values is not None else None

    @field_validator("allowed_source_kinds")
    @classmethod
    def source_kinds_are_unique(
        cls,
        values: list[PublisherSourceKind] | None,
    ) -> list[PublisherSourceKind] | None:
        if values is None:
            return None
        normalized = _normalized_unique(list(values), casefold=False)
        return [value for value in normalized]  # type: ignore[return-value]

    @model_validator(mode="after")
    def at_least_one_change(self) -> PublisherClientUpdate:
        if all(
            value is None
            for value in (
                self.name,
                self.enabled,
                self.max_tlp,
                self.allowed_providers,
                self.allowed_source_kinds,
            )
        ):
            raise ValueError("at least one client property must be supplied")
        return self


class PublisherClientView(StrictModel):
    id: UUID
    client_id: str
    name: str
    enabled: bool
    max_tlp: PublisherTlp
    allowed_providers: list[str]
    allowed_source_kinds: list[PublisherSourceKind]
    token_version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    last_seen_at: datetime | None


class PublisherClientCredential(StrictModel):
    client: PublisherClientView
    api_key: str = Field(min_length=32, max_length=512)
    warning: str = (
        "The API key is returned once. Store it in the customer's secret store."
    )


class PublisherClientPage(StrictModel):
    items: list[PublisherClientView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class PublisherRecordView(StrictModel):
    id: UUID
    provider: str
    external_id: str
    source_kind: PublisherSourceKind
    record_type: str
    title: str
    latest_revision: int = Field(ge=1)
    latest_modified_at: datetime
    latest_status: Literal["active", "revoked", "deleted"]
    latest_tlp: str
    publication_status: Literal["staged", "published", "restricted", "superseded", "rejected"]
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    updated_at: datetime


class PublisherRecordPage(StrictModel):
    items: list[PublisherRecordView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class PublisherPublishResult(StrictModel):
    record: PublisherRecordView
    published: bool
    change_sequences: list[int]
    warnings: list[str] = Field(default_factory=list)


class PublisherSigningKeyView(StrictModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str
    public_key_base64: str


class PublisherHealth(StrictModel):
    status: Literal["ok", "ready"]
    service: Literal["traceless-intelligence-publisher"] = (
        "traceless-intelligence-publisher"
    )
