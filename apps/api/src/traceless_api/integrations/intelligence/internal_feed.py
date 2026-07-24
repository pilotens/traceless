"""Versioned internal STIX-like threat-feed contract, parser, and adapter."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
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
    ExternalReference,
    IntelligenceBatch,
    ProviderName,
    SourceProvenance,
    StixId,
    ThreatIntelligenceObject,
    ThreatObjectType,
)
from traceless_api.integrations.intelligence.protocols import AsyncHttpClient
from traceless_api.models.common import StrictModel

DEFAULT_MAX_INTERNAL_FEED_BYTES = 10_000_000
DEFAULT_MAX_INTERNAL_FEED_RECORDS = 5_000


class _ThreatObjectPayload(StrictModel):
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

    @model_validator(mode="after")
    def validate_stix_shape(self) -> "_ThreatObjectPayload":
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
        return self


class _InternalThreatFeedPayload(StrictModel):
    schema_version: Literal["1.0"]
    feed_id: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=200,
            pattern=r"^[a-z0-9][a-z0-9._-]*$",
        ),
    ]
    feed_version: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    generated_at: AwareDatetime
    objects: tuple[_ThreatObjectPayload, ...] = Field(max_length=DEFAULT_MAX_INTERNAL_FEED_RECORDS)

    @model_validator(mode="after")
    def reject_unresolved_distribution_markings(self) -> "_InternalThreatFeedPayload":
        # The compact private-feed contract does not yet carry STIX
        # marking-definition objects or named-recipient assignments. Treating
        # an opaque object_marking_ref as shareable would be a confidentiality
        # bypass, so fail closed until it can be resolved explicitly.
        if any(record.object_marking_refs for record in self.objects):
            raise ValueError(
                "object_marking_refs require resolved marking-definition controls"
            )
        return self


def parse_internal_threat_feed(
    payload: bytes,
    *,
    source_url: str,
    provider_name: str = "internal-cti",
    retrieved_at: datetime | None = None,
    max_bytes: int = DEFAULT_MAX_INTERNAL_FEED_BYTES,
    max_records: int = DEFAULT_MAX_INTERNAL_FEED_RECORDS,
) -> IntelligenceBatch[ThreatIntelligenceObject]:
    """Validate the Traceless internal feed contract and retain object lineage."""

    endpoint = validate_http_endpoint(source_url)
    retrieved = validate_retrieved_at(retrieved_at or utc_now())
    try:
        normalized_provider = TypeAdapter(ProviderName).validate_python(provider_name)
    except ValidationError as exc:
        raise ValueError("provider_name is invalid") from exc

    decoded = decode_bounded_json(payload, max_bytes=max_bytes)
    try:
        source = _InternalThreatFeedPayload.model_validate(decoded)
    except ValidationError as exc:
        raise InvalidIntelligencePayload("Internal threat feed failed schema validation") from exc
    if len(source.objects) > max_records:
        raise InvalidIntelligencePayload(
            f"Internal threat feed exceeds the {max_records}-record limit"
        )

    identities = [record.id for record in source.objects]
    if len(identities) != len(set(identities)):
        raise InvalidIntelligencePayload("Internal threat feed contains duplicate object ids")

    payload_hash = digest_payload(payload)
    feed_provenance = SourceProvenance(
        provider=normalized_provider,
        source_url=endpoint,
        source_feed_id=source.feed_id,
        source_version=source.feed_version,
        source_updated_at=source.generated_at,
        retrieved_at=retrieved,
        payload_sha256=payload_hash,
    )
    records = tuple(
        ThreatIntelligenceObject(
            **record.model_dump(),
            provenance=feed_provenance.for_record(
                record.id,
                source_updated_at=record.modified,
            ),
        )
        for record in source.objects
    )
    return IntelligenceBatch[ThreatIntelligenceObject](
        provenance=feed_provenance,
        records=records,
    )


parse_internal_threat_feed_json = parse_internal_threat_feed


class InternalThreatFeedProvider:
    """Fetch the internal threat feed using an injected HTTP client."""

    def __init__(
        self,
        client: AsyncHttpClient,
        endpoint: str,
        *,
        token: str | None = None,
        provider_name: str = "internal-cti",
        timeout: float = 20.0,
        max_payload_bytes: int = DEFAULT_MAX_INTERNAL_FEED_BYTES,
        max_records: int = DEFAULT_MAX_INTERNAL_FEED_RECORDS,
        clock: Clock = utc_now,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_payload_bytes <= 0 or max_records <= 0:
            raise ValueError("payload and record limits must be positive")
        if token is not None and (not token or len(token) > 8_192):
            raise ValueError("token must be non-empty and at most 8192 characters")
        try:
            self._provider_name = TypeAdapter(ProviderName).validate_python(provider_name)
        except ValidationError as exc:
            raise ValueError("provider_name is invalid") from exc

        self._client = client
        self._endpoint = validate_http_endpoint(endpoint)
        self._token = token
        self._timeout = timeout
        self._max_payload_bytes = max_payload_bytes
        self._max_records = max_records
        self._clock = clock

    @property
    def provider_name(self) -> str:
        return self._provider_name

    async def fetch(self) -> IntelligenceBatch[ThreatIntelligenceObject]:
        headers = {"Accept": "application/json"}
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"
        response = await self._client.get(
            self._endpoint,
            headers=headers,
            timeout=self._timeout,
        )
        body = validated_json_response_body(
            response,
            max_bytes=self._max_payload_bytes,
        )
        return parse_internal_threat_feed(
            body,
            source_url=self._endpoint,
            provider_name=self._provider_name,
            retrieved_at=self._clock(),
            max_bytes=self._max_payload_bytes,
            max_records=self._max_records,
        )
