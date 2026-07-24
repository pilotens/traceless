"""CISA Known Exploited Vulnerabilities JSON adapter and parser."""

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StringConstraints, ValidationError, model_validator

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
    IntelligenceBatch,
    KevCatalogEntry,
    KnownRansomwareUse,
    SourceProvenance,
)
from traceless_api.integrations.intelligence.protocols import AsyncHttpClient
from traceless_api.models.common import StrictModel

DEFAULT_MAX_KEV_BYTES = 10_000_000
DEFAULT_MAX_KEV_RECORDS = 10_000


class _CisaKevPayloadRecord(StrictModel):
    cve_id: Annotated[
        str,
        Field(alias="cveID", pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$"),
    ]
    vendor_project: Annotated[
        str,
        Field(alias="vendorProject", min_length=1, max_length=200),
    ]
    product: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    vulnerability_name: Annotated[
        str,
        Field(alias="vulnerabilityName", min_length=1, max_length=500),
    ]
    date_added: Annotated[date, Field(alias="dateAdded")]
    short_description: Annotated[
        str,
        Field(alias="shortDescription", min_length=1, max_length=4_000),
    ]
    required_action: Annotated[
        str,
        Field(alias="requiredAction", min_length=1, max_length=4_000),
    ]
    due_date: Annotated[date, Field(alias="dueDate")]
    known_ransomware_campaign_use: Annotated[
        Literal["Known", "Unknown"],
        Field(alias="knownRansomwareCampaignUse"),
    ]
    notes: Annotated[str, StringConstraints(max_length=4_000)] = ""
    cwes: tuple[Annotated[str, StringConstraints(min_length=1, max_length=40)], ...] = Field(
        default_factory=tuple, max_length=50
    )


class _CisaKevPayload(StrictModel):
    title: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    catalog_version: Annotated[
        str,
        Field(alias="catalogVersion", min_length=1, max_length=100),
    ]
    date_released: Annotated[AwareDatetime, Field(alias="dateReleased")]
    count: Annotated[int, Field(ge=0, le=DEFAULT_MAX_KEV_RECORDS)]
    vulnerabilities: tuple[_CisaKevPayloadRecord, ...] = Field(
        min_length=1,
        max_length=DEFAULT_MAX_KEV_RECORDS,
    )

    @model_validator(mode="after")
    def count_matches_records(self) -> "_CisaKevPayload":
        if self.count != len(self.vulnerabilities):
            raise ValueError("CISA KEV count does not match vulnerabilities length")
        return self


def parse_cisa_kev(
    payload: bytes,
    *,
    source_url: str,
    retrieved_at: datetime | None = None,
    max_bytes: int = DEFAULT_MAX_KEV_BYTES,
    max_records: int = DEFAULT_MAX_KEV_RECORDS,
) -> IntelligenceBatch[KevCatalogEntry]:
    """Validate and normalize one official CISA KEV JSON snapshot."""

    endpoint = validate_http_endpoint(source_url)
    retrieved = validate_retrieved_at(retrieved_at or utc_now())
    decoded = decode_bounded_json(payload, max_bytes=max_bytes)
    try:
        source = _CisaKevPayload.model_validate(decoded)
    except ValidationError as exc:
        raise InvalidIntelligencePayload("CISA KEV payload failed schema validation") from exc
    if len(source.vulnerabilities) > max_records:
        raise InvalidIntelligencePayload(f"CISA KEV payload exceeds the {max_records}-record limit")

    identities = [record.cve_id for record in source.vulnerabilities]
    if len(identities) != len(set(identities)):
        raise InvalidIntelligencePayload("CISA KEV payload contains duplicate CVE records")

    payload_hash = digest_payload(payload)
    feed_provenance = SourceProvenance(
        provider=CisaKevProvider.provider_name,
        source_url=endpoint,
        source_feed_id="cisa-known-exploited-vulnerabilities",
        source_version=source.catalog_version,
        source_updated_at=source.date_released,
        retrieved_at=retrieved,
        payload_sha256=payload_hash,
    )
    records = tuple(
        KevCatalogEntry(
            cve_id=record.cve_id,
            vendor_project=record.vendor_project,
            product=record.product,
            vulnerability_name=record.vulnerability_name,
            date_added=record.date_added,
            short_description=record.short_description,
            required_action=record.required_action,
            due_date=record.due_date,
            known_ransomware_campaign_use=KnownRansomwareUse(
                record.known_ransomware_campaign_use.casefold()
            ),
            notes=record.notes,
            cwes=record.cwes,
            provenance=feed_provenance.for_record(record.cve_id),
        )
        for record in source.vulnerabilities
    )
    return IntelligenceBatch[KevCatalogEntry](
        provenance=feed_provenance,
        records=records,
    )


parse_cisa_kev_json = parse_cisa_kev


class CisaKevProvider:
    """Fetch CISA KEV through an injected asynchronous HTTP client."""

    provider_name = "cisa-kev"

    def __init__(
        self,
        client: AsyncHttpClient,
        endpoint: str,
        *,
        timeout: float = 20.0,
        max_payload_bytes: int = DEFAULT_MAX_KEV_BYTES,
        max_records: int = DEFAULT_MAX_KEV_RECORDS,
        clock: Clock = utc_now,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_payload_bytes <= 0 or max_records <= 0:
            raise ValueError("payload and record limits must be positive")
        self._client = client
        self._endpoint = validate_http_endpoint(endpoint)
        self._timeout = timeout
        self._max_payload_bytes = max_payload_bytes
        self._max_records = max_records
        self._clock = clock

    async def fetch(self) -> IntelligenceBatch[KevCatalogEntry]:
        response = await self._client.get(
            self._endpoint,
            headers={"Accept": "application/json"},
            timeout=self._timeout,
        )
        body = validated_json_response_body(
            response,
            max_bytes=self._max_payload_bytes,
        )
        return parse_cisa_kev(
            body,
            source_url=self._endpoint,
            retrieved_at=self._clock(),
            max_bytes=self._max_payload_bytes,
            max_records=self._max_records,
        )
