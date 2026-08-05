"""FIRST EPSS JSON API adapter and parser."""

import re
from datetime import UTC, date, datetime, time
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, ValidationError, model_validator

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
    EpssMetric,
    IntelligenceBatch,
    SourceProvenance,
)
from traceless_api.integrations.intelligence.protocols import AsyncHttpClient
from traceless_api.models.common import StrictModel

DEFAULT_MAX_EPSS_BYTES = 5_000_000
DEFAULT_MAX_EPSS_RECORDS = 10_000
MAX_EPSS_QUERY_CVES = 100
_CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


class _FirstEpssPayloadRecord(StrictModel):
    cve: Annotated[str, StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]
    epss: Annotated[Decimal, Field(ge=0, le=1)]
    percentile: Annotated[Decimal, Field(ge=0, le=1)]
    date: date


class _FirstEpssPayload(StrictModel):
    status: Literal["OK"]
    status_code: Annotated[int, Field(alias="status-code")]
    version: Annotated[str, StringConstraints(min_length=1, max_length=50)]
    access: Annotated[str, StringConstraints(min_length=1, max_length=50)]
    total: Annotated[int, Field(ge=0)]
    offset: Annotated[int, Field(ge=0)]
    limit: Annotated[int, Field(ge=0)]
    data: tuple[_FirstEpssPayloadRecord, ...] = Field(
        default_factory=tuple,
        max_length=DEFAULT_MAX_EPSS_RECORDS,
    )

    @model_validator(mode="after")
    def pagination_is_consistent(self) -> "_FirstEpssPayload":
        if self.status_code != 200:
            raise ValueError("FIRST EPSS status-code must be 200")
        if len(self.data) > self.limit:
            raise ValueError("FIRST EPSS data length exceeds response limit")
        if len(self.data) > self.total:
            raise ValueError("FIRST EPSS data length exceeds response total")
        if self.data and self.offset >= self.total:
            raise ValueError("FIRST EPSS offset is outside the result set")
        return self


def parse_first_epss(
    payload: bytes,
    *,
    source_url: str,
    retrieved_at: datetime | None = None,
    max_bytes: int = DEFAULT_MAX_EPSS_BYTES,
    max_records: int = DEFAULT_MAX_EPSS_RECORDS,
) -> IntelligenceBatch[EpssMetric]:
    """Validate and normalize one FIRST EPSS API response."""

    endpoint = validate_http_endpoint(source_url)
    retrieved = validate_retrieved_at(retrieved_at or utc_now())
    decoded = decode_bounded_json(payload, max_bytes=max_bytes)
    try:
        source = _FirstEpssPayload.model_validate(decoded)
    except ValidationError as exc:
        raise InvalidIntelligencePayload("FIRST EPSS payload failed schema validation") from exc
    if len(source.data) > max_records:
        raise InvalidIntelligencePayload(
            f"FIRST EPSS payload exceeds the {max_records}-record limit"
        )

    identities = [(record.cve, record.date) for record in source.data]
    if len(identities) != len(set(identities)):
        raise InvalidIntelligencePayload("FIRST EPSS payload contains duplicate CVE/date records")

    payload_hash = digest_payload(payload)
    feed_updated_at = (
        datetime.combine(max(record.date for record in source.data), time.min, tzinfo=UTC)
        if source.data
        else None
    )
    feed_provenance = SourceProvenance(
        provider=FirstEpssProvider.provider_name,
        source_url=endpoint,
        source_feed_id="first-epss",
        source_version=source.version,
        source_updated_at=feed_updated_at,
        retrieved_at=retrieved,
        payload_sha256=payload_hash,
    )
    records = tuple(
        EpssMetric(
            cve_id=record.cve,
            probability=record.epss,
            percentile=record.percentile,
            model_date=record.date,
            provenance=feed_provenance.for_record(
                f"{record.cve}@{record.date.isoformat()}",
                source_updated_at=datetime.combine(
                    record.date,
                    time.min,
                    tzinfo=UTC,
                ),
            ),
        )
        for record in source.data
    )
    return IntelligenceBatch[EpssMetric](
        provenance=feed_provenance,
        records=records,
    )


parse_first_epss_json = parse_first_epss


class FirstEpssProvider:
    """Fetch an EPSS response through an injected asynchronous HTTP client."""

    provider_name = "first-epss"

    def __init__(
        self,
        client: AsyncHttpClient,
        endpoint: str,
        *,
        cve_ids: tuple[str, ...] = (),
        timeout: float = 20.0,
        max_payload_bytes: int = DEFAULT_MAX_EPSS_BYTES,
        max_records: int = DEFAULT_MAX_EPSS_RECORDS,
        clock: Clock = utc_now,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_payload_bytes <= 0 or max_records <= 0:
            raise ValueError("payload and record limits must be positive")
        if len(cve_ids) > MAX_EPSS_QUERY_CVES:
            raise ValueError(f"At most {MAX_EPSS_QUERY_CVES} CVEs may be queried at once")
        if len(cve_ids) != len(set(cve_ids)):
            raise ValueError("EPSS query CVEs must be unique")
        if any(_CVE_PATTERN.fullmatch(cve_id) is None for cve_id in cve_ids):
            raise ValueError("EPSS query contains an invalid CVE id")

        self._client = client
        self._endpoint = validate_http_endpoint(endpoint)
        self._cve_ids = cve_ids
        self._timeout = timeout
        self._max_payload_bytes = max_payload_bytes
        self._max_records = max_records
        self._clock = clock

    async def fetch(self) -> IntelligenceBatch[EpssMetric]:
        params = {"cve": ",".join(self._cve_ids)} if self._cve_ids else None
        response = await self._client.get(
            self._endpoint,
            headers={"Accept": "application/json"},
            params=params,
            timeout=self._timeout,
        )
        body = validated_json_response_body(
            response,
            max_bytes=self._max_payload_bytes,
        )
        return parse_first_epss(
            body,
            source_url=self._endpoint,
            retrieved_at=self._clock(),
            max_bytes=self._max_payload_bytes,
            max_records=self._max_records,
        )
