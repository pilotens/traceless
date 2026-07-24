"""Pull-only adapter for a separately operated normalized intelligence API.

The adapter deliberately knows nothing about scraping. It retrieves bounded pages
from one operator-configured HTTPS endpoint, always reuses that endpoint during
cursor pagination, and turns explicit source lifecycle states into canonical
Traceless records without mixing source evidence with AI analysis.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from collections.abc import AsyncIterator, Collection, Mapping
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from hashlib import sha256
from typing import Annotated, Literal, Protocol
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import AwareDatetime, Field, StringConstraints, ValidationError, model_validator

from traceless_api.integrations.intelligence._json import decode_bounded_json
from traceless_api.integrations.intelligence.errors import (
    IntelligencePayloadTooLarge,
    InvalidIntelligencePayload,
    UnexpectedContentType,
)
from traceless_api.integrations.intelligence.protocols import HttpResponse
from traceless_api.models.common import StrictModel
from traceless_api.models.intelligence_hub import CanonicalIntelRecord

DEFAULT_PAGE_SIZE = 250
DEFAULT_MAX_PAGE_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_CURSOR_LENGTH = 2_048
STATUS_TAG_PREFIX = "traceless:source-status:"

Cursor = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_CURSOR_LENGTH, strip_whitespace=False),
]
SourceStatus = Literal["active", "revoked", "deleted"]
AuthScheme = Literal["Bearer", "X-API-Key"]
ScheduleState = Literal["manual", "disabled", "scheduled", "due"]
MIN_SYNC_INTERVAL_SECONDS = 60
MAX_SYNC_INTERVAL_SECONDS = 30 * 24 * 60 * 60


class ExternalDatapointHttpClient(Protocol):
    """HTTP surface used by the pull connector."""

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> AbstractAsyncContextManager[ExternalDatapointStreamResponse]: ...


class ExternalDatapointStreamResponse(HttpResponse, Protocol):
    """Response surface that permits a hard limit while bytes are received."""

    def aiter_bytes(self) -> AsyncIterator[bytes]: ...


class ExternalDatapoint(StrictModel):
    """A normalized record plus the producer's explicit lifecycle state."""

    status: SourceStatus
    status_changed_at: AwareDatetime | None = None
    status_reason: str | None = Field(default=None, min_length=2, max_length=1_000)
    record: CanonicalIntelRecord

    @model_validator(mode="after")
    def validate_lifecycle_and_provenance(self) -> ExternalDatapoint:
        expected_revoked = self.status != "active"
        if self.record.revoked is not expected_revoked:
            raise ValueError("record.revoked must agree with the external status")
        if expected_revoked:
            if self.status_changed_at is None or self.status_reason is None:
                raise ValueError("revoked and deleted records require status time and reason")
            if self.record.modified_at < self.status_changed_at:
                raise ValueError("record.modified_at must include the lifecycle change")

        if any(tag.casefold().startswith(STATUS_TAG_PREFIX) for tag in self.record.tags):
            raise ValueError("producer tags must not use the reserved Traceless status prefix")
        if len(self.record.tags) >= 100:
            raise ValueError("external records support at most 99 producer tags")

        analysis = self.record.ai_analysis
        if analysis is None:
            if self.record.confidence is not None:
                raise ValueError("confidence without AI analysis has no supported provenance")
        else:
            if (
                self.record.confidence is None
                or abs(self.record.confidence - analysis.confidence) > 1e-12
            ):
                raise ValueError("record confidence must equal the versioned AI confidence")
            if (
                analysis.model_version is None
                or analysis.confidence_method is None
                or analysis.confidence_method_version is None
            ):
                raise ValueError("pulled AI analysis requires model and confidence-method versions")

        if self.record.source_url is not None:
            parsed = urlsplit(str(self.record.source_url))
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("source_url must not contain credentials")
        return self

    def to_canonical_record(self) -> CanonicalIntelRecord:
        """Preserve source evidence and lifecycle metadata outside AI output."""

        source_evidence = self.record.raw_evidence
        source_sha256 = _canonical_json_sha256(source_evidence)
        lifecycle = {
            "status": self.status,
            "changed_at": (
                self.status_changed_at.isoformat() if self.status_changed_at is not None else None
            ),
            "reason": self.status_reason,
            "source_raw_sha256": source_sha256,
        }
        values = self.record.model_dump(mode="python")
        values["tags"] = [*self.record.tags, f"{STATUS_TAG_PREFIX}{self.status}"]
        values["raw_evidence"] = {
            "source": source_evidence,
            "source_lifecycle": lifecycle,
        }
        try:
            return CanonicalIntelRecord.model_validate(values)
        except ValidationError as exc:
            raise InvalidIntelligencePayload(
                "External record exceeds canonical bounds after provenance wrapping"
            ) from exc


class ExternalDatapointPage(StrictModel):
    """Stable legacy snapshot or signed v2 full/delta page."""

    schema_version: Literal["1.0", "2.0"] = "1.0"
    feed_id: str = Field(min_length=2, max_length=120)
    feed_version: str = Field(min_length=1, max_length=160)
    generated_at: AwareDatetime
    items: list[ExternalDatapoint] = Field(default_factory=list, max_length=1_000)
    has_more: bool
    next_cursor: Cursor | None = None
    feed_epoch: int | None = Field(default=None, ge=1)
    mode: Literal["full", "delta"] | None = None
    reset_required: bool = False
    from_sequence: int | None = Field(default=None, ge=0)
    through_sequence: int | None = Field(default=None, ge=0)
    next_sync_token: Cursor | None = None
    manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_page(self) -> ExternalDatapointPage:
        if self.has_more:
            if self.next_cursor is None:
                raise ValueError("has_more=true requires next_cursor")
            if not self.items:
                raise ValueError("intermediate cursor pages must not be empty")
        elif self.next_cursor is not None:
            raise ValueError("a complete page must not return next_cursor")

        if self.schema_version == "2.0":
            if any(
                value is None
                for value in (
                    self.feed_epoch,
                    self.mode,
                    self.from_sequence,
                    self.through_sequence,
                    self.manifest_sha256,
                )
            ):
                raise ValueError("v2 pages require delivery metadata")
            assert self.from_sequence is not None
            assert self.through_sequence is not None
            if self.through_sequence < self.from_sequence:
                raise ValueError("v2 through_sequence must not precede from_sequence")
            if self.has_more and self.next_sync_token is not None:
                raise ValueError("intermediate v2 pages must not return next_sync_token")
            if not self.has_more and self.next_sync_token is None:
                raise ValueError("complete v2 pages require next_sync_token")
        elif self.next_sync_token is not None:
            raise ValueError("legacy pages must not return next_sync_token")

        identities = [
            (item.record.provider.casefold(), item.record.external_id) for item in self.items
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("page contains duplicate provider/external_id identities")
        return self


class ExternalDatapointPageResult(StrictModel):
    page: ExternalDatapointPage
    raw_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_payload_bytes: int = Field(ge=1)
    signature_verified: bool = False
    signing_key_id: str | None = None


class ExternalIntelligencePullRequest(StrictModel):
    """An optional opaque continuation cursor and a bounded per-call page budget."""

    cursor: Cursor | None = None
    max_pages: int | None = Field(default=None, ge=1, le=1_000)

    @model_validator(mode="after")
    def validate_request_cursor(self) -> ExternalIntelligencePullRequest:
        validate_cursor(self.cursor)
        return self


class ExternalIntelligenceConnectorUpdate(StrictModel):
    """Tenant-owned configuration; the referenced credential stays outside the DB."""

    endpoint: str = Field(min_length=12, max_length=2_000)
    auth_scheme: AuthScheme = "Bearer"
    credential_reference: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    enabled: bool = True
    sync_interval_seconds: int | None = Field(
        default=None,
        ge=MIN_SYNC_INTERVAL_SECONDS,
        le=MAX_SYNC_INTERVAL_SECONDS,
        description="Null keeps the connector in manual-only mode.",
    )


class ExternalIntelligenceConnectorView(StrictModel):
    id: UUID
    organization_id: UUID
    name: str
    endpoint: str
    auth_scheme: AuthScheme
    credential_reference: str
    enabled: bool
    sync_interval_seconds: int | None
    next_sync_at: datetime | None
    config_version: int = Field(ge=1)
    created_by: str
    created_at: datetime
    updated_at: datetime


class ExternalIntelligenceSyncRunView(StrictModel):
    id: UUID
    connector_id: UUID
    snapshot_id: UUID
    status: Literal["running", "partial", "completed", "failed", "quarantined"]
    started_by: str
    started_at: datetime
    completed_at: datetime | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime
    start_cursor_sha256: str | None
    next_cursor_sha256: str | None
    feed_id: str | None
    feed_version: str | None
    feed_generated_at: datetime | None
    pages_fetched: int = Field(ge=0)
    records_fetched: int = Field(ge=0)
    bytes_fetched: int = Field(ge=0)
    batch_pages_fetched: int = Field(ge=0)
    batch_records_fetched: int = Field(ge=0)
    batch_bytes_fetched: int = Field(ge=0)
    created_count: int = Field(ge=0)
    updated_count: int = Field(ge=0)
    unchanged_count: int = Field(ge=0)
    quarantined_count: int = Field(ge=0)
    manifest_sha256: str | None
    error_code: str | None


class ExternalIntelligenceCheckpointView(StrictModel):
    snapshot_id: UUID
    cursor_sha256: str
    feed_id: str
    feed_version: str
    feed_generated_at: datetime
    pages_completed: int = Field(ge=1)
    records_completed: int = Field(ge=0)
    bytes_completed: int = Field(ge=1)
    page_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    identity_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    updated_at: datetime


class ExternalIntelligenceSyncStatus(StrictModel):
    configured: bool
    connector_id: UUID | None = None
    endpoint: str | None = None
    enabled: bool = False
    schedule_state: ScheduleState = "manual"
    sync_interval_seconds: int | None = None
    next_sync_at: datetime | None = None
    config_version: int | None = None
    credential_available: bool = False
    checkpoint: ExternalIntelligenceCheckpointView | None = None
    latest_run: ExternalIntelligenceSyncRunView | None = None


class ExternalIntelligenceSyncRunList(StrictModel):
    items: list[ExternalIntelligenceSyncRunView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class ExternalIntelligencePullResult(StrictModel):
    run_id: UUID
    feed_id: str
    feed_version: str
    pages_fetched: int = Field(ge=1)
    records_fetched: int = Field(ge=0)
    bytes_fetched: int = Field(ge=1)
    batch_pages_fetched: int = Field(ge=1)
    batch_records_fetched: int = Field(ge=0)
    batch_bytes_fetched: int = Field(ge=1)
    created: int = Field(ge=0)
    updated: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    quarantined: int = Field(ge=0)
    active: int = Field(ge=0)
    revoked: int = Field(ge=0)
    deleted: int = Field(ge=0)
    correlation_jobs_queued: int = Field(default=0, ge=0)
    complete: bool
    next_cursor: Cursor | None = None
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_completion(self) -> ExternalIntelligencePullResult:
        if self.complete is (self.next_cursor is not None):
            raise ValueError("complete pulls must omit, and partial pulls must return, a cursor")
        if self.batch_records_fetched != self.active + self.revoked + self.deleted:
            raise ValueError("source status counts must equal batch_records_fetched")
        if self.batch_records_fetched != (
            self.created + self.updated + self.unchanged + self.quarantined
        ):
            raise ValueError("import outcome counts must equal batch_records_fetched")
        if self.batch_pages_fetched > self.pages_fetched:
            raise ValueError("batch_pages_fetched cannot exceed cumulative pages_fetched")
        if self.batch_records_fetched > self.records_fetched:
            raise ValueError("batch_records_fetched cannot exceed cumulative records_fetched")
        if self.batch_bytes_fetched > self.bytes_fetched:
            raise ValueError("batch_bytes_fetched cannot exceed cumulative bytes_fetched")
        return self


def parse_external_datapoint_page(
    payload: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_PAGE_BYTES,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> ExternalDatapointPageResult:
    """Parse one bounded page and retain its exact payload digest."""

    if isinstance(page_size, bool) or not 1 <= page_size <= 1_000:
        raise ValueError("page_size must be between 1 and 1000")
    decoded = decode_bounded_json(payload, max_bytes=max_bytes)
    try:
        page = ExternalDatapointPage.model_validate(decoded)
    except ValidationError as exc:
        raise InvalidIntelligencePayload(
            "External datapoint page failed schema validation"
        ) from exc
    if len(page.items) > page_size:
        raise InvalidIntelligencePayload(
            f"External API returned more than the requested {page_size} records"
        )
    return ExternalDatapointPageResult(
        page=page,
        raw_payload_sha256=sha256(payload).hexdigest(),
        raw_payload_bytes=len(payload),
    )


class ExternalDatapointProvider:
    """Fetch and optionally verify pages from one fixed, allowlisted endpoint."""

    def __init__(
        self,
        client: ExternalDatapointHttpClient,
        endpoint: str,
        *,
        token: str,
        auth_scheme: AuthScheme = "Bearer",
        allowed_hosts: Collection[str],
        page_size: int = DEFAULT_PAGE_SIZE,
        max_page_bytes: int = DEFAULT_MAX_PAGE_BYTES,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        trusted_signing_keys: Mapping[str, str] | None = None,
        require_signature: bool = False,
    ) -> None:
        self._client = client
        self._endpoint = validate_external_datapoint_endpoint(endpoint, allowed_hosts)
        self._token = _validate_token(token)
        if auth_scheme not in {"Bearer", "X-API-Key"}:
            raise ValueError("auth_scheme must be Bearer or X-API-Key")
        self._auth_scheme = auth_scheme
        if isinstance(page_size, bool) or not 1 <= page_size <= 1_000:
            raise ValueError("page_size must be between 1 and 1000")
        if isinstance(max_page_bytes, bool) or not 1_024 <= max_page_bytes <= 64 * 1024 * 1024:
            raise ValueError("max_page_bytes must be between 1024 and 67108864")
        if isinstance(timeout_seconds, bool) or not 0.1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 0.1 and 120")
        self._page_size = page_size
        self._max_page_bytes = max_page_bytes
        self._timeout_seconds = timeout_seconds
        self._trusted_signing_keys = _decode_signing_keys(trusted_signing_keys or {})
        self._require_signature = require_signature
        if require_signature and not self._trusted_signing_keys:
            raise ValueError("signature verification requires at least one trusted key")

    async def fetch_page(
        self,
        cursor: str | None = None,
        *,
        sync_token: str | None = None,
    ) -> ExternalDatapointPageResult:
        normalized_cursor = validate_cursor(cursor)
        normalized_sync_token = validate_cursor(sync_token)
        if normalized_cursor is not None and normalized_sync_token is not None:
            raise ValueError("cursor and sync_token cannot be supplied together")
        headers = {"Accept": "application/json"}
        if self._auth_scheme == "Bearer":
            headers["Authorization"] = f"Bearer {self._token}"
        else:
            headers["X-API-Key"] = self._token
        params = {"limit": str(self._page_size)}
        if normalized_cursor is not None:
            params["cursor"] = normalized_cursor
        elif normalized_sync_token is not None:
            params["sync_token"] = normalized_sync_token
        async with self._client.stream(
            "GET",
            self._endpoint,
            headers=headers,
            params=params,
            timeout=self._timeout_seconds,
            follow_redirects=False,
        ) as response:
            payload = await _read_bounded_json_stream(
                response,
                max_bytes=self._max_page_bytes,
            )
            response_headers = dict(response.headers)
        verified, key_id = _verify_response_signature(
            response_headers,
            payload,
            trusted_keys=self._trusted_signing_keys,
            required=self._require_signature,
        )
        result = parse_external_datapoint_page(
            payload,
            max_bytes=self._max_page_bytes,
            page_size=self._page_size,
        )
        return result.model_copy(
            update={"signature_verified": verified, "signing_key_id": key_id}
        )


def validate_cursor(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_CURSOR_LENGTH:
        raise ValueError(f"cursor must contain between 1 and {MAX_CURSOR_LENGTH} characters")
    if value != value.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError("cursor must not contain surrounding whitespace or control characters")
    return value


def validate_external_datapoint_endpoint(
    endpoint: str,
    allowed_hosts: Collection[str],
) -> str:
    parsed = urlsplit(endpoint)
    host = parsed.hostname.rstrip(".").casefold() if parsed.hostname else ""
    normalized_hosts = {item.rstrip(".").casefold() for item in allowed_hosts}
    if (
        parsed.scheme.casefold() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("external datapoint endpoint must be a credential-free HTTPS URL")
    if not normalized_hosts or any(not item or item == "*" for item in normalized_hosts):
        raise ValueError("external datapoint connector requires an explicit hostname allowlist")
    if host not in normalized_hosts:
        raise ValueError("external datapoint endpoint host is not allowlisted")
    return endpoint


def _decode_signing_keys(values: Mapping[str, str]) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for key_id, encoded in values.items():
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("trusted signing keys must use standard base64") from error
        if len(raw) != 32:
            raise ValueError("trusted Ed25519 public keys must contain 32 bytes")
        try:
            keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as error:
            raise ValueError("trusted signing key is not valid Ed25519 material") from error
    return keys


def _verify_response_signature(
    headers: Mapping[str, str],
    payload: bytes,
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    required: bool,
) -> tuple[bool, str | None]:
    content_digest = _header(headers, "x-traceless-content-sha256")
    key_id = _header(headers, "x-traceless-key-id")
    encoded_signature = _header(headers, "x-traceless-signature")
    supplied = (content_digest, key_id, encoded_signature)
    if all(value is None for value in supplied):
        if required:
            raise InvalidIntelligencePayload("External feed response is unsigned")
        return False, None
    if any(value is None for value in supplied):
        raise InvalidIntelligencePayload("External feed signature headers are incomplete")
    assert content_digest is not None
    assert key_id is not None
    assert encoded_signature is not None
    expected_digest = sha256(payload).hexdigest()
    if not hmac.compare_digest(content_digest.casefold(), expected_digest):
        raise InvalidIntelligencePayload("External feed content digest is invalid")
    key = trusted_keys.get(key_id)
    if key is None:
        raise InvalidIntelligencePayload("External feed signing key is not trusted")
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidIntelligencePayload("External feed signature is invalid base64") from error
    try:
        key.verify(signature, payload)
    except InvalidSignature as error:
        raise InvalidIntelligencePayload("External feed signature verification failed") from error
    return True, key_id


def _validate_token(token: str) -> str:
    if not isinstance(token, str) or not 16 <= len(token) <= 8_192:
        raise ValueError("external datapoint token must contain between 16 and 8192 characters")
    if token != token.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in token
    ):
        raise ValueError(
            "external datapoint token contains invalid whitespace or control characters"
        )
    return token


def _canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return sha256(payload).hexdigest()


async def _read_bounded_json_stream(
    response: ExternalDatapointStreamResponse,
    *,
    max_bytes: int,
) -> bytes:
    """Reject oversized metadata first, then stop reading at the byte quota.

    ``httpx.AsyncClient.get`` buffers the complete decoded response before a
    caller can inspect its size. The external connector instead consumes the
    response iterator and aborts as soon as the configured decoded-byte limit
    would be exceeded. This also bounds compressed responses whose declared
    wire length is small.
    """

    content_length = _header(response.headers, "content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise InvalidIntelligencePayload("Invalid Content-Length header") from exc
        if declared_length < 0:
            raise InvalidIntelligencePayload("Invalid Content-Length header")
        if declared_length > max_bytes:
            raise IntelligencePayloadTooLarge(
                f"Provider declares a payload above the {max_bytes}-byte limit"
            )

    response.raise_for_status()
    content_type = _header(response.headers, "content-type")
    if content_type is not None:
        media_type = content_type.partition(";")[0].strip().casefold()
        if not (media_type == "application/json" or media_type.endswith("+json")):
            raise UnexpectedContentType(f"Expected a JSON response, received {media_type}")

    chunks: list[bytes] = []
    received = 0
    async for chunk in response.aiter_bytes():
        if not chunk:
            continue
        received += len(chunk)
        if received > max_bytes:
            raise IntelligencePayloadTooLarge(
                f"Provider response exceeds the {max_bytes}-byte limit"
            )
        chunks.append(chunk)
    if received == 0:
        raise InvalidIntelligencePayload("Intelligence payload is empty")
    return b"".join(chunks)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    target = name.casefold()
    return next(
        (value for key, value in headers.items() if key.casefold() == target),
        None,
    )
