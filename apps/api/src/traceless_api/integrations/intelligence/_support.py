"""Small validation helpers shared by intelligence providers."""

from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from urllib.parse import urlsplit

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


def validate_retrieved_at(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Provider clock must return a timezone-aware datetime")
    return value


def validate_http_endpoint(value: str) -> str:
    """Apply baseline URL safety; deployment egress policy remains a higher layer."""

    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("Intelligence endpoint must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Intelligence endpoint must not contain credentials")
    if parsed.fragment:
        raise ValueError("Intelligence endpoint must not contain a fragment")
    return value


def digest_payload(payload: bytes) -> str:
    return sha256(payload).hexdigest()
