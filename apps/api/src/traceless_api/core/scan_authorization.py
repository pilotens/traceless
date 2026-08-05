"""Time-limited scan authorization helpers."""

import hashlib
import json
from datetime import UTC, datetime, timedelta


class InvalidScanAuthorizationError(ValueError):
    pass


def validate_authorization_window(expires_at: datetime) -> None:
    now = datetime.now(UTC)
    if expires_at <= now:
        raise InvalidScanAuthorizationError("Authorization must expire in the future")
    if expires_at > now + timedelta(hours=24):
        raise InvalidScanAuthorizationError("Authorization may be valid for at most 24 hours")


def scope_sha256(targets: list[str], profile: str, expires_at: datetime) -> str:
    canonical = json.dumps(
        {
            "targets": targets,
            "profile": profile,
            "expires_at": expires_at.astimezone(UTC).isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()
