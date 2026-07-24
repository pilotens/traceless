"""Bounded JSON, hashing, clock and URL helpers for asset sources."""

import json
from collections.abc import Collection, Mapping
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import ip_address
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from traceless_api.integrations.asset_sources.errors import (
    AssetSourcePayloadTooLarge,
    InvalidAssetSourcePayload,
    InvalidAssetSourceUrl,
)
from traceless_api.integrations.asset_sources.protocols import HttpResponse


def utc_now() -> datetime:
    return datetime.now(UTC)


def validate_aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("asset-source clock must return a timezone-aware datetime")
    return value


def digest_payload(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def digest_canonical_json(value: Mapping[str, Any]) -> str:
    """Hash one decoded record deterministically without claiming original byte offsets."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return digest_payload(encoded)


def validate_netbox_base_url(
    value: str,
    *,
    allow_insecure_http: bool = False,
    allowed_hosts: Collection[str] | None = None,
) -> str:
    """Apply a local SSRF baseline without performing DNS resolution.

    Private address space remains valid because NetBox is commonly internal. The
    adapter additionally uses fixed paths, never follows pagination URLs, and
    disables redirects per request. Deployments should still enforce DNS pinning
    or egress policy and normally provide ``allowed_hosts``.
    """

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise InvalidAssetSourceUrl("NetBox base URL contains an invalid port") from exc

    allowed_schemes = {"https"}
    if allow_insecure_http:
        allowed_schemes.add("http")
    if parsed.scheme.casefold() not in allowed_schemes or parsed.hostname is None:
        message = "NetBox base URL must be an absolute HTTPS URL"
        if allow_insecure_http:
            message = "NetBox base URL must be an absolute HTTP(S) URL"
        raise InvalidAssetSourceUrl(message)
    if parsed.username is not None or parsed.password is not None:
        raise InvalidAssetSourceUrl("NetBox base URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise InvalidAssetSourceUrl("NetBox base URL must not contain a query or fragment")

    host = parsed.hostname.rstrip(".").casefold()
    if not host or host == "localhost" or host.endswith(".localhost") or "%" in host:
        raise InvalidAssetSourceUrl("NetBox base URL uses a forbidden host")
    try:
        literal_address = ip_address(host)
    except ValueError:
        literal_address = None
    if literal_address is not None and (
        literal_address.is_loopback
        or literal_address.is_link_local
        or literal_address.is_multicast
        or literal_address.is_unspecified
        or literal_address.is_reserved
    ):
        raise InvalidAssetSourceUrl("NetBox base URL uses a forbidden IP range")

    if allowed_hosts is not None:
        normalized_hosts = {candidate.rstrip(".").casefold() for candidate in allowed_hosts}
        if host not in normalized_hosts:
            raise InvalidAssetSourceUrl("NetBox host is not in the connector allowlist")

    decoded_path = unquote(parsed.path)
    if any(part == ".." for part in decoded_path.split("/")):
        raise InvalidAssetSourceUrl("NetBox base URL must not contain path traversal")
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = f"{path}/"

    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if port is not None:
        netloc = f"{hostname}:{port}"
    return urlunsplit((parsed.scheme.casefold(), netloc, path, "", ""))


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidAssetSourcePayload(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def decode_bounded_json(
    payload: bytes,
    *,
    max_bytes: int,
    max_depth: int = 32,
    max_nodes: int = 250_000,
) -> Any:
    if not payload:
        raise InvalidAssetSourcePayload("NetBox response is empty")
    if len(payload) > max_bytes:
        raise AssetSourcePayloadTooLarge(f"NetBox response exceeds the {max_bytes}-byte page limit")
    try:
        decoded = json.loads(
            payload.decode("utf-8-sig"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                InvalidAssetSourcePayload(f"non-finite JSON number: {value}")
            ),
        )
    except InvalidAssetSourcePayload:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InvalidAssetSourcePayload("NetBox response is not valid UTF-8 JSON") from exc

    nodes_seen = 0
    stack: list[tuple[Any, int]] = [(decoded, 1)]
    while stack:
        item, depth = stack.pop()
        nodes_seen += 1
        if nodes_seen > max_nodes:
            raise AssetSourcePayloadTooLarge(
                f"NetBox response exceeds the {max_nodes}-node structural limit"
            )
        if depth > max_depth:
            raise AssetSourcePayloadTooLarge(
                f"NetBox response exceeds the {max_depth}-level nesting limit"
            )
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return decoded


def _header(headers: Mapping[str, str], name: str) -> str | None:
    target = name.casefold()
    for key, value in headers.items():
        if key.casefold() == target:
            return value
    return None


def validated_json_response_body(response: HttpResponse, *, max_bytes: int) -> bytes:
    content_length = _header(response.headers, "content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise InvalidAssetSourcePayload("invalid Content-Length header") from exc
        if declared_length < 0:
            raise InvalidAssetSourcePayload("invalid Content-Length header")
        if declared_length > max_bytes:
            raise AssetSourcePayloadTooLarge(
                f"NetBox declares a response above the {max_bytes}-byte page limit"
            )

    content_type = _header(response.headers, "content-type")
    if content_type is not None:
        media_type = content_type.partition(";")[0].strip().casefold()
        if not (media_type == "application/json" or media_type.endswith("+json")):
            raise InvalidAssetSourcePayload(f"expected JSON, received {media_type}")

    body = response.content
    if len(body) > max_bytes:
        raise AssetSourcePayloadTooLarge(f"NetBox response exceeds the {max_bytes}-byte page limit")
    return body
