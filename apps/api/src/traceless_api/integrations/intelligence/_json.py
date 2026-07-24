"""Bounded JSON and HTTP-response validation shared by intelligence adapters."""

import json
from collections.abc import Mapping
from typing import Any

from traceless_api.integrations.intelligence.errors import (
    IntelligencePayloadTooLarge,
    InvalidIntelligencePayload,
    UnexpectedContentType,
)
from traceless_api.integrations.intelligence.protocols import HttpResponse


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidIntelligencePayload(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def decode_bounded_json(
    payload: bytes,
    *,
    max_bytes: int,
    max_depth: int = 32,
    max_nodes: int = 200_000,
) -> Any:
    """Decode UTF-8 JSON after enforcing byte, nesting, and node-count bounds."""

    if not payload:
        raise InvalidIntelligencePayload("Intelligence payload is empty")
    if len(payload) > max_bytes:
        raise IntelligencePayloadTooLarge(
            f"Intelligence payload exceeds the {max_bytes}-byte limit"
        )

    try:
        decoded = json.loads(
            payload.decode("utf-8-sig"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except InvalidIntelligencePayload:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InvalidIntelligencePayload("Intelligence payload is not valid UTF-8 JSON") from exc

    nodes_seen = 0
    stack: list[tuple[Any, int]] = [(decoded, 1)]
    while stack:
        value, depth = stack.pop()
        nodes_seen += 1
        if nodes_seen > max_nodes:
            raise InvalidIntelligencePayload(
                f"Intelligence payload exceeds the {max_nodes}-node limit"
            )
        if depth > max_depth:
            raise InvalidIntelligencePayload(
                f"Intelligence payload exceeds the {max_depth}-level nesting limit"
            )
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)

    return decoded


def _header(headers: Mapping[str, str], name: str) -> str | None:
    target = name.casefold()
    for key, value in headers.items():
        if key.casefold() == target:
            return value
    return None


def validated_json_response_body(response: HttpResponse, *, max_bytes: int) -> bytes:
    """Check status and explicit HTTP metadata before returning response bytes."""

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

    body = response.content
    if len(body) > max_bytes:
        raise IntelligencePayloadTooLarge(f"Provider response exceeds the {max_bytes}-byte limit")
    return body
