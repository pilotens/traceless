"""Bounded parser for Naabu's MIT-licensed JSONL output."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from traceless_api.integrations.scanners.scope import ValidatedTargets
from traceless_api.integrations.scanners.types import (
    AddressObservation,
    HostObservation,
    HostState,
    ScanCompleteness,
    ScannerOutputParser,
    ScannerResult,
    ServiceObservation,
)

MAX_NAABU_JSONL_BYTES = 16 * 1024 * 1024
MAX_NAABU_LINE_BYTES = 64 * 1024
MAX_NAABU_RECORDS = 100_000
MAX_NAABU_HOSTS = 4096
_PROTOCOLS = frozenset({"tcp", "udp"})
type IPAddress = IPv4Address | IPv6Address


class NaabuOutputError(ValueError):
    """Raised when Naabu JSONL is malformed, excessive, or outside scope."""


class NaabuJsonlParser:
    def parse(
        self,
        payload: str | bytes,
        *,
        targets: ValidatedTargets | None = None,
    ) -> ScannerResult:
        text = _decode_payload(payload)
        services_by_host: dict[IPAddress, dict[tuple[str, int], ServiceObservation]] = defaultdict(
            dict
        )
        hostnames_by_host: dict[IPAddress, set[str]] = defaultdict(set)
        record_count = 0
        source_times: list[datetime] = []

        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            record_count += 1
            if record_count > MAX_NAABU_RECORDS:
                raise NaabuOutputError(f"Naabu JSONL exceeds the {MAX_NAABU_RECORDS}-record limit")
            if len(line.encode("utf-8")) > MAX_NAABU_LINE_BYTES:
                raise NaabuOutputError(f"Naabu JSONL line {line_number} exceeds the size limit")
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise NaabuOutputError(f"Naabu JSONL line {line_number} is invalid JSON") from exc
            if not isinstance(record, dict):
                raise NaabuOutputError(f"Naabu JSONL line {line_number} must be an object")

            source_time = _parse_source_time(record.get("timestamp"))
            if source_time is not None:
                source_times.append(source_time)

            address = _parse_address(record, line_number=line_number)
            if targets is not None and not targets.contains(address):
                raise NaabuOutputError(
                    f"Naabu returned address {address} outside the validated targets"
                )
            if address not in services_by_host and len(services_by_host) >= MAX_NAABU_HOSTS:
                raise NaabuOutputError(f"Naabu JSONL exceeds the {MAX_NAABU_HOSTS}-host limit")

            service = _parse_service(record, line_number=line_number)
            services_by_host[address][(service.protocol, service.port)] = service
            hostname = _parse_hostname(record.get("host"), address=address)
            if hostname is not None:
                hostnames_by_host[address].add(hostname)

        hosts = tuple(
            HostObservation(
                addresses=(AddressObservation(address=address),),
                state=HostState.up,
                hostnames=tuple(sorted(hostnames_by_host[address])),
                services=tuple(
                    sorted(
                        services.values(),
                        key=lambda observation: (observation.protocol, observation.port),
                    )
                ),
            )
            for address, services in sorted(
                services_by_host.items(), key=lambda item: (item[0].version, int(item[0]))
            )
        )
        warnings = (
            "Naabu JSONL enumerates positive endpoints and is never a complete inventory snapshot.",
        )
        return ScannerResult(
            scanner="naabu",
            scanner_version=None,
            hosts=hosts,
            warnings=warnings,
            source_started_at=min(source_times) if source_times else None,
            source_completed_at=max(source_times) if source_times else None,
            completeness=ScanCompleteness.partial,
        )


def parse_naabu_jsonl(
    payload: str | bytes, *, targets: ValidatedTargets | None = None
) -> ScannerResult:
    """Parse bounded Naabu JSONL into normalized observations."""

    return NaabuJsonlParser().parse(payload, targets=targets)


def _decode_payload(payload: str | bytes) -> str:
    if not isinstance(payload, (str, bytes)):
        raise NaabuOutputError("Naabu JSONL must be text or bytes")
    if isinstance(payload, bytes):
        size = len(payload)
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NaabuOutputError("Naabu JSONL must be UTF-8") from exc
    else:
        try:
            size = len(payload.encode("utf-8"))
        except UnicodeError as exc:
            raise NaabuOutputError("Naabu JSONL must be UTF-8") from exc
        text = payload
    if size > MAX_NAABU_JSONL_BYTES:
        raise NaabuOutputError(f"Naabu JSONL exceeds the {MAX_NAABU_JSONL_BYTES}-byte limit")
    return text


def _parse_address(record: dict[str, Any], *, line_number: int) -> IPAddress:
    value = record.get("ip")
    if value is None:
        value = record.get("host")
    if not isinstance(value, str):
        raise NaabuOutputError(f"Naabu JSONL line {line_number} is missing an IP address")
    try:
        return ip_address(value)
    except ValueError as exc:
        raise NaabuOutputError(
            f"Naabu JSONL line {line_number} contains an invalid IP address"
        ) from exc


def _parse_service(record: dict[str, Any], *, line_number: int) -> ServiceObservation:
    port = record.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise NaabuOutputError(f"Naabu JSONL line {line_number} contains an invalid port")
    protocol = record.get("protocol", "tcp")
    if not isinstance(protocol, str) or protocol.lower() not in _PROTOCOLS:
        raise NaabuOutputError(f"Naabu JSONL line {line_number} contains an invalid protocol")
    tunnel = "tls" if record.get("tls") is True else None
    return ServiceObservation(
        port=port,
        protocol=protocol.lower(),
        state="open",
        tunnel=tunnel,
    )


def _parse_hostname(value: Any, *, address: IPAddress) -> str | None:
    if not isinstance(value, str) or value == str(address):
        return None
    cleaned = "".join(character for character in value.strip() if character.isprintable())[:253]
    return cleaned or None


def _parse_source_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value or len(value) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


assert isinstance(NaabuJsonlParser(), ScannerOutputParser)
