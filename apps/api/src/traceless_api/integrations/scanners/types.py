"""Shared, dependency-free scanner adapter types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Iterable

    from traceless_api.integrations.scanners.scope import (
        ScannerScope,
        TargetInput,
        ValidatedTargets,
    )

type IPAddress = IPv4Address | IPv6Address


class ScanProfile(StrEnum):
    """Reviewed scan behaviours exposed by the adapter layer."""

    discovery = "discovery"
    service_inventory = "service_inventory"


class HostState(StrEnum):
    up = "up"
    down = "down"
    unknown = "unknown"


class ScanCompleteness(StrEnum):
    """Whether an adapter can prove that its result represents the full run."""

    complete = "complete"
    partial = "partial"
    discovery = "discovery"


@dataclass(frozen=True, slots=True)
class AddressObservation:
    address: IPAddress


@dataclass(frozen=True, slots=True)
class HardwareAddressObservation:
    address: str
    vendor: str | None = None


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    port: int
    protocol: str
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    tunnel: str | None = None
    method: str | None = None
    confidence: int | None = None
    cpes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OperatingSystemObservation:
    name: str
    accuracy: int | None = None
    cpes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HostObservation:
    addresses: tuple[AddressObservation, ...]
    state: HostState
    hostnames: tuple[str, ...] = ()
    hardware_addresses: tuple[HardwareAddressObservation, ...] = ()
    services: tuple[ServiceObservation, ...] = ()
    operating_systems: tuple[OperatingSystemObservation, ...] = ()


@dataclass(frozen=True, slots=True)
class ScannerResult:
    scanner: str
    scanner_version: str | None
    hosts: tuple[HostObservation, ...]
    warnings: tuple[str, ...] = ()
    source_started_at: datetime | None = None
    source_completed_at: datetime | None = None
    completeness: ScanCompleteness = ScanCompleteness.partial


@dataclass(frozen=True, slots=True)
class ScannerCommand:
    """An argv vector intended for subprocess execution with ``shell=False``."""

    argv: tuple[str, ...]
    profile: ScanProfile
    targets: ValidatedTargets


@runtime_checkable
class ScannerCommandBuilder(Protocol):
    def build(
        self,
        *,
        profile: ScanProfile,
        targets: Iterable[TargetInput] | TargetInput,
        scope: ScannerScope,
    ) -> ScannerCommand: ...


@runtime_checkable
class ScannerOutputParser(Protocol):
    def parse(
        self,
        payload: str | bytes,
        *,
        targets: ValidatedTargets | None = None,
    ) -> ScannerResult: ...
