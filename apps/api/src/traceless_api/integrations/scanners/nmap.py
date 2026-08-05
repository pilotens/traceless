"""Safe Nmap command construction and XML normalization.

Nmap is intentionally not bundled or executed here. Deployments provide their own
licensed Nmap binary and execute :class:`ScannerCommand` with ``shell=False``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from ipaddress import ip_address
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree as DefusedElementTree
from defusedxml.common import DefusedXmlException

from traceless_api.integrations.scanners.scope import (
    ScannerScope,
    TargetInput,
    ValidatedTargets,
)
from traceless_api.integrations.scanners.types import (
    AddressObservation,
    HardwareAddressObservation,
    HostObservation,
    HostState,
    OperatingSystemObservation,
    ScanCompleteness,
    ScannerCommand,
    ScannerCommandBuilder,
    ScannerOutputParser,
    ScannerResult,
    ScanProfile,
    ServiceObservation,
)

MAX_NMAP_XML_BYTES = 16 * 1024 * 1024
MAX_PARSED_HOSTS = 4096
MAX_ADDRESSES_PER_HOST = 64
MAX_HOSTNAMES_PER_HOST = 256
MAX_PORTS_PER_HOST = 8192
MAX_OS_MATCHES_PER_HOST = 32
MAX_CPES_PER_OBSERVATION = 64
MAX_TEXT_LENGTH = 500
_MAC_ADDRESS = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_TRANSPORT_PROTOCOLS = frozenset({"tcp", "udp", "sctp"})


class NmapOutputError(ValueError):
    """Raised when Nmap output is unsafe, malformed, or outside the job scope."""


class NmapCommandBuilder:
    """Build one of the two reviewed, non-privileged Nmap command profiles."""

    _COMMON_ARGUMENTS = (
        "-n",
        "-T3",
        "--max-retries",
        "2",
        "--max-rate",
        "100",
        "--max-parallelism",
        "10",
        "--reason",
        "-oX",
        "-",
    )
    _PROFILE_ARGUMENTS = {
        ScanProfile.discovery: ("-sn", "--host-timeout", "30s"),
        ScanProfile.service_inventory: (
            "-sT",
            "-sV",
            "--version-light",
            "--top-ports",
            "1000",
            "--host-timeout",
            "5m",
        ),
    }

    def build(
        self,
        *,
        profile: ScanProfile,
        targets: Iterable[TargetInput] | TargetInput,
        scope: ScannerScope,
    ) -> ScannerCommand:
        try:
            normalized_profile = ScanProfile(profile)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported Nmap scan profile: {profile!r}") from exc
        validated = scope.validate_targets(targets)
        argv = (
            "nmap",
            *self._COMMON_ARGUMENTS,
            *self._PROFILE_ARGUMENTS[normalized_profile],
            *validated.argv,
        )
        return ScannerCommand(argv=argv, profile=normalized_profile, targets=validated)


class NmapXmlParser:
    def parse(
        self,
        payload: str | bytes,
        *,
        targets: ValidatedTargets | None = None,
    ) -> ScannerResult:
        xml_payload = _bounded_payload(payload)
        try:
            root = DefusedElementTree.fromstring(
                xml_payload,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
        except (DefusedXmlException, ParseError, UnicodeError, ValueError) as exc:
            raise NmapOutputError(
                "Nmap XML is malformed or contains forbidden XML features"
            ) from exc

        if root.tag != "nmaprun" or root.get("scanner") != "nmap":
            raise NmapOutputError("Nmap XML must be an nmaprun document produced by Nmap")

        finished = root.find("./runstats/finished")
        if finished is not None and finished.get("exit") == "error":
            message = _clean(finished.get("errormsg"), limit=200) or "unknown scanner error"
            raise NmapOutputError(f"Nmap reported an error: {message}")

        hosts: list[HostObservation] = []
        observed_addresses = set()
        host_limit = (
            min(MAX_PARSED_HOSTS, targets.host_count) if targets is not None else MAX_PARSED_HOSTS
        )
        for element in root:
            if element.tag != "host":
                continue
            if len(hosts) >= host_limit:
                raise NmapOutputError(f"Nmap XML exceeds the {host_limit}-host limit")
            host = _parse_host(element, targets=targets)
            for observation in host.addresses:
                if observation.address in observed_addresses:
                    raise NmapOutputError(
                        f"Nmap returned duplicate host address {observation.address}"
                    )
                observed_addresses.add(observation.address)
            hosts.append(host)

        source_started_at = _epoch_datetime(root.get("start"))
        source_completed_at = (
            _epoch_datetime(finished.get("time")) if finished is not None else None
        )
        complete = finished is not None and finished.get("exit") == "success"
        warnings = (
            ()
            if complete
            else ("Nmap output lacks a successful run completion marker.",)
        )
        return ScannerResult(
            scanner="nmap",
            scanner_version=_clean(root.get("version"), limit=50),
            hosts=tuple(hosts),
            warnings=warnings,
            source_started_at=source_started_at,
            source_completed_at=source_completed_at,
            completeness=(
                ScanCompleteness.complete if complete else ScanCompleteness.partial
            ),
        )


def build_nmap_command(
    *,
    profile: ScanProfile,
    targets: Iterable[TargetInput] | TargetInput,
    scope: ScannerScope,
) -> ScannerCommand:
    """Build a reviewed Nmap command without accepting caller-supplied flags."""

    return NmapCommandBuilder().build(profile=profile, targets=targets, scope=scope)


def parse_nmap_xml(
    payload: str | bytes, *, targets: ValidatedTargets | None = None
) -> ScannerResult:
    """Parse bounded, entity-free Nmap XML into normalized observations."""

    return NmapXmlParser().parse(payload, targets=targets)


def _bounded_payload(payload: str | bytes) -> str | bytes:
    if not isinstance(payload, (str, bytes)):
        raise NmapOutputError("Nmap XML must be text or bytes")
    try:
        size = len(payload) if isinstance(payload, bytes) else len(payload.encode("utf-8"))
    except UnicodeError as exc:
        raise NmapOutputError("Nmap XML is not valid UTF-8 text") from exc
    if size > MAX_NMAP_XML_BYTES:
        raise NmapOutputError(f"Nmap XML exceeds the {MAX_NMAP_XML_BYTES}-byte limit")
    return payload


def _clean(value: str | None, *, limit: int = MAX_TEXT_LENGTH) -> str | None:
    if value is None:
        return None
    cleaned = "".join(character for character in value.strip() if character.isprintable())
    return cleaned[:limit] or None


def _bounded_int(value: str | None, *, minimum: int, maximum: int) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if minimum <= parsed <= maximum else None


def _epoch_datetime(value: str | None) -> datetime | None:
    parsed = _bounded_int(value, minimum=0, maximum=253_402_300_799)
    if parsed is None:
        return None
    try:
        return datetime.fromtimestamp(parsed, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _parse_host(element: Element, *, targets: ValidatedTargets | None) -> HostObservation:
    addresses: list[AddressObservation] = []
    hardware_addresses: list[HardwareAddressObservation] = []
    for index, address_element in enumerate(element.findall("address")):
        if index >= MAX_ADDRESSES_PER_HOST:
            raise NmapOutputError(f"Nmap host exceeds the {MAX_ADDRESSES_PER_HOST}-address limit")
        value = address_element.get("addr")
        address_type = address_element.get("addrtype")
        if not value:
            continue
        if address_type in {"ipv4", "ipv6"}:
            try:
                parsed_address = ip_address(value)
            except ValueError as exc:
                raise NmapOutputError(f"Nmap returned an invalid IP address: {value!r}") from exc
            if parsed_address.version != (4 if address_type == "ipv4" else 6):
                raise NmapOutputError("Nmap address type does not match the returned IP address")
            if targets is not None and not targets.contains(parsed_address):
                raise NmapOutputError(
                    f"Nmap returned address {parsed_address} outside the validated targets"
                )
            observation = AddressObservation(address=parsed_address)
            if observation not in addresses:
                addresses.append(observation)
        elif address_type == "mac":
            if not _MAC_ADDRESS.fullmatch(value):
                raise NmapOutputError("Nmap returned an invalid MAC address")
            observation = HardwareAddressObservation(
                address=value.lower(),
                vendor=_clean(address_element.get("vendor"), limit=200),
            )
            if observation not in hardware_addresses:
                hardware_addresses.append(observation)

    if not addresses:
        raise NmapOutputError("Nmap host is missing a valid IP address")

    status_element = element.find("status")
    state_value = status_element.get("state") if status_element is not None else None
    try:
        state = HostState(state_value)
    except (TypeError, ValueError):
        state = HostState.unknown

    hostname_values: list[str] = []
    for index, hostname_element in enumerate(element.findall("./hostnames/hostname")):
        if index >= MAX_HOSTNAMES_PER_HOST:
            raise NmapOutputError(f"Nmap host exceeds the {MAX_HOSTNAMES_PER_HOST}-hostname limit")
        hostname = _clean(hostname_element.get("name"), limit=253)
        if hostname is not None and hostname not in hostname_values:
            hostname_values.append(hostname)
    hostnames = tuple(hostname_values)

    ports_parent = element.find("ports")
    services: list[ServiceObservation] = []
    if ports_parent is not None:
        for index, port_element in enumerate(ports_parent.findall("port")):
            if index >= MAX_PORTS_PER_HOST:
                raise NmapOutputError(
                    f"Nmap host exceeds the {MAX_PORTS_PER_HOST}-port result limit"
                )
            service = _parse_service(port_element)
            if service is not None:
                services.append(service)

    operating_systems: list[OperatingSystemObservation] = []
    for index, os_match in enumerate(element.findall("./os/osmatch")):
        if index >= MAX_OS_MATCHES_PER_HOST:
            raise NmapOutputError(
                f"Nmap host exceeds the {MAX_OS_MATCHES_PER_HOST}-OS result limit"
            )
        name = _clean(os_match.get("name"), limit=300)
        if name is None:
            continue
        cpes = _parse_cpes(os_match.findall("./osclass/cpe"))
        operating_systems.append(
            OperatingSystemObservation(
                name=name,
                accuracy=_bounded_int(os_match.get("accuracy"), minimum=0, maximum=100),
                cpes=cpes,
            )
        )

    return HostObservation(
        addresses=tuple(addresses),
        state=state,
        hostnames=hostnames,
        hardware_addresses=tuple(hardware_addresses),
        services=tuple(sorted(services, key=lambda item: (item.protocol, item.port))),
        operating_systems=tuple(operating_systems),
    )


def _parse_service(port_element: Element) -> ServiceObservation | None:
    port = _bounded_int(port_element.get("portid"), minimum=1, maximum=65_535)
    protocol = port_element.get("protocol")
    if port is None or protocol not in _TRANSPORT_PROTOCOLS:
        return None

    state_element = port_element.find("state")
    state = _clean(state_element.get("state"), limit=30) if state_element is not None else None
    service_element = port_element.find("service")
    if service_element is None:
        return ServiceObservation(port=port, protocol=protocol, state=state or "unknown")

    return ServiceObservation(
        port=port,
        protocol=protocol,
        state=state or "unknown",
        name=_clean(service_element.get("name"), limit=100),
        product=_clean(service_element.get("product"), limit=200),
        version=_clean(service_element.get("version"), limit=100),
        extra_info=_clean(service_element.get("extrainfo"), limit=300),
        tunnel=_clean(service_element.get("tunnel"), limit=30),
        method=_clean(service_element.get("method"), limit=30),
        confidence=_bounded_int(service_element.get("conf"), minimum=0, maximum=10),
        cpes=_parse_cpes(service_element.findall("cpe")),
    )


def _parse_cpes(elements: list[Element]) -> tuple[str, ...]:
    cpes: list[str] = []
    for index, element in enumerate(elements):
        if index >= MAX_CPES_PER_OBSERVATION:
            raise NmapOutputError(
                f"Nmap observation exceeds the {MAX_CPES_PER_OBSERVATION}-CPE limit"
            )
        value = _clean(element.text, limit=300)
        if value is not None and value.startswith(("cpe:/", "cpe:2.3:")) and value not in cpes:
            cpes.append(value)
    return tuple(cpes)


assert isinstance(NmapCommandBuilder(), ScannerCommandBuilder)
assert isinstance(NmapXmlParser(), ScannerOutputParser)
