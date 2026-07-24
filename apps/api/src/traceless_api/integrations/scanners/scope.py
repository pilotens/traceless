"""Strict IP/CIDR scope validation for scanner jobs."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    collapse_addresses,
    ip_address,
    ip_network,
)

from traceless_api.integrations.scanners.types import ScannerResult

type IPAddress = IPv4Address | IPv6Address
type IPNetwork = IPv4Network | IPv6Network
type TargetInput = str | IPAddress | IPNetwork

DEFAULT_MAX_TARGET_HOSTS = 256
ABSOLUTE_MAX_TARGET_HOSTS = 65_536
MAX_SCOPE_ENTRIES = 256


class ScopeValidationError(ValueError):
    """Raised when requested targets violate the approved scanner scope."""


_INTERNAL_RANGES: tuple[IPNetwork, ...] = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("100.64.0.0/10"),
    IPv6Network("fc00::/7"),
)

# These ranges must never be scanned by this adapter, even when they occur inside an
# otherwise approved range or public targets have received separate approval.
_FORBIDDEN_RANGES: tuple[IPNetwork, ...] = (
    IPv4Network("0.0.0.0/8"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("169.254.0.0/16"),
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.18.0.0/15"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("240.0.0.0/4"),
    IPv4Network("100.100.100.200/32"),
    IPv6Network("::/128"),
    IPv6Network("::1/128"),
    IPv6Network("2001:db8::/32"),
    IPv6Network("fe80::/10"),
    IPv6Network("ff00::/8"),
    IPv6Network("fd00:ec2::254/128"),
)


def _as_network(value: TargetInput, *, field_name: str) -> IPNetwork:
    if isinstance(value, (IPv4Network, IPv6Network)):
        return value
    if isinstance(value, (IPv4Address, IPv6Address)):
        return ip_network(f"{value}/{value.max_prefixlen}")
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ScopeValidationError(f"{field_name} must be an IP address or canonical CIDR")
    if value != value.strip():
        raise ScopeValidationError(f"{field_name} must not contain surrounding whitespace")
    try:
        if "/" in value:
            return ip_network(value, strict=True)
        address = ip_address(value)
        return ip_network(f"{address}/{address.max_prefixlen}")
    except ValueError as exc:
        raise ScopeValidationError(f"{field_name} must be an IP address or canonical CIDR") from exc


def _same_family(left: IPNetwork, right: IPNetwork) -> bool:
    return left.version == right.version


def _is_internal(network: IPNetwork) -> bool:
    return any(
        _same_family(network, internal) and network.subnet_of(internal)
        for internal in _INTERNAL_RANGES
    )


def _is_entirely_global(network: IPNetwork) -> bool:
    return network.network_address.is_global and network.broadcast_address.is_global


def _forbidden_overlap(network: IPNetwork) -> IPNetwork | None:
    return next(
        (
            blocked
            for blocked in _FORBIDDEN_RANGES
            if _same_family(network, blocked) and network.overlaps(blocked)
        ),
        None,
    )


def _collapse(networks: Iterable[IPNetwork]) -> tuple[IPNetwork, ...]:
    ipv4 = [network for network in networks if isinstance(network, IPv4Network)]
    ipv6 = [network for network in networks if isinstance(network, IPv6Network)]
    collapsed = [*collapse_addresses(ipv4), *collapse_addresses(ipv6)]
    return tuple(
        sorted(
            collapsed,
            key=lambda network: (network.version, int(network.network_address), network.prefixlen),
        )
    )


def _parse_entries(
    values: Iterable[TargetInput] | TargetInput, *, field_name: str
) -> tuple[IPNetwork, ...]:
    if isinstance(
        values,
        (str, IPv4Address, IPv6Address, IPv4Network, IPv6Network),
    ):
        entries: Iterable[TargetInput] = (values,)
    else:
        try:
            entries = iter(values)
        except TypeError as exc:
            raise ScopeValidationError(
                f"{field_name} must be an IP address, CIDR, or iterable of them"
            ) from exc

    parsed: list[IPNetwork] = []
    for value in entries:
        if len(parsed) >= MAX_SCOPE_ENTRIES:
            raise ScopeValidationError(f"{field_name} cannot exceed {MAX_SCOPE_ENTRIES} entries")
        parsed.append(_as_network(value, field_name=field_name))
    return tuple(parsed)


@dataclass(frozen=True, slots=True)
class ValidatedTargets:
    """Canonical, de-duplicated networks produced only after scope validation."""

    networks: tuple[IPNetwork, ...]
    host_count: int

    def __post_init__(self) -> None:
        if not self.networks:
            raise ScopeValidationError("at least one target is required")
        if any(not isinstance(network, (IPv4Network, IPv6Network)) for network in self.networks):
            raise ScopeValidationError("validated targets must contain IP networks")
        canonical = _collapse(self.networks)
        if self.networks != canonical:
            raise ScopeValidationError("validated targets must be canonical and de-duplicated")
        expected_count = sum(network.num_addresses for network in canonical)
        if self.host_count != expected_count:
            raise ScopeValidationError("target host count does not match the canonical targets")
        if self.host_count > ABSOLUTE_MAX_TARGET_HOSTS:
            raise ScopeValidationError(
                f"validated targets cannot exceed {ABSOLUTE_MAX_TARGET_HOSTS} addresses"
            )

    @property
    def argv(self) -> tuple[str, ...]:
        return tuple(str(network) for network in self.networks)

    def contains(self, address: IPAddress) -> bool:
        return any(
            address.version == network.version and address in network for network in self.networks
        )


@dataclass(frozen=True, slots=True)
class ScannerScope:
    """An approved scope and the per-job safety policy applied to it."""

    approved_networks: tuple[IPNetwork, ...]
    allow_public_targets: bool = False
    max_hosts: int = DEFAULT_MAX_TARGET_HOSTS

    def __post_init__(self) -> None:
        if not self.approved_networks:
            raise ScopeValidationError("at least one approved scope is required")
        if len(self.approved_networks) > MAX_SCOPE_ENTRIES:
            raise ScopeValidationError(f"approved scope cannot exceed {MAX_SCOPE_ENTRIES} entries")
        if any(
            not isinstance(network, (IPv4Network, IPv6Network))
            for network in self.approved_networks
        ):
            raise ScopeValidationError("approved scope must contain IP networks")
        if not 1 <= self.max_hosts <= ABSOLUTE_MAX_TARGET_HOSTS:
            raise ScopeValidationError(
                f"max_hosts must be between 1 and {ABSOLUTE_MAX_TARGET_HOSTS}"
            )

    @classmethod
    def from_strings(
        cls,
        approved_networks: Iterable[TargetInput] | TargetInput,
        *,
        allow_public_targets: bool = False,
        max_hosts: int = DEFAULT_MAX_TARGET_HOSTS,
    ) -> ScannerScope:
        parsed = _parse_entries(approved_networks, field_name="approved scope")
        return cls(
            approved_networks=_collapse(parsed),
            allow_public_targets=allow_public_targets,
            max_hosts=max_hosts,
        )

    def validate_targets(self, targets: Iterable[TargetInput] | TargetInput) -> ValidatedTargets:
        requested = _parse_entries(targets, field_name="target")
        if not requested:
            raise ScopeValidationError("at least one target is required")

        for target in requested:
            if not any(
                _same_family(target, approved) and target.subnet_of(approved)
                for approved in self.approved_networks
            ):
                raise ScopeValidationError(f"target {target} is outside the approved scope")

            blocked = _forbidden_overlap(target)
            if blocked is not None:
                raise ScopeValidationError(
                    f"target {target} overlaps the forbidden range {blocked}"
                )

            if not _is_internal(target):
                if not _is_entirely_global(target):
                    raise ScopeValidationError(
                        f"target {target} is not an allowed internal or globally routable range"
                    )
                if not self.allow_public_targets:
                    raise ScopeValidationError(
                        f"public target {target} requires separate explicit approval"
                    )

        canonical = _collapse(requested)
        host_count = sum(network.num_addresses for network in canonical)
        if host_count > self.max_hosts:
            raise ScopeValidationError(
                f"target set contains {host_count} addresses; maximum is {self.max_hosts}"
            )
        return ValidatedTargets(networks=canonical, host_count=host_count)


def normalize_scope(
    approved_networks: Iterable[TargetInput] | TargetInput,
    *,
    allow_public_targets: bool = False,
    max_hosts: int = DEFAULT_MAX_TARGET_HOSTS,
) -> ScannerScope:
    """Create a canonical scope object suitable for a signed scanner job."""

    return ScannerScope.from_strings(
        approved_networks,
        allow_public_targets=allow_public_targets,
        max_hosts=max_hosts,
    )


def validate_targets(
    scope: ScannerScope, targets: Iterable[TargetInput] | TargetInput
) -> ValidatedTargets:
    """Validate and canonicalize requested targets against an approved scope."""

    return scope.validate_targets(targets)


def validate_observations(result: ScannerResult, *, targets: ValidatedTargets) -> ScannerResult:
    """Reject normalized observations whose IP addresses escaped the job target set."""

    for host in result.hosts:
        if not host.addresses:
            raise ScopeValidationError("scanner observation is missing an IP address")
        for observation in host.addresses:
            if not targets.contains(observation.address):
                raise ScopeValidationError(
                    f"scanner observation {observation.address} is outside the validated targets"
                )
    return result
