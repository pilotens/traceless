"""Typed, source-preserving contracts for inventory connectors.

These models intentionally represent unreviewed source observations. They are not
approved Traceless architecture components and must pass a separate review and
reconciliation workflow before they can influence an approved model.
"""

from decimal import Decimal
from enum import StrEnum
from ipaddress import IPv4Interface, IPv4Network, IPv6Interface, IPv6Network
from typing import Annotated, Literal, Self

from pydantic import (
    AnyHttpUrl,
    AwareDatetime,
    Field,
    StringConstraints,
    model_validator,
)

from traceless_api.models.common import StrictModel

ProviderName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9._-]*$"),
]
ExternalId = Annotated[str, StringConstraints(min_length=1, max_length=200)]
DisplayName = Annotated[str, StringConstraints(min_length=1, max_length=500)]
SourceObjectType = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=100,
        pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$",
    ),
]
EndpointPath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300, pattern=r"^api/[a-z0-9_/-]+/$"),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
TagName = Annotated[str, StringConstraints(min_length=1, max_length=200)]

type IPAddressWithPrefix = IPv4Interface | IPv6Interface
type IPPrefix = IPv4Network | IPv6Network


class AssetKind(StrEnum):
    device = "device"
    virtual_machine = "virtual_machine"
    interface = "interface"
    ip_address = "ip_address"
    prefix = "prefix"
    vlan = "vlan"


class InterfaceKind(StrEnum):
    physical = "physical"
    virtual = "virtual"


class SourceObjectRef(StrictModel):
    """Stable reference to another object in the same external source."""

    object_type: SourceObjectType
    external_id: ExternalId
    display_name: DisplayName


class SourceRecordProvenance(StrictModel):
    """Lineage retained for one normalized source object."""

    provider: ProviderName
    source_base_url: AnyHttpUrl
    source_endpoint: EndpointPath
    source_object_type: SourceObjectType
    source_external_id: ExternalId
    source_record_url: AnyHttpUrl
    source_updated_at: AwareDatetime | None = None
    retrieved_at: AwareDatetime
    raw_record_sha256: Sha256 = Field(
        description="SHA-256 over the canonical JSON representation of the raw source record."
    )


class SourcePageProvenance(StrictModel):
    """Lineage for one exact HTTP response body in a paginated snapshot."""

    provider: ProviderName
    source_base_url: AnyHttpUrl
    source_endpoint: EndpointPath
    page_number: Annotated[int, Field(ge=1)]
    offset: Annotated[int, Field(ge=0)]
    declared_count: Annotated[int, Field(ge=0)] | None = None
    record_count: Annotated[int, Field(ge=0)]
    retrieved_at: AwareDatetime
    raw_payload_sha256: Sha256 = Field(
        description="SHA-256 over the exact response bytes before JSON decoding."
    )


class SourceAssetRecord(StrictModel):
    """Common fields for an unreviewed normalized source observation."""

    kind: AssetKind
    external_id: ExternalId
    display_name: DisplayName
    status: Annotated[str, StringConstraints(min_length=1, max_length=100)] | None = None
    description: Annotated[str, StringConstraints(max_length=10_000)] = ""
    tags: tuple[TagName, ...] = Field(default_factory=tuple, max_length=500)
    source_only: Literal[True] = True
    provenance: SourceRecordProvenance

    @model_validator(mode="after")
    def provenance_identifies_record(self) -> Self:
        if self.provenance.source_external_id != self.external_id:
            raise ValueError("record provenance must identify the external record")
        return self


class NetBoxDeviceRecord(SourceAssetRecord):
    kind: Literal[AssetKind.device] = AssetKind.device
    name: DisplayName
    serial: Annotated[str, StringConstraints(max_length=500)] = ""
    asset_tag: Annotated[str, StringConstraints(max_length=500)] | None = None
    role: SourceObjectRef | None = None
    device_type: SourceObjectRef | None = None
    site: SourceObjectRef | None = None
    location: SourceObjectRef | None = None
    platform: SourceObjectRef | None = None
    tenant: SourceObjectRef | None = None
    cluster: SourceObjectRef | None = None
    primary_ipv4: IPAddressWithPrefix | None = None
    primary_ipv6: IPAddressWithPrefix | None = None


class NetBoxVirtualMachineRecord(SourceAssetRecord):
    kind: Literal[AssetKind.virtual_machine] = AssetKind.virtual_machine
    name: DisplayName
    role: SourceObjectRef | None = None
    cluster: SourceObjectRef | None = None
    site: SourceObjectRef | None = None
    device: SourceObjectRef | None = None
    platform: SourceObjectRef | None = None
    tenant: SourceObjectRef | None = None
    vcpus: Annotated[Decimal, Field(ge=0, le=1_000_000)] | None = None
    memory_mb: Annotated[int, Field(ge=0, le=2**53)] | None = None
    disk_gb: Annotated[Decimal, Field(ge=0, le=2**53)] | None = None
    primary_ipv4: IPAddressWithPrefix | None = None
    primary_ipv6: IPAddressWithPrefix | None = None


class NetBoxInterfaceRecord(SourceAssetRecord):
    kind: Literal[AssetKind.interface] = AssetKind.interface
    interface_kind: InterfaceKind
    name: DisplayName
    owner: SourceObjectRef
    interface_type: Annotated[str, StringConstraints(min_length=1, max_length=100)] | None = None
    enabled: bool | None = None
    mac_address: (
        Annotated[
            str,
            StringConstraints(pattern=r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"),
        ]
        | None
    ) = None
    mtu: Annotated[int, Field(ge=0, le=1_000_000)] | None = None
    mode: Annotated[str, StringConstraints(min_length=1, max_length=100)] | None = None
    parent_interface: SourceObjectRef | None = None
    bridge: SourceObjectRef | None = None
    lag: SourceObjectRef | None = None
    untagged_vlan: SourceObjectRef | None = None
    tagged_vlans: tuple[SourceObjectRef, ...] = Field(default_factory=tuple, max_length=4094)


class NetBoxIpAddressRecord(SourceAssetRecord):
    kind: Literal[AssetKind.ip_address] = AssetKind.ip_address
    address: IPAddressWithPrefix
    dns_name: Annotated[str, StringConstraints(max_length=253)] = ""
    role: Annotated[str, StringConstraints(min_length=1, max_length=100)] | None = None
    assigned_object: SourceObjectRef | None = None
    vrf: SourceObjectRef | None = None
    tenant: SourceObjectRef | None = None


class NetBoxPrefixRecord(SourceAssetRecord):
    kind: Literal[AssetKind.prefix] = AssetKind.prefix
    prefix: IPPrefix
    role: SourceObjectRef | None = None
    vrf: SourceObjectRef | None = None
    tenant: SourceObjectRef | None = None
    vlan: SourceObjectRef | None = None
    scope: SourceObjectRef | None = None
    is_pool: bool | None = None
    mark_utilized: bool | None = None


class NetBoxVlanRecord(SourceAssetRecord):
    kind: Literal[AssetKind.vlan] = AssetKind.vlan
    vid: Annotated[int, Field(ge=1, le=4094)]
    name: DisplayName
    role: SourceObjectRef | None = None
    group: SourceObjectRef | None = None
    site: SourceObjectRef | None = None
    tenant: SourceObjectRef | None = None


type NetBoxAssetRecord = Annotated[
    NetBoxDeviceRecord
    | NetBoxVirtualMachineRecord
    | NetBoxInterfaceRecord
    | NetBoxIpAddressRecord
    | NetBoxPrefixRecord
    | NetBoxVlanRecord,
    Field(discriminator="kind"),
]


class AssetSourceSnapshot[RecordT](StrictModel):
    """Complete, bounded and immutable-by-convention source-only snapshot."""

    provider: ProviderName
    source_base_url: AnyHttpUrl
    started_at: AwareDatetime
    completed_at: AwareDatetime
    records: tuple[RecordT, ...] = Field(max_length=100_000)
    pages: tuple[SourcePageProvenance, ...] = Field(max_length=10_000)
    manifest_sha256: Sha256 = Field(
        description="SHA-256 over the ordered endpoint/page/raw-payload hash manifest."
    )
    approval_state: Literal["unreviewed_source_snapshot"] = "unreviewed_source_snapshot"
    complete: Literal[True] = True

    @model_validator(mode="after")
    def timestamps_are_ordered(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("snapshot completion cannot precede its start")
        return self
