"""Read-only asset-source contracts and optional adapters."""

from traceless_api.integrations.asset_sources._support import validate_netbox_base_url
from traceless_api.integrations.asset_sources.errors import (
    AssetSourceError,
    AssetSourceLimitExceeded,
    AssetSourcePayloadTooLarge,
    AssetSourceUnavailable,
    InvalidAssetSourcePayload,
    InvalidAssetSourceUrl,
)
from traceless_api.integrations.asset_sources.models import (
    AssetKind,
    AssetSourceSnapshot,
    InterfaceKind,
    NetBoxAssetRecord,
    NetBoxDeviceRecord,
    NetBoxInterfaceRecord,
    NetBoxIpAddressRecord,
    NetBoxPrefixRecord,
    NetBoxVirtualMachineRecord,
    NetBoxVlanRecord,
    SourceAssetRecord,
    SourceObjectRef,
    SourcePageProvenance,
    SourceRecordProvenance,
)
from traceless_api.integrations.asset_sources.netbox import (
    NetBoxAssetSource,
    NetBoxResource,
    RetryPolicy,
)
from traceless_api.integrations.asset_sources.protocols import (
    AssetSource,
    AsyncHttpClient,
    HttpResponse,
)

__all__ = [
    "AssetKind",
    "AssetSource",
    "AssetSourceError",
    "AssetSourceLimitExceeded",
    "AssetSourcePayloadTooLarge",
    "AssetSourceSnapshot",
    "AssetSourceUnavailable",
    "AsyncHttpClient",
    "HttpResponse",
    "InterfaceKind",
    "InvalidAssetSourcePayload",
    "InvalidAssetSourceUrl",
    "NetBoxAssetRecord",
    "NetBoxAssetSource",
    "NetBoxDeviceRecord",
    "NetBoxInterfaceRecord",
    "NetBoxIpAddressRecord",
    "NetBoxPrefixRecord",
    "NetBoxResource",
    "NetBoxVirtualMachineRecord",
    "NetBoxVlanRecord",
    "RetryPolicy",
    "SourceAssetRecord",
    "SourceObjectRef",
    "SourcePageProvenance",
    "SourceRecordProvenance",
    "validate_netbox_base_url",
]
