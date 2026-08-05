"""Read-only NetBox REST asset-source adapter.

The adapter retrieves a bounded, best-effort consistent source snapshot. It uses
only fixed list endpoints and GET requests, orders offset pagination by object ID,
does not follow redirects, and never dereferences NetBox's server-supplied ``next``
URL. A later, separate reconciliation workflow must review these observations
before creating or updating approved architecture components.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from hashlib import sha256
from typing import Any, Literal
from urllib.parse import quote, urljoin

import httpx
from pydantic import ValidationError

from traceless_api.integrations.asset_sources._support import (
    decode_bounded_json,
    digest_canonical_json,
    digest_payload,
    utc_now,
    validate_aware_datetime,
    validate_netbox_base_url,
    validated_json_response_body,
)
from traceless_api.integrations.asset_sources.errors import (
    AssetSourceLimitExceeded,
    AssetSourceUnavailable,
    InvalidAssetSourcePayload,
)
from traceless_api.integrations.asset_sources.models import (
    AssetSourceSnapshot,
    InterfaceKind,
    NetBoxAssetRecord,
    NetBoxDeviceRecord,
    NetBoxInterfaceRecord,
    NetBoxIpAddressRecord,
    NetBoxPrefixRecord,
    NetBoxVirtualMachineRecord,
    NetBoxVlanRecord,
    SourceObjectRef,
    SourcePageProvenance,
    SourceRecordProvenance,
)
from traceless_api.integrations.asset_sources.protocols import AsyncHttpClient, HttpResponse

Clock = Callable[[], datetime]
Sleeper = Callable[[float], Awaitable[None]]
Normalizer = Callable[[Mapping[str, Any], "_RecordContext"], NetBoxAssetRecord]

DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 1_000
DEFAULT_MAX_RECORDS = 50_000
DEFAULT_MAX_PAGE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 20.0
RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class NetBoxResource(StrEnum):
    devices = "devices"
    virtual_machines = "virtual_machines"
    interfaces = "interfaces"
    virtual_interfaces = "virtual_interfaces"
    ip_addresses = "ip_addresses"
    prefixes = "prefixes"
    vlans = "vlans"


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded retry policy for idempotent GET requests only."""

    max_attempts: int = 3
    backoff_seconds: tuple[float, ...] = (0.25, 1.0)

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 5:
            raise ValueError("max_attempts must be between 1 and 5")
        if len(self.backoff_seconds) != self.max_attempts - 1:
            raise ValueError("backoff_seconds must define one delay between each attempt")
        if any(
            not math.isfinite(delay) or delay < 0 or delay > 60 for delay in self.backoff_seconds
        ):
            raise ValueError("retry delays must be finite values between 0 and 60 seconds")


@dataclass(frozen=True, slots=True)
class _RecordContext:
    base_url: str
    endpoint_url: str
    endpoint_path: str
    object_type: str
    retrieved_at: datetime


@dataclass(frozen=True, slots=True)
class _EndpointSpec:
    resource: NetBoxResource
    path: str
    object_type: str
    normalizer: Normalizer


class NetBoxAssetSource:
    """Fetch normalized, source-only inventory records from NetBox REST endpoints."""

    def __init__(
        self,
        client: AsyncHttpClient,
        base_url: str,
        *,
        token: str | None = None,
        auth_scheme: Literal["Bearer", "Token"] = "Bearer",
        resources: Iterable[NetBoxResource] | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_records: int = DEFAULT_MAX_RECORDS,
        max_page_bytes: int = DEFAULT_MAX_PAGE_BYTES,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        retry_policy: RetryPolicy | None = None,
        clock: Clock = utc_now,
        sleeper: Sleeper = asyncio.sleep,
        allow_insecure_http: bool = False,
        allowed_hosts: Collection[str] | None = None,
    ) -> None:
        self._client = client
        self._base_url = validate_netbox_base_url(
            base_url,
            allow_insecure_http=allow_insecure_http,
            allowed_hosts=allowed_hosts,
        )
        self._token = _validate_token(token)
        self._auth_scheme = auth_scheme
        self._resources = _normalize_resources(resources)
        self._page_size = _bounded_integer("page_size", page_size, minimum=1, maximum=1_000)
        self._max_pages = _bounded_integer("max_pages", max_pages, minimum=1, maximum=10_000)
        self._max_records = _bounded_integer("max_records", max_records, minimum=1, maximum=100_000)
        self._max_page_bytes = _bounded_integer(
            "max_page_bytes",
            max_page_bytes,
            minimum=1_024,
            maximum=64 * 1024 * 1024,
        )
        if not math.isfinite(timeout_seconds) or not 0.1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 0.1 and 120")
        self._timeout_seconds = timeout_seconds
        self._retry_policy = retry_policy or RetryPolicy()
        self._clock = clock
        self._sleeper = sleeper

    @property
    def source_name(self) -> str:
        return "netbox"

    async def fetch(self) -> AssetSourceSnapshot[NetBoxAssetRecord]:
        started_at = validate_aware_datetime(self._clock())
        records: list[NetBoxAssetRecord] = []
        pages: list[SourcePageProvenance] = []
        seen_records: set[tuple[str, str]] = set()

        for resource in self._resources:
            spec = _ENDPOINTS[resource]
            await self._fetch_endpoint(
                spec,
                records=records,
                pages=pages,
                seen_records=seen_records,
            )

        completed_at = validate_aware_datetime(self._clock())
        manifest = "\n".join(
            f"{page.source_endpoint}:{page.page_number}:{page.raw_payload_sha256}" for page in pages
        ).encode()
        return AssetSourceSnapshot[NetBoxAssetRecord](
            provider=self.source_name,
            source_base_url=self._base_url,
            started_at=started_at,
            completed_at=completed_at,
            records=tuple(records),
            pages=tuple(pages),
            manifest_sha256=sha256(manifest).hexdigest(),
        )

    async def _fetch_endpoint(
        self,
        spec: _EndpointSpec,
        *,
        records: list[NetBoxAssetRecord],
        pages: list[SourcePageProvenance],
        seen_records: set[tuple[str, str]],
    ) -> None:
        endpoint_url = urljoin(self._base_url, spec.path)
        offset = 0
        endpoint_page = 0
        endpoint_record_count = 0
        expected_count: int | None = None

        while True:
            if len(pages) >= self._max_pages:
                raise AssetSourceLimitExceeded(
                    f"NetBox snapshot exceeds the {self._max_pages}-page limit"
                )
            response = await self._request_page(endpoint_url, spec.path, offset=offset)
            retrieved_at = validate_aware_datetime(self._clock())
            payload = validated_json_response_body(
                response,
                max_bytes=self._max_page_bytes,
            )
            page = _decode_page(payload, max_bytes=self._max_page_bytes)
            declared_count = page["count"]
            raw_records = page["results"]
            next_marker = page["next"]

            if expected_count is None:
                expected_count = declared_count
                if len(records) + declared_count > self._max_records:
                    raise AssetSourceLimitExceeded(
                        f"NetBox snapshot exceeds the {self._max_records}-record limit"
                    )
            elif declared_count != expected_count:
                raise InvalidAssetSourcePayload(
                    f"NetBox count changed during pagination for {spec.path}"
                )
            if len(raw_records) > self._page_size:
                raise InvalidAssetSourcePayload(
                    f"NetBox returned more than the requested {self._page_size} records"
                )

            endpoint_page += 1
            context = _RecordContext(
                base_url=self._base_url,
                endpoint_url=endpoint_url,
                endpoint_path=spec.path,
                object_type=spec.object_type,
                retrieved_at=retrieved_at,
            )
            for raw_record in raw_records:
                try:
                    normalized = spec.normalizer(raw_record, context)
                except InvalidAssetSourcePayload:
                    raise
                except (InvalidOperation, TypeError, ValueError, ValidationError) as exc:
                    raise InvalidAssetSourcePayload(
                        f"invalid {spec.object_type} record in NetBox response"
                    ) from exc
                key = (spec.object_type, normalized.external_id)
                if key in seen_records:
                    raise InvalidAssetSourcePayload(
                        f"NetBox returned duplicate {spec.object_type} id {normalized.external_id}"
                    )
                seen_records.add(key)
                records.append(normalized)

            pages.append(
                SourcePageProvenance(
                    provider=self.source_name,
                    source_base_url=self._base_url,
                    source_endpoint=spec.path,
                    page_number=endpoint_page,
                    offset=offset,
                    declared_count=declared_count,
                    record_count=len(raw_records),
                    retrieved_at=retrieved_at,
                    raw_payload_sha256=digest_payload(payload),
                )
            )
            endpoint_record_count += len(raw_records)
            if endpoint_record_count > declared_count:
                raise InvalidAssetSourcePayload(
                    f"NetBox returned more records than declared for {spec.path}"
                )

            has_more = next_marker is not None or endpoint_record_count < declared_count
            if not has_more:
                if endpoint_record_count != declared_count:
                    raise InvalidAssetSourcePayload(
                        f"NetBox pagination ended before its declared count for {spec.path}"
                    )
                return
            if not raw_records:
                raise InvalidAssetSourcePayload(
                    f"NetBox returned an empty intermediate page for {spec.path}"
                )
            offset += len(raw_records)

    async def _request_page(
        self,
        endpoint_url: str,
        endpoint_path: str,
        *,
        offset: int,
    ) -> HttpResponse:
        headers = {"Accept": "application/json"}
        if self._token is not None:
            headers["Authorization"] = f"{self._auth_scheme} {self._token}"
        params = {
            "limit": str(self._page_size),
            "offset": str(offset),
            "ordering": "id",
        }

        for attempt in range(self._retry_policy.max_attempts):
            try:
                response = await self._client.get(
                    endpoint_url,
                    headers=headers,
                    params=params,
                    timeout=self._timeout_seconds,
                    follow_redirects=False,
                )
            except (httpx.TransportError, ConnectionError, TimeoutError) as exc:
                if attempt + 1 >= self._retry_policy.max_attempts:
                    raise AssetSourceUnavailable(
                        f"NetBox transport failed for {endpoint_path}"
                    ) from exc
                await self._sleeper(self._retry_policy.backoff_seconds[attempt])
                continue

            status_code = response.status_code
            if status_code in RETRYABLE_STATUS_CODES and (
                attempt + 1 < self._retry_policy.max_attempts
            ):
                await self._sleeper(self._retry_policy.backoff_seconds[attempt])
                continue
            try:
                response.raise_for_status()
            except Exception as exc:
                raise AssetSourceUnavailable(
                    f"NetBox returned HTTP {status_code} for {endpoint_path}"
                ) from exc
            if status_code != 200:
                raise AssetSourceUnavailable(
                    f"NetBox returned unexpected HTTP {status_code} for {endpoint_path}"
                )
            return response

        raise AssertionError("retry loop exhausted without returning or raising")


def _validate_token(token: str | None) -> str | None:
    if token is None:
        return None
    if not isinstance(token, str) or not 1 <= len(token) <= 4_096:
        raise ValueError("NetBox token must contain between 1 and 4096 characters")
    if token != token.strip() or any(ord(character) < 32 for character in token):
        raise ValueError("NetBox token contains invalid whitespace or control characters")
    return token


def _bounded_integer(name: str, value: int, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _normalize_resources(
    resources: Iterable[NetBoxResource] | None,
) -> tuple[NetBoxResource, ...]:
    if resources is None:
        return tuple(NetBoxResource)
    normalized: list[NetBoxResource] = []
    for resource in resources:
        try:
            item = NetBoxResource(resource)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported NetBox resource: {resource!r}") from exc
        if item in normalized:
            raise ValueError(f"duplicate NetBox resource: {item.value}")
        normalized.append(item)
    if not normalized:
        raise ValueError("at least one NetBox resource must be selected")
    return tuple(normalized)


def _decode_page(payload: bytes, *, max_bytes: int) -> dict[str, Any]:
    decoded = decode_bounded_json(payload, max_bytes=max_bytes)
    if not isinstance(decoded, dict):
        raise InvalidAssetSourcePayload("NetBox list response must be a JSON object")
    required_keys = {"count", "next", "results"}
    if not required_keys.issubset(decoded):
        raise InvalidAssetSourcePayload("NetBox list response is missing pagination fields")
    count = decoded["count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise InvalidAssetSourcePayload("NetBox pagination count must be a non-negative integer")
    next_marker = decoded["next"]
    if next_marker is not None and not isinstance(next_marker, str):
        raise InvalidAssetSourcePayload("NetBox pagination next field must be a string or null")
    results = decoded["results"]
    if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
        raise InvalidAssetSourcePayload("NetBox pagination results must be an object list")
    return {"count": count, "next": next_marker, "results": results}


def _external_id(raw: Mapping[str, Any]) -> str:
    value = raw.get("id")
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise InvalidAssetSourcePayload("NetBox record is missing a stable id")
    external_id = str(value)
    if not external_id or len(external_id) > 200:
        raise InvalidAssetSourcePayload("NetBox record id is outside the supported bound")
    return external_id


def _text(
    value: Any,
    *,
    field: str,
    maximum: int,
    required: bool = False,
) -> str | None:
    if value is None:
        if required:
            raise InvalidAssetSourcePayload(f"NetBox record is missing {field}")
        return None
    if not isinstance(value, str):
        raise InvalidAssetSourcePayload(f"NetBox field {field} must be text")
    cleaned = value.strip()
    if required and not cleaned:
        raise InvalidAssetSourcePayload(f"NetBox field {field} must not be empty")
    if len(cleaned) > maximum:
        raise InvalidAssetSourcePayload(
            f"NetBox field {field} exceeds the {maximum}-character limit"
        )
    return cleaned or None


def _display_name(raw: Mapping[str, Any], external_id: str) -> str:
    for key in ("display", "name", "address", "prefix"):
        value = _text(raw.get(key), field=key, maximum=500)
        if value is not None:
            return value
    return external_id


def _choice(value: Any, *, field: str) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("value") or value.get("label") or value.get("display")
    return _text(value, field=field, maximum=100)


def _optional_bool(value: Any, *, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise InvalidAssetSourcePayload(f"NetBox field {field} must be boolean")
    return value


def _optional_int(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidAssetSourcePayload(f"NetBox field {field} must be an integer")
    return value


def _optional_decimal(value: Any, *, field: str) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise InvalidAssetSourcePayload(f"NetBox field {field} must be numeric")
    result = Decimal(str(value))
    if not result.is_finite():
        raise InvalidAssetSourcePayload(f"NetBox field {field} must be finite")
    return result


def _ref(value: Any, object_type: str, *, field: str) -> SourceObjectRef | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        external_id = _external_id(value)
        display_name = _display_name(value, external_id)
    elif isinstance(value, (int, str)) and not isinstance(value, bool):
        external_id = str(value)
        display_name = external_id
    else:
        raise InvalidAssetSourcePayload(f"NetBox relation {field} has an invalid shape")
    return SourceObjectRef(
        object_type=object_type,
        external_id=external_id,
        display_name=display_name,
    )


def _required_ref(value: Any, object_type: str, *, field: str) -> SourceObjectRef:
    result = _ref(value, object_type, field=field)
    if result is None:
        raise InvalidAssetSourcePayload(f"NetBox record is missing relation {field}")
    return result


def _tags(raw: Mapping[str, Any]) -> tuple[str, ...]:
    value = raw.get("tags")
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > 500:
        raise InvalidAssetSourcePayload("NetBox tags must be a bounded list")
    tags: list[str] = []
    for item in value:
        if isinstance(item, Mapping):
            item = item.get("name") or item.get("slug") or item.get("display")
        tag = _text(item, field="tag", maximum=200, required=True)
        if tag not in tags:
            tags.append(tag)
    return tuple(tags)


def _ip_value(value: Any, *, field: str) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("address")
    return _text(value, field=field, maximum=100)


def _common_fields(raw: Mapping[str, Any], context: _RecordContext) -> dict[str, Any]:
    external_id = _external_id(raw)
    description = _text(raw.get("description"), field="description", maximum=10_000) or ""
    source_updated_at = raw.get("last_updated", raw.get("updated"))
    record_url = f"{context.endpoint_url}{quote(external_id, safe='')}/"
    return {
        "external_id": external_id,
        "display_name": _display_name(raw, external_id),
        "status": _choice(raw.get("status"), field="status"),
        "description": description,
        "tags": _tags(raw),
        "provenance": SourceRecordProvenance(
            provider="netbox",
            source_base_url=context.base_url,
            source_endpoint=context.endpoint_path,
            source_object_type=context.object_type,
            source_external_id=external_id,
            source_record_url=record_url,
            source_updated_at=source_updated_at,
            retrieved_at=context.retrieved_at,
            raw_record_sha256=digest_canonical_json(raw),
        ),
    }


def _normalize_device(raw: Mapping[str, Any], context: _RecordContext) -> NetBoxDeviceRecord:
    common = _common_fields(raw, context)
    name = _text(raw.get("name"), field="name", maximum=500, required=True)
    return NetBoxDeviceRecord(
        **common,
        name=name,
        serial=_text(raw.get("serial"), field="serial", maximum=500) or "",
        asset_tag=_text(raw.get("asset_tag"), field="asset_tag", maximum=500),
        role=_ref(raw.get("role", raw.get("device_role")), "dcim.devicerole", field="role"),
        device_type=_ref(raw.get("device_type"), "dcim.devicetype", field="device_type"),
        site=_ref(raw.get("site"), "dcim.site", field="site"),
        location=_ref(raw.get("location"), "dcim.location", field="location"),
        platform=_ref(raw.get("platform"), "dcim.platform", field="platform"),
        tenant=_ref(raw.get("tenant"), "tenancy.tenant", field="tenant"),
        cluster=_ref(raw.get("cluster"), "virtualization.cluster", field="cluster"),
        primary_ipv4=_ip_value(raw.get("primary_ip4"), field="primary_ip4"),
        primary_ipv6=_ip_value(raw.get("primary_ip6"), field="primary_ip6"),
    )


def _normalize_virtual_machine(
    raw: Mapping[str, Any], context: _RecordContext
) -> NetBoxVirtualMachineRecord:
    common = _common_fields(raw, context)
    name = _text(raw.get("name"), field="name", maximum=500, required=True)
    return NetBoxVirtualMachineRecord(
        **common,
        name=name,
        role=_ref(raw.get("role"), "dcim.devicerole", field="role"),
        cluster=_ref(raw.get("cluster"), "virtualization.cluster", field="cluster"),
        site=_ref(raw.get("site"), "dcim.site", field="site"),
        device=_ref(raw.get("device"), "dcim.device", field="device"),
        platform=_ref(raw.get("platform"), "dcim.platform", field="platform"),
        tenant=_ref(raw.get("tenant"), "tenancy.tenant", field="tenant"),
        vcpus=_optional_decimal(raw.get("vcpus"), field="vcpus"),
        memory_mb=_optional_int(raw.get("memory"), field="memory"),
        disk_gb=_optional_decimal(raw.get("disk"), field="disk"),
        primary_ipv4=_ip_value(raw.get("primary_ip4"), field="primary_ip4"),
        primary_ipv6=_ip_value(raw.get("primary_ip6"), field="primary_ip6"),
    )


def _normalize_physical_interface(
    raw: Mapping[str, Any], context: _RecordContext
) -> NetBoxInterfaceRecord:
    return _normalize_interface(raw, context, interface_kind=InterfaceKind.physical)


def _normalize_virtual_interface(
    raw: Mapping[str, Any], context: _RecordContext
) -> NetBoxInterfaceRecord:
    return _normalize_interface(raw, context, interface_kind=InterfaceKind.virtual)


def _normalize_interface(
    raw: Mapping[str, Any],
    context: _RecordContext,
    *,
    interface_kind: InterfaceKind,
) -> NetBoxInterfaceRecord:
    common = _common_fields(raw, context)
    name = _text(raw.get("name"), field="name", maximum=500, required=True)
    owner_field = "device" if interface_kind is InterfaceKind.physical else "virtual_machine"
    owner_type = (
        "dcim.device"
        if interface_kind is InterfaceKind.physical
        else "virtualization.virtualmachine"
    )
    parent_type = context.object_type
    tagged_value = raw.get("tagged_vlans") or []
    if not isinstance(tagged_value, list) or len(tagged_value) > 4094:
        raise InvalidAssetSourcePayload("NetBox tagged_vlans must be a bounded list")
    return NetBoxInterfaceRecord(
        **common,
        interface_kind=interface_kind,
        name=name,
        owner=_required_ref(raw.get(owner_field), owner_type, field=owner_field),
        interface_type=_choice(raw.get("type"), field="type"),
        enabled=_optional_bool(raw.get("enabled"), field="enabled"),
        mac_address=_text(raw.get("mac_address"), field="mac_address", maximum=17),
        mtu=_optional_int(raw.get("mtu"), field="mtu"),
        mode=_choice(raw.get("mode"), field="mode"),
        parent_interface=_ref(raw.get("parent"), parent_type, field="parent"),
        bridge=_ref(raw.get("bridge"), parent_type, field="bridge"),
        lag=_ref(raw.get("lag"), parent_type, field="lag"),
        untagged_vlan=_ref(raw.get("untagged_vlan"), "ipam.vlan", field="untagged_vlan"),
        tagged_vlans=tuple(
            _required_ref(item, "ipam.vlan", field="tagged_vlans") for item in tagged_value
        ),
    )


def _normalize_ip_address(raw: Mapping[str, Any], context: _RecordContext) -> NetBoxIpAddressRecord:
    common = _common_fields(raw, context)
    address = _text(raw.get("address"), field="address", maximum=100, required=True)
    assigned_type = _text(
        raw.get("assigned_object_type"),
        field="assigned_object_type",
        maximum=100,
    )
    assigned_object = None
    if assigned_type is not None:
        assigned_value = raw.get("assigned_object")
        if assigned_value is None and raw.get("assigned_object_id") is not None:
            assigned_value = raw["assigned_object_id"]
        assigned_object = _ref(assigned_value, assigned_type, field="assigned_object")
    return NetBoxIpAddressRecord(
        **common,
        address=address,
        dns_name=_text(raw.get("dns_name"), field="dns_name", maximum=253) or "",
        role=_choice(raw.get("role"), field="role"),
        assigned_object=assigned_object,
        vrf=_ref(raw.get("vrf"), "ipam.vrf", field="vrf"),
        tenant=_ref(raw.get("tenant"), "tenancy.tenant", field="tenant"),
    )


def _normalize_prefix(raw: Mapping[str, Any], context: _RecordContext) -> NetBoxPrefixRecord:
    common = _common_fields(raw, context)
    prefix = _text(raw.get("prefix"), field="prefix", maximum=100, required=True)
    scope_type = _text(raw.get("scope_type"), field="scope_type", maximum=100)
    return NetBoxPrefixRecord(
        **common,
        prefix=prefix,
        role=_ref(raw.get("role"), "ipam.role", field="role"),
        vrf=_ref(raw.get("vrf"), "ipam.vrf", field="vrf"),
        tenant=_ref(raw.get("tenant"), "tenancy.tenant", field="tenant"),
        vlan=_ref(raw.get("vlan"), "ipam.vlan", field="vlan"),
        scope=_ref(raw.get("scope"), scope_type or "netbox.scope", field="scope"),
        is_pool=_optional_bool(raw.get("is_pool"), field="is_pool"),
        mark_utilized=_optional_bool(raw.get("mark_utilized"), field="mark_utilized"),
    )


def _normalize_vlan(raw: Mapping[str, Any], context: _RecordContext) -> NetBoxVlanRecord:
    common = _common_fields(raw, context)
    name = _text(raw.get("name"), field="name", maximum=500, required=True)
    vid = _optional_int(raw.get("vid"), field="vid")
    if vid is None:
        raise InvalidAssetSourcePayload("NetBox VLAN is missing vid")
    return NetBoxVlanRecord(
        **common,
        vid=vid,
        name=name,
        role=_ref(raw.get("role"), "ipam.role", field="role"),
        group=_ref(raw.get("group"), "ipam.vlangroup", field="group"),
        site=_ref(raw.get("site"), "dcim.site", field="site"),
        tenant=_ref(raw.get("tenant"), "tenancy.tenant", field="tenant"),
    )


_ENDPOINTS = {
    NetBoxResource.devices: _EndpointSpec(
        NetBoxResource.devices,
        "api/dcim/devices/",
        "dcim.device",
        _normalize_device,
    ),
    NetBoxResource.virtual_machines: _EndpointSpec(
        NetBoxResource.virtual_machines,
        "api/virtualization/virtual-machines/",
        "virtualization.virtualmachine",
        _normalize_virtual_machine,
    ),
    NetBoxResource.interfaces: _EndpointSpec(
        NetBoxResource.interfaces,
        "api/dcim/interfaces/",
        "dcim.interface",
        _normalize_physical_interface,
    ),
    NetBoxResource.virtual_interfaces: _EndpointSpec(
        NetBoxResource.virtual_interfaces,
        "api/virtualization/interfaces/",
        "virtualization.vminterface",
        _normalize_virtual_interface,
    ),
    NetBoxResource.ip_addresses: _EndpointSpec(
        NetBoxResource.ip_addresses,
        "api/ipam/ip-addresses/",
        "ipam.ipaddress",
        _normalize_ip_address,
    ),
    NetBoxResource.prefixes: _EndpointSpec(
        NetBoxResource.prefixes,
        "api/ipam/prefixes/",
        "ipam.prefix",
        _normalize_prefix,
    ),
    NetBoxResource.vlans: _EndpointSpec(
        NetBoxResource.vlans,
        "api/ipam/vlans/",
        "ipam.vlan",
        _normalize_vlan,
    ),
}
