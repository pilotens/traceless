import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from typing import Any

import pytest

from traceless_api.integrations.asset_sources import (
    AssetSource,
    AssetSourceLimitExceeded,
    AssetSourcePayloadTooLarge,
    InterfaceKind,
    InvalidAssetSourceUrl,
    NetBoxAssetSource,
    NetBoxDeviceRecord,
    NetBoxInterfaceRecord,
    NetBoxIpAddressRecord,
    NetBoxPrefixRecord,
    NetBoxResource,
    NetBoxVirtualMachineRecord,
    NetBoxVlanRecord,
    RetryPolicy,
    validate_netbox_base_url,
)

NOW = datetime(2026, 7, 17, 12, 30, tzinfo=UTC)
BASE_URL = "https://netbox.internal.example/netbox/"


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def _page(
    records: list[dict[str, Any]],
    *,
    count: int | None = None,
    next_url: str | None = None,
) -> bytes:
    return _json_bytes(
        {
            "count": len(records) if count is None else count,
            "next": next_url,
            "previous": None,
            "results": records,
        }
    )


@dataclass
class StubResponse:
    content: bytes
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    status_checked: bool = False

    def raise_for_status(self) -> None:
        self.status_checked = True
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class RecordingHttpClient:
    def __init__(self, responses: list[StubResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> StubResponse:
        self.requests.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
                "timeout": timeout,
                "follow_redirects": follow_redirects,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        return self.responses.pop(0)


def _device(device_id: int, name: str) -> dict[str, Any]:
    return {
        "id": device_id,
        "url": f"https://netbox.internal.example/api/dcim/devices/{device_id}/",
        "display": name,
        "name": name,
        "status": {"value": "active", "label": "Active"},
        "role": {"id": 5, "display": "Edge"},
        "device_type": {"id": 9, "display": "Router 9000"},
        "site": {"id": 3, "display": "Stockholm"},
        "primary_ip4": {"id": 81, "address": f"10.0.0.{device_id}/24"},
        "serial": f"SERIAL-{device_id}",
        "tags": [{"id": 1, "name": "production"}],
        "last_updated": "2026-07-17T11:45:00Z",
    }


def test_fetch_normalizes_device_and_retains_complete_source_lineage() -> None:
    raw_record = _device(42, "edge-01")
    payload = _page([raw_record])
    response = StubResponse(payload)
    client = RecordingHttpClient([response])
    connector = NetBoxAssetSource(
        client,
        BASE_URL,
        token="read-only-token",
        resources=(NetBoxResource.devices,),
        clock=lambda: NOW,
    )

    snapshot = asyncio.run(connector.fetch())

    assert isinstance(connector, AssetSource)
    assert snapshot.approval_state == "unreviewed_source_snapshot"
    assert snapshot.complete is True
    assert len(snapshot.records) == 1
    record = snapshot.records[0]
    assert isinstance(record, NetBoxDeviceRecord)
    assert record.external_id == "42"
    assert record.name == "edge-01"
    assert str(record.primary_ipv4) == "10.0.0.42/24"
    assert record.role is not None and record.role.external_id == "5"
    assert record.tags == ("production",)
    assert record.source_only is True
    assert not hasattr(record, "architecture_component_id")
    assert record.provenance.source_object_type == "dcim.device"
    assert record.provenance.source_updated_at == datetime(2026, 7, 17, 11, 45, tzinfo=UTC)
    expected_record_hash = sha256(
        json.dumps(
            raw_record,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    assert record.provenance.raw_record_sha256 == expected_record_hash
    assert snapshot.pages[0].raw_payload_sha256 == sha256(payload).hexdigest()
    assert "read-only-token" not in snapshot.model_dump_json()
    assert response.status_checked is True
    assert client.requests == [
        {
            "url": "https://netbox.internal.example/netbox/api/dcim/devices/",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer read-only-token",
            },
            "params": {"limit": "100", "offset": "0", "ordering": "id"},
            "timeout": 20.0,
            "follow_redirects": False,
        }
    ]


def test_pagination_never_dereferences_server_supplied_next_url() -> None:
    first = StubResponse(
        _page(
            [_device(1, "device-1")],
            count=2,
            next_url="http://169.254.169.254/latest/meta-data/",
        )
    )
    second = StubResponse(_page([_device(2, "device-2")], count=2))
    client = RecordingHttpClient([first, second])
    connector = NetBoxAssetSource(
        client,
        BASE_URL,
        resources=(NetBoxResource.devices,),
        page_size=1,
        clock=lambda: NOW,
    )

    snapshot = asyncio.run(connector.fetch())

    assert [record.external_id for record in snapshot.records] == ["1", "2"]
    assert [request["url"] for request in client.requests] == [
        "https://netbox.internal.example/netbox/api/dcim/devices/",
        "https://netbox.internal.example/netbox/api/dcim/devices/",
    ]
    assert [request["params"]["offset"] for request in client.requests] == ["0", "1"]
    assert all(request["follow_redirects"] is False for request in client.requests)


def test_normalizes_vms_both_interface_types_ip_prefix_and_vlan() -> None:
    responses = [
        StubResponse(
            _page(
                [
                    {
                        "id": 7,
                        "display": "payments-vm",
                        "name": "payments-vm",
                        "status": {"value": "active"},
                        "cluster": {"id": 4, "display": "prod-cluster"},
                        "vcpus": "2.5",
                        "memory": 8192,
                        "disk": 120,
                        "primary_ip4": {"id": 90, "address": "10.0.1.7/24"},
                        "last_updated": "2026-07-17T10:00:00Z",
                    }
                ]
            )
        ),
        StubResponse(
            _page(
                [
                    {
                        "id": 101,
                        "display": "eth0",
                        "name": "eth0",
                        "device": {"id": 42, "display": "edge-01"},
                        "type": {"value": "1000base-t"},
                        "enabled": True,
                        "mac_address": "00:11:22:33:44:55",
                        "mtu": 1500,
                        "mode": {"value": "tagged"},
                        "tagged_vlans": [{"id": 88, "display": "payments"}],
                    }
                ]
            )
        ),
        StubResponse(
            _page(
                [
                    {
                        "id": 102,
                        "display": "ens3",
                        "name": "ens3",
                        "virtual_machine": {"id": 7, "display": "payments-vm"},
                        "enabled": True,
                    }
                ]
            )
        ),
        StubResponse(
            _page(
                [
                    {
                        "id": 90,
                        "display": "10.0.1.7/24",
                        "address": "10.0.1.7/24",
                        "status": {"value": "active"},
                        "dns_name": "payments.internal.example",
                        "assigned_object_type": "virtualization.vminterface",
                        "assigned_object": {"id": 102, "display": "ens3"},
                    }
                ]
            )
        ),
        StubResponse(
            _page(
                [
                    {
                        "id": 50,
                        "display": "10.0.1.0/24",
                        "prefix": "10.0.1.0/24",
                        "status": {"value": "active"},
                        "scope_type": "dcim.site",
                        "scope": {"id": 3, "display": "Stockholm"},
                        "vlan": {"id": 88, "display": "payments"},
                        "is_pool": False,
                    }
                ]
            )
        ),
        StubResponse(
            _page(
                [
                    {
                        "id": 88,
                        "display": "payments (88)",
                        "vid": 88,
                        "name": "payments",
                        "status": {"value": "active"},
                        "site": {"id": 3, "display": "Stockholm"},
                    }
                ]
            )
        ),
    ]
    resources = (
        NetBoxResource.virtual_machines,
        NetBoxResource.interfaces,
        NetBoxResource.virtual_interfaces,
        NetBoxResource.ip_addresses,
        NetBoxResource.prefixes,
        NetBoxResource.vlans,
    )
    connector = NetBoxAssetSource(
        RecordingHttpClient(responses),
        BASE_URL,
        resources=resources,
        clock=lambda: NOW,
    )

    snapshot = asyncio.run(connector.fetch())

    vm, interface, vm_interface, address, prefix, vlan = snapshot.records
    assert isinstance(vm, NetBoxVirtualMachineRecord)
    assert vm.vcpus == Decimal("2.5")
    assert vm.cluster is not None and vm.cluster.display_name == "prod-cluster"
    assert isinstance(interface, NetBoxInterfaceRecord)
    assert interface.interface_kind is InterfaceKind.physical
    assert interface.owner.object_type == "dcim.device"
    assert interface.tagged_vlans[0].external_id == "88"
    assert isinstance(vm_interface, NetBoxInterfaceRecord)
    assert vm_interface.interface_kind is InterfaceKind.virtual
    assert vm_interface.owner.object_type == "virtualization.virtualmachine"
    assert isinstance(address, NetBoxIpAddressRecord)
    assert address.assigned_object is not None
    assert address.assigned_object.object_type == "virtualization.vminterface"
    assert isinstance(prefix, NetBoxPrefixRecord)
    assert str(prefix.prefix) == "10.0.1.0/24"
    assert prefix.scope is not None and prefix.scope.object_type == "dcim.site"
    assert isinstance(vlan, NetBoxVlanRecord)
    assert vlan.vid == 88


def test_retries_only_bounded_idempotent_get_and_records_backoff() -> None:
    response_503 = StubResponse(b"{}", status_code=503)
    success = StubResponse(_page([_device(9, "device-9")]))
    client = RecordingHttpClient([response_503, success])
    delays: list[float] = []

    async def record_delay(delay: float) -> None:
        delays.append(delay)

    connector = NetBoxAssetSource(
        client,
        BASE_URL,
        resources=(NetBoxResource.devices,),
        retry_policy=RetryPolicy(max_attempts=2, backoff_seconds=(0.5,)),
        sleeper=record_delay,
        clock=lambda: NOW,
    )

    snapshot = asyncio.run(connector.fetch())

    assert snapshot.records[0].external_id == "9"
    assert len(client.requests) == 2
    assert delays == [0.5]
    assert response_503.status_checked is False
    assert success.status_checked is True


def test_declared_record_and_response_size_limits_fail_closed() -> None:
    count_client = RecordingHttpClient([StubResponse(_page([_device(1, "device-1")], count=2))])
    count_connector = NetBoxAssetSource(
        count_client,
        BASE_URL,
        resources=(NetBoxResource.devices,),
        max_records=1,
        clock=lambda: NOW,
    )
    with pytest.raises(AssetSourceLimitExceeded, match="record limit"):
        asyncio.run(count_connector.fetch())

    size_response = StubResponse(
        b"{}",
        headers={"Content-Type": "application/json", "Content-Length": "1025"},
    )
    size_connector = NetBoxAssetSource(
        RecordingHttpClient([size_response]),
        BASE_URL,
        resources=(NetBoxResource.devices,),
        max_page_bytes=1024,
        clock=lambda: NOW,
    )
    with pytest.raises(AssetSourcePayloadTooLarge, match="page limit"):
        asyncio.run(size_connector.fetch())

    page_client = RecordingHttpClient(
        [
            StubResponse(
                _page(
                    [_device(1, "device-1")],
                    count=2,
                    next_url=f"{BASE_URL}api/dcim/devices/?limit=1&offset=1",
                )
            )
        ]
    )
    page_connector = NetBoxAssetSource(
        page_client,
        BASE_URL,
        resources=(NetBoxResource.devices,),
        page_size=1,
        max_pages=1,
        clock=lambda: NOW,
    )
    with pytest.raises(AssetSourceLimitExceeded, match="page limit"):
        asyncio.run(page_connector.fetch())
    assert len(page_client.requests) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://netbox.internal.example/",
        "file:///etc/passwd",
        "https://localhost/",
        "https://netbox.localhost/",
        "https://127.0.0.1/",
        "https://169.254.169.254/latest/",
        "https://[::1]/",
        "https://user:secret@netbox.internal.example/",
        "https://netbox.internal.example/?target=elsewhere",
        "https://netbox.internal.example/#fragment",
        "https://netbox.internal.example/%2e%2e/admin",
    ],
)
def test_ssrf_baseline_rejects_unsafe_base_urls(url: str) -> None:
    with pytest.raises(InvalidAssetSourceUrl):
        validate_netbox_base_url(url)


def test_ssrf_baseline_supports_internal_netbox_with_explicit_controls() -> None:
    assert validate_netbox_base_url("https://10.20.30.40/netbox") == ("https://10.20.30.40/netbox/")
    assert (
        validate_netbox_base_url(
            "http://netbox.dev.example/",
            allow_insecure_http=True,
            allowed_hosts={"netbox.dev.example"},
        )
        == "http://netbox.dev.example/"
    )
    with pytest.raises(InvalidAssetSourceUrl, match="allowlist"):
        validate_netbox_base_url(
            "https://netbox.other.example/",
            allowed_hosts={"netbox.internal.example"},
        )
