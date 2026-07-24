from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from traceless_api.extensions import (
    DuplicateExtensionIdError,
    ExtensionConnectorContractError,
    ExtensionManifest,
    ExtensionPermission,
    ExtensionPermissionPolicyError,
    ExtensionRegistry,
    ExtensionTransport,
    IncompatibleExtensionError,
    is_api_compatible,
)


def _http_manifest() -> dict[str, object]:
    return {
        "manifest_schema_version": "1.0",
        "id": "acme.asset-enricher",
        "name": "Acme Asset Enricher",
        "description": "Adds approved external asset context.",
        "version": "1.2.3",
        "api_compatibility": {
            "minimum": "1.0.0",
            "maximum_exclusive": "2.0.0",
        },
        "capabilities": ["asset_discovery", "architecture_enrichment"],
        "permissions": ["network_egress", "assets_read"],
        "entrypoint": {
            "transport": "http",
            "base_url": "https://extension.example.test/api/",
            "invoke_path": "/v1/invoke",
            "health_path": "/health",
        },
    }


def _queue_manifest() -> dict[str, object]:
    payload = _http_manifest()
    payload["id"] = "acme.queue-enricher"
    payload["permissions"] = ["queue_publish", "queue_consume"]
    payload["entrypoint"] = {
        "transport": "queue",
        "broker_binding": "brokers.extensions",
        "request_topic": "traceless.extension.requests",
        "response_topic": "traceless.extension.responses",
    }
    return payload


def test_manifest_schema_accepts_only_versioned_out_of_process_entrypoints() -> None:
    http = ExtensionManifest.model_validate(_http_manifest())
    queue = ExtensionManifest.model_validate(_queue_manifest())

    assert http.manifest_schema_version == "1.0"
    assert http.entrypoint.transport is ExtensionTransport.http
    assert queue.entrypoint.transport is ExtensionTransport.queue
    assert http.model_dump(mode="json")["permissions"] == ["network_egress", "assets_read"]


def test_manifest_rejects_unknown_schema_version_and_in_process_loader_fields() -> None:
    wrong_version = _http_manifest()
    wrong_version["manifest_schema_version"] = "2.0"
    in_process = _http_manifest()
    in_process["entrypoint"] = {
        "transport": "python",
        "module": "untrusted.plugin",
        "callable": "run",
    }

    with pytest.raises(ValidationError):
        ExtensionManifest.model_validate(wrong_version)
    with pytest.raises(ValidationError):
        ExtensionManifest.model_validate(in_process)


def test_manifest_rejects_unknown_and_duplicate_permissions() -> None:
    unknown = _http_manifest()
    unknown["permissions"] = ["network_egress", "filesystem_write"]
    duplicate = _http_manifest()
    duplicate["permissions"] = ["network_egress", "network_egress"]

    with pytest.raises(ValidationError, match="filesystem_write"):
        ExtensionManifest.model_validate(unknown)
    with pytest.raises(ValidationError, match="must not contain duplicates"):
        ExtensionManifest.model_validate(duplicate)


@pytest.mark.parametrize(
    "secret_field",
    ["api_key", "token", "client_secret", "password", "authorization"],
)
def test_manifest_rejects_secret_fields(secret_field: str) -> None:
    payload = _http_manifest()
    payload[secret_field] = "must-not-be-here"

    with pytest.raises(ValidationError, match="secret-bearing fields are forbidden"):
        ExtensionManifest.model_validate(payload)


def test_manifest_rejects_nested_headers_credentials_and_url_credentials() -> None:
    nested = _http_manifest()
    nested_entrypoint = deepcopy(nested["entrypoint"])
    assert isinstance(nested_entrypoint, dict)
    nested_entrypoint["headers"] = {"Authorization": "Bearer secret"}
    nested["entrypoint"] = nested_entrypoint

    url_credentials = _http_manifest()
    credentials_entrypoint = deepcopy(url_credentials["entrypoint"])
    assert isinstance(credentials_entrypoint, dict)
    credentials_entrypoint["base_url"] = "https://user:password@extension.example.test/"
    url_credentials["entrypoint"] = credentials_entrypoint

    with pytest.raises(ValidationError, match="secret-bearing fields are forbidden"):
        ExtensionManifest.model_validate(nested)
    with pytest.raises(ValidationError, match="credentials must not be embedded"):
        ExtensionManifest.model_validate(url_credentials)


def test_credential_binding_is_a_reference_and_requires_explicit_permission() -> None:
    missing_permission = _http_manifest()
    entrypoint = deepcopy(missing_permission["entrypoint"])
    assert isinstance(entrypoint, dict)
    entrypoint["credential_binding"] = "vault.acme-extension"
    missing_permission["entrypoint"] = entrypoint

    with pytest.raises(ValidationError, match="credential_binding_use"):
        ExtensionManifest.model_validate(missing_permission)

    missing_permission["permissions"] = [
        "network_egress",
        "assets_read",
        "credential_binding_use",
    ]
    manifest = ExtensionManifest.model_validate(missing_permission)
    assert manifest.entrypoint.credential_binding == "vault.acme-extension"


def test_registry_rejects_incompatible_api_range() -> None:
    payload = _http_manifest()
    payload["api_compatibility"] = {
        "minimum": "2.0.0",
        "maximum_exclusive": "3.0.0",
    }
    manifest = ExtensionManifest.model_validate(payload)
    registry = ExtensionRegistry(api_version="1.5.0")

    assert not is_api_compatible(manifest, "1.5.0")
    with pytest.raises(IncompatibleExtensionError, match="not 1.5.0"):
        registry.register(manifest)


def test_registry_rejects_duplicate_extension_ids() -> None:
    manifest = ExtensionManifest.model_validate(_http_manifest())
    registry = ExtensionRegistry()

    registry.register(manifest)

    with pytest.raises(DuplicateExtensionIdError, match="already registered"):
        registry.register(manifest)


def test_registry_enforces_host_permission_policy() -> None:
    manifest = ExtensionManifest.model_validate(_http_manifest())
    registry = ExtensionRegistry(allowed_permissions={ExtensionPermission.network_egress})

    with pytest.raises(ExtensionPermissionPolicyError, match="assets_read"):
        registry.register(manifest)


class _QueueConnectorForHttpManifest:
    transport = ExtensionTransport.queue

    async def health(self) -> object:
        return object()

    async def invoke(self, request: object) -> object:
        return request


def test_registry_rejects_connector_transport_mismatch() -> None:
    manifest = ExtensionManifest.model_validate(_http_manifest())

    with pytest.raises(ExtensionConnectorContractError, match="does not match"):
        ExtensionRegistry().register(
            manifest,
            connector=_QueueConnectorForHttpManifest(),  # type: ignore[arg-type]
        )
