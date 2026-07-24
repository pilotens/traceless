"""In-memory descriptor registry with API and permission compatibility checks."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from threading import RLock

from traceless_api.extensions.connectors import ExtensionConnector
from traceless_api.extensions.models import (
    CURRENT_EXTENSION_API_VERSION,
    ExtensionManifest,
    ExtensionPermission,
    ExtensionTransport,
    api_version_key,
)


class ExtensionRegistryError(ValueError):
    pass


class IncompatibleExtensionError(ExtensionRegistryError):
    pass


class DuplicateExtensionIdError(ExtensionRegistryError):
    pass


class ExtensionPermissionPolicyError(ExtensionRegistryError):
    pass


class ExtensionConnectorContractError(ExtensionRegistryError):
    pass


class ExtensionNotFoundError(KeyError):
    pass


def is_api_compatible(
    manifest: ExtensionManifest,
    api_version: str = CURRENT_EXTENSION_API_VERSION,
) -> bool:
    api_version_key(api_version)
    return manifest.api_compatibility.supports(api_version)


def validate_manifest_compatibility(
    manifest: ExtensionManifest,
    api_version: str = CURRENT_EXTENSION_API_VERSION,
) -> None:
    if not is_api_compatible(manifest, api_version):
        compatibility = manifest.api_compatibility
        raise IncompatibleExtensionError(
            f"extension {manifest.id} supports API >= {compatibility.minimum} and "
            f"< {compatibility.maximum_exclusive}, not {api_version}"
        )


@dataclass(frozen=True, slots=True)
class RegisteredExtension:
    manifest: ExtensionManifest
    connector: ExtensionConnector | None = None


class ExtensionRegistry:
    """Registers descriptors and injected connectors without loading extension code."""

    def __init__(
        self,
        *,
        api_version: str = CURRENT_EXTENSION_API_VERSION,
        allowed_permissions: Iterable[ExtensionPermission] | None = None,
    ) -> None:
        api_version_key(api_version)
        self._api_version = api_version
        try:
            self._allowed_permissions = frozenset(
                ExtensionPermission(permission)
                for permission in (
                    allowed_permissions
                    if allowed_permissions is not None
                    else tuple(ExtensionPermission)
                )
            )
        except (TypeError, ValueError) as exc:
            raise ExtensionPermissionPolicyError(
                "permission policy contains an unknown value"
            ) from exc
        self._extensions: dict[str, RegisteredExtension] = {}
        self._lock = RLock()

    @property
    def api_version(self) -> str:
        return self._api_version

    def register(
        self,
        manifest: ExtensionManifest,
        *,
        connector: ExtensionConnector | None = None,
    ) -> RegisteredExtension:
        validate_manifest_compatibility(manifest, self._api_version)
        denied = set(manifest.permissions).difference(self._allowed_permissions)
        if denied:
            names = ", ".join(sorted(permission.value for permission in denied))
            raise ExtensionPermissionPolicyError(
                f"extension {manifest.id} requests permissions denied by policy: {names}"
            )
        if connector is not None:
            _validate_connector(manifest, connector)

        registered = RegisteredExtension(manifest=manifest, connector=connector)
        with self._lock:
            if manifest.id in self._extensions:
                raise DuplicateExtensionIdError(
                    f"extension id {manifest.id!r} is already registered"
                )
            self._extensions[manifest.id] = registered
        return registered

    def get(self, extension_id: str) -> RegisteredExtension:
        with self._lock:
            try:
                return self._extensions[extension_id]
            except KeyError as exc:
                raise ExtensionNotFoundError(extension_id) from exc

    def list(self) -> tuple[RegisteredExtension, ...]:
        with self._lock:
            return tuple(self._extensions[key] for key in sorted(self._extensions))

    def unregister(self, extension_id: str) -> RegisteredExtension:
        with self._lock:
            try:
                return self._extensions.pop(extension_id)
            except KeyError as exc:
                raise ExtensionNotFoundError(extension_id) from exc

    def __len__(self) -> int:
        with self._lock:
            return len(self._extensions)


def _validate_connector(
    manifest: ExtensionManifest,
    connector: ExtensionConnector,
) -> None:
    try:
        transport = ExtensionTransport(connector.transport)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExtensionConnectorContractError(
            "connector must declare a supported out-of-process transport"
        ) from exc
    if transport is not manifest.entrypoint.transport:
        raise ExtensionConnectorContractError(
            f"connector transport {transport.value} does not match manifest transport "
            f"{manifest.entrypoint.transport.value}"
        )
    if not callable(getattr(connector, "health", None)) or not callable(
        getattr(connector, "invoke", None)
    ):
        raise ExtensionConnectorContractError(
            "connector must implement async health() and invoke() operations"
        )
