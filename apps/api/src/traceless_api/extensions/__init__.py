"""Declarative, out-of-process extension SDK contracts.

Manifests describe capabilities, permissions and HTTP/queue endpoints only. This
package intentionally provides no Python module loader, dynamic import or process
execution facility.
"""

from traceless_api.extensions.connectors import (
    ConnectorHealth,
    ExtensionConnector,
    ExtensionRequest,
    ExtensionResponse,
    ExtensionResponseStatus,
    HttpExtensionConnector,
    QueueExtensionConnector,
)
from traceless_api.extensions.models import (
    CURRENT_EXTENSION_API_VERSION,
    EXTENSION_MANIFEST_SCHEMA_VERSION,
    ApiCompatibility,
    ExtensionCapability,
    ExtensionEntrypoint,
    ExtensionManifest,
    ExtensionPermission,
    ExtensionTransport,
    HttpEntrypoint,
    QueueEntrypoint,
)
from traceless_api.extensions.registry import (
    DuplicateExtensionIdError,
    ExtensionConnectorContractError,
    ExtensionNotFoundError,
    ExtensionPermissionPolicyError,
    ExtensionRegistry,
    ExtensionRegistryError,
    IncompatibleExtensionError,
    RegisteredExtension,
    is_api_compatible,
    validate_manifest_compatibility,
)

__all__ = [
    "CURRENT_EXTENSION_API_VERSION",
    "EXTENSION_MANIFEST_SCHEMA_VERSION",
    "ApiCompatibility",
    "ConnectorHealth",
    "DuplicateExtensionIdError",
    "ExtensionCapability",
    "ExtensionConnector",
    "ExtensionConnectorContractError",
    "ExtensionEntrypoint",
    "ExtensionManifest",
    "ExtensionNotFoundError",
    "ExtensionPermission",
    "ExtensionPermissionPolicyError",
    "ExtensionRegistry",
    "ExtensionRegistryError",
    "ExtensionRequest",
    "ExtensionResponse",
    "ExtensionResponseStatus",
    "ExtensionTransport",
    "HttpEntrypoint",
    "HttpExtensionConnector",
    "IncompatibleExtensionError",
    "QueueEntrypoint",
    "QueueExtensionConnector",
    "RegisteredExtension",
    "is_api_compatible",
    "validate_manifest_compatibility",
]
