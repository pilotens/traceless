"""Versioned, declarative extension manifest schema."""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    AnyHttpUrl,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from traceless_api.models.common import StrictModel

EXTENSION_MANIFEST_SCHEMA_VERSION = "1.0"
CURRENT_EXTENSION_API_VERSION = "1.0.0"

ExtensionId = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=100,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
DisplayName = Annotated[str, StringConstraints(min_length=2, max_length=120)]
SemanticVersion = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
            r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
        )
    ),
]
ApiVersion = Annotated[
    str,
    StringConstraints(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"),
]
BindingName = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._/-][a-z0-9]+)*$",
    ),
]
TopicName = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$",
    ),
]
EndpointPath = Annotated[
    str,
    StringConstraints(
        min_length=2,
        max_length=200,
        pattern=r"^/[A-Za-z0-9._~!$&'()*+,;=:@/-]+$",
    ),
]


class ExtensionCapability(StrEnum):
    asset_discovery = "asset_discovery"
    service_inventory = "service_inventory"
    architecture_enrichment = "architecture_enrichment"
    threat_intelligence = "threat_intelligence"
    vulnerability_enrichment = "vulnerability_enrichment"
    risk_enrichment = "risk_enrichment"
    report_export = "report_export"
    notification = "notification"


class ExtensionPermission(StrEnum):
    network_egress = "network_egress"
    queue_publish = "queue_publish"
    queue_consume = "queue_consume"
    credential_binding_use = "credential_binding_use"
    assets_read = "assets_read"
    scan_results_read = "scan_results_read"
    architecture_read = "architecture_read"
    threats_read = "threats_read"
    vulnerabilities_read = "vulnerabilities_read"
    risks_read = "risks_read"
    reports_write = "reports_write"
    notifications_write = "notifications_write"


class ExtensionTransport(StrEnum):
    http = "http"
    queue = "queue"


class ExtensionModel(StrictModel):
    """Immutable strict base for manifest-controlled values."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        from_attributes=False,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


def api_version_key(value: str) -> tuple[int, int, int]:
    if re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value) is None:
        raise ValueError(f"invalid extension API version: {value!r}")
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


class ApiCompatibility(ExtensionModel):
    minimum: ApiVersion
    maximum_exclusive: ApiVersion

    @model_validator(mode="after")
    def ordered_range(self) -> ApiCompatibility:
        if api_version_key(self.minimum) >= api_version_key(self.maximum_exclusive):
            raise ValueError("minimum must be lower than maximum_exclusive")
        return self

    def supports(self, api_version: str) -> bool:
        candidate = api_version_key(api_version)
        return api_version_key(self.minimum) <= candidate < api_version_key(self.maximum_exclusive)


def _validate_endpoint_path(value: str) -> str:
    if any(segment in {".", ".."} for segment in value.split("/")):
        raise ValueError("endpoint paths cannot contain traversal segments")
    if "//" in value:
        raise ValueError("endpoint paths cannot contain empty segments")
    return value


class HttpEntrypoint(ExtensionModel):
    transport: Literal[ExtensionTransport.http]
    base_url: AnyHttpUrl
    invoke_path: EndpointPath = "/v1/invoke"
    health_path: EndpointPath = "/health"
    timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 15
    credential_binding: BindingName | None = None

    @field_validator("invoke_path", "health_path")
    @classmethod
    def safe_endpoint_path(cls, value: str) -> str:
        return _validate_endpoint_path(value)

    @model_validator(mode="after")
    def secure_base_url(self) -> HttpEntrypoint:
        if self.base_url.scheme != "https":
            raise ValueError("HTTP extensions require HTTPS")
        if self.base_url.username is not None or self.base_url.password is not None:
            raise ValueError("credentials must not be embedded in the extension URL")
        if self.base_url.query is not None or self.base_url.fragment is not None:
            raise ValueError("extension base_url cannot contain a query or fragment")
        return self


class QueueEntrypoint(ExtensionModel):
    transport: Literal[ExtensionTransport.queue]
    broker_binding: BindingName
    request_topic: TopicName
    response_topic: TopicName
    timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 30
    credential_binding: BindingName | None = None

    @model_validator(mode="after")
    def distinct_topics(self) -> QueueEntrypoint:
        if self.request_topic == self.response_topic:
            raise ValueError("request_topic and response_topic must differ")
        return self


ExtensionEntrypoint = Annotated[
    HttpEntrypoint | QueueEntrypoint,
    Field(discriminator="transport"),
]

_SENSITIVE_KEY_NAMES = frozenset(
    {
        "accesskey",
        "accesskeyid",
        "apikey",
        "authorization",
        "clientsecret",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "secret",
        "secrets",
        "token",
    }
)
_MAX_MANIFEST_INPUT_NODES = 2048


def _sensitive_paths(value: Any) -> tuple[str, ...]:
    found: list[str] = []
    pending: list[tuple[str, Any]] = [("$", value)]
    visited = 0
    while pending:
        path, current = pending.pop()
        visited += 1
        if visited > _MAX_MANIFEST_INPUT_NODES:
            raise ValueError("extension manifest input is too complex")
        if isinstance(current, Mapping):
            for key, nested in current.items():
                key_text = str(key)
                compact = re.sub(r"[^a-z0-9]", "", key_text.lower())
                child_path = f"{path}.{key_text}"
                if compact in _SENSITIVE_KEY_NAMES:
                    found.append(child_path)
                pending.append((child_path, nested))
        elif isinstance(current, (list, tuple)):
            pending.extend((f"{path}[{index}]", nested) for index, nested in enumerate(current))
    return tuple(sorted(found))


class ExtensionManifest(ExtensionModel):
    manifest_schema_version: Literal[EXTENSION_MANIFEST_SCHEMA_VERSION]
    id: ExtensionId
    name: DisplayName
    description: Annotated[str, StringConstraints(max_length=1000)] = ""
    version: SemanticVersion
    api_compatibility: ApiCompatibility
    capabilities: Annotated[tuple[ExtensionCapability, ...], Field(min_length=1, max_length=32)]
    permissions: Annotated[tuple[ExtensionPermission, ...], Field(max_length=32)] = ()
    entrypoint: ExtensionEntrypoint

    @model_validator(mode="before")
    @classmethod
    def reject_embedded_secrets(cls, value: Any) -> Any:
        sensitive = _sensitive_paths(value)
        if sensitive:
            locations = ", ".join(sensitive)
            raise ValueError(
                "secret-bearing fields are forbidden in extension manifests; "
                f"use credential_binding instead ({locations})"
            )
        return value

    @model_validator(mode="after")
    def validate_declared_access(self) -> ExtensionManifest:
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("capabilities must not contain duplicates")
        if len(set(self.permissions)) != len(self.permissions):
            raise ValueError("permissions must not contain duplicates")

        required_permissions = (
            {ExtensionPermission.network_egress}
            if self.entrypoint.transport is ExtensionTransport.http
            else {ExtensionPermission.queue_publish, ExtensionPermission.queue_consume}
        )
        if self.entrypoint.credential_binding is not None:
            required_permissions.add(ExtensionPermission.credential_binding_use)
        missing = required_permissions.difference(self.permissions)
        if missing:
            names = ", ".join(sorted(permission.value for permission in missing))
            raise ValueError(f"entrypoint requires explicit permissions: {names}")
        return self
