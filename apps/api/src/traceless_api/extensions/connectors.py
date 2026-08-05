"""Out-of-process connector contracts for extension hosts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable
from uuid import UUID

from traceless_api.extensions.models import (
    CURRENT_EXTENSION_API_VERSION,
    ExtensionCapability,
    ExtensionTransport,
)

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class ExtensionResponseStatus(StrEnum):
    succeeded = "succeeded"
    failed = "failed"
    partial = "partial"


@dataclass(frozen=True, slots=True)
class ExtensionRequest:
    request_id: UUID
    extension_id: str
    capability: ExtensionCapability
    payload: Mapping[str, JsonValue]
    deadline_at: datetime
    api_version: str = CURRENT_EXTENSION_API_VERSION

    def __post_init__(self) -> None:
        if self.deadline_at.tzinfo is None or self.deadline_at.utcoffset() is None:
            raise ValueError("extension request deadline_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ExtensionResponse:
    request_id: UUID
    status: ExtensionResponseStatus
    payload: Mapping[str, JsonValue]
    error_code: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        has_error = self.error_code is not None or self.error_message is not None
        if self.status is ExtensionResponseStatus.succeeded and has_error:
            raise ValueError("successful extension responses cannot contain an error")
        if self.status is ExtensionResponseStatus.failed and not has_error:
            raise ValueError("failed extension responses require an error")


@dataclass(frozen=True, slots=True)
class ConnectorHealth:
    healthy: bool
    detail: str = ""


@runtime_checkable
class ExtensionConnector(Protocol):
    """A host-owned connector; implementations communicate out of process only."""

    @property
    def transport(self) -> ExtensionTransport: ...

    async def health(self) -> ConnectorHealth: ...

    async def invoke(self, request: ExtensionRequest) -> ExtensionResponse: ...


@runtime_checkable
class HttpExtensionConnector(Protocol):
    @property
    def transport(self) -> Literal[ExtensionTransport.http]: ...

    async def health(self) -> ConnectorHealth: ...

    async def invoke(self, request: ExtensionRequest) -> ExtensionResponse: ...


@runtime_checkable
class QueueExtensionConnector(Protocol):
    @property
    def transport(self) -> Literal[ExtensionTransport.queue]: ...

    async def health(self) -> ConnectorHealth: ...

    async def invoke(self, request: ExtensionRequest) -> ExtensionResponse: ...
