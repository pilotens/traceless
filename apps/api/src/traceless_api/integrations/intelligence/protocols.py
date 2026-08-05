"""Typed, injectable integration protocols."""

from collections.abc import Mapping
from typing import Protocol, TypeVar

from traceless_api.integrations.intelligence.models import IntelligenceBatch


class HttpResponse(Protocol):
    """Small structural response surface required by the adapters."""

    @property
    def content(self) -> bytes: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    def raise_for_status(self) -> None: ...


class AsyncHttpClient(Protocol):
    """Compatible with an injected ``httpx.AsyncClient`` or a test double."""

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse: ...


RecordT_co = TypeVar("RecordT_co", covariant=True)


class IntelligenceProvider(Protocol[RecordT_co]):
    """Common provider boundary used by orchestration code."""

    @property
    def provider_name(self) -> str: ...

    async def fetch(self) -> IntelligenceBatch[RecordT_co]: ...
