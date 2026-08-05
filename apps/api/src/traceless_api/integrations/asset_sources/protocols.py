"""Generic typed protocols for read-only asset sources and HTTP injection."""

from collections.abc import Mapping
from typing import Protocol, TypeVar, runtime_checkable

from traceless_api.integrations.asset_sources.models import AssetSourceSnapshot


class HttpResponse(Protocol):
    @property
    def content(self) -> bytes: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    @property
    def status_code(self) -> int: ...

    def raise_for_status(self) -> None: ...


class AsyncHttpClient(Protocol):
    """Subset shared by ``httpx.AsyncClient`` and network-free test doubles."""

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = False,
    ) -> HttpResponse: ...


RecordT_co = TypeVar("RecordT_co", covariant=True)


@runtime_checkable
class AssetSource(Protocol[RecordT_co]):
    """Provider-neutral boundary consumed by future ingestion orchestration."""

    @property
    def source_name(self) -> str: ...

    async def fetch(self) -> AssetSourceSnapshot[RecordT_co]: ...
