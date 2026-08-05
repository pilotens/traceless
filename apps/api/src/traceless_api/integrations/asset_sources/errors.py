"""Errors raised at the read-only asset-source boundary."""


class AssetSourceError(Exception):
    """Base error for unavailable or rejected asset-source inputs."""


class InvalidAssetSourceUrl(AssetSourceError, ValueError):
    """The configured source URL fails the connector's SSRF baseline."""


class InvalidAssetSourcePayload(AssetSourceError, ValueError):
    """A source response does not satisfy the documented connector contract."""


class AssetSourcePayloadTooLarge(InvalidAssetSourcePayload):
    """A page exceeds the configured byte or structural processing bound."""


class AssetSourceLimitExceeded(InvalidAssetSourcePayload):
    """Pagination would exceed a configured page or record limit."""


class AssetSourceUnavailable(AssetSourceError):
    """The source could not be read after the configured retry policy."""
