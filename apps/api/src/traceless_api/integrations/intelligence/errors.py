"""Errors raised at the threat-intelligence integration boundary."""


class IntelligenceIntegrationError(Exception):
    """Base error for rejected or unavailable intelligence inputs."""


class InvalidIntelligencePayload(IntelligenceIntegrationError, ValueError):
    """The provider response does not satisfy its documented contract."""


class IntelligencePayloadTooLarge(InvalidIntelligencePayload):
    """The provider response exceeds the configured processing bound."""


class UnexpectedContentType(InvalidIntelligencePayload):
    """The provider returned an explicitly non-JSON media type."""
