"""Stable local tenant identity used only outside configured OIDC deployments."""

from uuid import UUID

DEFAULT_ORGANIZATION_ID = UUID("00000000-0000-4000-8000-000000000001")
DEFAULT_ORGANIZATION_KEY = "local-traceless"
DEFAULT_ORGANIZATION_NAME = "Local Traceless"
