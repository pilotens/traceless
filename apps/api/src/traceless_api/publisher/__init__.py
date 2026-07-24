"""Central intelligence publisher for customer-local Traceless deployments."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

    from traceless_api.publisher.config import PublisherSettings


def create_publisher_app(settings: PublisherSettings | None = None) -> FastAPI:
    """Import the ASGI factory lazily so migrations do not create an application."""

    from traceless_api.publisher.app import create_publisher_app as factory

    return factory(settings)


__all__ = ["create_publisher_app"]
