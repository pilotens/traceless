"""Shared response and validation types."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base model that rejects accidental/unknown API fields."""

    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"
    service: str = "traceless-api"
    version: str


class ReadinessResponse(StrictModel):
    status: Literal["ready", "not_ready"]
    checks: dict[str, Literal["ready", "not_ready"]]
