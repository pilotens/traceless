"""Stable pagination envelopes shared by high-cardinality API collections."""

from pydantic import Field, model_validator

from traceless_api.models.common import StrictModel


class Page[ItemT](StrictModel):
    items: list[ItemT]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)
    has_more: bool

    @model_validator(mode="after")
    def metadata_matches_items(self) -> "Page[ItemT]":
        if len(self.items) > self.limit:
            raise ValueError("page contains more items than its declared limit")
        if self.offset > self.total and self.items:
            raise ValueError("page beyond the result set cannot contain items")
        expected_more = self.offset + len(self.items) < self.total
        if self.has_more != expected_more:
            raise ValueError("has_more is inconsistent with total, offset and items")
        return self

    @classmethod
    def from_items(
        cls,
        items: list[ItemT],
        *,
        total: int,
        limit: int,
        offset: int,
    ) -> "Page[ItemT]":
        return cls(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_more=offset + len(items) < total,
        )
