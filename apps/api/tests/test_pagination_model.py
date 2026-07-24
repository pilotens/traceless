"""Pagination envelope invariants."""

import pytest
from pydantic import ValidationError

from traceless_api.models.pagination import Page


def test_page_computes_continuation_from_total() -> None:
    first = Page[int].from_items([1, 2], total=3, limit=2, offset=0)
    last = Page[int].from_items([3], total=3, limit=2, offset=2)

    assert first.has_more is True
    assert last.has_more is False


def test_page_rejects_inconsistent_metadata() -> None:
    with pytest.raises(ValidationError, match="has_more is inconsistent"):
        Page[int](items=[1], total=1, limit=10, offset=0, has_more=True)
    with pytest.raises(ValidationError, match="more items"):
        Page[int](items=[1, 2], total=2, limit=1, offset=0, has_more=False)
    with pytest.raises(ValidationError, match="beyond the result set"):
        Page[int](items=[1], total=0, limit=10, offset=1, has_more=False)
