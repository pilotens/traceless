"""Traffic Light Protocol normalization and fail-closed dissemination rules."""

from __future__ import annotations

from collections.abc import Iterable

TLP_CLEAR = "TLP:CLEAR"
TLP_GREEN = "TLP:GREEN"
TLP_AMBER = "TLP:AMBER"
TLP_AMBER_STRICT = "TLP:AMBER+STRICT"
TLP_RED = "TLP:RED"

TLP_MARKINGS = (
    TLP_CLEAR,
    TLP_GREEN,
    TLP_AMBER,
    TLP_AMBER_STRICT,
    TLP_RED,
)

_ALIASES = {
    "TLP:WHITE": TLP_CLEAR,
    "TLP:CLEAR": TLP_CLEAR,
    "TLP:GREEN": TLP_GREEN,
    "TLP:AMBER": TLP_AMBER,
    "TLP:AMBER+STRICT": TLP_AMBER_STRICT,
    "TLP:RED": TLP_RED,
}

_RESTRICTIVENESS = {
    TLP_CLEAR: 0,
    TLP_GREEN: 1,
    TLP_AMBER: 2,
    TLP_AMBER_STRICT: 3,
    TLP_RED: 4,
}


def normalize_markings(values: Iterable[str]) -> list[str]:
    """Canonicalize TLP 2.0, reject ambiguous labels and add a safe default."""

    normalized: list[str] = []
    seen: set[str] = set()
    tlp: str | None = None
    for raw_value in values:
        value = raw_value.strip()
        if not value:
            raise ValueError("markings must not contain empty values")
        if len(value) > 160:
            raise ValueError("markings must not exceed 160 characters")
        canonical = _ALIASES.get(value.upper(), value)
        if canonical.upper().startswith("TLP:") and canonical not in TLP_MARKINGS:
            raise ValueError("markings contain an unsupported TLP label")
        if canonical in TLP_MARKINGS:
            if tlp is not None and canonical != tlp:
                raise ValueError("a record must not contain conflicting TLP markings")
            tlp = canonical
        identity = canonical.casefold()
        if identity in seen:
            raise ValueError("markings must contain unique values")
        seen.add(identity)
        normalized.append(canonical)

    if tlp is None:
        # Unmarked intelligence is not assumed to be public. TLP:AMBER keeps it
        # inside the authenticated recipient organization until classified.
        normalized.insert(0, TLP_AMBER)
    return normalized


def tlp_marking(values: Iterable[str]) -> str:
    """Return the effective TLP label; legacy unmarked rows default to AMBER."""

    for value in values:
        canonical = _ALIASES.get(value.strip().upper())
        if canonical is not None:
            return canonical
    return TLP_AMBER


def most_restrictive_tlp(markings: Iterable[Iterable[str]]) -> str:
    """Return the most restrictive effective TLP label in a collection."""

    labels = [tlp_marking(values) for values in markings]
    # Operational reports contain tenant inventory even when no imported CTI
    # carries a marking, so an empty collection must never imply public data.
    return max(labels, key=_RESTRICTIVENESS.__getitem__, default=TLP_AMBER)


def is_more_restrictive_tlp(current: str, previous: str) -> bool:
    """Return whether a current TLP label narrows a prior dissemination grant."""

    normalized_current = _ALIASES.get(current.strip().upper())
    normalized_previous = _ALIASES.get(previous.strip().upper())
    if normalized_current is None or normalized_previous is None:
        # Stored reports are a dissemination boundary. Unknown historic labels
        # must not silently make a later export less restrictive.
        return True
    return _RESTRICTIVENESS[normalized_current] > _RESTRICTIVENESS[normalized_previous]


def permits_automated_processing(values: Iterable[str]) -> bool:
    """TLP:RED requires named-recipient controls and is never auto-correlated."""

    return tlp_marking(values) != TLP_RED


def permits_org_export(values: Iterable[str]) -> bool:
    """Only data permitted to remain within the recipient organization may export."""

    return tlp_marking(values) != TLP_RED
