"""Versioned behavior and predicate vocabularies for reachable attack chains."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from traceless_api.models.attack_chains import Predicate

BEHAVIOR_CLASSES: Final[tuple[str, ...]] = (
    "user_action",
    "delivery",
    "download",
    "exploitation",
    "execute",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "communication",
    "exfiltration",
    "impact",
    "other",
)


@dataclass(frozen=True, slots=True)
class PredicateSpec:
    category: str
    name: str
    arity: int
    initial_fact_eligible: bool = False
    aliases: tuple[str, ...] = ()

    @property
    def identifier(self) -> str:
        return f"{self.category}.{self.name}"


class PredicateVocabulary:
    """Closed vocabulary used for exact state matching and validation."""

    def __init__(self, *, version: str, specs: tuple[PredicateSpec, ...]) -> None:
        self.version = version
        self._specs = {spec.identifier: spec for spec in specs}
        aliases: dict[str, str] = {}
        for spec in specs:
            aliases[spec.identifier] = spec.identifier
            for alias in spec.aliases:
                aliases[alias.casefold()] = spec.identifier
        self._aliases = aliases

    @property
    def identifiers(self) -> frozenset[str]:
        return frozenset(self._specs)

    def resolve_identifier(self, category: str, name: str) -> str | None:
        identifier = f"{category.casefold()}.{name.casefold()}"
        return self._aliases.get(identifier)

    def spec_for(self, predicate: Predicate) -> PredicateSpec | None:
        resolved = self.resolve_identifier(predicate.category, predicate.name)
        return self._specs.get(resolved) if resolved is not None else None

    def canonicalize(self, predicate: Predicate) -> Predicate:
        resolved = self.resolve_identifier(predicate.category, predicate.name)
        if resolved is None:
            return Predicate(
                category=predicate.category.casefold(),
                name=predicate.name.casefold(),
                arguments=tuple(_canonical_argument(value) for value in predicate.arguments),
            )
        category, name = resolved.split(".", 1)
        return Predicate(
            category=category,
            name=name,
            arguments=tuple(_canonical_argument(value) for value in predicate.arguments),
        )

    def validation_error(self, predicate: Predicate) -> str | None:
        spec = self.spec_for(predicate)
        if spec is None:
            return f"Predicate {predicate.identifier} is not in vocabulary {self.version}."
        if len(predicate.arguments) != spec.arity:
            return (
                f"Predicate {spec.identifier} expects {spec.arity} arguments, "
                f"received {len(predicate.arguments)}."
            )
        return None

    def initial_fact_eligible(self, predicate: Predicate) -> bool:
        spec = self.spec_for(predicate)
        return bool(spec and spec.initial_fact_eligible)


def _canonical_argument(value: str) -> str:
    normalized = "_".join(value.strip().split())
    aliases = {
        "adversary": "attacker",
        "threat_actor": "attacker",
        "target": "victim_host",
        "target_host": "victim_host",
        "victim": "victim_host",
        "compromised_host": "victim_host",
        "command_and_control_server": "c2_server",
        "command-control-server": "c2_server",
        "command_control_server": "c2_server",
        "malware": "payload",
        "implant": "payload",
    }
    casefolded = normalized.casefold()
    if casefolded.startswith("cve-"):
        return casefolded.upper()
    if casefolded in {"http", "https", "dns", "tcp", "udp", "smb", "rdp", "ssh"}:
        return casefolded.upper()
    return aliases.get(casefolded, casefolded)


DEFAULT_VOCABULARY = PredicateVocabulary(
    version="traceless-reachable-chain-v1",
    specs=(
        PredicateSpec("network", "reachable", 3, True, ("network.can_reach",)),
        PredicateSpec("host", "vuln_present", 2, True, ("host.vulnerable",)),
        PredicateSpec("host", "software_present", 2, True),
        PredicateSpec("identity", "account_exists", 2, True),
        PredicateSpec("file", "delivered", 2),
        PredicateSpec("file", "present", 2),
        PredicateSpec("user", "opened", 2),
        PredicateSpec("user", "enabled_content", 2),
        PredicateSpec("privilege", "code_execution", 2),
        PredicateSpec("privilege", "level", 3),
        PredicateSpec("process", "running", 2),
        PredicateSpec("persistence", "established", 2),
        PredicateSpec("defense", "disabled", 2),
        PredicateSpec("credential", "obtained", 2),
        PredicateSpec("host", "discovered", 2),
        PredicateSpec("host", "access", 2),
        PredicateSpec("network", "session", 3),
        PredicateSpec("data", "collected", 2),
        PredicateSpec("data", "archived", 2),
        PredicateSpec("data", "c2_channel", 3),
        PredicateSpec("data", "exfiltrated", 3),
        PredicateSpec("host", "impacted", 2),
        PredicateSpec("host", "state_changed", 2),
    ),
)
