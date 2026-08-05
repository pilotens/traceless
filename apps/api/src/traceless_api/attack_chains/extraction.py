"""Staged deterministic extraction backend and adapter protocol."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from traceless_api.models.attack_chains import (
    AttackBehavior,
    AttackUnit,
    BranchChoice,
    EvidenceSpan,
    Predicate,
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_FILENAME = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|ps1|js|vbs|docm?|docx|pdf|rtf|zip|rar|bin)\b",
    re.IGNORECASE,
)
_PROTOCOL = re.compile(r"\b(HTTPS?|DNS|TCP|UDP|SMB|RDP|SSH)\b", re.IGNORECASE)
_NEGATED_BEHAVIOR = (
    "did not ",
    "was not ",
    "were not ",
    "failed to ",
    "attempted but failed",
    "blocked the ",
    "prevented the ",
    "inte ",
    "kunde inte ",
    "misslyckades med ",
    "blockerade ",
    "förhindrade ",
)

_BEHAVIOR_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "user_action",
        (
            "open",
            "clicked",
            "clicks",
            "enabled macros",
            "enable content",
            "öppnade",
            "klickade",
            "aktiverade makron",
            "aktiverade innehåll",
        ),
    ),
    (
        "delivery",
        (
            "delivered",
            "received",
            "sent",
            "spearphishing",
            "phishing email",
            "attachment",
            "levererades",
            "mottog",
            "skickades",
            "nätfiske",
            "phishingmejl",
            "bilaga",
        ),
    ),
    (
        "download",
        (
            "download",
            "retrieved",
            "fetched",
            "pulled",
            "dropped",
            "laddade ner",
            "hämtade",
            "släppte",
        ),
    ),
    (
        "exploitation",
        (
            "exploited",
            "exploitation",
            "exploit ",
            "leveraged cve-",
            "utnyttjade",
            "exploaterade",
            "exploatering",
            "använde cve-",
        ),
    ),
    (
        "execute",
        (
            "executed",
            "execute",
            "ran ",
            "run ",
            "launched",
            "spawned",
            "körde",
            "startade",
            "exekverade",
        ),
    ),
    (
        "persistence",
        (
            "scheduled task",
            "startup",
            "autorun",
            "persistence",
            "created a service",
            "schemalagd uppgift",
            "autostart",
            "beständighet",
            "skapade en tjänst",
        ),
    ),
    (
        "privilege_escalation",
        (
            "elevated",
            "privilege escalation",
            "administrator",
            "root access",
            "höjde privilegier",
            "privilegieeskalering",
            "administratör",
            "rootåtkomst",
        ),
    ),
    (
        "defense_evasion",
        (
            "disabled antivirus",
            "bypassed",
            "obfuscated",
            "defense evasion",
            "inaktiverade antivirus",
            "kringgick",
            "obfuskerade",
            "försvarsundvikande",
        ),
    ),
    (
        "credential_access",
        (
            "dumped credentials",
            "stole credentials",
            "password",
            "token theft",
            "dumpade autentiseringsuppgifter",
            "stal autentiseringsuppgifter",
            "stal lösenord",
            "lösenord",
            "tokenstöld",
        ),
    ),
    (
        "discovery",
        (
            "enumerated",
            "discovered",
            "system information",
            "network discovery",
            "kartlade",
            "upptäckte",
            "systeminformation",
            "nätverksinventering",
        ),
    ),
    (
        "lateral_movement",
        (
            "lateral movement",
            "psexec",
            "remote desktop",
            "moved to",
            "lateral förflyttning",
            "fjärrskrivbord",
            "förflyttade sig",
        ),
    ),
    (
        "collection",
        (
            "collected",
            "archived",
            "screenshots",
            "keylogging",
            "staged data",
            "samlade in",
            "arkiverade",
            "skärmdumpar",
            "tangentloggning",
            "förberedde data",
        ),
    ),
    (
        "communication",
        (
            "command and control",
            "c2",
            "beacon",
            "connected to",
            "callback",
            "kommando och kontroll",
            "anslöt till",
            "återkopplade",
        ),
    ),
    (
        "exfiltration",
        (
            "exfiltrated",
            "uploaded",
            "sent the archive",
            "data theft",
            "exfiltrerade",
            "laddade upp",
            "skickade arkivet",
            "datastöld",
        ),
    ),
    (
        "impact",
        (
            "encrypted",
            "wiped",
            "deleted",
            "ransomware",
            "disrupted",
            "krypterade",
            "raderade",
            "utpressningsprogram",
            "störde",
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class SkeletonStep:
    sequence: int
    behavior_class: str
    summary: str
    evidence: EvidenceSpan
    confidence: float
    branch: BranchChoice | None = None


@dataclass(frozen=True, slots=True)
class ExtractedConditions:
    preconditions: tuple[Predicate, ...]
    postconditions: tuple[Predicate, ...]


class StagedExtractionBackend(Protocol):
    name: str

    def extract_behavior_skeleton(self, source_text: str) -> list[SkeletonStep]: ...

    def extract_local_conditions(
        self, steps: list[SkeletonStep], index: int
    ) -> ExtractedConditions: ...

    def extract_global_conditions(
        self, source_text: str, steps: list[SkeletonStep], index: int
    ) -> ExtractedConditions: ...

    def extract_initial_facts(self, source_text: str) -> list[Predicate]: ...


class RuleBasedExtractionBackend:
    """Conservative local backend; production LLMs implement the same staged protocol."""

    name = "rule-based-v1"

    def extract_behavior_skeleton(self, source_text: str) -> list[SkeletonStep]:
        sentences = [item.strip() for item in _SENTENCE_SPLIT.split(source_text) if item.strip()]
        steps: list[SkeletonStep] = []
        for sentence_index, sentence in enumerate(sentences):
            lowered = sentence.casefold()
            if any(marker in lowered for marker in _NEGATED_BEHAVIOR):
                continue
            matches: dict[str, tuple[int, float]] = {}
            for behavior_class, keywords in _BEHAVIOR_PATTERNS:
                for keyword in keywords:
                    position = lowered.find(keyword)
                    if position < 0:
                        continue
                    confidence = _behavior_confidence(sentence, keyword)
                    previous = matches.get(behavior_class)
                    if previous is None or position < previous[0] or confidence > previous[1]:
                        matches[behavior_class] = (position, confidence)
            for behavior_class, (_position, confidence) in sorted(
                matches.items(), key=lambda item: item[1][0]
            ):
                sequence = len(steps)
                branch = None
                steps.append(
                    SkeletonStep(
                        sequence=sequence,
                        behavior_class=behavior_class,
                        summary=sentence,
                        evidence=EvidenceSpan(
                            channel="heuristic",
                            quote=sentence[:2_000],
                            sentence_index=sentence_index,
                        ),
                        confidence=confidence,
                        branch=branch,
                    )
                )
                if len(steps) >= 200:
                    return steps
        return steps

    def extract_local_conditions(
        self, steps: list[SkeletonStep], index: int
    ) -> ExtractedConditions:
        step = steps[index]
        context = step.summary
        filename = _first(_FILENAME, context, "payload")
        cve = _first(_CVE, context, "reported_vulnerability").upper()
        protocol = _first(_PROTOCOL, context, "HTTPS").upper()
        behavior_class = step.behavior_class
        pre: list[Predicate] = []
        post: list[Predicate] = []

        if behavior_class == "delivery":
            post.extend(
                [
                    _p("file", "delivered", "victim_host", filename),
                    _p("file", "present", "victim_host", filename),
                ]
            )
        elif behavior_class == "user_action":
            pre.append(_p("file", "delivered", "victim_host", filename))
            post.append(_p("user", "opened", "victim_host", filename))
        elif behavior_class == "download":
            pre.append(_p("network", "reachable", "victim_host", "remote_server", protocol))
            post.append(_p("file", "present", "victim_host", filename))
        elif behavior_class == "exploitation":
            pre.append(_p("host", "vuln_present", "victim_host", cve))
            post.append(_p("privilege", "code_execution", "victim_host", "attacker"))
        elif behavior_class == "execute":
            pre.append(_p("file", "present", "victim_host", filename))
            post.append(_p("process", "running", "victim_host", filename))
        elif behavior_class == "persistence":
            pre.append(_p("privilege", "code_execution", "victim_host", "attacker"))
            post.append(_p("persistence", "established", "victim_host", "reported_mechanism"))
        elif behavior_class == "privilege_escalation":
            pre.append(_p("privilege", "code_execution", "victim_host", "attacker"))
            post.append(_p("privilege", "level", "victim_host", "attacker", "administrator"))
        elif behavior_class == "defense_evasion":
            pre.append(_p("process", "running", "victim_host", "payload"))
            post.append(_p("defense", "disabled", "victim_host", "reported_control"))
        elif behavior_class == "credential_access":
            pre.append(_p("privilege", "code_execution", "victim_host", "attacker"))
            post.append(_p("credential", "obtained", "attacker", "reported_credential"))
        elif behavior_class == "discovery":
            pre.append(_p("privilege", "code_execution", "victim_host", "attacker"))
            post.append(_p("host", "discovered", "attacker", "lateral_host"))
        elif behavior_class == "lateral_movement":
            pre.extend(
                [
                    _p("credential", "obtained", "attacker", "reported_credential"),
                    _p("network", "reachable", "victim_host", "lateral_host", protocol),
                ]
            )
            post.append(_p("host", "access", "lateral_host", "attacker"))
        elif behavior_class == "collection":
            pre.append(_p("privilege", "code_execution", "victim_host", "attacker"))
            post.append(_p("data", "collected", "victim_host", "reported_data"))
        elif behavior_class == "communication":
            pre.append(_p("process", "running", "victim_host", "payload"))
            post.append(_p("data", "c2_channel", "victim_host", "c2_server", protocol))
        elif behavior_class == "exfiltration":
            pre.extend(
                [
                    _p("data", "collected", "victim_host", "reported_data"),
                    _p("data", "c2_channel", "victim_host", "c2_server", protocol),
                ]
            )
            post.append(_p("data", "exfiltrated", "victim_host", "c2_server", "reported_data"))
        elif behavior_class == "impact":
            pre.append(_p("privilege", "code_execution", "victim_host", "attacker"))
            post.append(_p("host", "impacted", "victim_host", "reported_impact"))
        else:
            post.append(_p("host", "state_changed", "victim_host", f"behavior_{index}"))
        return ExtractedConditions(tuple(pre), tuple(post))

    def extract_global_conditions(
        self, source_text: str, steps: list[SkeletonStep], index: int
    ) -> ExtractedConditions:
        step = steps[index]
        local = self.extract_local_conditions(steps, index)
        pre = list(local.preconditions)
        dependencies = {
            "exploitation": ("user_action", "user.opened"),
            "execute": ("download", "file.present"),
            "communication": ("execute", "process.running"),
            "exfiltration": ("collection", "data.collected"),
        }
        dependency = dependencies.get(step.behavior_class)
        if dependency is not None:
            prior_class, predicate_identifier = dependency
            prior = self._latest_postcondition(
                steps,
                index,
                prior_class=prior_class,
                predicate_identifier=predicate_identifier,
            )
            if prior is not None:
                pre = [
                    item for item in pre if item.identifier != predicate_identifier
                ]
                pre.append(prior)
        return ExtractedConditions(tuple(_unique(pre)), local.postconditions)

    def _latest_postcondition(
        self,
        steps: list[SkeletonStep],
        index: int,
        *,
        prior_class: str,
        predicate_identifier: str,
    ) -> Predicate | None:
        for prior_index in range(index - 1, -1, -1):
            if steps[prior_index].behavior_class != prior_class:
                continue
            conditions = self.extract_local_conditions(steps, prior_index)
            return next(
                (
                    predicate
                    for predicate in conditions.postconditions
                    if predicate.identifier == predicate_identifier
                ),
                None,
            )
        return None

    def extract_initial_facts(self, source_text: str) -> list[Predicate]:
        facts: list[Predicate] = []
        positive_terms = (
            "vulnerable", "affected", "exploited", "exploitation",
            "sårbar", "påverkad", "utnyttjade", "exploaterade", "exploatering",
        )
        negative_terms = (
            "not vulnerable", "unaffected", "patched", "not affected",
            "inte sårbar", "opåverkad", "patchad", "inte påverkad",
        )
        sentences = [
            item.strip() for item in _SENTENCE_SPLIT.split(source_text) if item.strip()
        ]
        for sentence in sentences:
            lowered_sentence = sentence.casefold()
            if any(term in lowered_sentence for term in negative_terms):
                continue
            if not any(term in lowered_sentence for term in positive_terms):
                continue
            for cve in _CVE.findall(sentence):
                facts.append(
                    _p("host", "vuln_present", "victim_host", cve.upper())
                )
        lowered = source_text.casefold()
        reachable_terms = (
            "internet-facing", "externally reachable", "could reach",
            "internetexponerad", "externt nåbar", "kunde nå",
        )
        if any(term in lowered for term in reachable_terms):
            protocol = _first(_PROTOCOL, source_text, "HTTPS").upper()
            facts.append(_p("network", "reachable", "attacker", "victim_host", protocol))
        return _unique(facts)


def build_units(
    source_text: str,
    backend: StagedExtractionBackend,
) -> tuple[list[AttackUnit], list[Predicate]]:
    steps = backend.extract_behavior_skeleton(source_text)
    units: list[AttackUnit] = []
    for index, step in enumerate(steps):
        local = backend.extract_local_conditions(steps, index)
        global_conditions = backend.extract_global_conditions(source_text, steps, index)
        preconditions = _fuse(local.preconditions, global_conditions.preconditions)
        postconditions = _fuse(local.postconditions, global_conditions.postconditions)
        attack_ids = [value.upper() for value in _ATTACK_ID.findall(step.summary)]
        units.append(
            AttackUnit(
                unit_id=f"unit-{index + 1}",
                behavior=AttackBehavior(
                    behavior_class=step.behavior_class,  # type: ignore[arg-type]
                    summary=step.summary,
                    sequence=step.sequence,
                    attack_ids=attack_ids,
                    confidence=step.confidence,
                    evidence=[step.evidence],
                ),
                preconditions=preconditions,
                postconditions=postconditions,
                branch=step.branch,
            )
        )
    return units, backend.extract_initial_facts(source_text)


def _behavior_confidence(sentence: str, keyword: str) -> float:
    if _ATTACK_ID.search(sentence):
        return 0.92
    if " " in keyword and len(keyword) >= 12:
        return 0.84
    if len(keyword) >= 8:
        return 0.76
    return 0.68


def _first(pattern: re.Pattern[str], text: str, default: str) -> str:
    match = pattern.search(text)
    return match.group(0) if match else default


def _p(category: str, name: str, *arguments: str) -> Predicate:
    return Predicate(category=category, name=name, arguments=arguments)


def _unique(values: list[Predicate]) -> list[Predicate]:
    return list({value.key: value for value in values}.values())


def _fuse(
    local: tuple[Predicate, ...], global_conditions: tuple[Predicate, ...]
) -> list[Predicate]:
    merged: dict[str, Predicate] = {}
    for predicate in [*local, *global_conditions]:
        merged[predicate.key] = predicate
    return list(merged.values())[:20]
