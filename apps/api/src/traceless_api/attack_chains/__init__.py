"""Reachable attack-chain extraction and symbolic reasoning."""

from traceless_api.attack_chains.pipeline import (
    PIPELINE_VERSION,
    StagedExtractionPipeline,
    analysis_input_sha256,
    analyze_document,
    normalize_document,
)
from traceless_api.attack_chains.reasoning import compile_rules, reason
from traceless_api.attack_chains.vocabulary import DEFAULT_VOCABULARY, PredicateVocabulary

__all__ = [
    "DEFAULT_VOCABULARY",
    "PIPELINE_VERSION",
    "PredicateVocabulary",
    "StagedExtractionPipeline",
    "analysis_input_sha256",
    "analyze_document",
    "compile_rules",
    "normalize_document",
    "reason",
]
