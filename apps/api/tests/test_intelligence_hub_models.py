from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from traceless_api.models.intelligence_hub import (
    AiAnalysis,
    CanonicalIntelFeed,
    CanonicalIntelRecord,
    IndicatorObservable,
    VulnerabilitySignals,
)

NOW = datetime.now(UTC)
CPE = "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"


def _record() -> dict[str, object]:
    return {
        "source_kind": "news",
        "provider": "test-provider",
        "external_id": "record-1",
        "record_type": "threat",
        "title": "A concrete intelligence record",
        "summary": "Source-grounded summary for contract validation.",
        "source_url": "https://example.test/record-1",
        "published_at": (NOW - timedelta(hours=1)).isoformat(),
        "modified_at": NOW.isoformat(),
        "retrieved_at": NOW.isoformat(),
        "severity": "high",
        "confidence": 0.8,
        "cve_ids": ["CVE-2026-12345"],
        "cpes": [CPE],
        "affected_products": ["Apache httpd"],
        "mitre_attack_ids": ["T1190", "T1059.001"],
        "indicators": [{"type": "domain", "value": "host.example.test"}],
        "tags": ["campaign"],
        "sectors": ["finance"],
        "regions": ["SE"],
        "markings": ["TLP:CLEAR"],
        "valid_from": NOW.isoformat(),
        "valid_until": (NOW + timedelta(days=1)).isoformat(),
        "revoked": False,
        "raw_evidence": {"source_id": "record-1"},
        "ai_analysis": None,
        "vulnerability": None,
    }


@pytest.mark.parametrize(
    ("indicator_type", "value"),
    [
        ("ipv4", "2001:db8::1"),
        ("ipv6", "192.0.2.1"),
        ("domain", "localhost"),
        ("domain", "-bad.example"),
        ("url", "relative/path"),
        ("file_sha256", "not-a-hash"),
        ("email", "missing-at.example"),
    ],
)
def test_indicator_contract_rejects_ambiguous_values(
    indicator_type: str, value: str
) -> None:
    with pytest.raises(ValidationError):
        IndicatorObservable.model_validate({"type": indicator_type, "value": value})


def test_indicator_contract_accepts_normalized_misp_shapes() -> None:
    for fixture in [
        {"type": "ipv4", "value": "192.0.2.1"},
        {"type": "ipv6", "value": "2001:db8::1"},
        {"type": "url", "value": "https://host.example.test/path"},
        {"type": "file_sha256", "value": "a" * 64},
        {"type": "email", "value": "soc@example.test"},
    ]:
        assert IndicatorObservable.model_validate(fixture).value == fixture["value"]


def test_ai_analysis_rejects_duplicate_and_unbounded_entities() -> None:
    base = {
        "model_name": "classifier",
        "prompt_version": "3",
        "taxonomy_version": "2",
        "analyzed_at": NOW.isoformat(),
        "confidence": 0.8,
    }
    with pytest.raises(ValidationError, match="categories must contain unique"):
        AiAnalysis.model_validate({**base, "categories": ["Threat", "threat"]})
    with pytest.raises(ValidationError, match="at most 50 entity types"):
        AiAnalysis.model_validate(
            {**base, "extracted_entities": {f"key-{index}": [] for index in range(51)}}
        )
    with pytest.raises(ValidationError, match="entity type names"):
        AiAnalysis.model_validate({**base, "extracted_entities": {"": ["value"]}})


def test_vulnerability_signals_require_concrete_consistent_values() -> None:
    with pytest.raises(ValidationError, match="affected_cpes must contain unique"):
        VulnerabilitySignals(affected_cpes=[CPE, CPE])
    with pytest.raises(ValidationError, match="concrete product"):
        VulnerabilitySignals(affected_cpes=["cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*"])
    with pytest.raises(ValidationError, match="cvss_vector requires cvss_score"):
        VulnerabilitySignals(affected_cpes=[CPE], cvss_vector="CVSS:3.1/AV:N")
    with pytest.raises(ValidationError, match="CWE"):
        VulnerabilitySignals(affected_cpes=[CPE], cwe_ids=["not-cwe"])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("cve_ids", ["CVE-bad"], "CVE-YYYY"),
        ("cpes", ["not-a-cpe"], "concrete CPE"),
        ("mitre_attack_ids", ["T1"], "T####"),
        ("affected_products", ["Apache", "apache"], "unique"),
    ],
)
def test_record_rejects_invalid_normalized_links(
    field: str, value: object, message: str
) -> None:
    fixture = _record()
    fixture[field] = value
    with pytest.raises(ValidationError, match=message):
        CanonicalIntelRecord.model_validate(fixture)


def test_record_enforces_time_type_indicator_and_raw_evidence_boundaries() -> None:
    fixture = _record()
    fixture["modified_at"] = (NOW - timedelta(days=1)).isoformat()
    with pytest.raises(ValidationError, match="must not precede"):
        CanonicalIntelRecord.model_validate(fixture)

    fixture = _record()
    fixture["valid_until"] = (NOW - timedelta(days=1)).isoformat()
    with pytest.raises(ValidationError, match="valid_until"):
        CanonicalIntelRecord.model_validate(fixture)

    fixture = _record()
    fixture["indicators"] = [
        {"type": "domain", "value": "host.example.test"},
        {"type": "domain", "value": "HOST.EXAMPLE.TEST"},
    ]
    with pytest.raises(ValidationError, match="indicators must have unique"):
        CanonicalIntelRecord.model_validate(fixture)

    fixture = _record()
    fixture["raw_evidence"] = {"score": float("nan")}
    with pytest.raises(ValidationError, match="finite JSON"):
        CanonicalIntelRecord.model_validate(fixture)

    fixture = _record()
    fixture["raw_evidence"] = {"body": "x" * 262_145}
    with pytest.raises(ValidationError, match="256 KiB"):
        CanonicalIntelRecord.model_validate(fixture)


def test_vulnerability_shape_and_feed_identity_are_enforced() -> None:
    fixture = _record()
    fixture["record_type"] = "vulnerability"
    with pytest.raises(ValidationError, match="require cve_ids and vulnerability"):
        CanonicalIntelRecord.model_validate(fixture)

    fixture = _record()
    fixture["vulnerability"] = {"affected_cpes": [CPE]}
    with pytest.raises(ValidationError, match="only valid for vulnerability"):
        CanonicalIntelRecord.model_validate(fixture)

    item = CanonicalIntelRecord.model_validate(_record())
    with pytest.raises(ValidationError, match="unique provider/external_id"):
        CanonicalIntelFeed(
            feed_id="test-feed",
            feed_version="1",
            generated_at=NOW,
            items=[item, deepcopy(item)],
        )
