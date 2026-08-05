import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from secrets import token_urlsafe

import pytest

from traceless_api.integrations.intelligence import (
    CisaKevProvider,
    CvssMetric,
    FirstEpssProvider,
    IntelligencePayloadTooLarge,
    InternalThreatFeedProvider,
    InvalidIntelligencePayload,
    KevCatalogEntry,
    SourceProvenance,
    parse_cisa_kev,
    parse_first_epss,
    parse_internal_threat_feed,
)

RETRIEVED_AT = datetime(2026, 7, 17, 10, 30, tzinfo=UTC)
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
INTERNAL_URL = "https://threat.example.test/v1/feed"


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _kev_payload() -> dict[str, object]:
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.07.17",
        "dateReleased": "2026-07-17T09:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2099-12345",
                "vendorProject": "Example Vendor",
                "product": "Example Gateway",
                "vulnerabilityName": "Example Gateway Code Execution",
                "dateAdded": "2026-07-15",
                "shortDescription": "An authenticated attacker can execute code.",
                "requiredAction": "Apply mitigations or discontinue use.",
                "dueDate": "2026-08-05",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "Use the vendor advisory for supported releases.",
                "cwes": ["CWE-78"],
            }
        ],
    }


def _epss_payload(*, probability: str = "0.734250000") -> dict[str, object]:
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": 1,
        "offset": 0,
        "limit": 100,
        "data": [
            {
                "cve": "CVE-2099-12345",
                "epss": probability,
                "percentile": "0.981230000",
                "date": "2026-07-17",
            }
        ],
    }


def _internal_feed_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "feed_id": "internal-threat-feed",
        "feed_version": "2026-07-17.1",
        "generated_at": "2026-07-17T10:00:00Z",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--11111111-1111-4111-8111-111111111111",
                "created": "2026-07-17T08:00:00Z",
                "modified": "2026-07-17T09:30:00Z",
                "name": "Example command-and-control address",
                "confidence": 80,
                "labels": ["command-and-control"],
                "cve_ids": ["CVE-2099-12345"],
                "mitre_attack_ids": ["T1071.001"],
                "pattern": "[ipv4-addr:value = '203.0.113.25']",
                "pattern_type": "stix",
                "valid_from": "2026-07-17T08:00:00Z",
                "external_references": [
                    {
                        "source_name": "internal-case-system",
                        "external_id": "CASE-2481",
                    }
                ],
            }
        ],
    }


@dataclass
class StubResponse:
    content: bytes
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    status_checked: bool = False

    def raise_for_status(self) -> None:
        self.status_checked = True


class RecordingHttpClient:
    def __init__(self, response: StubResponse) -> None:
        self.response = response
        self.requests: list[dict[str, object]] = []

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> StubResponse:
        self.requests.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
                "timeout": timeout,
            }
        )
        return self.response


def test_cisa_kev_parser_preserves_catalogue_semantics_and_provenance() -> None:
    payload = _json_bytes(_kev_payload())

    batch = parse_cisa_kev(
        payload,
        source_url=CISA_URL,
        retrieved_at=RETRIEVED_AT,
    )

    assert len(batch.records) == 1
    record = batch.records[0]
    assert record.cve_id == "CVE-2099-12345"
    assert record.known_ransomware_campaign_use.value == "unknown"
    assert "score" not in KevCatalogEntry.model_fields
    assert batch.provenance.source_version == "2026.07.17"
    assert batch.provenance.source_updated_at == datetime(2026, 7, 17, 9, tzinfo=UTC)
    assert batch.provenance.payload_sha256 == sha256(payload).hexdigest()
    assert record.provenance.source_record_id == record.cve_id
    assert record.provenance.retrieved_at == RETRIEVED_AT


def test_cisa_kev_parser_rejects_count_mismatch() -> None:
    source = _kev_payload()
    source["count"] = 2

    with pytest.raises(InvalidIntelligencePayload, match="schema validation"):
        parse_cisa_kev(
            _json_bytes(source),
            source_url=CISA_URL,
            retrieved_at=RETRIEVED_AT,
        )


def test_cisa_kev_parser_rejects_an_empty_authoritative_catalogue() -> None:
    source = _kev_payload()
    source["count"] = 0
    source["vulnerabilities"] = []

    with pytest.raises(InvalidIntelligencePayload, match="schema validation"):
        parse_cisa_kev(
            _json_bytes(source),
            source_url=CISA_URL,
            retrieved_at=RETRIEVED_AT,
        )


def test_first_epss_parser_preserves_decimal_probability_and_model_date() -> None:
    batch = parse_first_epss(
        _json_bytes(_epss_payload()),
        source_url=EPSS_URL,
        retrieved_at=RETRIEVED_AT,
    )

    record = batch.records[0]
    assert record.probability == Decimal("0.734250000")
    assert record.percentile == Decimal("0.981230000")
    assert record.model_date.isoformat() == "2026-07-17"
    assert record.provenance.source_record_id == "CVE-2099-12345@2026-07-17"
    assert record.provenance.source_updated_at == datetime(2026, 7, 17, tzinfo=UTC)
    assert not hasattr(record, "cvss_score")
    assert not hasattr(record, "is_kev")


def test_first_epss_parser_rejects_out_of_range_probability() -> None:
    with pytest.raises(InvalidIntelligencePayload, match="schema validation"):
        parse_first_epss(
            _json_bytes(_epss_payload(probability="1.00001")),
            source_url=EPSS_URL,
            retrieved_at=RETRIEVED_AT,
        )


def test_internal_feed_parser_validates_stix_shape_and_preserves_object_lineage() -> None:
    payload = _json_bytes(_internal_feed_payload())

    batch = parse_internal_threat_feed(
        payload,
        source_url=INTERNAL_URL,
        retrieved_at=RETRIEVED_AT,
    )

    record = batch.records[0]
    assert record.type.value == "indicator"
    assert record.mitre_attack_ids == ("T1071.001",)
    assert record.cve_ids == ("CVE-2099-12345",)
    assert record.provenance.source_feed_id == "internal-threat-feed"
    assert record.provenance.source_record_id == record.id
    assert record.provenance.source_updated_at == datetime(2026, 7, 17, 9, 30, tzinfo=UTC)
    assert record.provenance.payload_sha256 == sha256(payload).hexdigest()


def test_internal_feed_parser_rejects_incomplete_relationship() -> None:
    source = _internal_feed_payload()
    source["objects"] = [
        {
            "type": "relationship",
            "id": "relationship--22222222-2222-4222-8222-222222222222",
            "created": "2026-07-17T08:00:00Z",
            "modified": "2026-07-17T08:00:00Z",
        }
    ]

    with pytest.raises(InvalidIntelligencePayload, match="schema validation"):
        parse_internal_threat_feed(
            _json_bytes(source),
            source_url=INTERNAL_URL,
            retrieved_at=RETRIEVED_AT,
        )


def test_providers_use_injected_http_client_without_network_calls() -> None:
    kev_response = StubResponse(_json_bytes(_kev_payload()))
    kev_client = RecordingHttpClient(kev_response)
    kev_provider = CisaKevProvider(
        kev_client,
        CISA_URL,
        clock=lambda: RETRIEVED_AT,
    )
    kev_batch = asyncio.run(kev_provider.fetch())

    epss_response = StubResponse(_json_bytes(_epss_payload()))
    epss_client = RecordingHttpClient(epss_response)
    epss_provider = FirstEpssProvider(
        epss_client,
        EPSS_URL,
        cve_ids=("CVE-2099-12345",),
        clock=lambda: RETRIEVED_AT,
    )
    epss_batch = asyncio.run(epss_provider.fetch())

    assert kev_response.status_checked is True
    assert kev_client.requests[0]["headers"] == {"Accept": "application/json"}
    assert kev_batch.records[0].cve_id == "CVE-2099-12345"
    assert epss_response.status_checked is True
    assert epss_client.requests[0]["params"] == {"cve": "CVE-2099-12345"}
    assert epss_batch.records[0].probability == Decimal("0.734250000")


def test_internal_provider_sends_token_but_does_not_add_it_to_provenance() -> None:
    response = StubResponse(_json_bytes(_internal_feed_payload()))
    client = RecordingHttpClient(response)
    credential = token_urlsafe(32)
    provider = InternalThreatFeedProvider(
        client,
        INTERNAL_URL,
        token=credential,
        clock=lambda: RETRIEVED_AT,
    )

    batch = asyncio.run(provider.fetch())

    assert client.requests[0]["headers"] == {
        "Accept": "application/json",
        "Authorization": f"Bearer {credential}",
    }
    assert credential not in batch.model_dump_json()


def test_provider_rejects_declared_oversized_response_before_parsing() -> None:
    response = StubResponse(
        b"{}",
        headers={
            "Content-Type": "application/json",
            "Content-Length": "1001",
        },
    )
    provider = CisaKevProvider(
        RecordingHttpClient(response),
        CISA_URL,
        max_payload_bytes=1_000,
        clock=lambda: RETRIEVED_AT,
    )

    with pytest.raises(IntelligencePayloadTooLarge):
        asyncio.run(provider.fetch())


def test_cvss_model_remains_an_independent_provider_attributed_signal() -> None:
    provenance = SourceProvenance(
        provider="example-cvss-source",
        source_url="https://vulnerability.example/api",
        source_record_id="CVE-2099-12345",
        source_version="2026-07-17",
        source_updated_at=RETRIEVED_AT,
        retrieved_at=RETRIEVED_AT,
        payload_sha256="0" * 64,
    )

    metric = CvssMetric(
        cve_id="CVE-2099-12345",
        version="4.0",
        score=Decimal("9.3"),
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        provenance=provenance,
    )

    assert metric.score == Decimal("9.3")
    assert not hasattr(metric, "epss_probability")
    assert not hasattr(metric, "is_kev")
