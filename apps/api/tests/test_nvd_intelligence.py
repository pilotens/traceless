import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from traceless_api.integrations.intelligence import (
    NVD_API_DISCLAIMER,
    InvalidIntelligencePayload,
    NvdCveProvider,
    NvdQuery,
    parse_nvd_cves,
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RETRIEVED_AT = datetime(2026, 7, 17, 12, tzinfo=UTC)
CPE_NAME = "cpe:2.3:a:example:gateway:1.5:*:*:*:*:*:*:*"


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _nvd_payload() -> dict[str, object]:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 3,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-07-17T11:55:00.000",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "sourceIdentifier": "security@example.test",
                    "published": "2026-07-10T08:00:00.000",
                    "lastModified": "2026-07-17T11:00:00.000",
                    "vulnStatus": "Analyzed",
                    "cveTags": [
                        {
                            "sourceIdentifier": "security@example.test",
                            "tags": ["disputed"],
                        }
                    ],
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "An example gateway input validation vulnerability.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV40": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "4.0",
                                    "vectorString": (
                                        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/"
                                        "SC:N/SI:N/SA:N"
                                    ),
                                    "baseScore": 9.3,
                                    "baseSeverity": "CRITICAL",
                                    "attackVector": "NETWORK",
                                },
                            }
                        ],
                        "cvssMetricV31": [
                            {
                                "source": "security@example.test",
                                "type": "Secondary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                    ),
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "attackVector": "NETWORK",
                                },
                                "exploitabilityScore": 3.9,
                                "impactScore": 5.9,
                            }
                        ],
                        "cvssMetricV30": [
                            {
                                "source": "legacy@example.test",
                                "type": "Secondary",
                                "cvssData": {
                                    "version": "3.0",
                                    "vectorString": (
                                        "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
                                    ),
                                    "baseScore": 7.5,
                                    "baseSeverity": "HIGH",
                                },
                                "exploitabilityScore": 1.6,
                                "impactScore": 5.9,
                            }
                        ],
                        "cvssMetricV2": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "baseScore": 7.5,
                                },
                            }
                        ],
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-78"}],
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "negate": False,
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": (
                                                "cpe:2.3:a:example:gateway:*:*:*:*:*:*:*:*"
                                            ),
                                            "matchCriteriaId": (
                                                "1D07F493-9C8D-44A4-8652-F28B46CBA27C"
                                            ),
                                            "versionStartIncluding": "1.0-beta",
                                            "versionEndExcluding": "2.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://advisories.example.test/CVE-2026-12345",
                            "source": "security@example.test",
                            "tags": ["Vendor Advisory"],
                        }
                    ],
                    "evaluatorComment": "Applicability requires configuration evaluation.",
                    "cisaExploitAdd": "2026-07-15",
                    "cisaActionDue": "2026-08-05",
                    "cisaRequiredAction": "Apply mitigations.",
                    "cisaVulnerabilityName": "Example vulnerability",
                    "ssvcV203": [
                        {
                            "source": "11111111-1111-4111-8111-111111111111",
                            "ssvcData": {
                                "version": "2.0.3",
                                "options": [{"exploitation": "poc"}],
                            },
                        }
                    ],
                    "affected": [
                        {
                            "source": "security@example.test",
                            "affectedData": [
                                {
                                    "vendor": "Example",
                                    "product": "Gateway",
                                    "versions": [{"version": "1.5", "status": "affected"}],
                                }
                            ],
                        }
                    ],
                }
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


def test_nvd_parser_preserves_each_cvss_provider_metric_and_provenance() -> None:
    batch = parse_nvd_cves(
        _json_bytes(_nvd_payload()),
        source_url=NVD_URL,
        retrieved_at=RETRIEVED_AT,
    )

    record = batch.records[0]
    assert [metric.version for metric in record.cvss_metrics] == ["4.0", "3.1", "3.0"]
    assert [metric.metric_source for metric in record.cvss_metrics] == [
        "nvd@nist.gov",
        "security@example.test",
        "legacy@example.test",
    ]
    assert record.cvss_metrics[0].score == Decimal("9.3")
    assert record.cvss_metrics[1].exploitability_score == Decimal("3.9")
    assert record.cvss_metrics[2].base_severity == "HIGH"
    assert record.has_legacy_cvss_v2 is True
    assert record.provenance.source_record_id == "CVE-2026-12345"
    assert record.provenance.source_updated_at == datetime(2026, 7, 17, 11, tzinfo=UTC)
    assert all(metric.provenance.provider == "nvd" for metric in record.cvss_metrics)
    assert batch.provenance.source_updated_at == datetime(2026, 7, 17, 11, 55, tzinfo=UTC)


def test_nvd_parser_preserves_cwe_references_and_uninterpreted_applicability() -> None:
    batch = parse_nvd_cves(
        _json_bytes(_nvd_payload()),
        source_url=NVD_URL,
        retrieved_at=RETRIEVED_AT,
    )

    record = batch.records[0]
    assert record.weaknesses[0].descriptions[0].value == "CWE-78"
    assert record.references[0].tags == ("Vendor Advisory",)
    cpe_match = record.applicability_configurations[0].nodes[0].cpe_matches[0]
    assert cpe_match.criteria == "cpe:2.3:a:example:gateway:*:*:*:*:*:*:*:*"
    assert cpe_match.version_start_including == "1.0-beta"
    assert cpe_match.version_end_excluding == "2.0"
    assert not hasattr(record, "is_applicable")
    assert not hasattr(record, "is_kev")


def test_nvd_batch_carries_required_notice_and_pagination() -> None:
    batch = parse_nvd_cves(
        _json_bytes(_nvd_payload()),
        source_url=NVD_URL,
        retrieved_at=RETRIEVED_AT,
    )

    assert batch.disclaimer == NVD_API_DISCLAIMER
    assert batch.next_start_index == 1
    assert batch.total_results == 3


def test_nvd_query_requires_full_concrete_cpe_name() -> None:
    query = NvdQuery(cpe_name=CPE_NAME, results_per_page=100, start_index=200)
    assert query.as_params() == {
        "cpeName": CPE_NAME,
        "resultsPerPage": "100",
        "startIndex": "200",
    }

    with pytest.raises(ValidationError, match="exactly 11 components"):
        NvdQuery(cpe_name="cpe:2.3:a:example:gateway:1.5")
    with pytest.raises(ValidationError, match="concrete vendor, product, and version"):
        NvdQuery(cpe_name="cpe:2.3:a:example:gateway:*:*:*:*:*:*:*:*")


def test_nvd_query_validates_complete_bounded_modified_window() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    query = NvdQuery(
        last_modified_start=start,
        last_modified_end=start + timedelta(days=120),
    )

    assert query.as_params()["lastModStartDate"] == "2026-01-01T00:00:00.000+00:00"
    assert query.as_params()["lastModEndDate"] == "2026-05-01T00:00:00.000+00:00"

    with pytest.raises(ValidationError, match="both start and end"):
        NvdQuery(last_modified_start=start)
    with pytest.raises(ValidationError, match="120 consecutive days"):
        NvdQuery(
            last_modified_start=start,
            last_modified_end=start + timedelta(days=120, seconds=1),
        )
    with pytest.raises(ValidationError):
        NvdQuery(
            last_modified_start=datetime(2026, 1, 1),
            last_modified_end=datetime(2026, 1, 2),
        )


def test_nvd_provider_uses_encoded_params_and_injected_client() -> None:
    response = StubResponse(_json_bytes(_nvd_payload()))
    client = RecordingHttpClient(response)
    start = datetime(2026, 7, 1, tzinfo=UTC)
    query = NvdQuery(
        cpe_name=CPE_NAME,
        last_modified_start=start,
        last_modified_end=start + timedelta(days=16),
        results_per_page=1,
    )
    provider = NvdCveProvider(
        client,
        NVD_URL,
        query,
        api_key="test-nvd-key",
        clock=lambda: RETRIEVED_AT,
    )

    batch = asyncio.run(provider.fetch())

    request = client.requests[0]
    assert request["url"] == NVD_URL
    assert request["headers"] == {
        "Accept": "application/json",
        "apiKey": "test-nvd-key",
    }
    assert request["params"] == query.as_params()
    assert response.status_checked is True
    assert batch.query == query
    assert "test-nvd-key" not in batch.model_dump_json()


def test_nvd_parser_rejects_cvss_metric_in_wrong_version_collection() -> None:
    payload = _nvd_payload()
    vulnerabilities = payload["vulnerabilities"]
    assert isinstance(vulnerabilities, list)
    cve = vulnerabilities[0]["cve"]
    cve["metrics"]["cvssMetricV31"][0]["cvssData"]["version"] = "3.0"

    with pytest.raises(InvalidIntelligencePayload, match="collection contains another version"):
        parse_nvd_cves(
            _json_bytes(payload),
            source_url=NVD_URL,
            retrieved_at=RETRIEVED_AT,
        )


def test_nvd_parser_rejects_ambiguous_cpe_version_boundaries() -> None:
    payload = _nvd_payload()
    vulnerabilities = payload["vulnerabilities"]
    assert isinstance(vulnerabilities, list)
    cve = vulnerabilities[0]["cve"]
    cpe_match = cve["configurations"][0]["nodes"][0]["cpeMatch"][0]
    cpe_match["versionStartExcluding"] = "1.1"

    with pytest.raises(InvalidIntelligencePayload, match="schema validation"):
        parse_nvd_cves(
            _json_bytes(payload),
            source_url=NVD_URL,
            retrieved_at=RETRIEVED_AT,
        )
