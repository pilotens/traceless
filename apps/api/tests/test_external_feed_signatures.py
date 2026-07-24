import asyncio
import base64
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from traceless_api.integrations.intelligence.errors import InvalidIntelligencePayload
from traceless_api.integrations.intelligence.external_datapoints import ExternalDatapointProvider


class SignedResponse:
    def __init__(self, payload: bytes, headers: dict[str, str]) -> None:
        self.payload = payload
        self.headers = {"content-type": "application/json", **headers}
        self.status_code = 200
        self.content = payload

    def raise_for_status(self) -> None:
        return None

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        yield self.payload


class RecordingClient:
    def __init__(self, response: SignedResponse) -> None:
        self.response = response
        self.params: dict[str, str] | None = None

    @asynccontextmanager
    async def stream(self, method: str, url: str, **kwargs):
        assert method == "GET"
        assert url == "https://publisher.example.test/v2/datapoints"
        self.params = kwargs["params"]
        yield self.response


def _page() -> bytes:
    observed = datetime.now(UTC).isoformat()
    return json.dumps(
        {
            "schema_version": "2.0",
            "feed_id": "signed-feed",
            "feed_version": "v2-e1-full-1",
            "feed_epoch": 1,
            "generated_at": observed,
            "mode": "full",
            "reset_required": False,
            "from_sequence": 0,
            "through_sequence": 1,
            "items": [
                {
                    "status": "active",
                    "status_changed_at": None,
                    "status_reason": None,
                    "record": {
                        "source_kind": "news",
                        "provider": "central-analysis",
                        "external_id": "signed-1",
                        "record_type": "threat",
                        "title": "Signed feed test",
                        "summary": "Verified bytes before parsing.",
                        "modified_at": observed,
                        "retrieved_at": observed,
                        "markings": ["TLP:CLEAR"],
                        "revoked": False,
                        "raw_evidence": {"source_id": "signed-1"},
                    },
                }
            ],
            "has_more": False,
            "next_cursor": None,
            "next_sync_token": "signed-sync-token",
            "manifest_sha256": "a" * 64,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _signed_response(payload: bytes, private_key: Ed25519PrivateKey) -> SignedResponse:
    import hashlib

    return SignedResponse(
        payload,
        {
            "x-traceless-content-sha256": hashlib.sha256(payload).hexdigest(),
            "x-traceless-key-id": "publisher-key-1",
            "x-traceless-signature": base64.b64encode(
                private_key.sign(payload)
            ).decode("ascii"),
        },
    )


def test_provider_verifies_exact_bytes_and_sends_delta_token() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    payload = _page()
    client = RecordingClient(_signed_response(payload, private_key))
    provider = ExternalDatapointProvider(
        client,
        "https://publisher.example.test/v2/datapoints",
        token="traceless.customer.secret-value-1234567890",
        allowed_hosts=["publisher.example.test"],
        trusted_signing_keys={"publisher-key-1": public_key},
        require_signature=True,
    )

    result = asyncio.run(provider.fetch_page(sync_token="prior-sync-token"))
    assert result.signature_verified is True
    assert result.signing_key_id == "publisher-key-1"
    assert result.page.schema_version == "2.0"
    assert client.params == {"limit": "250", "sync_token": "prior-sync-token"}


def test_provider_rejects_tampering_and_unsigned_v2() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    original = _page()
    signed = _signed_response(original, private_key)
    signed.payload = original + b" "
    signed.content = signed.payload
    provider = ExternalDatapointProvider(
        RecordingClient(signed),
        "https://publisher.example.test/v2/datapoints",
        token="traceless.customer.secret-value-1234567890",
        allowed_hosts=["publisher.example.test"],
        trusted_signing_keys={"publisher-key-1": public_key},
        require_signature=True,
    )
    with pytest.raises(InvalidIntelligencePayload, match="digest"):
        asyncio.run(provider.fetch_page())

    unsigned = ExternalDatapointProvider(
        RecordingClient(SignedResponse(original, {})),
        "https://publisher.example.test/v2/datapoints",
        token="traceless.customer.secret-value-1234567890",
        allowed_hosts=["publisher.example.test"],
        trusted_signing_keys={"publisher-key-1": public_key},
        require_signature=True,
    )
    with pytest.raises(InvalidIntelligencePayload, match="unsigned"):
        asyncio.run(unsigned.fetch_page())
