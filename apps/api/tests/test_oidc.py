import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

from traceless_api.core.oidc import OidcJwtVerifier, OidcTokenError


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _integer(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(size, "big"))


def _token(private_key: rsa.RSAPrivateKey, claims: dict[str, object], **headers: object) -> str:
    header = {"alg": "RS256", "kid": "key-1", "typ": "JWT", **headers}
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_claims = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_claims}".encode()
    signature = private_key.sign(signing_input, padding.PKCS1v15(), SHA256())
    return f"{encoded_header}.{encoded_claims}.{_b64url(signature)}"


@pytest.mark.anyio
async def test_oidc_verifier_accepts_configured_rs256_access_token() -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    numbers = private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "key-1",
                "n": _integer(numbers.n),
                "e": _integer(numbers.e),
            }
        ]
    }

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=jwks))
        )

    verifier = OidcJwtVerifier(
        issuer="https://identity.example/tenant/v2.0",
        audience="api://traceless",
        jwks_url="https://identity.example/tenant/keys",
        http_client_factory=factory,
    )
    claims = {
        "iss": "https://identity.example/tenant/v2.0",
        "aud": "api://traceless",
        "sub": "person-1",
        "tid": "3d1f3772-d637-4cc6-ad43-3ae158c52c29",
        "roles": ["analyst"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }

    verified = await verifier.verify(_token(private_key, claims))

    assert verified.claims["sub"] == "person-1"
    assert verified.claims["roles"] == ["analyst"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("claim", "value", "message"),
    [
        ("iss", "https://attacker.example", "issuer"),
        ("aud", "api://another-service", "audience"),
        ("exp", 1, "expired"),
        ("sub", "", "subject"),
    ],
)
async def test_oidc_verifier_rejects_untrusted_claims(
    claim: str, value: object, message: str
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    numbers = private_key.public_key().public_numbers()

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    json={
                        "keys": [
                            {
                                "kty": "RSA",
                                "kid": "key-1",
                                "n": _integer(numbers.n),
                                "e": _integer(numbers.e),
                            }
                        ]
                    },
                )
            )
        )

    verifier = OidcJwtVerifier(
        issuer="https://identity.example/tenant/v2.0",
        audience="api://traceless",
        jwks_url="https://identity.example/tenant/keys",
        http_client_factory=factory,
    )
    claims: dict[str, object] = {
        "iss": "https://identity.example/tenant/v2.0",
        "aud": "api://traceless",
        "sub": "person-1",
        "exp": int(time.time()) + 300,
    }
    claims[claim] = value

    with pytest.raises(OidcTokenError, match=message):
        await verifier.verify(_token(private_key, claims))


@pytest.mark.anyio
async def test_oidc_verifier_rejects_header_supplied_key_location() -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)

    verifier = OidcJwtVerifier(
        issuer="https://identity.example/tenant/v2.0",
        audience="api://traceless",
        jwks_url="https://identity.example/tenant/keys",
        http_client_factory=lambda: httpx.AsyncClient(),
    )
    claims = {
        "iss": "https://identity.example/tenant/v2.0",
        "aud": "api://traceless",
        "sub": "person-1",
        "exp": int(time.time()) + 300,
    }

    with pytest.raises(OidcTokenError, match="unsupported"):
        await verifier.verify(
            _token(private_key, claims, jku="https://attacker.example/keys")
        )
