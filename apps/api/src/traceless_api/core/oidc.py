"""Minimal, fail-closed OIDC access-token verification.

Only signed RS256 JWT access tokens are accepted. Discovery is deliberately
not performed from request data: the issuer, audience and JWKS endpoint are
operator configuration, which keeps key retrieval outside attacker-controlled
SSRF scope.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256


class OidcTokenError(ValueError):
    """Raised when an access token cannot be trusted."""


@dataclass(frozen=True, slots=True)
class VerifiedAccessToken:
    claims: Mapping[str, Any]


def _decode_segment(value: str, *, limit: int) -> bytes:
    if not value or len(value) > limit:
        raise OidcTokenError("JWT segment is empty or exceeds the configured limit")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise OidcTokenError("JWT contains invalid base64url") from error


def _json_object(value: bytes, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OidcTokenError(f"JWT {label} is not valid JSON") from error
    if not isinstance(parsed, dict):
        raise OidcTokenError(f"JWT {label} must be an object")
    return parsed


def _integer_claim(claims: Mapping[str, Any], name: str, *, required: bool) -> int | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OidcTokenError(f"JWT {name} claim must be numeric")
    return int(value)


def _b64url_integer(value: str) -> int:
    return int.from_bytes(_decode_segment(value, limit=2_048), "big")


class OidcJwtVerifier:
    """Verify configured OIDC JWTs and cache only provider-supplied public keys."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        http_client_factory: Callable[[], httpx.AsyncClient],
        cache_seconds: int = 900,
        clock_skew_seconds: int = 60,
        max_token_bytes: int = 16_384,
        max_jwks_bytes: int = 1_048_576,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = jwks_url
        self.http_client_factory = http_client_factory
        self.cache_seconds = cache_seconds
        self.clock_skew_seconds = clock_skew_seconds
        self.max_token_bytes = max_token_bytes
        self.max_jwks_bytes = max_jwks_bytes
        self._keys: dict[str, rsa.RSAPublicKey] = {}
        self._keys_expire_at = 0.0

    async def verify(self, token: str) -> VerifiedAccessToken:
        if not token or len(token.encode("utf-8")) > self.max_token_bytes:
            raise OidcTokenError("Access token is empty or exceeds the configured limit")
        segments = token.split(".")
        if len(segments) != 3:
            raise OidcTokenError("Access token is not a compact JWT")
        encoded_header, encoded_claims, encoded_signature = segments
        header = _json_object(
            _decode_segment(encoded_header, limit=8_192), label="header"
        )
        claims = _json_object(
            _decode_segment(encoded_claims, limit=self.max_token_bytes), label="claims"
        )
        if header.get("alg") != "RS256":
            raise OidcTokenError("Only RS256 access tokens are accepted")
        if header.get("crit") or any(name in header for name in ("jku", "jwk", "x5u")):
            raise OidcTokenError("JWT contains unsupported key or critical headers")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > 256:
            raise OidcTokenError("JWT kid header is missing or invalid")

        key = await self._key(kid)
        signature = _decode_segment(encoded_signature, limit=8_192)
        try:
            key.verify(
                signature,
                f"{encoded_header}.{encoded_claims}".encode("ascii"),
                padding.PKCS1v15(),
                SHA256(),
            )
        except (InvalidSignature, UnicodeEncodeError) as error:
            raise OidcTokenError("Access-token signature is invalid") from error

        self._validate_claims(claims)
        return VerifiedAccessToken(claims=claims)

    async def _key(self, kid: str) -> rsa.RSAPublicKey:
        now = time.monotonic()
        if now >= self._keys_expire_at or kid not in self._keys:
            await self._refresh_keys()
        key = self._keys.get(kid)
        if key is None:
            # One forced rotation refresh handles providers that rotate before
            # the configured cache window ends.
            await self._refresh_keys()
            key = self._keys.get(kid)
        if key is None:
            raise OidcTokenError("Access-token signing key is unknown")
        return key

    async def _refresh_keys(self) -> None:
        async with self.http_client_factory() as client:
            response = await client.get(
                self.jwks_url,
                headers={"Accept": "application/json"},
                timeout=10.0,
            )
            response.raise_for_status()
            if len(response.content) > self.max_jwks_bytes:
                raise OidcTokenError("OIDC JWKS response exceeds the configured limit")
            try:
                payload = response.json()
            except json.JSONDecodeError as error:
                raise OidcTokenError("OIDC JWKS response is not valid JSON") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
            raise OidcTokenError("OIDC JWKS response does not contain a key set")
        keys: dict[str, rsa.RSAPublicKey] = {}
        for item in payload["keys"]:
            if not isinstance(item, dict):
                continue
            if item.get("kty") != "RSA" or item.get("use", "sig") != "sig":
                continue
            if item.get("alg", "RS256") != "RS256":
                continue
            kid, modulus, exponent = item.get("kid"), item.get("n"), item.get("e")
            if not all(isinstance(value, str) and value for value in (kid, modulus, exponent)):
                continue
            try:
                keys[kid] = rsa.RSAPublicNumbers(
                    _b64url_integer(exponent), _b64url_integer(modulus)
                ).public_key()
            except (ValueError, TypeError):
                continue
        if not keys:
            raise OidcTokenError("OIDC JWKS response contains no supported signing keys")
        self._keys = keys
        self._keys_expire_at = time.monotonic() + self.cache_seconds

    def _validate_claims(self, claims: Mapping[str, Any]) -> None:
        now = int(time.time())
        issuer = claims.get("iss")
        if not isinstance(issuer, str) or issuer.rstrip("/") != self.issuer:
            raise OidcTokenError("Access-token issuer is invalid")
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience
        if not isinstance(audiences, list) or self.audience not in audiences:
            raise OidcTokenError("Access-token audience is invalid")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 512:
            raise OidcTokenError("Access-token subject is missing or invalid")
        expires_at = _integer_claim(claims, "exp", required=True)
        not_before = _integer_claim(claims, "nbf", required=False)
        issued_at = _integer_claim(claims, "iat", required=False)
        assert expires_at is not None
        if expires_at <= now - self.clock_skew_seconds:
            raise OidcTokenError("Access token has expired")
        if not_before is not None and not_before > now + self.clock_skew_seconds:
            raise OidcTokenError("Access token is not active yet")
        if issued_at is not None and issued_at > now + self.clock_skew_seconds:
            raise OidcTokenError("Access token was issued in the future")
