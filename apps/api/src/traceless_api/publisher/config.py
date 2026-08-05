"""Configuration for the separately deployed central intelligence publisher."""

from __future__ import annotations

import base64
import binascii
import hashlib
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PublisherSurface = Literal["combined", "admin", "ingest", "review", "feed"]
PublisherRole = Literal["publisher_admin", "publisher_ingest", "publisher_reviewer"]


class PublisherSettings(BaseSettings):
    """Environment-backed settings for the public feed boundary."""

    model_config = SettingsConfigDict(
        env_prefix="TRACELESS_PUBLISHER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    surface: PublisherSurface = "combined"
    database_url: str = "sqlite+pysqlite:///./traceless-publisher.db"
    migration_role: str | None = Field(
        default=None,
        min_length=1,
        max_length=63,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )
    auto_create_schema: bool = True
    enable_docs: bool = True

    # Static service identities remain available for automation. Human administration
    # should use the optional OIDC verifier in production.
    admin_api_key: SecretStr | None = None
    ingest_api_key: SecretStr | None = None
    reviewer_api_key: SecretStr | None = None
    admin_actor: str = Field(default="publisher-admin-service", min_length=2, max_length=160)
    ingest_actor: str = Field(default="publisher-ingest-service", min_length=2, max_length=160)
    reviewer_actor: str = Field(
        default="publisher-reviewer-service", min_length=2, max_length=160
    )

    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_allowed_hosts: list[str] = Field(default_factory=list)
    oidc_roles_claim: str = Field(default="roles", min_length=1, max_length=80)
    oidc_role_map: dict[str, PublisherRole] = Field(default_factory=dict)
    oidc_jwks_cache_seconds: int = Field(default=900, ge=60, le=86_400)
    oidc_clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    oidc_max_token_bytes: int = Field(default=16_384, ge=1_024, le=65_536)
    oidc_max_jwks_bytes: int = Field(default=1_048_576, ge=1_024, le=8 * 1_048_576)

    cursor_secret: SecretStr | None = None
    signing_private_key: SecretStr | None = None
    signing_key_id: str = Field(
        default="traceless-publisher-development-1",
        min_length=3,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    previous_signing_public_keys: dict[str, str] = Field(default_factory=dict)

    feed_id: str = Field(
        default="traceless-central-intelligence",
        min_length=2,
        max_length=120,
    )
    feed_epoch: int = Field(default=1, ge=1, le=2_147_483_647)
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver", "publisher"]
    )
    max_request_body_bytes: int = Field(
        default=32 * 1024 * 1024,
        ge=1_024,
        le=512 * 1024 * 1024,
    )
    max_page_size: int = Field(default=1_000, ge=1, le=1_000)
    max_import_items: int = Field(default=1_000, ge=1, le=1_000)
    cursor_max_age_seconds: int = Field(
        default=30 * 24 * 60 * 60,
        ge=300,
        le=365 * 24 * 60 * 60,
    )
    credential_overlap_seconds: int = Field(default=3_600, ge=0, le=30 * 24 * 60 * 60)
    credential_ttl_seconds: int = Field(
        default=365 * 24 * 60 * 60,
        ge=3_600,
        le=10 * 365 * 24 * 60 * 60,
    )
    import_lease_seconds: int = Field(default=15 * 60, ge=60, le=24 * 60 * 60)
    allow_automatic_publish: bool | None = None
    enable_legacy_v1_feed: bool | None = None
    automatic_publish_feed_ids: list[str] = Field(default_factory=list)
    automatic_publish_providers: list[str] = Field(default_factory=list)

    # Per-process defense in depth. Production still requires a shared edge limiter.
    feed_rate_limit_per_minute: int = Field(default=600, ge=10, le=100_000)
    admin_rate_limit_per_minute: int = Field(default=120, ge=5, le=10_000)
    rate_limit_max_buckets: int = Field(default=50_000, ge=100, le=1_000_000)
    expected_database_role: str | None = Field(
        default=None,
        min_length=1,
        max_length=63,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )
    required_schema_revision: str = Field(default="p4e1c6a2f540", min_length=3, max_length=32)

    @field_validator("allowed_hosts", "oidc_allowed_hosts")
    @classmethod
    def hosts_are_explicit(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().casefold().rstrip(".") for value in values]
        if values and any(not value or value == "*" for value in normalized):
            raise ValueError("publisher host allowlists must contain explicit hostnames")
        if len(set(normalized)) != len(normalized):
            raise ValueError("publisher host allowlists must be unique")
        return normalized

    @field_validator("previous_signing_public_keys")
    @classmethod
    def public_keys_are_valid(cls, values: dict[str, str]) -> dict[str, str]:
        for key_id, encoded in values.items():
            if not key_id or len(key_id) > 120:
                raise ValueError("publisher previous signing key IDs must be bounded")
            _decode_public_key(encoded)
        return values

    @model_validator(mode="after")
    def secure_production_defaults(self) -> PublisherSettings:
        for name, value in (
            ("admin_api_key", self.admin_api_key),
            ("ingest_api_key", self.ingest_api_key),
            ("reviewer_api_key", self.reviewer_api_key),
            ("cursor_secret", self.cursor_secret),
        ):
            if value is not None and len(value.get_secret_value()) < 32:
                raise ValueError(f"publisher {name} must contain at least 32 characters")
        if self.signing_private_key is not None:
            _decode_private_key(self.signing_private_key.get_secret_value())

        oidc_values = (self.oidc_issuer, self.oidc_audience, self.oidc_jwks_url)
        if any(value is not None for value in oidc_values) and not all(
            value is not None for value in oidc_values
        ):
            raise ValueError(
                "publisher oidc_issuer, oidc_audience and oidc_jwks_url must be configured together"
            )
        if self.oidc_issuer is not None:
            if not self.oidc_allowed_hosts or not self.oidc_role_map:
                raise ValueError("publisher OIDC requires host allowlisting and a role map")
            allowed = set(self.oidc_allowed_hosts)
            for name, endpoint in (
                ("oidc_issuer", self.oidc_issuer),
                ("oidc_jwks_url", self.oidc_jwks_url),
            ):
                assert endpoint is not None
                parsed = urlsplit(endpoint)
                host = parsed.hostname.rstrip(".").casefold() if parsed.hostname else ""
                if (
                    parsed.scheme.casefold() != "https"
                    or not host
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.query
                    or parsed.fragment
                    or host not in allowed
                ):
                    raise ValueError(f"publisher {name} must be an allowlisted HTTPS URL")

        if self.environment == "production":
            if self.surface in {"combined", "feed"} and self.cursor_secret is None:
                raise ValueError("production feed delivery requires cursor_secret")
            if self.surface in {"combined", "admin", "feed"} and self.signing_private_key is None:
                raise ValueError("production signing surfaces require signing_private_key")
            required_static = {
                "admin": (self.admin_api_key,),
                "ingest": (self.ingest_api_key,),
                "review": (self.reviewer_api_key,),
                "combined": (
                    self.admin_api_key,
                    self.ingest_api_key,
                    self.reviewer_api_key,
                ),
            }.get(self.surface, ())
            if required_static and not all(value is not None for value in required_static):
                if self.oidc_issuer is None:
                    raise ValueError(
                        "production publisher trust surfaces require OIDC or an explicit "
                        "service key for every exposed administrative role"
                    )
            if self.auto_create_schema:
                raise ValueError("production publisher must use Alembic, not auto_create_schema")
            if self.database_url.startswith("sqlite"):
                raise ValueError("production publisher requires PostgreSQL")
            if self.enable_legacy_v1_feed:
                raise ValueError("production publisher does not permit the legacy v1 feed")
            self.enable_docs = False
        return self

    def legacy_v1_enabled(self) -> bool:
        if self.enable_legacy_v1_feed is not None:
            return self.enable_legacy_v1_feed
        return self.environment != "production"

    def automatic_publish_enabled(self, *, feed_id: str, providers: set[str]) -> bool:
        enabled = (
            self.environment != "production"
            if self.allow_automatic_publish is None
            else self.allow_automatic_publish
        )
        if not enabled:
            return False
        allowed_feeds = set(self.automatic_publish_feed_ids)
        allowed_providers = {value.casefold() for value in self.automatic_publish_providers}
        if self.environment != "production" and not allowed_feeds and not allowed_providers:
            return True
        return feed_id in allowed_feeds and providers.issubset(allowed_providers)

    def admin_key_value(self) -> str | None:
        if self.admin_api_key is not None:
            return self.admin_api_key.get_secret_value()
        if self.environment != "production":
            return "development-publisher-admin-key-not-for-production"
        return None

    def ingest_key_value(self) -> str | None:
        if self.ingest_api_key is not None:
            return self.ingest_api_key.get_secret_value()
        if self.environment != "production":
            return self.admin_key_value()
        return None

    def reviewer_key_value(self) -> str | None:
        if self.reviewer_api_key is not None:
            return self.reviewer_api_key.get_secret_value()
        if self.environment != "production":
            return self.admin_key_value()
        return None

    def cursor_secret_bytes(self) -> bytes:
        if self.cursor_secret is not None:
            return self.cursor_secret.get_secret_value().encode("utf-8")
        return hashlib.sha256(b"traceless-development-publisher-cursor-secret").digest()

    def signing_private_key_bytes(self) -> bytes:
        if self.signing_private_key is not None:
            return _decode_private_key(self.signing_private_key.get_secret_value())
        return hashlib.sha256(b"traceless-development-publisher-ed25519-key").digest()


def _decode_private_key(value: str) -> bytes:
    decoded = _decode_base64(value, label="signing_private_key")
    if len(decoded) != 32:
        raise ValueError("publisher signing_private_key must decode to 32 Ed25519 bytes")
    try:
        Ed25519PrivateKey.from_private_bytes(decoded)
    except ValueError as error:
        raise ValueError("publisher signing_private_key is not a valid Ed25519 key") from error
    return decoded


def _decode_public_key(value: str) -> bytes:
    decoded = _decode_base64(value, label="signing public key")
    if len(decoded) != 32:
        raise ValueError("publisher signing public keys must decode to 32 bytes")
    return decoded


def _decode_base64(value: str, *, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"publisher {label} must use standard base64") from error


@lru_cache
def get_publisher_settings() -> PublisherSettings:
    return PublisherSettings()
