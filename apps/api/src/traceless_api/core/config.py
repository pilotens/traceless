"""Environment-backed application configuration."""

import base64
import binascii
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from traceless_api.core.tenancy import (
    DEFAULT_ORGANIZATION_ID,
    DEFAULT_ORGANIZATION_KEY,
    DEFAULT_ORGANIZATION_NAME,
)


class ExternalIntelligenceCredentialBinding(BaseModel):
    """Feed token and trusted signing keys pinned to one exact HTTPS origin."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    secret: SecretStr
    origin: str
    signing_keys: dict[str, str] = Field(default_factory=dict)
    require_signature: bool = False

    @field_validator("origin")
    @classmethod
    def origin_is_canonical_https(cls, value: str) -> str:
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("credential origin contains an invalid port") from error
        host = parsed.hostname.rstrip(".").casefold() if parsed.hostname else ""
        if (
            parsed.scheme.casefold() != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "credential origin must be a credential-free HTTPS origin without a path"
            )
        rendered_host = f"[{host}]" if ":" in host else host
        rendered_port = f":{port}" if port not in {None, 443} else ""
        return f"https://{rendered_host}{rendered_port}"

    @field_validator("signing_keys")
    @classmethod
    def signing_keys_are_ed25519(cls, values: dict[str, str]) -> dict[str, str]:
        normalized: set[str] = set()
        for key_id, encoded in values.items():
            identity = key_id.casefold()
            if (
                not key_id
                or len(key_id) > 120
                or identity in normalized
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", key_id) is None
            ):
                raise ValueError("external signing key IDs must be bounded and unique")
            normalized.add(identity)
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError("external signing public keys must use standard base64") from error
            if len(decoded) != 32:
                raise ValueError("external signing public keys must decode to 32 bytes")
        return values


class Settings(BaseSettings):
    """Runtime settings with conservative defaults."""

    model_config = SettingsConfigDict(
        env_prefix="TRACELESS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Traceless API"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    enable_docs: bool = True
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"]
    )
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    database_url: str = "sqlite+pysqlite:///./traceless.db"
    auto_create_schema: bool = True
    report_directory: str = ".local/reports"
    max_request_body_bytes: int = Field(default=32 * 1024 * 1024, ge=1_024, le=100_000_000)
    operational_api_key: SecretStr | None = None
    operational_actor_name: str = Field(
        default="authenticated-api-client", min_length=2, max_length=160
    )
    operational_organization_id: UUID = DEFAULT_ORGANIZATION_ID
    operational_organization_key: str = Field(
        default=DEFAULT_ORGANIZATION_KEY, min_length=1, max_length=255
    )
    operational_organization_name: str = Field(
        default=DEFAULT_ORGANIZATION_NAME, min_length=2, max_length=160
    )
    operational_roles: list[Literal["admin", "analyst", "viewer", "scanner"]] = Field(
        default_factory=lambda: ["admin"]
    )
    operational_project_ids: list[UUID] = Field(default_factory=list)
    operational_system_ids: list[UUID] = Field(default_factory=list)
    operational_resource_scope_all: bool = False

    # Browser users authenticate with an OIDC access token. The API never
    # performs discovery from token content; issuer, audience and JWKS are
    # fixed operator configuration and signatures are verified locally.
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_allowed_hosts: list[str] = Field(default_factory=list)
    oidc_organization_claim: str = Field(default="tid", min_length=1, max_length=80)
    oidc_organization_name_claim: str = Field(default="tenant_name", min_length=1, max_length=80)
    oidc_roles_claim: str = Field(default="roles", min_length=1, max_length=80)
    oidc_project_ids_claim: str = Field(
        default="traceless_project_ids", min_length=1, max_length=80
    )
    oidc_system_ids_claim: str = Field(
        default="traceless_system_ids", min_length=1, max_length=80
    )
    oidc_role_map: dict[str, Literal["admin", "analyst", "viewer", "scanner"]] = Field(
        default_factory=lambda: {
            "Traceless.Admin": "admin",
            "Traceless.Analyst": "analyst",
            "Traceless.Viewer": "viewer",
            "Traceless.Scanner": "scanner",
        }
    )
    oidc_jwks_cache_seconds: int = Field(default=900, ge=60, le=86_400)
    oidc_clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    oidc_max_token_bytes: int = Field(default=16_384, ge=1_024, le=65_536)
    oidc_max_jwks_bytes: int = Field(default=1_048_576, ge=1_024, le=8 * 1_048_576)

    # Active scanning is deliberately disabled until an operator enables the
    # isolated worker. The API never accepts arbitrary Nmap flags.
    nmap_enabled: bool = False
    nmap_binary: str = "nmap"
    scan_max_hosts: int = Field(default=256, ge=1, le=4096)
    scan_timeout_seconds: int = Field(default=900, ge=30, le=3600)
    scan_worker_id: str = Field(default="scanner-worker", min_length=2, max_length=160)
    scan_lease_grace_seconds: int = Field(default=60, ge=10, le=600)
    scan_heartbeat_seconds: int = Field(default=15, ge=2, le=120)
    scan_max_attempts: int = Field(default=3, ge=1, le=10)
    allow_public_scan_targets: bool = False
    max_nmap_xml_bytes: int = Field(default=10_000_000, ge=1_000, le=16_000_000)
    retain_raw_scan_evidence: bool = False
    max_vulnerability_scan_bytes: int = Field(
        default=32 * 1024 * 1024, ge=1_000, le=100 * 1024 * 1024
    )
    max_vulnerability_observations: int = Field(default=50_000, ge=1, le=50_000)

    # CPU- and database-heavy imports/reports run in a separate durable worker.
    background_job_worker_id: str = Field(default="background-worker", min_length=2, max_length=120)
    background_job_lease_seconds: int = Field(default=300, ge=30, le=3_600)
    background_job_heartbeat_seconds: int = Field(default=15, ge=2, le=120)
    background_job_retry_delay_seconds: int = Field(default=5, ge=0, le=3_600)
    background_job_max_attempts: int = Field(default=3, ge=1, le=10)

    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: SecretStr | None = None
    internal_threat_feed_url: str | None = None
    internal_threat_feed_token: SecretStr | None = None
    internal_threat_feed_organization_id: UUID | None = None
    # Pull-only connector for a separately operated scraper/analysis API.
    external_intelligence_url: str | None = None
    external_intelligence_token: SecretStr | None = None
    # Persisted tenant connectors store only a credential reference. Operators
    # resolve those references from this process-level nested secret map (JSON
    # env): organization key -> credential reference -> secret. Keeping the two
    # namespaces structurally separate avoids ambiguous/colliding flat keys.
    external_intelligence_credentials: dict[
        str, dict[str, ExternalIntelligenceCredentialBinding]
    ] = Field(default_factory=dict)
    external_intelligence_auth_scheme: Literal["Bearer", "X-API-Key"] = "Bearer"
    external_intelligence_page_size: int = Field(default=250, ge=1, le=1_000)
    external_intelligence_max_pages: int = Field(default=20, ge=1, le=1_000)
    external_intelligence_max_records: int = Field(default=5_000, ge=1, le=100_000)
    external_intelligence_max_snapshot_bytes: int = Field(
        default=32 * 1024 * 1024,
        ge=1_048_576,
        le=512 * 1024 * 1024,
    )
    external_intelligence_max_page_bytes: int = Field(
        default=4 * 1024 * 1024,
        ge=1_024,
        le=64 * 1024 * 1024,
    )
    external_intelligence_timeout_seconds: float = Field(default=20.0, ge=0.1, le=120)
    external_intelligence_clock_skew_seconds: int = Field(default=300, ge=0, le=3_600)
    external_intelligence_stale_run_seconds: int = Field(default=3_600, ge=60, le=86_400)
    external_intelligence_heartbeat_seconds: int = Field(default=15, ge=2, le=120)
    external_intelligence_worker_id: str = Field(
        default="external-intelligence-worker", min_length=2, max_length=120
    )
    external_intelligence_scheduler_batch_size: int = Field(default=50, ge=1, le=500)
    external_intelligence_schedule_claim_seconds: int = Field(default=300, ge=30, le=3_600)
    external_intelligence_schedule_retry_seconds: int = Field(default=300, ge=30, le=86_400)
    intelligence_allowed_hosts: list[str] = Field(
        default_factory=lambda: [
            "www.cisa.gov",
            "api.first.org",
            "services.nvd.nist.gov",
        ]
    )

    # NetBox remains an optional, read-only source. The URL is configured by an
    # operator rather than accepted from an API request, and every hostname must
    # be explicitly allowlisted to constrain server-side requests.
    netbox_base_url: str | None = None
    netbox_token: SecretStr | None = None
    netbox_organization_id: UUID | None = None
    netbox_auth_scheme: Literal["Bearer", "Token"] = "Bearer"
    netbox_allowed_hosts: list[str] = Field(default_factory=list)
    netbox_allow_insecure_http: bool = False
    netbox_page_size: int = Field(default=100, ge=1, le=1_000)
    netbox_max_pages: int = Field(default=250, ge=1, le=10_000)
    netbox_max_records: int = Field(default=10_000, ge=1, le=100_000)
    netbox_max_page_bytes: int = Field(
        default=4 * 1024 * 1024,
        ge=1_024,
        le=64 * 1024 * 1024,
    )
    netbox_timeout_seconds: float = Field(default=20.0, ge=0.1, le=120)

    @model_validator(mode="after")
    def secure_production_defaults(self) -> "Settings":
        if not self.api_v1_prefix.startswith("/"):
            raise ValueError("api_v1_prefix must start with '/'")
        if self.background_job_heartbeat_seconds >= self.background_job_lease_seconds:
            raise ValueError("background_job_heartbeat_seconds must be shorter than the lease")
        if (
            self.external_intelligence_heartbeat_seconds
            >= self.external_intelligence_stale_run_seconds
        ):
            raise ValueError(
                "external_intelligence_heartbeat_seconds must be shorter than the run lease"
            )
        if self.external_intelligence_stale_run_seconds <= (
            self.external_intelligence_timeout_seconds
            + self.external_intelligence_heartbeat_seconds
        ):
            raise ValueError(
                "external_intelligence_stale_run_seconds must exceed the HTTP timeout "
                "plus one heartbeat interval"
            )
        if (
            self.external_intelligence_max_page_bytes
            > self.external_intelligence_max_snapshot_bytes
        ):
            raise ValueError(
                "external_intelligence_max_page_bytes must not exceed the snapshot byte quota"
            )
        if "*" in self.cors_origins:
            raise ValueError("Wildcard CORS origins are not permitted")
        if self.netbox_token is not None and self.netbox_base_url is None:
            raise ValueError("netbox_base_url is required when a NetBox token is configured")
        if (self.external_intelligence_url is None) != (self.external_intelligence_token is None):
            raise ValueError(
                "external_intelligence_url and external_intelligence_token must be "
                "configured together"
            )
        oidc_values = (self.oidc_issuer, self.oidc_audience, self.oidc_jwks_url)
        if any(value is not None for value in oidc_values) and not all(
            value is not None for value in oidc_values
        ):
            raise ValueError(
                "oidc_issuer, oidc_audience and oidc_jwks_url must be configured together"
            )
        if self.oidc_issuer is not None:
            oidc_hosts = {host.rstrip(".").casefold() for host in self.oidc_allowed_hosts}
            if not oidc_hosts or any(not host or host == "*" for host in oidc_hosts):
                raise ValueError("Configured OIDC requires explicit oidc_allowed_hosts")
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
                ):
                    raise ValueError(f"{name} must be an absolute credential-free HTTPS URL")
                if host not in oidc_hosts:
                    raise ValueError(f"{name} host must be explicitly allowlisted")
            if not self.oidc_role_map:
                raise ValueError("Configured OIDC requires an explicit oidc_role_map")
        normalized_role_claims: set[str] = set()
        for source_role in self.oidc_role_map:
            normalized = source_role.strip().casefold()
            if not normalized or len(source_role) > 160 or normalized in normalized_role_claims:
                raise ValueError(
                    "oidc_role_map keys must be non-empty, bounded and case-insensitively unique"
                )
            normalized_role_claims.add(normalized)
        if not self.operational_roles or len(set(self.operational_roles)) != len(
            self.operational_roles
        ):
            raise ValueError("operational_roles must be non-empty and unique")
        if len(set(self.operational_project_ids)) != len(self.operational_project_ids):
            raise ValueError("operational_project_ids must be unique")
        if len(set(self.operational_system_ids)) != len(self.operational_system_ids):
            raise ValueError("operational_system_ids must be unique")
        authorization_claims = {
            self.oidc_organization_claim,
            self.oidc_roles_claim,
            self.oidc_project_ids_claim,
            self.oidc_system_ids_claim,
        }
        if len(authorization_claims) != 4:
            raise ValueError("OIDC authorization claim names must be distinct")
        if self.netbox_base_url is not None and not self.netbox_allowed_hosts:
            raise ValueError("A configured NetBox source requires netbox_allowed_hosts")
        intelligence_hosts = {
            host.rstrip(".").casefold() for host in self.intelligence_allowed_hosts
        }
        if not intelligence_hosts or any(not host or host == "*" for host in intelligence_hosts):
            raise ValueError("intelligence_allowed_hosts must contain explicit hostnames")
        for name, endpoint in (
            ("cisa_kev_url", self.cisa_kev_url),
            ("epss_api_url", self.epss_api_url),
            ("nvd_api_url", self.nvd_api_url),
            ("internal_threat_feed_url", self.internal_threat_feed_url),
            ("external_intelligence_url", self.external_intelligence_url),
        ):
            if endpoint is None:
                continue
            parsed = urlsplit(endpoint)
            host = parsed.hostname.rstrip(".").casefold() if parsed.hostname else ""
            if (
                parsed.scheme.casefold() != "https"
                or not host
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(f"{name} must be an absolute credential-free HTTPS URL")
            if host not in intelligence_hosts:
                raise ValueError(f"{name} host must be explicitly allowlisted")
        if self.external_intelligence_token is not None:
            token = self.external_intelligence_token.get_secret_value()
            if not 16 <= len(token) <= 8_192:
                raise ValueError(
                    "external_intelligence_token must contain between 16 and 8192 characters"
                )
            if token != token.strip() or any(
                ord(character) < 32 or ord(character) == 127 for character in token
            ):
                raise ValueError(
                    "external_intelligence_token must not contain invalid whitespace or "
                    "control characters"
                )
        normalized_organization_keys: set[str] = set()
        for organization_key, credentials in self.external_intelligence_credentials.items():
            normalized_organization_key = organization_key.casefold()
            if (
                not organization_key
                or organization_key != organization_key.strip()
                or len(organization_key) > 255
                or any(
                    ord(character) < 33 or ord(character) == 127 for character in organization_key
                )
                or normalized_organization_key in normalized_organization_keys
            ):
                raise ValueError(
                    "external_intelligence_credentials organization keys must be "
                    "non-empty, bounded, case-insensitively unique and free of "
                    "whitespace/control characters"
                )
            normalized_organization_keys.add(normalized_organization_key)
            if not credentials:
                raise ValueError("external_intelligence_credentials tenant maps must not be empty")
            normalized_references: set[str] = set()
            for reference, binding in credentials.items():
                normalized_reference = reference.casefold()
                if (
                    not reference
                    or reference != reference.strip()
                    or len(reference) > 160
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", reference) is None
                    or any(ord(character) < 33 or ord(character) == 127 for character in reference)
                    or normalized_reference in normalized_references
                ):
                    raise ValueError(
                        "external_intelligence_credentials references must be non-empty, "
                        "bounded and case-insensitively unique within each organization"
                    )
                normalized_references.add(normalized_reference)
                token = binding.secret.get_secret_value()
                if (
                    not 16 <= len(token) <= 8_192
                    or token != token.strip()
                    or any(ord(character) < 32 or ord(character) == 127 for character in token)
                ):
                    raise ValueError(
                        "external_intelligence_credentials values must contain valid "
                        "16-8192 character credentials"
                    )
                binding_host = urlsplit(binding.origin).hostname
                if binding_host is None or binding_host.rstrip(".").casefold() not in (
                    intelligence_hosts
                ):
                    raise ValueError(
                        "external intelligence credential origins must be explicitly allowlisted"
                    )
                if binding.require_signature and not binding.signing_keys:
                    raise ValueError(
                        "signature-required external intelligence credentials need trusted keys"
                    )
                if self.environment == "production" and (
                    not binding.require_signature or not binding.signing_keys
                ):
                    raise ValueError(
                        "production external intelligence credentials require pinned signatures"
                    )
        if self.operational_api_key is not None:
            api_key = self.operational_api_key.get_secret_value()
            if len(api_key) < 32 or len(api_key) > 512:
                raise ValueError("operational_api_key must contain between 32 and 512 characters")
            if any(ord(character) < 32 or ord(character) == 127 for character in api_key):
                raise ValueError("operational_api_key must not contain control characters")
        if self.environment == "production":
            if self.debug:
                raise ValueError("Debug mode cannot be enabled in production")
            if "*" in self.allowed_hosts:
                raise ValueError("Wildcard hosts are not permitted in production")
            if self.database_url.startswith("sqlite"):
                raise ValueError("Production requires PostgreSQL; SQLite is development-only")
            if self.auto_create_schema:
                raise ValueError("Production schema changes must use Alembic migrations")
            if self.netbox_allow_insecure_http:
                raise ValueError("Production NetBox connections must use HTTPS")
            if self.netbox_base_url is not None and self.netbox_organization_id is None:
                raise ValueError("Production NetBox configuration requires netbox_organization_id")
            if (
                self.internal_threat_feed_url is not None
                and self.internal_threat_feed_organization_id is None
            ):
                raise ValueError(
                    "Production internal threat feed configuration requires "
                    "internal_threat_feed_organization_id"
                )
            if self.operational_api_key is None and self.oidc_issuer is None:
                raise ValueError(
                    "Production requires configured OIDC or an operational service API key"
                )
            if self.nmap_enabled and not Path(self.nmap_binary).is_absolute():
                raise ValueError("Production active scanning requires an absolute Nmap binary path")
            self.enable_docs = False
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return Settings()
