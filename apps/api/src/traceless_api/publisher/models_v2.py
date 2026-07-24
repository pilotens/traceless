"""Publisher v2 contracts for delta delivery and controlled publication."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from traceless_api.integrations.intelligence.external_datapoints import (
    Cursor,
    ExternalDatapoint,
)
from traceless_api.models.common import StrictModel


class PublisherPublicationRequest(StrictModel):
    reason: str = Field(min_length=10, max_length=2_000)


class PublisherRejectionRequest(StrictModel):
    reason: str = Field(min_length=10, max_length=2_000)


class PublisherFeedPageV2(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    feed_id: str = Field(min_length=2, max_length=120)
    feed_version: str = Field(min_length=1, max_length=160)
    feed_epoch: int = Field(ge=1)
    generated_at: AwareDatetime
    mode: Literal["full", "delta"]
    reset_required: bool = False
    from_sequence: int = Field(ge=0)
    through_sequence: int = Field(ge=0)
    items: list[ExternalDatapoint] = Field(default_factory=list, max_length=1_000)
    has_more: bool
    next_cursor: Cursor | None = None
    next_sync_token: str | None = Field(default=None, min_length=1, max_length=2_048)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_page(self) -> PublisherFeedPageV2:
        if self.through_sequence < self.from_sequence:
            raise ValueError("through_sequence must not precede from_sequence")
        if self.has_more:
            if self.next_cursor is None or self.next_sync_token is not None:
                raise ValueError("intermediate pages require only next_cursor")
            if not self.items:
                raise ValueError("intermediate pages must not be empty")
        else:
            if self.next_cursor is not None or self.next_sync_token is None:
                raise ValueError("complete pages require only next_sync_token")
        identities = [
            (item.record.provider.casefold(), item.record.external_id)
            for item in self.items
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("page contains duplicate provider/external_id identities")
        return self


class PublisherSigningKeyItem(StrictModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(min_length=3, max_length=120)
    public_key_base64: str
    fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["active", "retiring", "retired"]
    not_before: datetime
    not_after: datetime | None = None


class PublisherSigningKeySetView(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_at: datetime
    active_key_id: str
    keys: list[PublisherSigningKeyItem]




class PublisherAccountCreate(StrictModel):
    account_key: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    name: str = Field(min_length=2, max_length=160)
    enabled: bool = True


class PublisherAccountView(StrictModel):
    id: UUID
    account_key: str
    name: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class PublisherAccountPage(StrictModel):
    items: list[PublisherAccountView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class PublisherInstallationCreate(StrictModel):
    client_id: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    installation_key: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    name: str = Field(min_length=2, max_length=160)
    environment: Literal["production", "test", "development", "disaster_recovery"] = "production"
    region: str | None = Field(default=None, min_length=2, max_length=80)
    enabled: bool = True
    max_tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"] = "TLP:AMBER"
    allowed_providers: list[str] = Field(default_factory=list, max_length=500)
    allowed_source_kinds: list[str] = Field(default_factory=list, max_length=100)


class PublisherInstallationCredential(StrictModel):
    installation: PublisherInstallationView
    api_key: str = Field(min_length=32)


class PublisherInstallationView(StrictModel):
    id: UUID
    account_id: UUID
    client_id: str
    installation_key: str
    environment: Literal["production", "test", "development", "disaster_recovery"]
    region: str | None = None
    name: str
    enabled: bool
    max_tlp: str
    entitlement_epoch: int = Field(ge=1)
    reset_generation: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    last_seen_at: datetime | None


class PublisherCredentialMetadata(StrictModel):
    id: UUID
    token_version: int = Field(ge=1)
    not_before: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    created_by: str
    created_at: datetime


class PublisherImportRunView(StrictModel):
    id: UUID
    feed_id: str
    feed_version: str
    generated_at: datetime
    item_count: int = Field(ge=0)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["running", "completed", "failed", "abandoned"]
    actor: str
    heartbeat_at: datetime
    lease_expires_at: datetime | None
    attempt_count: int = Field(ge=1)
    error_code: str | None
    result: dict[str, object] | None = None
    created_at: datetime
    completed_at: datetime | None


class PublisherInstallationPage(StrictModel):
    items: list[PublisherInstallationView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class PublisherCredentialPage(StrictModel):
    items: list[PublisherCredentialMetadata]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class PublisherImportRunPage(StrictModel):
    items: list[PublisherImportRunView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class PublisherPublicationDecisionView(StrictModel):
    id: UUID
    record_id: UUID
    revision_id: UUID
    decision: Literal["published", "rejected", "emergency_withdrawal", "automatic"]
    actor: str
    reason: str
    created_at: datetime


class PublisherPublicationDecisionPage(StrictModel):
    items: list[PublisherPublicationDecisionView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)
