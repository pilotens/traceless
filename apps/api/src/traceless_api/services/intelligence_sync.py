"""Orchestrate configured intelligence providers into contextual findings and risks."""

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from traceless_api.core.config import Settings
from traceless_api.integrations.intelligence import (
    NVD_API_DISCLAIMER,
    AsyncHttpClient,
    CisaKevProvider,
    FirstEpssProvider,
    InternalThreatFeedProvider,
    InvalidIntelligencePayload,
    NvdCveProvider,
    NvdQuery,
)
from traceless_api.models.operational import IntelligenceSyncResult
from traceless_api.services.operational_repository import (
    OperationalConflictError,
    OperationalRepository,
)
from traceless_api.services.private_integration_scope import require_private_integration_scope


async def sync_cisa_kev(
    *,
    settings: Settings,
    repository: OperationalRepository,
    system_id: UUID,
    client: AsyncHttpClient,
    actor: str,
) -> IntelligenceSyncResult:
    # Resolve the tenant/system authorization boundary before using any
    # configured provider endpoint.
    repository.get_system(system_id)
    batch = await CisaKevProvider(client, settings.cisa_kev_url).fetch()
    if not batch.records:
        raise InvalidIntelligencePayload("CISA KEV returned an empty catalogue")
    _reject_future_provider_timestamps(
        provider="CISA KEV",
        retrieved_at=batch.provenance.retrieved_at,
        timestamps=(batch.provenance.source_updated_at,),
        max_future_skew_seconds=settings.external_intelligence_clock_skew_seconds,
    )
    matched, updated = repository.apply_kev_batch(system_id, batch, actor)
    return IntelligenceSyncResult(
        provider=batch.provenance.provider,
        fetched=len(batch.records),
        matched=matched,
        updated=updated,
        feed_version=batch.provenance.source_version,
        payload_sha256=batch.provenance.payload_sha256,
        warnings=[
            "KEV is catalogue membership, not a score.",
            "The KEV due date is a US federal deadline, not a customer remediation SLA.",
        ],
    )


async def sync_first_epss(
    *,
    settings: Settings,
    repository: OperationalRepository,
    system_id: UUID,
    client: AsyncHttpClient,
    actor: str,
) -> IntelligenceSyncResult:
    cve_ids = sorted(
        {finding.cve_id for finding in repository.list_findings(system_id) if finding.cve_id}
    )
    if not cve_ids:
        raise OperationalConflictError("At least one CVE finding is required before EPSS sync")
    hashes: list[str] = []
    versions: list[str] = []
    fetched = matched = updated = 0
    for chunk in _chunks(cve_ids, 100):
        batch = await FirstEpssProvider(
            client,
            settings.epss_api_url,
            cve_ids=tuple(chunk),
        ).fetch()
        _reject_future_provider_timestamps(
            provider="FIRST EPSS",
            retrieved_at=batch.provenance.retrieved_at,
            timestamps=(
                batch.provenance.source_updated_at,
                *(
                    datetime.combine(record.model_date, datetime.min.time(), tzinfo=UTC)
                    for record in batch.records
                ),
            ),
            max_future_skew_seconds=settings.external_intelligence_clock_skew_seconds,
        )
        chunk_matched, chunk_updated = repository.apply_epss_batch(system_id, batch, actor)
        fetched += len(batch.records)
        matched += chunk_matched
        updated += chunk_updated
        hashes.append(batch.provenance.payload_sha256)
        versions.append(batch.provenance.source_version)
    combined_hash = hashlib.sha256("".join(hashes).encode()).hexdigest()
    return IntelligenceSyncResult(
        provider="first-epss",
        fetched=fetched,
        matched=matched,
        updated=updated,
        feed_version=",".join(sorted(set(versions))),
        payload_sha256=combined_hash,
        warnings=["EPSS is a dated probability estimate and is not a severity score."],
    )


async def sync_nvd(
    *,
    settings: Settings,
    repository: OperationalRepository,
    system_id: UUID,
    client: AsyncHttpClient,
    actor: str,
) -> IntelligenceSyncResult:
    cpes = sorted(
        {
            cpe
            for service in repository.list_services(system_id)
            for cpe in service.cpes
            if cpe.startswith("cpe:2.3:")
        }
    )
    if not cpes:
        raise OperationalConflictError("An observed concrete CPE 2.3 is required before NVD sync")
    if len(cpes) > 50:
        raise OperationalConflictError(
            "NVD sync is limited to 50 unique CPEs per request; use scheduled batches"
        )
    api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    hashes: list[str] = []
    versions: list[str] = []
    fetched = matched = updated = 0
    for cpe in cpes:
        start_index = 0
        page_count = 0
        cpe_batches = []
        while True:
            query = NvdQuery(cpe_name=cpe, start_index=start_index)
            batch = await NvdCveProvider(
                client,
                settings.nvd_api_url,
                query,
                api_key=api_key,
            ).fetch()
            _reject_future_provider_timestamps(
                provider="NVD",
                retrieved_at=batch.provenance.retrieved_at,
                timestamps=(
                    batch.provenance.source_updated_at,
                    *(record.last_modified_at for record in batch.records),
                ),
                max_future_skew_seconds=settings.external_intelligence_clock_skew_seconds,
            )
            cpe_batches.append(batch)
            fetched += len(batch.records)
            hashes.append(batch.provenance.payload_sha256)
            versions.append(batch.provenance.source_version)
            page_count += 1
            if batch.next_start_index is None:
                break
            if page_count >= 10:
                raise OperationalConflictError(
                    "NVD result exceeded ten pages; continue through a scheduled mirror job"
                )
            start_index = batch.next_start_index
        cpe_manifest = hashlib.sha256(
            "".join(batch.provenance.payload_sha256 for batch in cpe_batches).encode()
        ).hexdigest()
        cpe_revision = max(
            batch.provenance.source_updated_at or batch.provenance.retrieved_at
            for batch in cpe_batches
        )
        cpe_version = ",".join(
            sorted({batch.provenance.source_version for batch in cpe_batches})
        )
        if not repository.accept_nvd_snapshot(
            system_id,
            queried_cpe=cpe,
            source_updated_at=cpe_revision,
            source_version=cpe_version,
            payload_sha256=cpe_manifest,
        ):
            continue
        active_cve_ids: set[str] = set()
        for batch in cpe_batches:
            active_cve_ids.update(
                record.cve_id
                for record in batch.records
                if record.vulnerability_status.casefold() != "rejected"
            )
            chunk_matched, chunk_updated = repository.apply_nvd_batch(
                system_id, batch, cpe, actor
            )
            matched += chunk_matched
            updated += chunk_updated
        repository.retire_nvd_snapshot(
            system_id,
            queried_cpe=cpe,
            active_cve_ids=active_cve_ids,
            actor=actor,
        )
    combined_hash = hashlib.sha256("".join(hashes).encode()).hexdigest()
    return IntelligenceSyncResult(
        provider="nvd",
        fetched=fetched,
        matched=matched,
        updated=updated,
        feed_version=",".join(sorted(set(versions))),
        payload_sha256=combined_hash,
        warnings=[
            NVD_API_DISCLAIMER,
            "NVD cpeName results remain candidate findings until applicability is evaluated.",
        ],
    )


async def sync_internal_threat_feed(
    *,
    settings: Settings,
    repository: OperationalRepository,
    system_id: UUID,
    client: AsyncHttpClient,
    actor: str,
) -> IntelligenceSyncResult:
    repository.get_system(system_id)
    require_private_integration_scope(
        settings=settings,
        configured_organization_id=settings.internal_threat_feed_organization_id,
        request_organization_id=repository.organization_id,
    )
    if settings.internal_threat_feed_url is None:
        raise OperationalConflictError("TRACELESS_INTERNAL_THREAT_FEED_URL is not configured")
    token = (
        settings.internal_threat_feed_token.get_secret_value()
        if settings.internal_threat_feed_token
        else None
    )
    batch = await InternalThreatFeedProvider(
        client,
        settings.internal_threat_feed_url,
        token=token,
    ).fetch()
    future_cutoff = batch.provenance.retrieved_at + timedelta(
        seconds=settings.external_intelligence_clock_skew_seconds
    )
    if (
        batch.provenance.source_updated_at is not None
        and batch.provenance.source_updated_at > future_cutoff
    ) or any(record.modified > future_cutoff for record in batch.records):
        # Do not let an untrusted source timestamp become the repository's
        # newest revision and suppress later legitimate updates. Keep the
        # rejection reason generic at the HTTP boundary.
        raise InvalidIntelligencePayload(
            "Internal threat feed contains an update beyond the permitted clock skew"
        )
    matched, updated = repository.apply_internal_threat_batch(system_id, batch, actor)
    return IntelligenceSyncResult(
        provider=batch.provenance.provider,
        fetched=len(batch.records),
        matched=matched,
        updated=updated,
        feed_version=batch.provenance.source_version,
        payload_sha256=batch.provenance.payload_sha256,
        warnings=["Threat-feed relevance is contextual evidence and does not prove compromise."],
    )


def _reject_future_provider_timestamps(
    *,
    provider: str,
    retrieved_at: datetime,
    timestamps: Sequence[datetime | None],
    max_future_skew_seconds: int,
) -> None:
    """Reject clock-skewed provider revisions before persisting a watermark."""

    cutoff = retrieved_at + timedelta(seconds=max_future_skew_seconds)
    if any(timestamp is not None and timestamp > cutoff for timestamp in timestamps):
        raise InvalidIntelligencePayload(
            f"{provider} contains an update beyond the permitted clock skew"
        )


def _chunks(values: Sequence[str], size: int) -> list[Sequence[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]
