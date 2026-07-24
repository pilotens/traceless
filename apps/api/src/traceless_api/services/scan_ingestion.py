"""Normalize scanner adapter output into persistent assets and architecture drafts."""

import base64
import hashlib
from datetime import UTC, datetime

from traceless_api.db.models import ArchitectureSnapshotRow, ScanJobRow
from traceless_api.integrations.scanners import ScannerResult
from traceless_api.services.operational_repository import OperationalRepository


def ingest_scanner_result(
    *,
    repository: OperationalRepository,
    scan: ScanJobRow,
    result: ScannerResult,
    raw_payload: bytes,
    retain_raw_evidence: bool,
    actor: str,
    lease_token: str | None = None,
) -> ArchitectureSnapshotRow | None:
    """Persist one immutable scan observation and derive a reviewable graph."""

    # Serialize every scan-derived write for one system before touching the
    # stable asset rows. This covers both live workers and direct file imports.
    repository.lock_system_for_scan_ingestion(scan.system_id)
    received_at = datetime.now(UTC)
    repository.prepare_scan_generation(
        scan,
        source_started_at=result.source_started_at,
        source_completed_at=result.source_completed_at,
        completeness=result.completeness.value,
        received_at=received_at,
    )
    observed_at = scan.source_observed_at or received_at
    asset_count = 0
    service_count = 0
    observed_asset_ids = set()
    for host in result.hosts:
        primary_address = str(host.addresses[0].address)
        hardware = host.hardware_addresses[0] if host.hardware_addresses else None
        operating_system = (
            max(
                host.operating_systems,
                key=lambda item: item.accuracy if item.accuracy is not None else -1,
            )
            if host.operating_systems
            else None
        )
        asset = repository.upsert_asset(
            system_id=scan.system_id,
            scan_id=scan.id,
            primary_ip=primary_address,
            hostname=host.hostnames[0] if host.hostnames else None,
            mac_address=hardware.address if hardware else None,
            state=host.state.value,
            os_family=operating_system.name if operating_system else None,
            os_accuracy=operating_system.accuracy if operating_system else None,
            observed_at=observed_at,
            promote_current=scan.is_current_inventory,
        )
        observed_asset_ids.add(asset.id)
        asset_count += 1
        for service in host.services:
            repository.add_service(
                asset_id=asset.id,
                scan_id=scan.id,
                port=service.port,
                protocol=service.protocol,
                state=service.state,
                service_name=service.name,
                product=service.product,
                version=service.version,
                cpes=list(service.cpes),
                confidence=(service.confidence / 10 if service.confidence is not None else 0.5),
            )
            service_count += 1

    repository.finalize_current_inventory(
        scan,
        observed_asset_ids=observed_asset_ids,
    )

    digest = hashlib.sha256(raw_payload).hexdigest()
    raw_text = base64.b64encode(raw_payload).decode("ascii") if retain_raw_evidence else None
    return repository.complete_scan(
        scan,
        raw_evidence=raw_text,
        raw_sha256=digest,
        result_summary={
            "scanner": result.scanner,
            "scanner_version": result.scanner_version,
            "assets_observed": asset_count,
            "services_observed": service_count,
            "warnings": list(result.warnings),
            "raw_evidence_retained": retain_raw_evidence,
            "raw_evidence_encoding": "base64" if retain_raw_evidence else None,
            "source_started_at": (
                scan.source_started_at.isoformat() if scan.source_started_at else None
            ),
            "source_completed_at": (
                scan.source_completed_at.isoformat() if scan.source_completed_at else None
            ),
            "source_observed_at": (
                scan.source_observed_at.isoformat() if scan.source_observed_at else None
            ),
            "source_time_status": scan.source_time_status,
            "scope_targets": list(scan.scope_targets),
            "scope_sha256": scan.scope_sha256,
            "profile": scan.scan_profile,
            "completeness": scan.completeness,
            "inventory_role": scan.inventory_role,
            "is_current_inventory": scan.is_current_inventory,
        },
        actor=actor,
        lease_token=lease_token,
    )
