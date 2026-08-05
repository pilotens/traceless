import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from traceless_api.core.config import Settings
from traceless_api.db.models import (
    AssetRow,
    BackgroundJobRow,
    ExternalIntelligenceConnectorRow,
    FindingRow,
    OrganizationRow,
    ProjectRow,
    ScanAuthorizationRow,
    ScanJobRow,
    SystemRow,
)
from traceless_api.db.session import apply_tenant_rls_scope
from traceless_api.main import create_app
from traceless_api.services.operational_repository import OperationalRepository

NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host><status state="up"/>
    <address addr="100.64.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="payments.example.test" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="https" product="Apache httpd" version="0.0.0"/>
    </port></ports>
  </host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>"""


@pytest.fixture
def postgres_client() -> Iterator[TestClient]:
    database_url = os.getenv("TRACELESS_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("TRACELESS_TEST_POSTGRES_URL is not configured")
    app = create_app(
        Settings(
            environment="test",
            allowed_hosts=["testserver"],
            database_url=database_url,
            auto_create_schema=False,
        )
    )
    with TestClient(app) as client:
        yield client


def test_postgres_request_transaction_and_tenant_scoped_intelligence(
    postgres_client: TestClient,
) -> None:
    suffix = uuid4().hex[:12]
    project = postgres_client.post(
        "/api/v1/operational/projects",
        json={"name": f"PostgreSQL {suffix}", "description": "Full-stack CI"},
    )
    assert project.status_code == 201, project.text
    system = postgres_client.post(
        f"/api/v1/operational/projects/{project.json()['id']}/systems",
        json={
            "name": f"System {suffix}",
            "description": "PostgreSQL-backed operational system",
            "owner": "CI",
            "criticality": "high",
        },
    )
    assert system.status_code == 201, system.text

    now = datetime.now(UTC).isoformat()
    imported = postgres_client.post(
        "/api/v1/operational/intelligence/records/import",
        json={
            "schema_version": "1.0",
            "feed_id": f"postgres-ci-{suffix}",
            "feed_version": "1",
            "generated_at": now,
            "items": [
                {
                    "source_kind": "news",
                    "provider": "postgres-ci",
                    "external_id": f"article-{suffix}",
                    "record_type": "report",
                    "title": "PostgreSQL full-stack evidence",
                    "summary": "Normalized source datapoint persisted through the API.",
                    "modified_at": now,
                    "retrieved_at": now,
                    "raw_evidence": {"source_id": f"article-{suffix}"},
                }
            ],
        },
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["created"] == 1
    listed = postgres_client.get(
        "/api/v1/operational/intelligence/records", params={"query": suffix}
    )
    assert listed.status_code == 200
    assert listed.json()["total"] == 1


def test_postgres_runtime_role_is_confined_by_forced_tenant_rls(
    postgres_client: TestClient,
) -> None:
    """Prove the database boundary with a non-owner role, not only ORM filters."""

    suffix = uuid4().hex
    role_name = f"traceless_rls_probe_{suffix}"
    first_organization = OrganizationRow(
        external_key=f"rls-first-{suffix}",
        name="RLS first tenant",
    )
    second_organization = OrganizationRow(
        external_key=f"rls-second-{suffix}",
        name="RLS second tenant",
    )
    session_factory = postgres_client.app.state.session_factory
    with session_factory() as owner_session:
        owner_session.add_all([first_organization, second_organization])
        owner_session.flush()
        first_project = ProjectRow(
            organization_id=first_organization.id,
            name="Visible project",
            description="RLS probe",
        )
        second_project = ProjectRow(
            organization_id=second_organization.id,
            name="Hidden project",
            description="RLS probe",
        )
        owner_session.add_all([first_project, second_project])
        owner_session.commit()
        first_organization_id = first_organization.id
        first_project_id = first_project.id
        second_project_id = second_project.id

    engine = postgres_client.app.state.engine
    with engine.connect() as connection:
        connection.execute(text(f'CREATE ROLE "{role_name}" NOLOGIN'))
        connection.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
        connection.execute(
            text(f'GRANT SELECT ON organizations, projects TO "{role_name}"')
        )
        connection.commit()
        try:
            with Session(
                bind=connection,
                autoflush=False,
                expire_on_commit=False,
            ) as runtime_session:
                runtime_session.execute(text(f'SET ROLE "{role_name}"'))
                runtime_session.commit()
                apply_tenant_rls_scope(runtime_session, first_organization_id)

                def visible_project_ids() -> set[UUID]:
                    return set(
                        runtime_session.execute(
                            text(
                                "SELECT id FROM projects "
                                "WHERE id IN (:first_project_id, :second_project_id)"
                            ),
                            {
                                "first_project_id": first_project_id,
                                "second_project_id": second_project_id,
                            },
                        ).scalars()
                    )

                assert visible_project_ids() == {first_project_id}
                runtime_session.commit()
                # A mid-request commit clears SET LOCAL. The Session hook must
                # restore it before the next read or write transaction.
                assert visible_project_ids() == {first_project_id}
                runtime_session.commit()
                runtime_session.execute(text("RESET ROLE"))
                runtime_session.commit()

            policy_state = connection.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity "
                    "FROM pg_class WHERE oid = 'projects'::regclass"
                )
            ).one()
            assert policy_state == (True, True)
            connection.commit()
        finally:
            with connection.begin():
                connection.execute(text(f'DROP OWNED BY "{role_name}"'))
                connection.execute(text(f'DROP ROLE "{role_name}"'))


def test_postgres_worker_claims_queue_without_bypassing_tenant_domain_rls(
    postgres_client: TestClient,
) -> None:
    """A definer exposes queue headers; the executor remains tenant-confined."""

    suffix = uuid4().hex
    first_organization = OrganizationRow(
        external_key=f"worker-rls-{suffix}",
        name="Worker RLS first tenant",
    )
    second_organization = OrganizationRow(
        external_key=f"worker-rls-second-{suffix}",
        name="Worker RLS second tenant",
    )
    session_factory = postgres_client.app.state.session_factory
    with session_factory() as owner_session:
        owner_session.add_all([first_organization, second_organization])
        owner_session.flush()
        first_project = ProjectRow(
            organization_id=first_organization.id,
            name="Worker RLS first project",
            description="Queue versus domain probe",
        )
        second_project = ProjectRow(
            organization_id=second_organization.id,
            name="Worker RLS second project",
            description="Cross-tenant queue payload probe",
        )
        owner_session.add_all([first_project, second_project])
        owner_session.flush()
        first_system = SystemRow(
            project_id=first_project.id,
            name="Worker RLS first system",
            description="Queue versus domain probe",
            owner="CI",
            criticality="medium",
        )
        second_system = SystemRow(
            project_id=second_project.id,
            name="Worker RLS second system",
            description="Cross-tenant queue payload probe",
            owner="CI",
            criticality="medium",
        )
        owner_session.add_all([first_system, second_system])
        owner_session.flush()
        first_authorization = ScanAuthorizationRow(
            system_id=first_system.id,
            targets=["100.64.0.10"],
            profile="discovery",
            approved_by="CI",
            purpose="RLS queue regression",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope_sha256="a" * 64,
        )
        second_authorization = ScanAuthorizationRow(
            system_id=second_system.id,
            targets=["100.64.0.20"],
            profile="discovery",
            approved_by="CI",
            purpose="RLS queue cross-tenant regression",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope_sha256="b" * 64,
        )
        owner_session.add_all([first_authorization, second_authorization])
        owner_session.flush()
        first_scan = ScanJobRow(
            organization_id=first_organization.id,
            system_id=first_system.id,
            authorization_id=first_authorization.id,
            mode="live",
            status="queued",
            requested_at=datetime(2000, 1, 1, tzinfo=UTC),
            raw_evidence="first-tenant-scan-evidence",
        )
        second_scan = ScanJobRow(
            organization_id=second_organization.id,
            system_id=second_system.id,
            authorization_id=second_authorization.id,
            mode="live",
            status="queued",
            requested_at=datetime(2001, 1, 1, tzinfo=UTC),
            raw_evidence="second-tenant-scan-evidence",
        )
        owner_session.add_all([first_scan, second_scan])
        owner_session.flush()
        asset = AssetRow(
            system_id=first_system.id,
            source_scan_id=first_scan.id,
            stable_key=f"worker-rls-{suffix}",
            primary_ip="100.64.0.10",
        )
        first_job = BackgroundJobRow(
            organization_id=first_organization.id,
            system_id=first_system.id,
            job_type="report_generation",
            payload={"tenant_secret": "first-background-payload"},
            payload_sha256="1" * 64,
            idempotency_key_sha256="2" * 64,
            requested_by="ci",
        )
        second_job = BackgroundJobRow(
            organization_id=second_organization.id,
            system_id=second_system.id,
            job_type="report_generation",
            payload={"tenant_secret": "second-background-payload"},
            payload_sha256="3" * 64,
            idempotency_key_sha256="4" * 64,
            requested_by="ci",
        )
        first_connector = ExternalIntelligenceConnectorRow(
            organization_id=first_organization.id,
            endpoint="https://first.example.test/datapoints",
            auth_scheme="Bearer",
            credential_reference="first-credential-reference",
            enabled=False,
            identity_sha256="5" * 64,
            created_by="ci",
        )
        second_connector = ExternalIntelligenceConnectorRow(
            organization_id=second_organization.id,
            endpoint="https://second.example.test/datapoints",
            auth_scheme="Bearer",
            credential_reference="second-credential-reference",
            enabled=False,
            identity_sha256="6" * 64,
            created_by="ci",
        )
        owner_session.add_all(
            [asset, first_job, second_job, first_connector, second_connector]
        )
        owner_session.commit()
        organization_id = first_organization.id
        second_organization_id = second_organization.id
        scan_id = first_scan.id
        second_scan_id = second_scan.id
        asset_id = asset.id
        first_job_id = first_job.id
        second_job_id = second_job.id
        first_connector_id = first_connector.id
        second_connector_id = second_connector.id

    engine = postgres_client.app.state.engine
    for table, resource_id in (
        ("scan_jobs", scan_id),
        ("background_jobs", first_job_id),
    ):
        with pytest.raises(DBAPIError):
            with engine.begin() as mismatch:
                mismatch.execute(
                    text(
                        f"UPDATE {table} SET organization_id = :organization_id "
                        "WHERE id = :resource_id"
                    ),
                    {
                        "organization_id": second_organization_id,
                        "resource_id": resource_id,
                    },
                )

    with engine.connect() as connection:
        role_state = connection.execute(
            text(
                "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls "
                "FROM pg_roles WHERE rolname = 'traceless_worker'"
            )
        ).one()
        assert role_state == (False, False, False, False)
        dispatch_role_state = connection.execute(
            text(
                "SELECT rolcanlogin, rolsuper, rolinherit, rolbypassrls FROM pg_roles "
                "WHERE rolname = 'traceless_dispatch_owner'"
            )
        ).one()
        assert dispatch_role_state == (False, False, False, True)
        assert connection.scalar(
            text(
                "SELECT EXISTS ("
                "SELECT 1 FROM pg_auth_members AS m "
                "JOIN pg_roles AS granted ON granted.oid = m.roleid "
                "JOIN pg_roles AS member ON member.oid = m.member "
                "WHERE granted.rolname = 'traceless_worker' "
                "AND member.rolname = 'traceless_dispatch_owner')"
            )
        ) is False
        assert connection.scalar(
            text(
                "SELECT has_table_privilege("
                "'traceless_dispatch_owner', 'assets', 'SELECT')"
            )
        ) is False
        assert connection.scalar(
            text(
                "SELECT has_schema_privilege("
                "'traceless_dispatch_owner', 'public', 'CREATE')"
            )
        ) is False
        assert list(
            connection.execute(
                text(
                    "SELECT tablename FROM pg_policies "
                    "WHERE policyname LIKE 'traceless_worker_queue_%'"
                )
            ).scalars()
        ) == []
        dispatch_functions = set(
            connection.execute(
                text(
                    "SELECT p.proname, p.prosecdef, r.rolname "
                    "FROM pg_proc AS p JOIN pg_roles AS r ON r.oid = p.proowner "
                    "WHERE p.proname LIKE 'traceless_dispatch_%' "
                    "AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']"
                )
            )
        )
        assert dispatch_functions == {
            ("traceless_dispatch_expired_background_job", True, "traceless_dispatch_owner"),
            ("traceless_dispatch_expired_scan_job", True, "traceless_dispatch_owner"),
            ("traceless_dispatch_due_connector", True, "traceless_dispatch_owner"),
            ("traceless_dispatch_runnable_background_job", True, "traceless_dispatch_owner"),
            ("traceless_dispatch_runnable_scan_job", True, "traceless_dispatch_owner"),
        }
        assert connection.scalar(
            text(
                "SELECT bool_and(position('clock_timestamp()' "
                "IN pg_get_functiondef(p.oid)) > 0) FROM pg_proc AS p "
                "WHERE p.proname LIKE 'traceless_dispatch_%'"
            )
        ) is True
        assert connection.scalar(
            text(
                "SELECT to_regprocedure("
                "'public.traceless_dispatch_runnable_scan_job(timestamptz)') IS NULL"
            )
        ) is True
        assert connection.scalar(
            text(
                "SELECT count(*) FROM pg_proc AS p "
                "CROSS JOIN LATERAL aclexplode(p.proacl) AS acl "
                "WHERE p.proname LIKE 'traceless_dispatch_%' "
                "AND acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'"
            )
        ) == 0
        connection.execute(text("SET ROLE traceless_worker"))
        connection.commit()
        try:
            with Session(bind=connection, autoflush=False, expire_on_commit=False) as worker:
                # Direct queue rows and every payload column are invisible before binding.
                assert worker.scalar(
                    text("SELECT raw_evidence FROM scan_jobs WHERE id = :scan_id"),
                    {"scan_id": scan_id},
                ) is None
                assert worker.execute(
                    text(
                        "UPDATE scan_jobs SET claimed_by = 'rls-probe' "
                        "WHERE id = :scan_id AND status = 'queued'"
                    ),
                    {"scan_id": scan_id},
                ).rowcount == 0

                # The definer returns only the locked queue header.
                dispatched = worker.execute(
                    text(
                        "SELECT job_id, organization_id "
                        "FROM public.traceless_dispatch_runnable_scan_job()"
                    ),
                ).one()
                assert dispatched == (scan_id, organization_id)

                assert worker.scalar(
                    text("SELECT id FROM assets WHERE id = :asset_id"),
                    {"asset_id": asset_id},
                ) is None
                apply_tenant_rls_scope(worker, organization_id)
                assert worker.execute(
                    text(
                        "UPDATE scan_jobs SET claimed_by = 'rls-probe' "
                        "WHERE id = :scan_id AND status = 'queued'"
                    ),
                    {"scan_id": scan_id},
                ).rowcount == 1
                assert worker.scalar(
                    text("SELECT id FROM assets WHERE id = :asset_id"),
                    {"asset_id": asset_id},
                ) == asset_id
                assert worker.scalar(
                    text("SELECT payload FROM background_jobs WHERE id = :job_id"),
                    {"job_id": first_job_id},
                ) == {"tenant_secret": "first-background-payload"}
                assert worker.scalar(
                    text(
                        "SELECT credential_reference "
                        "FROM external_intelligence_connectors WHERE id = :connector_id"
                    ),
                    {"connector_id": first_connector_id},
                ) == "first-credential-reference"

                # A bound executor still cannot see another tenant's queue secrets.
                assert worker.scalar(
                    text("SELECT raw_evidence FROM scan_jobs WHERE id = :scan_id"),
                    {"scan_id": second_scan_id},
                ) is None
                assert worker.scalar(
                    text("SELECT payload FROM background_jobs WHERE id = :job_id"),
                    {"job_id": second_job_id},
                ) is None
                assert worker.scalar(
                    text(
                        "SELECT credential_reference "
                        "FROM external_intelligence_connectors WHERE id = :connector_id"
                    ),
                    {"connector_id": second_connector_id},
                ) is None
                worker.rollback()
        finally:
            connection.execute(text("RESET ROLE"))
            connection.commit()


def test_postgres_system_lock_orders_scanner_and_analyst_finding_mutations(
    postgres_client: TestClient,
) -> None:
    suffix = uuid4().hex[:12]
    project = postgres_client.post(
        "/api/v1/operational/projects",
        json={"name": f"Lifecycle {suffix}", "description": "PostgreSQL locking"},
    )
    assert project.status_code == 201, project.text
    system = postgres_client.post(
        f"/api/v1/operational/projects/{project.json()['id']}/systems",
        json={
            "name": f"Locked system {suffix}",
            "description": "Concurrent lifecycle test",
            "owner": "CI",
            "criticality": "high",
        },
    )
    assert system.status_code == 201, system.text
    system_id = UUID(system.json()["id"])
    authorization = postgres_client.post(
        f"/api/v1/operational/systems/{system_id}/scan-authorizations",
        json={
            "targets": ["100.64.0.10"],
            "profile": "service_inventory",
            "approved_by": "CI owner",
            "purpose": "Verify PostgreSQL mutation ordering",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "confirmation": "Jag bekräftar att jag har tillstånd att skanna angivna mål.",
        },
    )
    assert authorization.status_code == 201, authorization.text
    scan = postgres_client.post(
        f"/api/v1/operational/systems/{system_id}/scans/import/nmap",
        params={"authorization_id": authorization.json()["id"]},
        content=NMAP_XML,
        headers={"Content-Type": "application/xml"},
    )
    assert scan.status_code == 201, scan.text
    observed_at = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    imported = postgres_client.post(
        f"/api/v1/operational/systems/{system_id}/vulnerability-scans/import",
        json={
            "provider": "qualys",
            "source_name": f"locking-{suffix}.json",
            "scan_completed_at": observed_at,
            "observations": [
                {
                    "provider_finding_id": f"QID-{suffix}",
                    "asset_identifier": "payments.example.test",
                    "ip_address": "100.64.0.10",
                    "hostname": "payments.example.test",
                    "port": 443,
                    "protocol": "tcp",
                    "title": "Concurrent lifecycle evidence",
                    "severity": "high",
                    "state": "open",
                    "cve_ids": ["CVE-2099-12345"],
                    "cvss_score": 8.8,
                    "evidence": {"source": "postgres-lock-test"},
                    "observed_at": observed_at,
                }
            ],
        },
    )
    assert imported.status_code == 201, imported.text
    overview = postgres_client.get(
        f"/api/v1/operational/systems/{system_id}/overview"
    )
    assert overview.status_code == 200, overview.text
    finding_id = UUID(overview.json()["findings"][0]["id"])

    session_factory = postgres_client.app.state.session_factory
    with session_factory() as lookup_session:
        organization = lookup_session.scalar(
            select(OrganizationRow)
            .join(ProjectRow, ProjectRow.organization_id == OrganizationRow.id)
            .join(SystemRow, SystemRow.project_id == ProjectRow.id)
            .where(SystemRow.id == system_id)
        )
        assert organization is not None
        organization_context = (
            organization.id,
            organization.external_key,
            organization.name,
        )

    started = Event()
    finished = Event()
    result: dict[str, object] = {}

    def apply_analyst_decision() -> None:
        try:
            with session_factory() as analyst_session:
                repository = OperationalRepository(
                    analyst_session,
                    organization_id=organization_context[0],
                    organization_key=organization_context[1],
                    organization_name=organization_context[2],
                )
                started.set()
                finding = repository.update_finding_lifecycle(
                    system_id,
                    finding_id,
                    "accepted",
                    "Concurrent analyst decision",
                    "oidc:postgres-lock-test",
                )
                analyst_session.commit()
                result["status"] = finding.lifecycle_status
        except BaseException as error:  # pragma: no cover - surfaced in the main thread
            result["error"] = error
        finally:
            finished.set()

    with session_factory() as scanner_session:
        scanner_repository = OperationalRepository(
            scanner_session,
            organization_id=organization_context[0],
            organization_key=organization_context[1],
            organization_name=organization_context[2],
        )
        scanner_repository._lock_system(system_id)
        stale_finding = scanner_session.get(FindingRow, finding_id)
        assert stale_finding is not None
        stale_finding.lifecycle_status = "reopened"
        worker = Thread(target=apply_analyst_decision, daemon=True)
        worker.start()
        assert started.wait(timeout=2)
        assert not finished.wait(timeout=0.2)
        scanner_session.commit()

    assert finished.wait(timeout=5)
    worker.join(timeout=1)
    assert "error" not in result, result.get("error")
    assert result["status"] == "accepted"
    with session_factory() as verification_session:
        persisted = verification_session.get(FindingRow, finding_id)
        assert persisted is not None
        assert persisted.lifecycle_status == "accepted"
