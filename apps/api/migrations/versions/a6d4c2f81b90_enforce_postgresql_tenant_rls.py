"""Enforce PostgreSQL tenant RLS for API and worker runtime connections.

Revision ID: a6d4c2f81b90
Revises: e4b7a2c93f10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a6d4c2f81b90"
down_revision: str | Sequence[str] | None = "e4b7a2c93f10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DIRECT_ORGANIZATION_TABLES = (
    "projects",
    "global_intel_records",
    "external_intelligence_connectors",
    "external_intelligence_sync_runs",
    "external_intelligence_sync_pages",
    "external_intelligence_sync_identities",
    "external_intelligence_checkpoints",
    "global_intel_revisions",
    "background_jobs",
    "audit_events",
    "scan_jobs",
)

_SYSTEM_TABLES = (
    "scan_authorizations",
    "assets",
    "architecture_snapshots",
    "vulnerability_scan_imports",
    "vulnerability_observations",
    "intelligence_sync_states",
    "threats_operational",
    "findings_operational",
    "risks_operational",
    "asset_source_snapshots",
    "reports",
)

_ALL_RLS_TABLES = (
    "organizations",
    *_DIRECT_ORGANIZATION_TABLES,
    "systems_operational",
    *_SYSTEM_TABLES,
    "asset_aliases",
    "asset_observations",
    "services",
    "finding_evidence",
    "global_intel_observables",
)

_GRANT_TABLES = (*_ALL_RLS_TABLES, "intelligence_cache")

_DISPATCH_FUNCTIONS = (
    "traceless_dispatch_expired_scan_job()",
    "traceless_dispatch_runnable_scan_job()",
    "traceless_dispatch_expired_background_job()",
    "traceless_dispatch_runnable_background_job()",
    "traceless_dispatch_due_connector(uuid[])",
)


def _enable_policy(table: str, predicate: str) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY traceless_tenant_isolation ON "{table}" '
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


def upgrade() -> None:
    bind = op.get_bind()

    with op.batch_alter_table("scan_jobs") as batch:
        batch.add_column(sa.Column("organization_id", sa.Uuid(), nullable=True))
    op.execute(
        """
        UPDATE scan_jobs
        SET organization_id = (
            SELECT p.organization_id
            FROM systems_operational AS s
            JOIN projects AS p ON p.id = s.project_id
            WHERE s.id = scan_jobs.system_id
        )
        """
    )
    with op.batch_alter_table("scan_jobs") as batch:
        batch.alter_column("organization_id", existing_type=sa.Uuid(), nullable=False)
        batch.create_foreign_key(
            "fk_scan_jobs_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_index("ix_scan_jobs_organization", ["organization_id"])

    if bind.dialect.name != "postgresql":
        return

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM scan_jobs AS j
                JOIN systems_operational AS s ON s.id = j.system_id
                JOIN projects AS p ON p.id = s.project_id
                WHERE j.organization_id <> p.organization_id
            ) OR EXISTS (
                SELECT 1
                FROM background_jobs AS j
                JOIN systems_operational AS s ON s.id = j.system_id
                JOIN projects AS p ON p.id = s.project_id
                WHERE j.organization_id <> p.organization_id
            ) THEN
                RAISE EXCEPTION 'job tenant backfill contains mismatched systems';
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION traceless_current_organization_id()
        RETURNS uuid
        LANGUAGE sql
        STABLE
        PARALLEL SAFE
        AS $$
            SELECT NULLIF(current_setting('traceless.organization_id', true), '')::uuid
        $$
        """
    )

    current_org = "traceless_current_organization_id()"
    _enable_policy("organizations", f"id = {current_org}")
    for table in _DIRECT_ORGANIZATION_TABLES:
        _enable_policy(table, f"organization_id = {current_org}")

    system_predicate = (
        "EXISTS (SELECT 1 FROM projects p "
        "WHERE p.id = systems_operational.project_id "
        f"AND p.organization_id = {current_org})"
    )
    _enable_policy("systems_operational", system_predicate)

    for table in _SYSTEM_TABLES:
        predicate = (
            "EXISTS (SELECT 1 FROM systems_operational s "
            "JOIN projects p ON p.id = s.project_id "
            f"WHERE s.id = {table}.system_id AND p.organization_id = {current_org})"
        )
        _enable_policy(table, predicate)

    def asset_predicate(table: str) -> str:
        return (
            "EXISTS (SELECT 1 FROM assets a "
            "JOIN systems_operational s ON s.id = a.system_id "
            "JOIN projects p ON p.id = s.project_id "
            f"WHERE a.id = {table}.asset_id AND p.organization_id = {current_org})"
        )
    for table in ("asset_aliases", "asset_observations", "services"):
        _enable_policy(table, asset_predicate(table))

    _enable_policy(
        "finding_evidence",
        "EXISTS (SELECT 1 FROM findings_operational f "
        "JOIN systems_operational s ON s.id = f.system_id "
        "JOIN projects p ON p.id = s.project_id "
        "WHERE f.id = finding_evidence.finding_id "
        f"AND p.organization_id = {current_org})",
    )
    _enable_policy(
        "global_intel_observables",
        "EXISTS (SELECT 1 FROM global_intel_records r "
        "WHERE r.id = global_intel_observables.record_id "
        f"AND r.organization_id = {current_org})",
    )

    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'traceless_dispatch_owner'
            ) OR NOT EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'traceless_worker'
            ) THEN
                RAISE EXCEPTION
                    'Provision traceless_dispatch_owner and traceless_worker before migration';
            END IF;
        END
        $$
        """
    )
    op.execute(
        "GRANT SELECT, UPDATE ON scan_jobs, background_jobs, "
        "external_intelligence_connectors TO traceless_dispatch_owner"
    )
    op.execute("GRANT CREATE ON SCHEMA public TO traceless_dispatch_owner")
    op.execute(
        """
        CREATE FUNCTION traceless_dispatch_expired_scan_job()
        RETURNS TABLE(job_id uuid, organization_id uuid)
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
            SELECT j.id, j.organization_id
            FROM public.scan_jobs AS j
            WHERE j.status = 'running'
              AND (
                  (j.cancel_requested_at IS NOT NULL AND (
                      j.lease_expires_at IS NULL
                      OR j.lease_expires_at <= clock_timestamp()
                  ))
                  OR (
                      j.cancel_requested_at IS NULL
                      AND j.lease_expires_at IS NOT NULL
                      AND j.lease_expires_at <= clock_timestamp()
                      AND j.attempt_count >= j.max_attempts
                  )
            )
            ORDER BY j.requested_at, j.id
            LIMIT 1
            FOR UPDATE OF j SKIP LOCKED
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION traceless_dispatch_runnable_scan_job()
        RETURNS TABLE(job_id uuid, organization_id uuid)
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
            SELECT j.id, j.organization_id
            FROM public.scan_jobs AS j
            WHERE j.scanner = 'nmap'
              AND j.cancel_requested_at IS NULL
              AND (
                  j.status = 'queued'
                  OR (
                      j.status = 'running'
                      AND j.lease_expires_at IS NOT NULL
                      AND j.lease_expires_at <= clock_timestamp()
                      AND j.attempt_count < j.max_attempts
                  )
            )
            ORDER BY j.requested_at, j.id
            LIMIT 1
            FOR UPDATE OF j SKIP LOCKED
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION traceless_dispatch_expired_background_job()
        RETURNS TABLE(job_id uuid, organization_id uuid)
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
            SELECT j.id, j.organization_id
            FROM public.background_jobs AS j
            WHERE j.status = 'running'
              AND j.lease_expires_at IS NOT NULL
              AND j.lease_expires_at <= clock_timestamp()
              AND (
                  j.cancel_requested_at IS NOT NULL
                  OR j.attempt_count >= j.max_attempts
              )
            ORDER BY j.requested_at, j.id
            LIMIT 1
            FOR UPDATE OF j SKIP LOCKED
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION traceless_dispatch_runnable_background_job()
        RETURNS TABLE(job_id uuid, organization_id uuid)
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
            SELECT j.id, j.organization_id
            FROM public.background_jobs AS j
            WHERE j.cancel_requested_at IS NULL
              AND (
                  (j.status = 'queued' AND j.available_at <= clock_timestamp())
                  OR (
                      j.status = 'running'
                      AND j.lease_expires_at IS NOT NULL
                      AND j.lease_expires_at <= clock_timestamp()
                      AND j.attempt_count < j.max_attempts
                  )
              )
            ORDER BY j.available_at, j.requested_at, j.id
            LIMIT 1
            FOR UPDATE OF j SKIP LOCKED
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION traceless_dispatch_due_connector(
            p_excluded uuid[]
        )
        RETURNS TABLE(
            connector_id uuid,
            organization_id uuid,
            config_version integer,
            sync_interval_seconds integer
        )
        LANGUAGE sql
        VOLATILE
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
            SELECT c.id, c.organization_id, c.config_version, c.sync_interval_seconds
            FROM public.external_intelligence_connectors AS c
            WHERE c.enabled = true
              AND c.sync_interval_seconds IS NOT NULL
              AND c.next_sync_at IS NOT NULL
              AND c.next_sync_at <= clock_timestamp()
              AND NOT (c.id = ANY(COALESCE(p_excluded, ARRAY[]::uuid[])))
            ORDER BY c.next_sync_at, c.id
            LIMIT 1
            FOR UPDATE OF c SKIP LOCKED
        $$
        """
    )
    for signature in _DISPATCH_FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO traceless_worker")
        op.execute(
            f"ALTER FUNCTION {signature} OWNER TO traceless_dispatch_owner"
        )
    op.execute("REVOKE CREATE ON SCHEMA public FROM traceless_dispatch_owner")

    op.execute(
        """
        CREATE FUNCTION traceless_enforce_job_tenant_match()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, pg_temp
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM public.systems_operational AS s
                JOIN public.projects AS p ON p.id = s.project_id
                WHERE s.id = NEW.system_id
                  AND p.organization_id = NEW.organization_id
            ) THEN
                RAISE EXCEPTION 'job organization does not own its system'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER traceless_scan_job_tenant_match
        BEFORE INSERT OR UPDATE OF organization_id, system_id ON scan_jobs
        FOR EACH ROW EXECUTE FUNCTION traceless_enforce_job_tenant_match()
        """
    )
    op.execute(
        """
        CREATE TRIGGER traceless_background_job_tenant_match
        BEFORE INSERT OR UPDATE OF organization_id, system_id ON background_jobs
        FOR EACH ROW EXECUTE FUNCTION traceless_enforce_job_tenant_match()
        """
    )

    tables = ", ".join(f'"{table}"' for table in _GRANT_TABLES)
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'traceless_api') THEN
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {tables} TO traceless_api';
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'traceless_worker') THEN
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {tables}'
                    || ' TO traceless_worker';
            END IF;
        END
        $$
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS traceless_background_job_tenant_match "
            "ON background_jobs"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS traceless_scan_job_tenant_match ON scan_jobs"
        )
        op.execute("DROP FUNCTION IF EXISTS traceless_enforce_job_tenant_match()")
        for signature in reversed(_DISPATCH_FUNCTIONS):
            op.execute(f"DROP FUNCTION IF EXISTS {signature}")
        op.execute(
            "REVOKE SELECT, UPDATE ON scan_jobs, background_jobs, "
            "external_intelligence_connectors FROM traceless_dispatch_owner"
        )
        for table in reversed(_ALL_RLS_TABLES):
            op.execute(f'DROP POLICY IF EXISTS traceless_tenant_isolation ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
        op.execute("DROP FUNCTION IF EXISTS traceless_current_organization_id()")

    with op.batch_alter_table("scan_jobs") as batch:
        batch.drop_index("ix_scan_jobs_organization")
        batch.drop_constraint(
            "fk_scan_jobs_organization_id_organizations", type_="foreignkey"
        )
        batch.drop_column("organization_id")
