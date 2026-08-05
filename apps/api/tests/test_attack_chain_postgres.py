import os

import pytest
from sqlalchemy import create_engine, text


def test_postgres_attack_chain_table_has_forced_tenant_controls() -> None:
    database_url = os.getenv("TRACELESS_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("TRACELESS_TEST_POSTGRES_URL is not configured")

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            state = connection.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity "
                    "FROM pg_class WHERE oid = 'attack_chain_analyses'::regclass"
                )
            ).one()
            assert state == (True, True)

            policy = connection.execute(
                text(
                    "SELECT qual, with_check FROM pg_policies "
                    "WHERE schemaname = 'public' "
                    "AND tablename = 'attack_chain_analyses' "
                    "AND policyname = 'traceless_tenant_isolation'"
                )
            ).one()
            assert "traceless_current_organization_id" in policy.qual
            assert "traceless_current_organization_id" in policy.with_check

            trigger_count = connection.scalar(
                text(
                    "SELECT count(*) FROM pg_trigger "
                    "WHERE tgrelid = 'attack_chain_analyses'::regclass "
                    "AND tgname = 'traceless_attack_chain_source_tenant' "
                    "AND NOT tgisinternal"
                )
            )
            assert trigger_count == 1
            assert connection.scalar(
                text(
                    "SELECT has_table_privilege("
                    "'traceless_api', 'attack_chain_analyses', 'SELECT')"
                )
            ) is True
            assert connection.scalar(
                text(
                    "SELECT has_table_privilege("
                    "'traceless_worker', 'attack_chain_analyses', 'SELECT')"
                )
            ) is True
    finally:
        engine.dispose()
