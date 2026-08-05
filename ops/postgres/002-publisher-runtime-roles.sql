\set ON_ERROR_STOP on

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'publisher_owner') THEN
        CREATE ROLE publisher_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'publisher_migrator') THEN
        CREATE ROLE publisher_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'publisher_admin_api') THEN
        CREATE ROLE publisher_admin_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'publisher_ingest_api') THEN
        CREATE ROLE publisher_ingest_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'publisher_review_api') THEN
        CREATE ROLE publisher_review_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'publisher_feed_api') THEN
        CREATE ROLE publisher_feed_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END
$$;

GRANT publisher_owner TO publisher_migrator;
GRANT CONNECT ON DATABASE traceless_publisher TO
    publisher_migrator,
    publisher_admin_api,
    publisher_ingest_api,
    publisher_review_api,
    publisher_feed_api;

ALTER SCHEMA public OWNER TO publisher_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO
    publisher_admin_api,
    publisher_ingest_api,
    publisher_review_api,
    publisher_feed_api;
GRANT USAGE, CREATE ON SCHEMA public TO publisher_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM
    publisher_admin_api,
    publisher_ingest_api,
    publisher_review_api,
    publisher_feed_api;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM
    publisher_admin_api,
    publisher_ingest_api,
    publisher_review_api,
    publisher_feed_api;

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'publisher_clients', 'publisher_accounts', 'publisher_installations',
        'publisher_client_credentials', 'publisher_entitlements'
    ] LOOP
        IF to_regclass('public.' || table_name) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT, INSERT, UPDATE ON TABLE public.%I TO publisher_admin_api',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY[
        'publisher_records', 'publisher_revisions', 'publisher_import_runs',
        'publisher_publication_decisions', 'publisher_signing_keys',
        'publisher_audit_events'
    ] LOOP
        IF to_regclass('public.' || table_name) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO publisher_admin_api', table_name
            );
        END IF;
    END LOOP;
    IF to_regclass('public.publisher_entitlements') IS NOT NULL THEN
        GRANT DELETE ON TABLE publisher_entitlements TO publisher_admin_api;
    END IF;
    IF to_regclass('public.publisher_signing_keys') IS NOT NULL THEN
        GRANT INSERT, UPDATE ON TABLE publisher_signing_keys TO publisher_admin_api;
    END IF;
    IF to_regclass('public.publisher_audit_events') IS NOT NULL THEN
        GRANT INSERT ON TABLE publisher_audit_events TO publisher_admin_api;
    END IF;

    FOREACH table_name IN ARRAY ARRAY[
        'publisher_records', 'publisher_revisions', 'publisher_import_runs',
        'publisher_current_projections'
    ] LOOP
        IF to_regclass('public.' || table_name) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT, INSERT, UPDATE ON TABLE public.%I TO publisher_ingest_api',
                table_name
            );
        END IF;
    END LOOP;
    IF to_regclass('public.publisher_current_projections') IS NOT NULL THEN
        GRANT DELETE ON TABLE publisher_current_projections TO publisher_ingest_api;
    END IF;
    FOREACH table_name IN ARRAY ARRAY[
        'publisher_changes', 'publisher_publication_decisions',
        'publisher_audit_events'
    ] LOOP
        IF to_regclass('public.' || table_name) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT, INSERT ON TABLE public.%I TO publisher_ingest_api',
                table_name
            );
        END IF;
    END LOOP;

    FOREACH table_name IN ARRAY ARRAY[
        'publisher_records', 'publisher_revisions', 'publisher_import_runs',
        'publisher_publication_decisions', 'publisher_audit_events'
    ] LOOP
        IF to_regclass('public.' || table_name) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO publisher_review_api', table_name
            );
        END IF;
    END LOOP;
    IF to_regclass('public.publisher_revisions') IS NOT NULL THEN
        GRANT UPDATE ON TABLE publisher_revisions TO publisher_review_api;
    END IF;
    IF to_regclass('public.publisher_changes') IS NOT NULL THEN
        GRANT SELECT, INSERT ON TABLE publisher_changes TO publisher_review_api;
    END IF;
    IF to_regclass('public.publisher_current_projections') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE publisher_current_projections
            TO publisher_review_api;
    END IF;
    IF to_regclass('public.publisher_publication_decisions') IS NOT NULL THEN
        GRANT INSERT ON TABLE publisher_publication_decisions TO publisher_review_api;
    END IF;
    IF to_regclass('public.publisher_audit_events') IS NOT NULL THEN
        GRANT INSERT ON TABLE publisher_audit_events TO publisher_review_api;
    END IF;


    IF to_regclass('public.alembic_version') IS NOT NULL THEN
        GRANT SELECT ON TABLE alembic_version TO
            publisher_admin_api,
            publisher_ingest_api,
            publisher_review_api,
            publisher_feed_api;
    END IF;

    FOREACH table_name IN ARRAY ARRAY[
        'publisher_clients', 'publisher_installations',
        'publisher_client_credentials', 'publisher_entitlements',
        'publisher_current_projections', 'publisher_changes',
        'publisher_signing_keys'
    ] LOOP
        IF to_regclass('public.' || table_name) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO publisher_feed_api', table_name
            );
        END IF;
    END LOOP;
END
$$;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO
    publisher_admin_api,
    publisher_ingest_api,
    publisher_review_api;

ALTER DEFAULT PRIVILEGES FOR ROLE publisher_owner IN SCHEMA public
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE publisher_owner IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
