-- Development/reference separation between schema owner, tenant API, tenant workers
-- and a non-login owner for the minimal SECURITY DEFINER dispatch functions.
-- Production deployments must replace trust authentication with managed secrets.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'traceless_api') THEN
        CREATE ROLE traceless_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'traceless_worker') THEN
        CREATE ROLE traceless_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'traceless_dispatch_owner'
    ) THEN
        CREATE ROLE traceless_dispatch_owner NOLOGIN NOSUPERUSER NOCREATEDB
            NOCREATEROLE NOINHERIT BYPASSRLS;
    END IF;
END
$$;

-- Re-running provisioning must also harden roles created by an older release.
ALTER ROLE traceless_api NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
ALTER ROLE traceless_worker NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
ALTER ROLE traceless_dispatch_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOINHERIT BYPASSRLS;
GRANT traceless_dispatch_owner TO traceless;

GRANT CONNECT ON DATABASE traceless TO traceless_api, traceless_worker;
GRANT USAGE ON SCHEMA public TO traceless_api, traceless_worker;
GRANT USAGE ON SCHEMA public TO traceless_dispatch_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
    TO traceless_api, traceless_worker;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
    TO traceless_api, traceless_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE traceless IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO traceless_api, traceless_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE traceless IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO traceless_api, traceless_worker;
