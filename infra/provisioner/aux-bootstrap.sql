-- Additive Supabase aux bootstrap. Safe to re-run. Requires env vars:
--   AUTHENTICATOR_PW AUTH_ADMIN_PW STORAGE_ADMIN_PW REALTIME_ADMIN_PW
-- Run as postgres superuser against the target project DB.
\set ON_ERROR_STOP on
\set authenticator_pw `echo "$AUTHENTICATOR_PW"`
\set auth_admin_pw `echo "$AUTH_ADMIN_PW"`
\set storage_admin_pw `echo "$STORAGE_ADMIN_PW"`
\set realtime_admin_pw `echo "$REALTIME_ADMIN_PW"`

-- Extensions needed by gotrue/storage migrations (additive, no-op if present).
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Roles: create only if absent (never modify pre-existing production roles).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon') THEN
    CREATE ROLE anon NOLOGIN NOINHERIT; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN
    CREATE ROLE authenticated NOLOGIN NOINHERIT; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='service_role') THEN
    CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticator') THEN
    CREATE ROLE authenticator LOGIN NOINHERIT; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='supabase_auth_admin') THEN
    CREATE ROLE supabase_auth_admin LOGIN CREATEROLE NOINHERIT; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='supabase_storage_admin') THEN
    CREATE ROLE supabase_storage_admin LOGIN NOINHERIT; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='supabase_realtime_admin') THEN
    CREATE ROLE supabase_realtime_admin LOGIN NOINHERIT; END IF;
END $$;

-- Passwords / login attrs for the roles WE own (login roles created above).
ALTER ROLE authenticator            WITH LOGIN PASSWORD :'authenticator_pw';
ALTER ROLE supabase_auth_admin      WITH LOGIN CREATEROLE PASSWORD :'auth_admin_pw';
ALTER ROLE supabase_storage_admin   WITH LOGIN PASSWORD :'storage_admin_pw';
ALTER ROLE supabase_realtime_admin  WITH LOGIN PASSWORD :'realtime_admin_pw';

-- authenticator may assume the three API roles (PostgREST SET ROLE).
GRANT anon           TO authenticator;
GRANT authenticated  TO authenticator;
GRANT service_role   TO authenticator;

-- Schemas owned by their service admins.
CREATE SCHEMA IF NOT EXISTS auth       AUTHORIZATION supabase_auth_admin;
CREATE SCHEMA IF NOT EXISTS storage    AUTHORIZATION supabase_storage_admin;
CREATE SCHEMA IF NOT EXISTS _realtime  AUTHORIZATION supabase_realtime_admin;

-- Schema USAGE only for the API roles. anon gets NO table privileges (prod safety).
GRANT USAGE ON SCHEMA public  TO anon, authenticated, service_role;
GRANT USAGE ON SCHEMA storage TO anon, authenticated, service_role, authenticator;

-- service_role: full DML on existing public objects (bypasses RLS via role attr).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES     IN SCHEMA public TO service_role;
GRANT USAGE, SELECT                  ON ALL SEQUENCES  IN SCHEMA public TO service_role;
GRANT EXECUTE                        ON ALL FUNCTIONS  IN SCHEMA public TO service_role;

-- Default privileges so service_role also gets DML on FUTURE public objects,
-- for every current owner of public tables (e.g. <ref>_app) plus postgres.
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT tableowner AS owner FROM pg_tables WHERE schemaname='public'
    UNION SELECT 'postgres'
  LOOP
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO service_role', r.owner);
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO service_role', r.owner);
    EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO service_role', r.owner);
  END LOOP;
END $$;

-- Empty realtime publication (CDC only functions at wal_level=logical).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_publication WHERE pubname='supabase_realtime') THEN
    CREATE PUBLICATION supabase_realtime;
  END IF;
END $$;

SELECT 'bootstrap-ok' AS status;
