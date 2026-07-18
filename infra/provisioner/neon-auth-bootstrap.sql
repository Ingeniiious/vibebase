-- Neon-Auth-compatible schema bootstrap. Safe to re-run (fully additive).
-- Byte-identical to the `neon_auth` schema the CURRENT (Better-Auth-based)
-- Neon Auth provisions, captured from a live Neon project 2026-07-17:
-- better-auth core (user/session/account/verification) + admin plugin columns
-- + organization plugin (organization/member/invitation) + jwt plugin (jwks)
-- + Neon's own project_config (kept for parity; our service configures via env
-- and never reads it).
--
-- Requires env var: NEON_AUTH_OWNER — the role that will own the schema and
-- tables (the project's <ref>_app role, which the neon-auth service dials).
-- Run as postgres superuser against the target project DB.
\set ON_ERROR_STOP on
\set owner `echo "$NEON_AUTH_OWNER"`

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS neon_auth;

CREATE TABLE IF NOT EXISTS neon_auth."user" (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL,
  email         text NOT NULL UNIQUE,
  "emailVerified" boolean NOT NULL,
  image         text,
  "createdAt"   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  role          text,
  banned        boolean,
  "banReason"   text,
  "banExpires"  timestamptz
);

CREATE TABLE IF NOT EXISTS neon_auth.session (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "expiresAt"   timestamptz NOT NULL,
  token         text NOT NULL UNIQUE,
  "createdAt"   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"   timestamptz NOT NULL,
  "ipAddress"   text,
  "userAgent"   text,
  "userId"      uuid NOT NULL REFERENCES neon_auth."user"(id) ON DELETE CASCADE,
  "impersonatedBy" text,
  "activeOrganizationId" text
);

CREATE TABLE IF NOT EXISTS neon_auth.account (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "accountId"   text NOT NULL,
  "providerId"  text NOT NULL,
  "userId"      uuid NOT NULL REFERENCES neon_auth."user"(id) ON DELETE CASCADE,
  "accessToken" text,
  "refreshToken" text,
  "idToken"     text,
  "accessTokenExpiresAt"  timestamptz,
  "refreshTokenExpiresAt" timestamptz,
  scope         text,
  password      text,
  "createdAt"   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"   timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS neon_auth.verification (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier    text NOT NULL,
  value         text NOT NULL,
  "expiresAt"   timestamptz NOT NULL,
  "createdAt"   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS neon_auth.jwks (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "publicKey"   text NOT NULL,
  "privateKey"  text NOT NULL,
  "createdAt"   timestamptz NOT NULL,
  "expiresAt"   timestamptz
);

CREATE TABLE IF NOT EXISTS neon_auth.organization (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL,
  slug          text NOT NULL UNIQUE,
  logo          text,
  "createdAt"   timestamptz NOT NULL,
  metadata      text
);

CREATE TABLE IF NOT EXISTS neon_auth.member (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "organizationId" uuid NOT NULL REFERENCES neon_auth.organization(id) ON DELETE CASCADE,
  "userId"      uuid NOT NULL REFERENCES neon_auth."user"(id) ON DELETE CASCADE,
  role          text NOT NULL,
  "createdAt"   timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS neon_auth.invitation (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "organizationId" uuid NOT NULL REFERENCES neon_auth.organization(id) ON DELETE CASCADE,
  email         text NOT NULL,
  role          text,
  status        text NOT NULL,
  "expiresAt"   timestamptz NOT NULL,
  "createdAt"   timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "inviterId"   uuid NOT NULL REFERENCES neon_auth."user"(id) ON DELETE CASCADE
);

-- Neon control-plane config table. Parity only — unused by our service.
CREATE TABLE IF NOT EXISTS neon_auth.project_config (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL,
  endpoint_id   text NOT NULL UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  trusted_origins  jsonb NOT NULL,
  social_providers jsonb NOT NULL,
  email_provider   jsonb,
  email_and_password jsonb,
  allow_localhost  boolean NOT NULL,
  plugin_configs   jsonb,
  webhook_config   jsonb
);

-- Hand the whole schema to the service role. psql variables do NOT interpolate
-- inside dollar-quoted DO bodies, so build the statements at top level and
-- \gexec them (idempotent).
SELECT format('ALTER SCHEMA neon_auth OWNER TO %I', :'owner') \gexec
SELECT format('ALTER TABLE neon_auth.%I OWNER TO %I', tablename, :'owner')
  FROM pg_tables WHERE schemaname = 'neon_auth' \gexec

SELECT 'neon-auth-bootstrap-ok' AS status;
