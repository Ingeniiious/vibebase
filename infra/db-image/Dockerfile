# vibe-postgres — pgvector/pgvector:pg17 + the Supabase extension set.
#
# The console's Extensions page reads pg_available_extensions from each
# project DB; the stock pgvector image only ships contrib + vector, so
# everything Supabase users expect (pg_cron, pg_net, http, pg_graphql,
# postgis, ...) was missing. This image adds them as prebuilt Debian debs
# from PGDG (already configured in the base image) plus the Pigsty
# extension repo (repo.pigsty.io — PGDG-compatible builds of the
# Supabase-specific extensions: pg_graphql, pg_net, pgsodium, wrappers,
# supabase_vault, pgmq, pg_jsonschema, pgjwt, pg_hashids, index_advisor).
#
# Same postgres major (17, pgdg Debian bookworm) and same data-dir layout
# as the stock pgvector image, so existing containers can be recreated on
# their volumes with only an image swap + conf update. See README.md here.
#
# Build:  docker build -t vibe-postgres:17-ext1 .
#
# NOTE: several extensions also need postgresql.conf additions (the
# provisioner writes these for new projects):
#   shared_preload_libraries = 'supautils,pg_stat_statements,pg_cron,pg_net,pgaudit,pgsodium,supabase_vault'
#   cron.database_name = '<project db>'
#   supautils.privileged_extensions = '<list of extension names>'
#   supautils.privileged_extensions_superuser = 'postgres'
#   supautils.extension_custom_scripts_path = '/etc/postgresql-custom/extension-custom-scripts'
# supautils (same one Supabase runs in cloud) lets the NON-superuser
# <ref>_app role that the studio connects as run CREATE EXTENSION for the
# whitelisted extensions — without it, the studio's Enable button only
# works for trusted contrib + pgmq and fails for pg_cron/vector/etc.

FROM pgvector/pgvector:pg17

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates gnupg; \
    mkdir -p /etc/apt/keyrings; \
    curl -fsSL https://repo.pigsty.io/key | gpg --dearmor -o /etc/apt/keyrings/pigsty.gpg; \
    echo "deb [signed-by=/etc/apt/keyrings/pigsty.gpg] https://repo.pigsty.io/apt/pgsql/bookworm bookworm main" \
        > /etc/apt/sources.list.d/pigsty.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        # --- PGDG contrib-adjacent ---
        postgresql-17-cron \
        postgresql-17-http \
        postgresql-17-postgis-3 \
        postgresql-17-pgaudit \
        postgresql-17-pgrouting \
        postgresql-17-hypopg \
        postgresql-17-rum \
        postgresql-17-repack \
        postgresql-17-partman \
        postgresql-17-pgtap \
        postgresql-17-plpgsql-check \
        postgresql-17-wal2json \
        # --- Supabase set (Pigsty) ---
        postgresql-17-pgmq \
        postgresql-17-pg-net \
        postgresql-17-pgjwt \
        postgresql-17-pg-graphql \
        postgresql-17-pg-jsonschema \
        postgresql-17-wrappers \
        postgresql-17-pgsodium \
        postgresql-17-vault \
        postgresql-17-pg-hashids \
        postgresql-17-index-advisor \
        postgresql-17-pgroonga \
        postgresql-17-supautils \
    ; \
    apt-get purge -y --auto-remove gnupg; \
    rm -rf /var/lib/apt/lists/*

# pgsodium refuses to preload without a getkey script. Like supabase/postgres,
# generate a per-cluster root key on first use and keep it in PGDATA (0600,
# postgres-owned, lives on the data volume).
RUN printf '%s\n' '#!/bin/sh' 'set -eu' \
      'KEY_FILE="${PGSODIUM_KEY_FILE:-$PGDATA/pgsodium_root.key}"' \
      'if [ ! -f "$KEY_FILE" ]; then' \
      '  head -c 32 /dev/urandom | od -A n -t x1 | tr -d " \\n" > "$KEY_FILE"' \
      '  chmod 600 "$KEY_FILE"' \
      'fi' \
      'cat "$KEY_FILE"' \
      > /usr/share/postgresql/17/extension/pgsodium_getkey; \
    chmod 755 /usr/share/postgresql/17/extension/pgsodium_getkey

# supautils after-create hooks: grant the per-project <db>_app role usage of
# pg_cron/pgmq the moment the extension is enabled from the studio.
COPY extension-custom-scripts /etc/postgresql-custom/extension-custom-scripts
