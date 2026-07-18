# db-image — `vibe-postgres:17-ext1`

The image every project database runs: `pgvector/pgvector:pg17` + the
Supabase extension set, as prebuilt debs (PGDG + the
[Pigsty](https://pigsty.io) extension repo). Same postgres major (17.x,
pgdg/bookworm) and identical data-dir layout as the stock pgvector image,
so containers can be recreated on existing volumes with only an image +
conf change — no dump/restore, no initdb.

Why not `supabase/postgres`? Their images are Nix-built with a different
build/layout and their PG17 line is not a drop-in for a pgdg 17 data dir;
adding .so files on top of the exact base we run is far safer than an
image family swap.

## Build

`deploy-stack.sh` (`step_aux_images`) builds this automatically during
install. Manual build:

```sh
docker build -t vibe-postgres:17-ext1 .
```

## What it adds (extension names)

- **needs `shared_preload_libraries`**: pg_cron, pg_net, pgaudit, pgsodium,
  supabase_vault (+ pg_stat_statements from contrib, which only works when
  preloaded)
- **plain**: http, pgjwt, pg_graphql, pg_jsonschema, wrappers, pgmq,
  pg_partman, pg_hashids, index_advisor, hypopg, rum, pg_repack, pgtap,
  plpgsql_check, pgroonga, pgrouting, postgis (+ topology, raster, tiger,
  address_standardizer), wal2json (logical-decoding plugin, no extension)
- **supautils** (the same extension Supabase cloud runs): the dashboard and
  apps connect as the NON-superuser `<db>_app`, and almost every extension
  above needs superuser to `CREATE EXTENSION`. supautils intercepts
  CREATE EXTENSION from non-superusers and runs whitelisted ones as
  `postgres`, so the dashboard's Enable button works. Its after-create
  hooks (`extension-custom-scripts/` here, baked into the image)
  additionally grant `<db>_app` usage of the `cron` and `pgmq` schemas the
  moment those extensions are enabled — required for the Cron and Queues
  pages to actually function.

Required conf additions (the provisioner writes these into every new
project's `custom-postgres.conf` automatically —
`PRIVILEGED_EXTENSIONS` is the list in `infra/provisioner/provisioner.py`):

```
shared_preload_libraries = 'supautils,pg_stat_statements,pg_cron,pg_net,pgaudit,pgsodium,supabase_vault'
cron.database_name = '<project db name>'   # pg_cron runs in exactly one DB
supautils.privileged_extensions = '<PRIVILEGED_EXTENSIONS>'
supautils.privileged_extensions_superuser = 'postgres'
supautils.extension_custom_scripts_path = '/etc/postgresql-custom/extension-custom-scripts'
```

Not included (deliberately): timescaledb / plv8 (Supabase itself dropped
both from its PG17 images), pg_tle and pg_stat_monitor (hidden by the
dashboard UI).
