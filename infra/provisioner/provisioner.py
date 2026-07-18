#!/usr/bin/env python3
"""provisioner: self-service create/delete of per-project Postgres databases
(+ optional Supabase aux services) for Vibe Base.

Security model:
- HMAC-authed HTTP API (same scheme as svc-agent): HMAC-SHA256 hexdigest over
  "<ts>.<method>.<path>.<body>" with CONSOLE_PROXY_HMAC_SECRET, sent as
  X-Console-Ts / X-Console-Sig headers; timestamp within 300s (replay guard).
- Docker access ONLY through the provisioner-proxy socket proxy (DOCKER_HOST);
  the raw socket is never mounted in this container.
- Template-enforced: every container this service creates is named
  <ref>-{db,auth,rest,storage,realtime} from a regex-validated ref and uses a
  fixed image + fixed argv. The single exception is recreating the shared
  key-proxy container (fixed name/image/mount/cmd). Arbitrary containers can
  never be created, whatever the request body says.
- Seed projects (pre-existing refs listed in SEED_REFS) can never be
  provisioned over or deprovisioned — hard guard.
- Public exposure is NOT done by publishing the DB port on a public IP
  (docker-published ports bypass ufw). Instead
  the DB publishes on 127.0.0.1:<port> and this service writes a desired-state
  file to /root/provisioner-expose.d/<ref>; the host-side
  provisioner-expose-sync systemd path unit creates the socat relay unit
  (dbexpose-<ref>.service) + ufw allow, mirroring the seed projects.

Secrets are written to /root/<ref>-aux.env (0600) and returned once over the
HMAC channel for the studio to persist; they are NEVER logged.
"""
import hashlib
import hmac
import json
import os
import re
import secrets as pysecrets
import shutil
import socket
import string
import subprocess
import time
from base64 import urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, HTTPServer

SECRET = os.environ["CONSOLE_PROXY_HMAC_SECRET"].encode()
MON_PASSWORD = os.environ["CONSOLE_MON_PASSWORD"]
os.environ.setdefault("DOCKER_HOST", "tcp://provisioner-proxy:2375")

# Parameterized per box via container env (always set by deploy-stack.sh).
DOMAIN_SUFFIX = os.environ.get("DOMAIN_SUFFIX", "")
PUBLIC_IP = os.environ.get("PUBLIC_IP", "")
DOCKER_NET = os.environ.get("DOCKER_NET", "coolify")

# Container-side views of the host bind mounts (docker -v uses the HOST path).
HOST_ROOT = "/host/root"                 # host /root
TRAEFIK_DIR = "/host/traefik-dynamic"    # host /data/coolify/proxy/dynamic
DB_DIR = "/host/databases"               # host /data/coolify/databases
STORAGE_DIR = "/host/storage"            # host /data/storage
EXPOSE_DIR = f"{HOST_ROOT}/provisioner-expose.d"
BOOTSTRAP_SQL = "/app/aux-bootstrap.sql"

REF_RE = re.compile(r"^[a-z][a-z0-9]{1,30}$")
SEED_REFS = set()  # refs of pre-existing projects to protect (none on a fresh box)
# refs whose <REF>_* env prefix or container names would collide with existing
# studio/app env vars or infrastructure.
RESERVED_REFS = SEED_REFS | {
    "supabase", "console", "studio", "postgres", "pg", "svc", "key",
    "next", "better", "autosend", "enabled", "provisioner", "coolify",
    "traefik", "docker",
}
ALL_SERVICES = ["auth", "rest", "storage", "realtime"]
# Per-project auth backend for the "auth" service slot. gotrue = the Supabase
# stack (default, unchanged). neon-auth = the Neon-Auth-compatible Better Auth
# service (infra/neon-auth) for apps that integrate against NEON_AUTH_BASE_URL.
AUTH_BACKENDS = {"gotrue", "neon-auth"}

# Per-project resource caps — MUST mirror the studio's resource-plan.ts. Each aux
# container gets a fixed floor cap; the DB gets the remainder. A cap below these
# floors would OOM the container, so /set-resources and /provision refuse it.
AUX_MEMORY_FLOOR_MB = {"auth": 64, "rest": 64, "storage": 192, "realtime": 256}
DB_MEMORY_FLOOR_MB = 384
PROJECT_MEMORY_MAX_MB = 12288
PROJECT_CPUS_MIN = 0.25
PROJECT_CPUS_MAX = 4

# Seed projects are Coolify-managed with hash container names, so <ref>-db doesn't
# resolve their DB. This env maps a seed ref -> its DB container name so
# /set-resources can cap it (provision/deprovision stay hard-blocked for seeds).
try:
    SEED_DB_CONTAINERS = json.loads(os.environ.get("SEED_DB_CONTAINERS", "{}"))
    if not isinstance(SEED_DB_CONTAINERS, dict):
        SEED_DB_CONTAINERS = {}
except ValueError:
    SEED_DB_CONTAINERS = {}

IMAGES = {
    # pgvector/pgvector:pg17 + the Supabase extension set (pg_cron, pg_net,
    # http, pg_graphql, postgis, ...). Built locally from infra/db-image/.
    "db": "vibe-postgres:17-ext1",
    "auth": "supabase/gotrue:v2.189.0",
    "rest": "postgrest/postgrest:v14.12",
    "storage": "supabase/storage-api:v1.60.4",
    "realtime": "supabase/realtime:v2.102.3",
    "key-proxy": "python:3.12-alpine",
    # Built on the box from infra/neon-auth (docker build -t vibe-neon-auth:v1).
    "neonauth": "vibe-neon-auth:v1",
}
NEON_AUTH_SQL = "/app/neon-auth-bootstrap.sql"
# Node baseline RSS makes the gotrue 64 MiB auth floor fatal for the neonauth
# container; it gets at least this much regardless of the planned auth share
# (documented deviation from resource-plan.ts — slight oversubscription only
# for capped neon-auth projects).
NEONAUTH_MEMORY_FLOOR_MB = 192
PORT_MIN, PORT_MAX = 5435, 5999
# Extensions the studio's non-superuser <ref>_app role may CREATE EXTENSION;
# supautils runs them as postgres. Everything shipped in vibe-postgres:17-ext1
# except server-filesystem/low-level ones (file_fdw, pageinspect, pg_surgery,
# lo, adminpack) which stay superuser-only.
PRIVILEGED_EXTENSIONS = ",".join([
    "vector", "pg_cron", "pg_net", "http", "pgjwt", "pgsodium",
    "supabase_vault", "pg_graphql", "pg_jsonschema", "wrappers", "pgmq",
    "pg_partman", "pgaudit", "pg_hashids", "index_advisor", "hypopg", "rum",
    "pg_repack", "pgtap", "plpgsql_check", "pgrouting", "postgis",
    "postgis_topology", "postgis_raster", "postgis_tiger_geocoder",
    "address_standardizer", "address_standardizer_data_us", "pgroonga",
    "pgroonga_database", "pg_stat_statements", "pg_trgm", "pgcrypto",
    "uuid-ossp", "hstore", "citext", "btree_gin", "btree_gist", "ltree",
    "unaccent", "fuzzystrmatch", "intarray", "tablefunc", "dblink",
    "postgres_fdw", "cube", "seg", "earthdistance", "isn", "dict_int",
    "dict_xsyn", "tcn", "tsm_system_rows", "tsm_system_time",
    "pg_buffercache", "pg_prewarm", "pgstattuple", "pgrowlocks", "sslinfo",
    "moddatetime", "insert_username", "autoinc", "refint", "bloom", "amcheck",
])
# env vars the python:3.12-alpine image sets itself; never carry these over
# when recreating key-proxy.
IMAGE_DEFAULT_ENV = {"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256"}

ALNUM = string.ascii_letters + string.digits


def log(msg):
    # NEVER pass secret values to this.
    print(time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg, flush=True)


class ProvisionError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def docker(*args, timeout=180):
    # Fixed argv, never shell — args are only ever our own literals plus
    # regex-validated refs. Talks to provisioner-proxy via DOCKER_HOST.
    try:
        return subprocess.run(["docker", *args], capture_output=True,
                              text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(["docker", *args], 125,
                                           stdout="", stderr=str(e))


def docker_ok(*args, **kw):
    r = docker(*args, **kw)
    if r.returncode != 0:
        raise ProvisionError(500, f"docker {args[0]} failed: {r.stderr.strip()[:400]}")
    return r


def container_exists(name):
    return docker("inspect", "--type", "container", name).returncode == 0


def volume_exists(name):
    return docker("volume", "inspect", name).returncode == 0


# ---------------------------------------------------------------- secrets ---

def b64url(b):
    return urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(role, secret, iat, exp):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"role": role, "iss": "supabase", "iat": iat, "exp": exp}
    seg = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
          b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), seg.encode(), hashlib.sha256).digest()
    return seg + "." + b64url(sig)


def rand_alnum(n):
    return "".join(pysecrets.choice(ALNUM) for _ in range(n))


def load_env_file(path):
    vals = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.rstrip("\n")
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    vals[k] = v
    return vals


def write_env_file(path, vals):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for k, v in vals.items():
            f.write(f"{k}={v}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def ensure_secrets(ref):
    """gen-aux-secrets.py logic (additive/idempotent), plus the db-level
    passwords this provisioner needs. Existing values are never changed."""
    REF = ref.upper()
    path = f"{HOST_ROOT}/{ref}-aux.env"
    vals = load_env_file(path)
    existing = dict(vals)

    def ensure(key, gen):
        if not vals.get(key):
            vals[key] = gen()

    ensure(f"{REF}_JWT_SECRET", lambda: pysecrets.token_hex(32))
    jwt_secret = vals[f"{REF}_JWT_SECRET"]
    iat = int(time.time())
    exp = iat + 10 * 365 * 24 * 3600
    ensure(f"{REF}_ANON_KEY", lambda: make_jwt("anon", jwt_secret, iat, exp))
    ensure(f"{REF}_SERVICE_KEY", lambda: make_jwt("service_role", jwt_secret, iat, exp))
    ensure("AUTHENTICATOR_PW", lambda: pysecrets.token_hex(24))
    ensure("AUTH_ADMIN_PW", lambda: pysecrets.token_hex(24))
    ensure("STORAGE_ADMIN_PW", lambda: pysecrets.token_hex(24))
    ensure("REALTIME_ADMIN_PW", lambda: pysecrets.token_hex(24))
    ensure("REALTIME_DB_ENC_KEY", lambda: pysecrets.token_hex(8))
    ensure("REALTIME_SECRET_KEY_BASE", lambda: pysecrets.token_hex(32))
    ensure(f"{REF}_PUBLISHABLE_KEY", lambda: "sb_publishable_" + rand_alnum(32))
    ensure(f"{REF}_SECRET_KEY", lambda: "sb_secret_" + rand_alnum(40))
    # better-auth secret for the neon-auth backend (cookie/state signing +
    # private-key-at-rest encryption). Generated for every project so switching
    # backends later never mints a new one.
    ensure(f"{REF}_NEON_AUTH_SECRET", lambda: pysecrets.token_hex(32))
    # db-level credentials (superuser, owner app role, studio RW role).
    ensure(f"{REF}_POSTGRES_PASSWORD", lambda: pysecrets.token_hex(24))
    ensure(f"{REF}_APP_PASSWORD", lambda: pysecrets.token_hex(24))
    ensure(f"{REF}_STUDIO_PASSWORD", lambda: pysecrets.token_hex(24))

    if vals != existing:
        write_env_file(path, vals)
        log(f"[{ref}] wrote {ref}-aux.env (added {len(vals) - len(existing)} keys)")
    return vals


# ------------------------------------------------------------------ ports ---

def used_host_ports():
    ports = set()
    ids = docker_ok("ps", "-aq").stdout.split()
    if ids:
        r = docker_ok("inspect", *ids)
        for c in json.loads(r.stdout):
            for binds in ((c.get("HostConfig") or {}).get("PortBindings") or {}).values():
                for b in binds or []:
                    hp = (b or {}).get("HostPort") or ""
                    if hp.isdigit():
                        ports.add(int(hp))
    if os.path.isdir(EXPOSE_DIR):
        for f in os.listdir(EXPOSE_DIR):
            try:
                ports.add(int(open(os.path.join(EXPOSE_DIR, f)).read().strip()))
            except (ValueError, OSError):
                pass
    return ports


def alloc_port():
    used = used_host_ports() | {5433, 5434}
    p = PORT_MIN
    while p in used:
        p += 1
    if p > PORT_MAX:
        raise ProvisionError(507, "no free public port in 5435-5999")
    return p


# --------------------------------------------------------------- postgres ---

def pg_conf(ref):
    # Mirrors the seed DBs' custom-postgres.conf (TLS + scram), with memory
    # sized for many small projects instead of one big one. Cert paths are
    # absolute because fresh volumes can't have certs pre-seeded in PGDATA.
    return f"""shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 128MB
work_mem = 16MB
max_wal_size = 1GB
checkpoint_completion_target = 0.9
wal_compression = on
random_page_cost = 2.0
synchronous_commit = off
listen_addresses = '*'
ssl = on
ssl_cert_file = '/etc/postgresql/certs/server.crt'
ssl_key_file = '/etc/postgresql/certs/server.key'
password_encryption = 'scram-sha-256'
hba_file = '/etc/postgresql/pg_hba.conf'
shared_preload_libraries = 'supautils,pg_stat_statements,pg_cron,pg_net,pgaudit,pgsodium,supabase_vault'
cron.database_name = '{ref}'
supautils.privileged_extensions = '{PRIVILEGED_EXTENSIONS}'
supautils.privileged_extensions_superuser = 'postgres'
supautils.extension_custom_scripts_path = '/etc/postgresql-custom/extension-custom-scripts'
"""


def write_db_config(ref):
    d = f"{DB_DIR}/{ref}-db"
    certs = f"{d}/certs"
    os.makedirs(certs, exist_ok=True)
    with open(f"{d}/custom-postgres.conf", "w") as f:
        f.write(pg_conf(ref))
    # hostssl-only pg_hba (parity with seed DBs): local socket trusted so the
    # image entrypoint's initdb setup works; all TCP must use TLS + scram.
    with open(f"{d}/pg_hba.conf", "w") as f:
        f.write("local   all all           trust\n"
                "hostssl all all 0.0.0.0/0 scram-sha-256\n"
                "hostssl all all ::/0       scram-sha-256\n")
    os.chmod(f"{d}/pg_hba.conf", 0o644)
    crt, key = f"{certs}/server.crt", f"{certs}/server.key"
    if not (os.path.exists(crt) and os.path.exists(key)):
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", crt, "-days", "3650",
             "-subj", f"/CN={ref}.{DOMAIN_SUFFIX}"],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise ProvisionError(500, f"openssl cert generation failed: {r.stderr[:300]}")
    # postgres (uid 999 in pgvector/pgvector:pg17) must own the key, 0600.
    for p, mode in ((crt, 0o644), (key, 0o600)):
        os.chown(p, 999, 999)
        os.chmod(p, mode)
    os.chmod(f"{d}/custom-postgres.conf", 0o644)


def cap_flags(mem_mb=None, cpus=None):
    """`docker run/update` --memory/--cpus flags; [] when uncapped. memory-swap is
    pinned to the memory cap so a capped container can't grow into host swap."""
    flags = []
    if mem_mb:
        flags += ["--memory", f"{int(mem_mb)}m", "--memory-swap", f"{int(mem_mb)}m"]
    if cpus:
        flags += ["--cpus", format_cpus(cpus)]
    return flags


def format_cpus(cpus):
    # 1.0 -> "1", 0.5 -> "0.5" (docker accepts decimals; keep it tidy).
    return f"{cpus:g}"


def run_db_container(ref, port, pg_password, mem_mb=None, cpus=None):
    host_dir = f"/data/coolify/databases/{ref}-db"  # host-side path for -v
    docker_ok(
        "run", "-d", "--name", f"{ref}-db",
        "--network", DOCKER_NET, "--restart", "unless-stopped",
        *cap_flags(mem_mb, cpus),
        "-p", f"127.0.0.1:{port}:5432",
        "-e", f"POSTGRES_DB={ref}",
        "-e", "POSTGRES_USER=postgres",
        "-e", "PGUSER=postgres",
        "-e", f"POSTGRES_PASSWORD={pg_password}",
        "-v", f"{host_dir}/custom-postgres.conf:/etc/postgresql/postgresql.conf:ro",
        "-v", f"{host_dir}/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro",
        "-v", f"{host_dir}/certs:/etc/postgresql/certs:ro",
        "-v", f"postgres-data-{ref}-db:/var/lib/postgresql/data",
        IMAGES["db"],
        "postgres", "-c", "config_file=/etc/postgresql/postgresql.conf")


def psql(ref, pg_password, sql=None, sql_file=None, dbname=None, extra_env=None,
         variables=None, timeout=120):
    """Run psql over TCP (coolify network) as the postgres superuser.
    Passwords go via PGPASSWORD / psql variables, never into argv or logs."""
    conn = f"host={ref}-db port=5432 dbname={dbname or ref} user=postgres sslmode=require"
    args = ["psql", conn, "-v", "ON_ERROR_STOP=1", "-q", "-t", "-A"]
    for k, v in (variables or {}).items():
        args += ["-v", f"{k}={v}"]
    stdin_data = None
    if sql_file:
        args += ["-f", sql_file]
    else:
        # Feed inline SQL via stdin (not -c): psql only performs :'var'
        # interpolation in its normal input loop, never for -c.
        stdin_data = sql
    env = dict(os.environ)
    env["PGPASSWORD"] = pg_password
    env.update(extra_env or {})
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout, env=env, input=stdin_data)


def wait_for_db(ref, pg_password, timeout=120):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        r = psql(ref, pg_password, sql="SELECT 1", timeout=15)
        if r.returncode == 0:
            return
        last = r.stderr.strip()[-200:]
        time.sleep(2)
    raise ProvisionError(500, f"{ref}-db never became ready over TLS: {last}")


def setup_roles(ref, sec):
    REF = ref.upper()
    # ref is regex-validated ([a-z][a-z0-9]{1,30}) so identifier interpolation
    # is safe; passwords go through psql variables (:'var'), never inline SQL.
    sql = f"""
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{ref}_app') THEN
    CREATE ROLE {ref}_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{ref}_studio') THEN
    CREATE ROLE {ref}_studio LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION IN ROLE {ref}_app;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='console_mon') THEN
    CREATE ROLE console_mon LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION IN ROLE pg_monitor;
  END IF;
END $$;
ALTER ROLE {ref}_app PASSWORD :'app_pw';
ALTER ROLE {ref}_studio PASSWORD :'studio_pw';
ALTER ROLE console_mon PASSWORD :'mon_pw';
ALTER DATABASE {ref} OWNER TO {ref}_app;
GRANT CONNECT ON DATABASE {ref} TO console_mon;
"""
    r = psql(ref, sec[f"{REF}_POSTGRES_PASSWORD"], sql=sql, variables={
        "app_pw": sec[f"{REF}_APP_PASSWORD"],
        "studio_pw": sec[f"{REF}_STUDIO_PASSWORD"],
        "mon_pw": MON_PASSWORD,
    })
    if r.returncode != 0:
        raise ProvisionError(500, f"role setup failed: {r.stderr.strip()[:400]}")


def run_bootstrap(ref, sec):
    REF = ref.upper()
    r = psql(ref, sec[f"{REF}_POSTGRES_PASSWORD"], sql_file=BOOTSTRAP_SQL,
             extra_env={
                 "AUTHENTICATOR_PW": sec["AUTHENTICATOR_PW"],
                 "AUTH_ADMIN_PW": sec["AUTH_ADMIN_PW"],
                 "STORAGE_ADMIN_PW": sec["STORAGE_ADMIN_PW"],
                 "REALTIME_ADMIN_PW": sec["REALTIME_ADMIN_PW"],
             })
    if r.returncode != 0:
        raise ProvisionError(500, f"aux bootstrap failed: {r.stderr.strip()[:400]}")
    # GoTrue/storage migrators run as their admin role with default search_path=
    # public (no CREATE there) -> crash-loop. Pin their per-DB search_path.
    r2 = psql(ref, sec[f"{REF}_POSTGRES_PASSWORD"], sql=(
        f"ALTER ROLE supabase_auth_admin IN DATABASE {ref} SET search_path='auth';\n"
        f"ALTER ROLE supabase_storage_admin IN DATABASE {ref} SET search_path='storage';"))
    if r2.returncode != 0:
        raise ProvisionError(500, f"search_path setup failed: {r2.stderr.strip()[:400]}")


# ---------------------------------------------------------- aux services ----

def neon_auth_base_url(ref):
    # Mirrors Neon's URL shape <host>/<dbname>/auth; the path is opaque to apps
    # (they read the whole URL from NEON_AUTH_BASE_URL).
    return f"https://{ref}-api.{DOMAIN_SUFFIX}/{ref}/auth"


def run_neonauth_container(ref, sec, mem_mb=None, cpus=None):
    """The Neon-Auth-compatible Better Auth service (infra/neon-auth).
    Container is <ref>-neonauth so it can coexist with a GoTrue <ref>-auth
    (backend switch / seed migration)."""
    REF = ref.upper()
    if mem_mb:
        mem_mb = max(mem_mb, NEONAUTH_MEMORY_FLOOR_MB)
    url = f"postgres://{ref}_app:{sec[f'{REF}_APP_PASSWORD']}@{ref}-db:5432/{ref}?sslmode=no-verify"
    env = {
        "PORT": "3000",
        "NEON_AUTH_DATABASE_URL": url,
        "NEON_AUTH_BASE_URL": neon_auth_base_url(ref),
        "NEON_AUTH_SECRET": sec[f"{REF}_NEON_AUTH_SECRET"],
        "NEON_AUTH_TRUSTED_ORIGINS": "",
    }
    args = ["run", "-d", "--name", f"{ref}-neonauth",
            "--network", DOCKER_NET, "--restart", "unless-stopped",
            *cap_flags(mem_mb, cpus)]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    args.append(IMAGES["neonauth"])
    docker_ok(*args)


def run_neonauth_bootstrap(ref, sec):
    REF = ref.upper()
    r = psql(ref, sec[f"{REF}_POSTGRES_PASSWORD"], sql_file=NEON_AUTH_SQL,
             extra_env={"NEON_AUTH_OWNER": f"{ref}_app"})
    if r.returncode != 0:
        raise ProvisionError(500, f"neon-auth bootstrap failed: {r.stderr.strip()[:400]}")


def run_aux_container(ref, svc, sec, mem_mb=None, cpus=None):
    """Mirrors /root/deploy-aux.sh exactly, per service."""
    REF = ref.upper()
    domain = f"{ref}-api.{DOMAIN_SUFFIX}"
    dbc, dbname = f"{ref}-db", ref
    jwt = sec[f"{REF}_JWT_SECRET"]
    base = ["run", "-d", "--name", f"{ref}-{svc}",
            "--network", DOCKER_NET, "--restart", "unless-stopped",
            *cap_flags(mem_mb, cpus)]

    if svc == "auth":
        url = f"postgres://supabase_auth_admin:{sec['AUTH_ADMIN_PW']}@{dbc}:5432/{dbname}?sslmode=require"
        env = {
            "GOTRUE_API_HOST": "0.0.0.0", "GOTRUE_API_PORT": "9999",
            "API_EXTERNAL_URL": f"https://{domain}",
            "GOTRUE_DB_DRIVER": "postgres",
            "GOTRUE_DB_DATABASE_URL": url,
            "GOTRUE_SITE_URL": f"https://{domain}",
            "GOTRUE_URI_ALLOW_LIST": "",
            "GOTRUE_DISABLE_SIGNUP": "true",
            "GOTRUE_JWT_ADMIN_ROLES": "service_role",
            "GOTRUE_JWT_AUD": "authenticated",
            "GOTRUE_JWT_DEFAULT_GROUP_NAME": "authenticated",
            "GOTRUE_JWT_EXP": "3600",
            "GOTRUE_JWT_SECRET": jwt,
            "GOTRUE_JWT_ISSUER": f"https://{domain}",
            "GOTRUE_EXTERNAL_EMAIL_ENABLED": "true",
            "GOTRUE_MAILER_AUTOCONFIRM": "true",
            "GOTRUE_EXTERNAL_PHONE_ENABLED": "false",
            "GOTRUE_SMS_AUTOCONFIRM": "true",
        }
    elif svc == "rest":
        url = f"postgres://authenticator:{sec['AUTHENTICATOR_PW']}@{dbc}:5432/{dbname}?sslmode=require"
        env = {
            "PGRST_DB_URI": url,
            "PGRST_DB_SCHEMAS": "public,storage",
            "PGRST_DB_ANON_ROLE": "anon",
            "PGRST_JWT_SECRET": jwt,
            "PGRST_DB_USE_LEGACY_GUCS": "false",
            "PGRST_DB_EXTRA_SEARCH_PATH": "public",
            "PGRST_ADMIN_SERVER_PORT": "3001",
        }
    elif svc == "storage":
        os.makedirs(f"{STORAGE_DIR}/{ref}", exist_ok=True)
        url = f"postgres://supabase_storage_admin:{sec['STORAGE_ADMIN_PW']}@{dbc}:5432/{dbname}?sslmode=no-verify"
        env = {
            "ANON_KEY": sec[f"{REF}_ANON_KEY"],
            "SERVICE_KEY": sec[f"{REF}_SERVICE_KEY"],
            "AUTH_JWT_SECRET": jwt,
            "DATABASE_URL": url,
            "DB_INSTALL_ROLES": "false",
            "POSTGREST_URL": f"http://{ref}-rest:3000",
            "FILE_SIZE_LIMIT": "52428800",
            "STORAGE_BACKEND": "file",
            "FILE_STORAGE_BACKEND_PATH": "/var/lib/storage",
            "TENANT_ID": ref,
            "REGION": "stub",
            "GLOBAL_S3_BUCKET": "stub",
            "ENABLE_IMAGE_TRANSFORMATION": "false",
        }
        base += ["-v", f"/data/storage/{ref}:/var/lib/storage"]
    elif svc == "realtime":
        env = {
            "PORT": "4000",
            "DB_HOST": dbc, "DB_PORT": "5432",
            "DB_USER": "supabase_realtime_admin",
            "DB_PASSWORD": sec["REALTIME_ADMIN_PW"],
            "DB_NAME": dbname,
            "DB_AFTER_CONNECT_QUERY": "SET search_path TO _realtime",
            "DB_ENC_KEY": sec["REALTIME_DB_ENC_KEY"],
            "API_JWT_SECRET": jwt,
            "METRICS_JWT_SECRET": jwt,
            "SECRET_KEY_BASE": sec["REALTIME_SECRET_KEY_BASE"],
            "ERL_AFLAGS": "-proto_dist inet_tcp",
            "DNS_NODES": "''",
            "RLIMIT_NOFILE": "10000",
            "APP_NAME": "realtime",
            "SEED_SELF_HOST": "true",
            "RUN_JANITOR": "true",
            "DISABLE_HEALTHCHECK_LOGGING": "true",
            "DB_SSL": "true",
        }
    else:
        raise ProvisionError(400, f"unknown service {svc}")

    args = list(base)
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    args.append(IMAGES[svc])
    docker_ok(*args)


# ----------------------------------------------------------------- traefik --

AUX_PORTS = {"auth": 9999, "rest": 3000, "storage": 5000, "realtime": 4000}


def write_traefik_yaml(ref, services, auth_backend="gotrue"):
    domain = f"{ref}-api.{DOMAIN_SUFFIX}"
    routers, middlewares, svcdefs = [], [], []
    for svc in services:
        if svc == "auth" and auth_backend == "neon-auth":
            # Neon-Auth-compatible service: serves its base path itself
            # (no strip), bypasses key-proxy (no sb_* keys in this contract).
            svcdefs.append(f"""    {ref}-neonauth:
      loadBalancer:
        servers:
          - url: http://{ref}-neonauth:3000""")
            routers.append(f"""    {ref}-neonauth-https:
      entryPoints: [https]
      rule: "Host(`{domain}`) && PathPrefix(`/{ref}/auth`)"
      service: {ref}-neonauth
      tls:
        certresolver: letsencrypt""")
            continue
        port = AUX_PORTS[svc]
        svcdefs.append(f"""    {ref}-{svc}:
      loadBalancer:
        servers:
          - url: http://{ref}-{svc}:{port}""")
        middlewares.append(f"""    {ref}-{svc}-strip:
      stripPrefix:
        prefixes: ["/{svc}/v1"]""")
        if svc == "realtime":
            middlewares.append(f"""    {ref}-realtime-socket:
      addPrefix:
        prefix: "/socket\"""")
            routers.append(f"""    {ref}-realtime-https:
      entryPoints: [https]
      rule: "Host(`{domain}`) && PathPrefix(`/realtime/v1`)"
      middlewares: [{ref}-realtime-strip, {ref}-realtime-socket]
      service: {ref}-realtime
      tls:
        certresolver: letsencrypt""")
        else:
            middlewares.append(f"""    {ref}-{svc}-keyproxy-hdr:
      headers:
        customRequestHeaders:
          X-Key-Proxy-Upstream: "http://{ref}-{svc}:{port}\"""")
            routers.append(f"""    {ref}-{svc}-https:
      entryPoints: [https]
      rule: "Host(`{domain}`) && PathPrefix(`/{svc}/v1`)"
      middlewares: [{ref}-{svc}-strip, {ref}-{svc}-keyproxy-hdr]
      service: key-proxy
      tls:
        certresolver: letsencrypt""")
    routers.append(f"""    {ref}-redirect-http:
      entryPoints: [http]
      rule: "Host(`{domain}`)"
      middlewares: [redirect-to-https]
      service: key-proxy""")
    yaml = (f"# {ref} Supabase aux API — managed by the provisioner agent.\n"
            "# key-proxy variant: auth/rest/storage routed through the key-proxy\n"
            "# container (sb_* key -> role-JWT translation); realtime stays direct.\n"
            "# neon-auth variant (when chosen): /<ref>/auth routed straight to\n"
            "# <ref>-neonauth, no strip, no key-proxy.\n"
            "http:\n  routers:\n" + "\n".join(routers) +
            ("\n  middlewares:\n" + "\n".join(middlewares) if middlewares else "") +
            "\n  services:\n"
            "    # the shared `key-proxy` service is defined once in key-proxy.yaml\n"
            + "\n".join(svcdefs) + "\n")
    tmp = f"{TRAEFIK_DIR}/.{ref}-api.yaml.tmp"
    with open(tmp, "w") as f:
        f.write(yaml)
    os.replace(tmp, f"{TRAEFIK_DIR}/{ref}-api.yaml")


# --------------------------------------------------------------- key-proxy --

def keyproxy_current():
    r = docker("inspect", "key-proxy")
    if r.returncode != 0:
        return None, None
    cfg = json.loads(r.stdout)[0]["Config"]
    env = {}
    for e in cfg.get("Env") or []:
        k, _, v = e.partition("=")
        env[k] = v
    hostmap = json.loads(env.get("KEY_PROXY_MAP", "{}"))
    return hostmap, env


def keyproxy_recreate(hostmap, env):
    """Recreate the shared key-proxy with a minimal env: KEY_PROXY_MAP plus the
    4 key vars per mapped ref. Fixed name/image/mount/cmd — template guard."""
    keep = {"KEY_PROXY_MAP": json.dumps(hostmap, separators=(",", ":"))}
    missing = []
    for REF in hostmap.values():
        for k in (f"{REF}_PUBLISHABLE_KEY", f"{REF}_SECRET_KEY",
                  f"{REF}_ANON_KEY", f"{REF}_SERVICE_KEY"):
            if env.get(k):
                keep[k] = env[k]
            else:
                missing.append(k)
    if missing:
        raise ProvisionError(500, f"key-proxy env incomplete, refusing recreate (missing {missing})")
    docker("rm", "-f", "key-proxy")
    args = ["run", "-d", "--name", "key-proxy", "--network", DOCKER_NET,
            "--restart", "unless-stopped",
            "-v", "/root/key-proxy.py:/key-proxy.py:ro"]
    for k, v in keep.items():
        args += ["-e", f"{k}={v}"]
    args += [IMAGES["key-proxy"], "python3", "/key-proxy.py"]
    docker_ok(*args)
    log(f"key-proxy recreated with {len(hostmap)} host mappings")


def keyproxy_add(ref, sec):
    REF = ref.upper()
    hostmap, env = keyproxy_current()
    if hostmap is None:
        raise ProvisionError(500, "key-proxy container not found; cannot add mapping")
    host = f"{ref}-api.{DOMAIN_SUFFIX}"
    for k in (f"{REF}_PUBLISHABLE_KEY", f"{REF}_SECRET_KEY",
              f"{REF}_ANON_KEY", f"{REF}_SERVICE_KEY"):
        env[k] = sec[k]
    hostmap[host] = REF
    keyproxy_recreate(hostmap, env)


def keyproxy_remove(ref):
    REF = ref.upper()
    hostmap, env = keyproxy_current()
    if hostmap is None:
        return False
    host = f"{ref}-api.{DOMAIN_SUFFIX}"
    if host not in hostmap:
        return False
    del hostmap[host]
    for k in list(env):
        if k.startswith(f"{REF}_"):
            del env[k]
    keyproxy_recreate(hostmap, env)
    return True


# ----------------------------------------------------------------- expose ---

def expose_write(ref, port):
    os.makedirs(EXPOSE_DIR, exist_ok=True)
    tmp = f"{EXPOSE_DIR}/.{ref}.tmp"
    with open(tmp, "w") as f:
        f.write(str(port))
    os.replace(tmp, f"{EXPOSE_DIR}/{ref}")


def expose_remove(ref):
    try:
        os.remove(f"{EXPOSE_DIR}/{ref}")
        return True
    except FileNotFoundError:
        return False


def wait_public(port, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((PUBLIC_IP, port), timeout=3):
                return True
        except OSError:
            time.sleep(1.5)
    return False


# ------------------------------------------------------------- resources ---
# Cap math MIRRORS studio's resource-plan.ts (planResourceSplit / validateResourceCaps).
# Studio validates before calling us; we re-validate as defense in depth.

def validate_caps(memory_mb, cpus, services):
    if not isinstance(memory_mb, int) or isinstance(memory_mb, bool):
        return "memory_mb must be an integer (MiB)"
    if not isinstance(cpus, (int, float)) or isinstance(cpus, bool):
        return "cpus must be a number"
    if cpus < PROJECT_CPUS_MIN or cpus > PROJECT_CPUS_MAX:
        return f"cpus must be between {PROJECT_CPUS_MIN} and {PROJECT_CPUS_MAX}"
    min_mb = DB_MEMORY_FLOOR_MB + sum(AUX_MEMORY_FLOOR_MB.get(s, 0) for s in services)
    if memory_mb < min_mb:
        return f"memory_mb must be at least {min_mb} MiB for services {services}"
    if memory_mb > PROJECT_MEMORY_MAX_MB:
        return f"memory_mb must be at most {PROJECT_MEMORY_MAX_MB} MiB"
    return None


def resource_split(memory_mb, cpus, services):
    """service -> {memory_mb, cpus}. Aux take their fixed floor; DB takes the
    remainder. DB may use the full project cpus; each aux is capped at half."""
    aux = [s for s in ALL_SERVICES if s in services]
    aux_total = sum(AUX_MEMORY_FLOOR_MB[s] for s in aux)
    aux_cpus = min(cpus, max(0.25, round(cpus / 2, 2)))
    plan = {"db": {"memory_mb": memory_mb - aux_total, "cpus": cpus}}
    for s in aux:
        plan[s] = {"memory_mb": AUX_MEMORY_FLOOR_MB[s], "cpus": aux_cpus}
    return plan


def do_set_resources(body):
    ref = body.get("ref")
    if not isinstance(ref, str) or not REF_RE.match(ref):
        raise ProvisionError(400, "ref must match ^[a-z][a-z0-9]{1,30}$")
    memory_mb = body.get("memory_mb")
    cpus = body.get("cpus")
    # Discover which aux this project actually runs (only cap what exists).
    services = [s for s in ALL_SERVICES if container_exists(f"{ref}-{s}")]
    err = validate_caps(memory_mb, cpus, services)
    if err:
        raise ProvisionError(400, err)

    # DB container: seeds are Coolify-managed (hash name via SEED_DB_CONTAINERS);
    # provisioned projects use <ref>-db.
    if ref in SEED_REFS:
        db_container = SEED_DB_CONTAINERS.get(ref)
        if not db_container:
            raise ProvisionError(404, f"no DB container mapped for seed '{ref}'")
    else:
        db_container = f"{ref}-db"
    if not container_exists(db_container):
        raise ProvisionError(404, f"{db_container} does not exist")

    plan = resource_split(memory_mb, cpus, services)
    targets = {"db": db_container}
    for s in services:
        targets[s] = f"{ref}-{s}"

    applied, errors = {}, []
    for svc, cname in targets.items():
        caps = plan[svc]
        r = docker("update", *cap_flags(caps["memory_mb"], caps["cpus"]), cname)
        if r.returncode == 0:
            applied[svc] = caps
        else:
            errors.append(f"{cname}: {r.stderr.strip()[:200]}")
    log(f"[{ref}] set-resources memory_mb={memory_mb} cpus={cpus} "
        f"applied={list(applied)} errors={len(errors)}")
    out = {"ok": not errors, "ref": ref, "applied": applied}
    if errors:
        out["errors"] = errors
    return out


# -------------------------------------------------------------- lifecycle ---

def validate_ref(ref, for_deprovision=False):
    if not isinstance(ref, str) or not REF_RE.match(ref):
        raise ProvisionError(400, "ref must match ^[a-z][a-z0-9]{1,30}$")
    if ref in SEED_REFS:
        raise ProvisionError(403, f"ref '{ref}' is a protected seed project")
    if not for_deprovision and ref in RESERVED_REFS:
        raise ProvisionError(400, f"ref '{ref}' is reserved")
    return ref


def do_provision(body):
    ref = validate_ref(body.get("ref"))
    name = str(body.get("name") or ref)[:80].replace("\n", " ")
    services = body.get("services") or []
    if not isinstance(services, list) or any(s not in ALL_SERVICES for s in services):
        raise ProvisionError(400, f"services must be a subset of {ALL_SERVICES}")
    services = [s for s in ALL_SERVICES if s in services]  # canonical order
    auth_backend = body.get("auth_backend") or "gotrue"
    if auth_backend not in AUTH_BACKENDS:
        raise ProvisionError(400, f"auth_backend must be one of {sorted(AUTH_BACKENDS)}")
    REF = ref.upper()

    # Optional resource caps applied at `docker run` (both-or-neither; omitted =
    # uncapped legacy behavior). Split mirrors /set-resources.
    memory_mb, cpus = body.get("memory_mb"), body.get("cpus")
    plan = None
    if memory_mb is not None or cpus is not None:
        err = validate_caps(memory_mb, cpus, services)
        if err:
            raise ProvisionError(400, err)
        plan = resource_split(memory_mb, cpus, services)

    if container_exists(f"{ref}-db"):
        raise ProvisionError(409, f"{ref}-db already exists")

    log(f"[{ref}] provision start (services={services or 'none'}, "
        f"caps={'yes' if plan else 'none'})")
    port = alloc_port()
    vol_preexisted = volume_exists(f"postgres-data-{ref}-db")
    created = []
    try:
        sec = ensure_secrets(ref)
        write_db_config(ref)
        db_caps = plan["db"] if plan else {}
        run_db_container(ref, port, sec[f"{REF}_POSTGRES_PASSWORD"],
                         mem_mb=db_caps.get("memory_mb"), cpus=db_caps.get("cpus"))
        created.append(f"{ref}-db")
        log(f"[{ref}] db container up on 127.0.0.1:{port}, waiting for TLS readiness")
        wait_for_db(ref, sec[f"{REF}_POSTGRES_PASSWORD"])
        setup_roles(ref, sec)
        if services:
            run_bootstrap(ref, sec)
            if auth_backend == "neon-auth" and "auth" in services:
                run_neonauth_bootstrap(ref, sec)
            for svc in services:
                svc_caps = plan[svc] if plan else {}
                if svc == "auth" and auth_backend == "neon-auth":
                    run_neonauth_container(ref, sec,
                                           mem_mb=svc_caps.get("memory_mb"),
                                           cpus=svc_caps.get("cpus"))
                    created.append(f"{ref}-neonauth")
                else:
                    run_aux_container(ref, svc, sec,
                                      mem_mb=svc_caps.get("memory_mb"),
                                      cpus=svc_caps.get("cpus"))
                    created.append(f"{ref}-{svc}")
            write_traefik_yaml(ref, services, auth_backend)
            keyproxy_add(ref, sec)
            log(f"[{ref}] aux stack deployed: {services} (auth_backend={auth_backend})")
        expose_write(ref, port)
        public_ready = wait_public(port)
        log(f"[{ref}] provisioned (publicPort={port}, publicReady={public_ready})")
    except Exception:
        log(f"[{ref}] provision FAILED — rolling back {created}")
        try:
            _teardown(ref, drop_data=not vol_preexisted)
        except Exception as e2:
            log(f"[{ref}] rollback incomplete: {e2}")
        raise

    env = {k: sec[k] for k in (
        f"{REF}_APP_PASSWORD", f"{REF}_STUDIO_PASSWORD", f"{REF}_POSTGRES_PASSWORD",
        f"{REF}_JWT_SECRET", f"{REF}_ANON_KEY", f"{REF}_SERVICE_KEY",
        f"{REF}_PUBLISHABLE_KEY", f"{REF}_SECRET_KEY", f"{REF}_NEON_AUTH_SECRET")}
    neon_auth_active = auth_backend == "neon-auth" and "auth" in services
    return {
        "ok": True,
        "ref": ref,
        "name": name,
        "auth_backend": auth_backend,
        "neonAuthUrl": neon_auth_base_url(ref) if neon_auth_active else None,
        "neonAuthJwksUrl": (neon_auth_base_url(ref) + "/.well-known/jwks.json")
                           if neon_auth_active else None,
        "publicHost": f"{ref}.{DOMAIN_SUFFIX}",
        "publicPort": port,
        "publicReady": public_ready,
        "db": ref,
        "user": f"{ref}_app",
        "host": f"{ref}-db",
        "port": 5432,
        "sslmode": "no-verify",
        "studioUser": f"{ref}_studio",
        "readOnlyUser": "console_mon",
        "readOnlyPasswordEnv": "CONSOLE_MON_PASSWORD",
        "apiUrl": f"https://{ref}-api.{DOMAIN_SUFFIX}" if services else None,
        "enabled_services": services,
        "env": env,
    }


def _teardown(ref, drop_data):
    removed, errors = [], []
    for suffix in ("auth", "neonauth", "rest", "storage", "realtime", "db"):
        cname = f"{ref}-{suffix}"
        if container_exists(cname):
            r = docker("rm", "-f", cname)
            (removed if r.returncode == 0 else errors).append(f"container:{cname}")
    if expose_remove(ref):
        removed.append(f"expose:{ref}")
    yaml_path = f"{TRAEFIK_DIR}/{ref}-api.yaml"
    if os.path.exists(yaml_path):
        os.remove(yaml_path)
        removed.append(f"traefik:{ref}-api.yaml")
    try:
        if keyproxy_remove(ref):
            removed.append("keyproxy-mapping")
    except ProvisionError as e:
        errors.append(f"keyproxy:{e}")
    if drop_data:
        vol = f"postgres-data-{ref}-db"
        if volume_exists(vol):
            r = docker("volume", "rm", vol)
            (removed if r.returncode == 0 else errors).append(f"volume:{vol}")
        for path, tag in ((f"{HOST_ROOT}/{ref}-aux.env", "auxenv"),
                          (f"{DB_DIR}/{ref}-db", "dbconf"),
                          (f"{STORAGE_DIR}/{ref}", "storage-dir")):
            if os.path.exists(path):
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)
                removed.append(tag)
    return removed, errors


def do_deprovision(body):
    ref = validate_ref(body.get("ref"), for_deprovision=True)
    drop_data = bool(body.get("dropData"))
    log(f"[{ref}] deprovision start (dropData={drop_data})")
    removed, errors = _teardown(ref, drop_data)
    log(f"[{ref}] deprovision done: {removed} errors={errors}")
    out = {"ok": not errors, "ref": ref, "removed": removed}
    if errors:
        out["errors"] = errors
    return out


# --------------------------------------------------------------------- http -

def sign(ts, method, path, body):
    msg = f"{ts}.{method}.{path}.{body}".encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "provisioner/1"

    def log_message(self, *a):
        pass  # request logging is done explicitly, without bodies/secrets

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _verify(self, method, body):
        ts = self.headers.get("X-Console-Ts", "")
        sig = self.headers.get("X-Console-Sig", "")
        if not ts.isdigit() or abs(time.time() - int(ts)) > 300:
            return False
        return hmac.compare_digest(sign(ts, method, self.path, body), sig)

    def do_GET(self):
        if not self._verify("GET", ""):
            return self._send(401, {"error": "bad signature"})
        if self.path == "/health":
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode() if n else ""
        if not self._verify("POST", body):
            return self._send(401, {"error": "bad signature"})
        try:
            req = json.loads(body or "{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        try:
            if self.path == "/provision":
                return self._send(200, do_provision(req))
            if self.path == "/deprovision":
                return self._send(200, do_deprovision(req))
            if self.path == "/set-resources":
                return self._send(200, do_set_resources(req))
            return self._send(404, {"error": "not found"})
        except ProvisionError as e:
            return self._send(e.code, {"ok": False, "error": str(e)})
        except Exception as e:
            log(f"unhandled error: {type(e).__name__}")
            return self._send(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})


if __name__ == "__main__":
    port = int(os.environ.get("PROVISIONER_PORT", "8900"))
    log(f"provisioner listening on :{port} (docker via {os.environ['DOCKER_HOST']})")
    # Intentionally single-threaded: provisions are serialized so port
    # allocation and key-proxy recreation can never race.
    HTTPServer(("0.0.0.0", port), H).serve_forever()
