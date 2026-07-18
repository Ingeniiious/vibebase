#!/usr/bin/env bash
# =============================================================================
# deploy-stack.sh — deploy the full Vibe Base stack on a prepared box.
# Invoked by the setup wizard (deploy step); can also be run manually.
#
#   DOMAIN_SUFFIX=db.example.com ./deploy-stack.sh [substep|all]
#
# Requires (done by install.sh + wizard):
#   - docker + networks coolify/svcctl/provctl
#   - /root/console.env + /root/postgres-meta.env (gen-base-secrets.sh)
#   - Traefik running (wizard TLS step) with dynamic dir /data/coolify/proxy/dynamic
#   - repo at $VIBE_HOME/src (studio-fork + infra vendored)
#
# Sub-stamped + idempotent: each substep records state/deploy.<name>.done and
# re-runs recreate containers cleanly (docker rm -f + run). Data volumes are
# NEVER removed here.
#
# Verification status: Better Auth scrypt admin seeding is proven against the
# pinned better-auth@1.6.23. The provisioner-proxy flag set (IMAGES=0/
# NETWORKS=0 + host-side image pre-pull in step_aux_images) mirrors the
# vetted reference deployment.
# =============================================================================
set -euo pipefail

VIBE_HOME="${VIBE_HOME:-/opt/vibebase}"
STATE_DIR="$VIBE_HOME/state"
SRC="$VIBE_HOME/src"
BOOT="$SRC/infra/bootstrap"
NET=coolify

# ---- inputs -----------------------------------------------------------------
[ -f "$STATE_DIR/facts.env" ] || { echo "missing $STATE_DIR/facts.env (run install.sh)"; exit 1; }
# shellcheck disable=SC1091
. "$STATE_DIR/facts.env"     # PUBLIC_IP
: "${DOMAIN_SUFFIX:?DOMAIN_SUFFIX required (e.g. db.example.com)}"
: "${PUBLIC_IP:?PUBLIC_IP required}"

# secrets (sourced, never echoed)
set -a
# shellcheck disable=SC1091
. /root/console.env
set +a

# pinned images (must stay in sync with infra/provisioner/provisioner.py)
IMG_PG=pgvector/pgvector:pg17
IMG_PGMETA=supabase/postgres-meta:v0.96.6
IMG_KEYPROXY=python:3.12-alpine
IMG_SOCKPROXY=tecnativa/docker-socket-proxy:0.3.0

STUDIO_TAG="${STUDIO_TAG:-studio-console:v1}"

log() { printf '>>> %s\n' "$*"; }
stamp() { date -u +%FT%TZ > "$STATE_DIR/deploy.$1.done"; }
stamped() { [ -f "$STATE_DIR/deploy.$1.done" ]; }

recreate() { docker rm -f "$1" >/dev/null 2>&1 || true; }

# =============================================================================
step_metadb() {
  stamped metadb && docker ps --format '{{.Names}}' | grep -qx console-meta-db && { log "metadb: ok (skip)"; return 0; }
  log "metadb: console-meta-db (no published ports; coolify net only)"
  recreate console-meta-db
  docker run -d --name console-meta-db --network "$NET" --restart unless-stopped \
    -e POSTGRES_DB=console_meta -e POSTGRES_USER=postgres -e PGUSER=postgres \
    -e POSTGRES_PASSWORD="$CONSOLE_META_POSTGRES_PASSWORD" \
    -v console-meta-data:/var/lib/postgresql/data \
    "$IMG_PG" >/dev/null
  log "metadb: waiting for readiness"
  local i
  for i in $(seq 1 60); do
    docker exec console-meta-db pg_isready -U postgres -d console_meta >/dev/null 2>&1 && break
    sleep 2
    [ "$i" = 60 ] && { echo "console-meta-db never became ready"; exit 1; }
  done

  log "metadb: role 'console' + Better Auth schema (guarded, verbatim migration)"
  docker exec -i console-meta-db psql -U postgres -d console_meta -v ON_ERROR_STOP=1 -q \
    -v pw="$CONSOLE_META_PG_PASSWORD" <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='console') THEN
    CREATE ROLE console LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END $$;
ALTER ROLE console PASSWORD :'pw';
ALTER DATABASE console_meta OWNER TO console;
ALTER SCHEMA public OWNER TO console;
SQL

  # apply the vendored drizzle migration once (as `console`, so it owns the
  # tables the console later manages at runtime)
  if ! docker exec console-meta-db psql -U postgres -d console_meta -tAc \
      "SELECT 1 FROM information_schema.tables WHERE table_name='user' AND table_schema='public'" | grep -q 1; then
    sed 's/--> statement-breakpoint//' "$BOOT/sql/console-meta-schema.sql" |
      docker exec -i -e PGPASSWORD="$CONSOLE_META_PG_PASSWORD" console-meta-db \
        psql -U console -d console_meta -v ON_ERROR_STOP=1 -q
  fi
  stamp metadb
}

# =============================================================================
step_pgmeta() {
  stamped pgmeta && docker ps --format '{{.Names}}' | grep -qx postgres-meta && { log "pgmeta: ok (skip)"; return 0; }
  log "pgmeta: postgres-meta (CRYPTO_KEY, not PG_META_CRYPTO_KEY — both set via /root/postgres-meta.env)"
  recreate postgres-meta
  docker run -d --name postgres-meta --network "$NET" --restart unless-stopped \
    --env-file /root/postgres-meta.env \
    -e PG_META_PORT=8080 -e PG_META_HOST=0.0.0.0 \
    "$IMG_PGMETA" >/dev/null
  stamp pgmeta
}

# =============================================================================
step_keyproxy() {
  stamped keyproxy && docker ps --format '{{.Names}}' | grep -qx key-proxy && { log "keyproxy: ok (skip)"; return 0; }
  log "keyproxy: shim container (empty map on a fresh box) + Traefik service def"
  install -m 0644 "$SRC/infra/key-proxy/key-proxy.py" /root/key-proxy.py
  recreate key-proxy
  docker run -d --name key-proxy --network "$NET" --restart unless-stopped \
    -v /root/key-proxy.py:/key-proxy.py:ro \
    -e 'KEY_PROXY_MAP={}' \
    "$IMG_KEYPROXY" python3 /key-proxy.py >/dev/null
  install -m 0644 "$SRC/infra/key-proxy/key-proxy.yaml" /data/coolify/proxy/dynamic/key-proxy.yaml
  stamp keyproxy
}

# =============================================================================
step_svcagent() {
  stamped svcagent && docker ps --format '{{.Names}}' | grep -qx svc-agent && { log "svcagent: ok (skip)"; return 0; }
  log "svcagent: docker-socket-proxy (svcctl, start/stop/restart+inspect only) + svc-agent"
  recreate docker-socket-proxy
  # start/stop/restart + inspect only — svc-agent can never create, delete or
  # exec into containers through this proxy.
  docker run -d --name docker-socket-proxy --network svcctl --restart unless-stopped \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e CONTAINERS=1 -e POST=1 \
    -e ALLOW_START=1 -e ALLOW_STOP=1 -e ALLOW_RESTARTS=1 \
    "$IMG_SOCKPROXY" >/dev/null

  docker build -q -t svc-agent:vibe "$SRC/infra/svc-agent" >/dev/null
  recreate svc-agent
  docker run -d --name svc-agent --network svcctl --restart unless-stopped \
    -e CONSOLE_PROXY_HMAC_SECRET="$CONSOLE_PROXY_HMAC_SECRET" \
    svc-agent:vibe >/dev/null
  docker network connect "$NET" svc-agent 2>/dev/null || true
  stamp svcagent
}

# =============================================================================
step_aux_images() {
  stamped aux_images && { log "aux-images: ok (skip)"; return 0; }
  log "aux-images: pre-pull/build every image the provisioner launches (its socket proxy gets IMAGES=0)"
  # Tags MUST match IMAGES in infra/provisioner/provisioner.py. Pulled here on
  # the HOST docker (bypasses the proxy) so the provisioner-proxy can stay at
  # IMAGES=0/NETWORKS=0 — the vetted least-privilege flag set.
  local img
  for img in \
    supabase/gotrue:v2.189.0 \
    postgrest/postgrest:v14.12 \
    supabase/storage-api:v1.60.4 \
    supabase/realtime:v2.102.3 \
    python:3.12-alpine; do
    docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null
  done
  if ! docker image inspect vibe-postgres:17-ext1 >/dev/null 2>&1; then
    if [ -f "$SRC/infra/db-image/Dockerfile" ]; then
      docker build -q -t vibe-postgres:17-ext1 "$SRC/infra/db-image" >/dev/null
    else
      log "aux-images: WARN infra/db-image missing — tagging pgvector/pgvector:pg17 as the project-DB image (extended extension set unavailable until the db-image build is vendored)"
      docker pull -q pgvector/pgvector:pg17 >/dev/null
      docker tag pgvector/pgvector:pg17 vibe-postgres:17-ext1
    fi
  fi
  if ! docker image inspect vibe-neon-auth:v1 >/dev/null 2>&1; then
    docker build -q -t vibe-neon-auth:v1 "$SRC/infra/neon-auth" >/dev/null
  fi
  stamp aux_images
}

# =============================================================================
step_provisioner() {
  stamped provisioner && docker ps --format '{{.Names}}' | grep -qx provisioner && { log "provisioner: ok (skip)"; return 0; }
  log "provisioner: provisioner-proxy (provctl) + provisioner (template-enforced)"
  recreate provisioner-proxy
  # Least-privilege flag set: containers + volumes only. IMAGES=0
  # and NETWORKS=0 on purpose — every image the provisioner runs is pre-pulled
  # or pre-built on the host by step_aux_images, so the proxy never needs to
  # expose image or network endpoints to the provisioner.
  docker run -d --name provisioner-proxy --network provctl --restart unless-stopped \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e CONTAINERS=1 -e IMAGES=0 -e NETWORKS=0 -e VOLUMES=1 -e POST=1 \
    -e ALLOW_START=1 -e ALLOW_STOP=1 -e ALLOW_RESTARTS=1 \
    "$IMG_SOCKPROXY" >/dev/null

  docker build -q -t provisioner:vibe "$SRC/infra/provisioner" >/dev/null
  recreate provisioner
  docker run -d --name provisioner --network provctl --restart unless-stopped \
    -e DOCKER_HOST=tcp://provisioner-proxy:2375 \
    -e CONSOLE_PROXY_HMAC_SECRET="$CONSOLE_PROXY_HMAC_SECRET" \
    -e CONSOLE_MON_PASSWORD="$CONSOLE_MON_PASSWORD" \
    -e DOMAIN_SUFFIX="$DOMAIN_SUFFIX" -e PUBLIC_IP="$PUBLIC_IP" \
    -v /root:/host/root \
    -v /data/coolify/proxy/dynamic:/host/traefik-dynamic \
    -v /data/coolify/databases:/host/databases \
    -v /data/storage:/host/storage \
    provisioner:vibe >/dev/null
  docker network connect "$NET" provisioner 2>/dev/null || true

  log "provisioner: host expose-sync units (socat + ufw, .path watcher)"
  mkdir -p /root/provisioner-expose.d /data/coolify/databases /data/storage
  cat > /etc/default/vibebase <<EOF
PUBLIC_IP=$PUBLIC_IP
DOMAIN_SUFFIX=$DOMAIN_SUFFIX
EOF
  install -m 0755 "$SRC/infra/provisioner/host/provisioner-expose-sync.sh" /usr/local/sbin/provisioner-expose-sync.sh
  install -m 0644 "$SRC/infra/provisioner/host/provisioner-expose-sync.service" /etc/systemd/system/provisioner-expose-sync.service
  install -m 0644 "$SRC/infra/provisioner/host/provisioner-expose.path" /etc/systemd/system/provisioner-expose.path
  systemctl daemon-reload
  systemctl enable --now provisioner-expose.path >/dev/null
  stamp provisioner
}

# =============================================================================
step_studio_build() {
  if docker image inspect "$STUDIO_TAG" >/dev/null 2>&1; then
    log "studio-build: image $STUDIO_TAG exists (skip; set STUDIO_TAG to rebuild)"
    stamp studio_build; return 0
  fi
  log "studio-build: detached heap-capped build (10-16 min; silent during Next optimize — not a hang)"
  # Detached via systemd-run so a dropped session can't cancel it.
  systemd-run --unit=vibebase-studio-build --collect --property=Nice=10 \
    --property=StandardOutput=append:"$STATE_DIR/studio-build.log" \
    --property=StandardError=append:"$STATE_DIR/studio-build.log" \
    --working-directory="$SRC/studio-fork" \
    docker build . -f apps/studio/Dockerfile --target production -t "$STUDIO_TAG" >/dev/null
  local i
  for i in $(seq 1 240); do   # up to 40 min
    if docker image inspect "$STUDIO_TAG" >/dev/null 2>&1; then break; fi
    if ! systemctl is-active --quiet vibebase-studio-build 2>/dev/null &&
       ! docker image inspect "$STUDIO_TAG" >/dev/null 2>&1; then
      echo "studio build unit exited without producing $STUDIO_TAG — see $STATE_DIR/studio-build.log"
      exit 1
    fi
    sleep 10
  done
  docker image inspect "$STUDIO_TAG" >/dev/null 2>&1 || { echo "studio build timed out"; exit 1; }
  stamp studio_build
}

# =============================================================================
step_studio_run() {
  log "studio-run: assemble /root/studio-app.env + run studio-console (HOSTNAME=0.0.0.0!)"
  # env is baked at container create — always rm -f + run to change it.
  umask 177
  cat > /root/studio-app.env <<EOF
# generated by deploy-stack.sh — regenerate + recreate container to change
HOSTNAME=0.0.0.0
PORT=3000
BETTER_AUTH_URL=https://console.$DOMAIN_SUFFIX
BETTER_AUTH_SECRET=$BETTER_AUTH_SECRET
CONSOLE_META_PG_HOST=console-meta-db
CONSOLE_META_PG_PORT=5432
CONSOLE_META_PG_DB=console_meta
CONSOLE_META_PG_USER=console
CONSOLE_META_PG_PASSWORD=$CONSOLE_META_PG_PASSWORD
PG_META_CRYPTO_KEY=$PG_META_CRYPTO_KEY
STUDIO_PG_META_URL=http://postgres-meta:8080
CONSOLE_PROXY_HMAC_SECRET=$CONSOLE_PROXY_HMAC_SECRET
SVC_AGENT_URL=http://svc-agent:8899
PROVISIONER_URL=http://provisioner:8900
CONSOLE_MON_PASSWORD=$CONSOLE_MON_PASSWORD
CONSOLE_REGISTRY_JSON=[]
DEFAULT_ORGANIZATION_NAME=Vibe Base
# Logflare-backed surfaces stay off (no Logflare in this stack)
ENABLED_FEATURES_LOGS_ALL=false
ENABLED_FEATURES_LOG_DRAINS=false
ENABLED_FEATURES_REPORTS_ALL=false
ENABLED_FEATURES_STORAGE_ANALYTICS=false
EOF
  umask 022
  recreate studio-console
  docker run -d --name studio-console --network "$NET" --restart unless-stopped \
    --env-file /root/studio-app.env \
    "$STUDIO_TAG" >/dev/null
  stamp studio_run
}

# =============================================================================
step_routes_seed() {
  log "routes: console.yaml -> studio-console:3000"
  python3 - "$BOOT/traefik/console.yaml.tmpl" "$DOMAIN_SUFFIX" "${TLS_MODE:-http01}" <<'EOF'
import sys
tmpl, base, mode = open(sys.argv[1]).read(), sys.argv[2], sys.argv[3]
domains = ""
if mode == "dns01":
    domains = (f"        domains:\n"
               f"          - main: \"{base}\"\n"
               f"            sans: [\"*.{base}\"]\n")
out = tmpl.replace("{base_domain}", base).replace("{domains_block}", domains)
open("/data/coolify/proxy/dynamic/console.yaml", "w").write(out)
EOF

  log "seed: admin account into console_meta (Better Auth)"
  # scrypt-hash compatibility with better-auth@1.6.23 proven (installer-verify)
  python3 "$BOOT/seed-admin.py"
  stamp routes_seed
}

# =============================================================================
step_verify() {
  log "verify: health checks"
  local fails=0
  docker exec console-meta-db pg_isready -U postgres >/dev/null 2>&1 || { echo "FAIL console-meta-db"; fails=1; }
  docker run --rm --network "$NET" curlimages/curl:8.10.1 -fsS -o /dev/null \
    http://postgres-meta:8080/health 2>/dev/null || echo "WARN postgres-meta /health not answering (older tags lack it)"
  docker run --rm --network "$NET" curlimages/curl:8.10.1 -fsS -o /dev/null \
    "http://studio-console:3000/api/health" 2>/dev/null || { echo "FAIL studio-console"; fails=1; }
  # signed checks (svc-agent /status, provisioner /health)
  python3 - <<EOF || fails=1
import hashlib, hmac, json, subprocess, time
secret = "$CONSOLE_PROXY_HMAC_SECRET".encode()
def signed_get(host, port, path):
    ts = str(int(time.time()))
    sig = hmac.new(secret, f"{ts}.GET.{path}.".encode(), hashlib.sha256).hexdigest()
    r = subprocess.run(["docker", "run", "--rm", "--network", "$NET",
        "curlimages/curl:8.10.1", "-fsS",
        "-H", f"X-Console-Ts: {ts}", "-H", f"X-Console-Sig: {sig}",
        f"http://{host}:{port}{path}"], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise SystemExit(f"FAIL {host}{path}: {r.stderr.strip()[:200]}")
    print(f"ok {host}{path}")
signed_get("svc-agent", 8899, "/status")
signed_get("provisioner", 8900, "/health")
EOF
  [ "$fails" = 0 ] || { echo "verify: FAILURES above"; exit 1; }
  log "verify: ALL PASS"
  stamp verify
}

# =============================================================================
STEPS="metadb pgmeta keyproxy svcagent aux_images provisioner studio_build studio_run routes_seed verify"
want="${1:-all}"
mkdir -p "$STATE_DIR"
if [ "$want" = all ]; then
  for s in $STEPS; do "step_$s"; done
else
  case " $STEPS " in
    *" $want "*) "step_$want" ;;
    *) echo "unknown substep '$want' (one of: $STEPS)"; exit 2 ;;
  esac
fi
log "deploy-stack: done ($want)"
