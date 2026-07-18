#!/usr/bin/env bash
# =============================================================================
# Vibe Base — one-command installer
#
# Turns a fresh Ubuntu server into a hardened host running the first-run
# setup wizard, which then deploys the full multi-project self-hosted
# database console (Postgres + Auth + REST + Storage + Realtime per project).
#
#   curl -fsSL https://raw.githubusercontent.com/Ingeniiious/vibebase/main/install.sh | sudo bash
#   sudo ./install.sh              # from a repo checkout
#   sudo ./install.sh --dry-run    # print the plan, mutate nothing
#
# Guarantees:
#   - Idempotent + resumable: phases stamp themselves in /opt/vibebase/state
#     and re-check reality before skipping; re-running is always safe.
#   - Never closes a pre-existing port: ufw is enabled default-deny only after
#     auto-allowing everything currently listening. Interactive keep/close
#     decisions happen later, in the wizard.
#   - Refuses to run on a box that already hosts a console deployment it
#     did not install (protects existing production stacks).
#   - Secrets are generated locally, 0600, never printed.
# =============================================================================
set -euo pipefail

VIBE_HOME=/opt/vibebase
STATE_DIR="$VIBE_HOME/state"
SRC_DIR="$VIBE_HOME/src"
WIZARD_PORT="${WIZARD_PORT:-8642}"
REPO_URL_DEFAULT="https://github.com/Ingeniiious/vibebase.git"
VIBE_REPO_URL="${VIBE_REPO_URL:-$REPO_URL_DEFAULT}"

# Console source (the studio fork) ships as a GitHub release asset, not in git,
# to keep the repo small. Pinned by tag + sha256 (both hardcoded so a tampered
# or truncated download is rejected). Overridable via env for testing.
STUDIO_SRC_TAG="${STUDIO_SRC_TAG:-v0.1.0-beta}"
STUDIO_SRC_ASSET="vibebase-studio-src.tar.gz"
STUDIO_SRC_URL="${STUDIO_SRC_URL:-https://github.com/Ingeniiious/vibebase/releases/download/${STUDIO_SRC_TAG}/${STUDIO_SRC_ASSET}}"
STUDIO_SRC_SHA256="${STUDIO_SRC_SHA256:-189fa2bb97a46038a555da3a966e6090f7feeadbae8c1939482687b3256adf05}"
STUDIO_FORK_DIR="$SRC_DIR/studio-fork"

DRY_RUN=0
FORCE_WIZARD=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --force-wizard) FORCE_WIZARD=1 ;;
    -h|--help)
      sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m[vibebase]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[vibebase WARN]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[vibebase FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

stamp_path() { echo "$STATE_DIR/phase.$1.done"; }
stamped()    { [ -f "$(stamp_path "$1")" ]; }
stamp() {
  [ "$DRY_RUN" = 1 ] && return 0
  date -u +%FT%TZ > "$(stamp_path "$1")"
}

# Where is this script running from? A repo checkout next to the script wins;
# under `curl | bash` BASH_SOURCE is empty and we fall back to the /opt clone.
script_src_dir() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]:-/nonexistent}")" 2>/dev/null && pwd || echo /nonexistent)"
  if [ -f "$here/infra/bootstrap/wizard/wizard.py" ]; then
    echo "$here"
  else
    echo "$SRC_DIR"
  fi
}

# =============================================================================
# Phase a — preflight + spec scan + capacity estimate
# =============================================================================
detect_public_ip() {
  local ip_route ip_web
  ip_route="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')" || true
  ip_web="$(curl -fsS4 --max-time 5 https://ifconfig.me 2>/dev/null || curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  if [ -n "$ip_web" ]; then
    echo "$ip_web"
  elif [ -n "$ip_route" ]; then
    echo "$ip_route"
  else
    echo ""
  fi
}

phase_preflight() {
  log "phase a: preflight + spec scan"
  if [ "$(id -u)" != 0 ]; then
    if [ "$DRY_RUN" = 1 ]; then warn "not root — fine for --dry-run"; else die "must run as root (sudo ./install.sh)"; fi
  fi

  # Ubuntu check
  local os_id="" os_ver=""
  if [ -r /etc/os-release ]; then
    # shellcheck source=/dev/null
    os_id="$(. /etc/os-release && echo "${ID:-}")"
    # shellcheck source=/dev/null
    os_ver="$(. /etc/os-release && echo "${VERSION_ID:-0}")"
  fi
  if [ "$os_id" != "ubuntu" ]; then
    if [ "$DRY_RUN" = 1 ]; then warn "not Ubuntu ($os_id) — continuing because --dry-run"; else die "this installer supports Ubuntu only (found: ${os_id:-unknown})"; fi
  fi
  case "$os_ver" in
    2[2-9].*|[3-9][0-9].*) : ;;  # 22.04+
    *) warn "Ubuntu ${os_ver:-?} is older than 22.04 — untested" ;;
  esac

  # Existing-deployment guard: if console containers exist but WE didn't
  # install them (no state dir), this box already hosts a deployment.
  if command -v docker >/dev/null 2>&1 && [ ! -f "$STATE_DIR/facts.env" ]; then
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qxE 'studio-console|console-meta-db'; then
      die "found an existing console stack (studio-console/console-meta-db) not installed by this tool — refusing to touch a box that already hosts a deployment."
    fi
  fi

  # Spec scan ---------------------------------------------------------------
  local cores ram_kb ram_gib disk_free_gb disk_total_gb cpu_model hyper steal rotational
  cores="$(nproc 2>/dev/null || echo 1)"
  ram_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  ram_gib=$(( ram_kb / 1024 / 1024 ))
  disk_free_gb="$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)"
  disk_total_gb="$(df -BG --output=size / 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)"
  cpu_model="$(awk -F: '/model name/{gsub(/^ /,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)"
  hyper="$(lscpu 2>/dev/null | awk -F: '/Hypervisor vendor/{gsub(/^ +/,"",$2); print $2}' || true)"
  # CPU steal % sampled over 1s (shared-vCPU signal)
  steal=0
  if [ -r /proc/stat ]; then
    steal="$(
      read -r _ u n s i io irq sirq st _ < /proc/stat
      t0=$((u+n+s+i+io+irq+sirq+st)); s0=$st
      sleep 1
      read -r _ u n s i io irq sirq st _ < /proc/stat
      t1=$((u+n+s+i+io+irq+sirq+st)); s1=$st
      dt=$((t1-t0))
      if [ "$dt" -gt 0 ]; then echo $(( (s1-s0)*100/dt )); else echo 0; fi
    )" || steal=0
  fi
  local root_dev
  root_dev="$(findmnt -no SOURCE / 2>/dev/null | sed 's|/dev/||; s|[0-9]*$||; s|p$||' || true)"
  rotational="$(cat "/sys/block/${root_dev:-none}/queue/rotational" 2>/dev/null || echo unknown)"

  # Resource floor (dry-run downgrades hard failures to warnings)
  floor() { # floor <condition-ok:0|1> <message>
    if [ "$1" != 0 ]; then return 0; fi
    if [ "$DRY_RUN" = 1 ]; then warn "$2"; else die "$2"; fi
  }
  cores="${cores:-0}"; ram_gib="${ram_gib:-0}"
  disk_free_gb="${disk_free_gb:-0}"; disk_total_gb="${disk_total_gb:-0}"
  local ok
  ok=0; if [ "$cores" -ge 2 ] 2>/dev/null; then ok=1; fi
  floor "$ok" "need >= 2 vCPU (found $cores)"
  ok=0; if [ "$ram_gib" -ge 3 ] 2>/dev/null; then ok=1; fi
  floor "$ok" "need >= 3 GiB RAM (found ${ram_gib} GiB)"
  if [ "$ram_gib" -ge 3 ] && [ "$ram_gib" -lt 8 ]; then
    warn "only ${ram_gib} GiB RAM — workable, but capacity will be low (see estimate below)"
  fi
  ok=0; if [ "$disk_free_gb" -ge 30 ] 2>/dev/null; then ok=1; fi
  floor "$ok" "need >= 30 GB free disk (found ${disk_free_gb} GB)"

  # Public IP
  local public_ip
  public_ip="$(detect_public_ip)"
  [ -n "$public_ip" ] || die "could not detect a public IPv4 address"

  # Capacity estimate (measured footprints on the reference deployment):
  #   plain-Postgres project  ~0.7 GiB    full stack (DB + auth/rest/storage/
  #   realtime)               ~1.4 GiB    reserved: 3 GiB + 10% of RAM
  local usable_mib cap_plain cap_full
  usable_mib=$(( ram_gib * 1024 - 3072 - ram_gib * 102 ))
  [ "$usable_mib" -lt 0 ] && usable_mib=0
  cap_plain=$(( usable_mib / 717 ))
  cap_full=$(( usable_mib / 1434 ))

  # Swap recommendation (created ONLY after the user confirms, in the wizard):
  #   clamp(2 x RAM, 8, 64) GiB, capped at 30% of free disk.
  local swap_rec swap_cap swap_existing_gib
  swap_rec=$(( ram_gib * 2 )); [ "$swap_rec" -lt 8 ] && swap_rec=8; [ "$swap_rec" -gt 64 ] && swap_rec=64
  swap_cap=$(( disk_free_gb * 30 / 100 ))
  local swap_capped=0
  if [ "$swap_rec" -gt "$swap_cap" ]; then swap_rec=$swap_cap; swap_capped=1; fi
  swap_existing_gib="$(awk '/SwapTotal/{printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)"

  echo
  echo "  ┌─ System specs ─────────────────────────────────────────────"
  echo "  │ CPU:   ${cores} cores — ${cpu_model}"
  echo "  │        virtualization: ${hyper:-none/bare-metal}; CPU steal: ${steal}%$( [ "${steal:-0}" -gt 5 ] && echo '  << shared/oversold vCPU signal' )"
  echo "  │ RAM:   ${ram_gib} GiB   Swap now: ${swap_existing_gib} GiB"
  echo "  │ Disk:  ${disk_total_gb} GB total, ${disk_free_gb} GB free ($( [ "$rotational" = 0 ] && echo SSD/NVMe || echo "rotational=$rotational" ))"
  echo "  ├─ Capacity estimate (assumptions shown in the wizard) ──────"
  echo "  │ ~${cap_plain} plain-Postgres projects  OR  ~${cap_full} full-stack projects"
  echo "  │ (plain ~0.7 GiB, full stack ~1.4 GiB, 3 GiB + 10% reserved)"
  echo "  ├─ Swap recommendation (you choose in the wizard) ───────────"
  echo "  │ recommended ${swap_rec} GiB$( [ "$swap_capped" = 1 ] && echo ' (capped at 30% of free disk)' )"
  echo "  └─────────────────────────────────────────────────────────────"
  echo

  if [ "$DRY_RUN" = 0 ]; then
    mkdir -p "$STATE_DIR"
    chmod 700 "$VIBE_HOME" "$STATE_DIR"
    cat > "$STATE_DIR/facts.env" <<EOF
PUBLIC_IP=$public_ip
WIZARD_PORT=$WIZARD_PORT
EOF
    python3 - "$STATE_DIR/specs.json" <<EOF
import json, sys
json.dump({
  "cores": $cores, "cpu_model": """$cpu_model""",
  "hypervisor": """${hyper:-}""", "steal_pct": ${steal:-0},
  "ram_gib": $ram_gib, "disk_total_gb": $disk_total_gb,
  "disk_free_gb": $disk_free_gb, "rotational": "${rotational}",
  "swap_existing_gib": $swap_existing_gib,
  "swap_recommended_gib": $swap_rec, "swap_disk_cap_gib": $swap_cap,
  "cap_plain": $cap_plain, "cap_full": $cap_full,
  "public_ip": "$public_ip",
}, open(sys.argv[1], "w"), indent=1)
EOF
    chmod 600 "$STATE_DIR/specs.json"
  fi
  stamp preflight
}

# =============================================================================
# Phase b — sources (sync the repo into /opt/vibebase/src FIRST — later
# phases install scripts out of it)
# =============================================================================
phase_sources() {
  if [ -f "$SRC_DIR/infra/bootstrap/wizard/wizard.py" ] && stamped sources; then
    log "phase b: sources already in $SRC_DIR — skipping"; return 0
  fi
  local src
  src="$(script_src_dir)"
  if [ "$DRY_RUN" = 1 ]; then
    if [ "$src" != "$SRC_DIR" ]; then
      echo "  [plan] sync repo checkout ($src) -> $SRC_DIR"
    else
      echo "  [plan] git clone --depth 1 $VIBE_REPO_URL $SRC_DIR"
    fi
    return 0
  fi
  log "phase b: install sources -> $SRC_DIR"
  mkdir -p "$SRC_DIR"
  if [ "$src" != "$SRC_DIR" ]; then
    if command -v rsync >/dev/null 2>&1; then
      rsync -a --delete --exclude .git --exclude node_modules "$src/" "$SRC_DIR/"
    else
      tar -C "$src" --exclude .git --exclude node_modules -cf - . | tar -C "$SRC_DIR" -xf -
    fi
  else
    command -v git >/dev/null 2>&1 || {
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq && apt-get install -y -qq git >/dev/null
    }
    if [ -d "$SRC_DIR/.git" ]; then
      git -C "$SRC_DIR" pull --ff-only || true
    else
      git clone --depth 1 "$VIBE_REPO_URL" "$SRC_DIR"
    fi
  fi
  [ -f "$SRC_DIR/infra/bootstrap/wizard/wizard.py" ] || die "sources incomplete under $SRC_DIR (wizard.py missing)"
  stamp sources
}

# =============================================================================
# Phase b2 — console source (the studio fork)
#
# The dashboard source is a fork of Supabase Studio, too large to keep in git,
# so it ships as a pinned GitHub release asset. Fetch it, verify its sha256
# against the hardcoded digest (rejects a tampered/truncated download), and
# extract it to $SRC_DIR/studio-fork — exactly where deploy-stack.sh's
# studio_build step (`--working-directory=$SRC/studio-fork`) expects it. The
# repo only carries a placeholder studio-fork/README.md until this runs.
# =============================================================================
phase_studio_src() {
  if [ -f "$STUDIO_FORK_DIR/apps/studio/Dockerfile" ] && stamped studio_src; then
    log "phase b2: console source already present in $STUDIO_FORK_DIR — skipping"; return 0
  fi
  if [ "$DRY_RUN" = 1 ]; then
    cat <<EOF
  [plan] download $STUDIO_SRC_URL
  [plan] verify sha256 == $STUDIO_SRC_SHA256 (abort on mismatch)
  [plan] extract (strip 1) -> $STUDIO_FORK_DIR   [then deploy builds apps/studio/Dockerfile]
EOF
    return 0
  fi
  log "phase b2: fetch + verify console source (studio-fork) release asset"
  command -v curl >/dev/null 2>&1 || {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq curl >/dev/null
  }
  mkdir -p "$STUDIO_FORK_DIR"
  local tmp="$STATE_DIR/${STUDIO_SRC_ASSET}"
  log "  downloading $STUDIO_SRC_URL"
  curl -fSL --retry 3 --retry-delay 2 -o "$tmp" "$STUDIO_SRC_URL" \
    || die "console source download failed: $STUDIO_SRC_URL"
  # Verify integrity BEFORE trusting the archive.
  if ! echo "${STUDIO_SRC_SHA256}  ${tmp}" | sha256sum -c - >/dev/null 2>&1; then
    local got; got="$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')"
    rm -f "$tmp"
    die "console source checksum mismatch (expected $STUDIO_SRC_SHA256, got ${got:-none}) — refusing to build"
  fi
  log "  sha256 OK — extracting to $STUDIO_FORK_DIR"
  # Tarball has a single top-level dir (vibebase-studio-src/); strip it so the
  # tree lands directly under studio-fork/.
  tar -xzf "$tmp" -C "$STUDIO_FORK_DIR" --strip-components=1 || die "console source extract failed"
  rm -f "$tmp"
  [ -f "$STUDIO_FORK_DIR/apps/studio/Dockerfile" ] || die "console source incomplete after extract (apps/studio/Dockerfile missing)"
  stamp studio_src
}

# =============================================================================
# Phase c — docker
# =============================================================================
phase_docker() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    log "phase c: docker already installed — skipping"
    stamp docker; return 0
  fi
  log "phase c: install docker + compose plugin"
  if [ "$DRY_RUN" = 1 ]; then
    echo "  [plan] curl -fsSL https://get.docker.com | sh; enable docker; live-restore"
    return 0
  fi
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
  mkdir -p /etc/docker
  if [ ! -f /etc/docker/daemon.json ]; then
    echo '{ "live-restore": true }' > /etc/docker/daemon.json
    systemctl restart docker
  fi
  systemctl enable --now docker
  docker info >/dev/null || die "docker did not come up"
  stamp docker
}

# =============================================================================
# Phase d — harden (ADDITIVE: snapshots ports, never closes anything)
# =============================================================================
snapshot_ports() {
  # Record every non-loopback listener (proto/port/process) + current ufw
  # rules. The wizard's Firewall-review step walks this list with the user.
  ss -tlnpu > "$STATE_DIR/ports-baseline.ss" 2>/dev/null || true
  ufw status verbose > "$STATE_DIR/ports-baseline.ufw" 2>/dev/null || true
  python3 - "$STATE_DIR/ports-baseline.ss" "$STATE_DIR/ports-baseline.json" <<'EOF'
import json, re, sys
rows = []
for line in open(sys.argv[1]):
    parts = line.split()
    if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
        continue
    state = parts[1]
    if parts[0] == "tcp" and state != "LISTEN":
        continue
    local = parts[4]
    m = re.match(r"^(.*):(\d+)$", local)
    if not m:
        continue
    addr, port = m.group(1), int(m.group(2))
    if addr in ("127.0.0.1", "[::1]", "127.0.0.53%lo", "127.0.0.54"):
        continue
    proc = ""
    pm = re.search(r'users:\(\("([^"]+)"', line)
    if pm:
        proc = pm.group(1)
    rows.append({"proto": parts[0], "port": port, "addr": addr, "process": proc})
seen, uniq = set(), []
for r in rows:
    k = (r["proto"], r["port"])
    if k not in seen:
        seen.add(k); uniq.append(r)
json.dump(uniq, open(sys.argv[2], "w"), indent=1)
EOF
  chmod 600 "$STATE_DIR"/ports-baseline.* 2>/dev/null || true
}

phase_harden() {
  if stamped harden && ufw status 2>/dev/null | grep -q "Status: active"; then
    log "phase d: harden already done — skipping"; return 0
  fi
  log "phase d: harden (additive — nothing pre-existing gets closed)"

  if [ "$DRY_RUN" = 1 ]; then
    cat <<EOF
  [plan] snapshot listening ports + ufw rules -> state/ports-baseline.*
  [plan] apt install ufw fail2ban unattended-upgrades earlyoom
  [plan] IF ufw inactive: ufw allow <every currently-listening public port>
  [plan] ufw allow OpenSSH; ufw allow ${WIZARD_PORT}/tcp (wizard, transient)
  [plan] ufw default deny incoming / allow outgoing; ufw --force enable
  [plan] enable fail2ban (sshd) + unattended-upgrades + earlyoom
  [plan] install pg-oom-shield.sh + 5-min timer (oom_score_adj -800 on *-db postgres)
  [plan] NO swap here — user chooses size in the wizard
EOF
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ufw fail2ban unattended-upgrades earlyoom socat curl python3 >/dev/null

  snapshot_ports

  local ufw_was_active=0
  ufw status 2>/dev/null | grep -q "Status: active" && ufw_was_active=1
  if [ "$ufw_was_active" = 0 ]; then
    # Fail-safe: before default-deny, allow everything that is listening right
    # now so enabling the firewall breaks nothing. The wizard reviews these.
    python3 - "$STATE_DIR/ports-baseline.json" <<'EOF' |
import json, sys
for r in json.load(open(sys.argv[1])):
    print(f"{r['port']}/{r['proto']} {r.get('process') or 'unknown'}")
EOF
    while read -r rule proc; do
      [ -z "$rule" ] && continue
      [ "${rule%%/*}" = "$WIZARD_PORT" ] && continue
      [ "${rule%%/*}" = "22" ] && continue
      ufw allow "$rule" comment "vibebase-preexisting-$proc" >/dev/null || true
    done
  fi
  ufw allow OpenSSH >/dev/null || ufw allow 22/tcp >/dev/null
  ufw allow "${WIZARD_PORT}/tcp" comment "vibebase-wizard (transient)" >/dev/null
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw --force enable >/dev/null

  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
  systemctl enable --now earlyoom >/dev/null 2>&1 || true
  sysctl -w vm.swappiness=10 >/dev/null
  grep -q '^vm.swappiness' /etc/sysctl.d/99-vibebase.conf 2>/dev/null || \
    echo 'vm.swappiness=10' >> /etc/sysctl.d/99-vibebase.conf

  # pg-oom-shield: keep the kernel OOM killer away from project databases.
  install -m 0755 "$SRC_DIR/infra/bootstrap/pg-oom-shield.sh" /usr/local/sbin/pg-oom-shield.sh
  cat > /etc/systemd/system/pg-oom-shield.service <<'EOF'
[Unit]
Description=Set oom_score_adj=-800 on project postgres processes
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/pg-oom-shield.sh
EOF
  cat > /etc/systemd/system/pg-oom-shield.timer <<'EOF'
[Unit]
Description=Re-apply pg-oom-shield every 5 minutes (containers restart)
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now pg-oom-shield.timer >/dev/null

  stamp harden
}

# =============================================================================
# Phase e — docker networks
# =============================================================================
phase_networks() {
  log "phase e: docker networks (coolify, svcctl, provctl)"
  if [ "$DRY_RUN" = 1 ]; then
    echo "  [plan] docker network create coolify; create --internal svcctl provctl"
    return 0
  fi
  docker network inspect coolify >/dev/null 2>&1 || docker network create coolify >/dev/null
  docker network inspect svcctl  >/dev/null 2>&1 || docker network create --internal svcctl >/dev/null
  docker network inspect provctl >/dev/null 2>&1 || docker network create --internal provctl >/dev/null
  stamp networks
}

# =============================================================================
# Phase f — base secrets + wizard token
# =============================================================================
phase_secrets() {
  log "phase f: base secrets (/root/console.env, /root/postgres-meta.env)"
  if [ "$DRY_RUN" = 1 ]; then
    if [ -f "$(script_src_dir)/infra/bootstrap/gen-base-secrets.sh" ]; then
      bash "$(script_src_dir)/infra/bootstrap/gen-base-secrets.sh" --dry-run || true
    fi
    echo "  [plan] mint one-time wizard setup token (sha256 -> state, plaintext only in banner)"
    return 0
  fi
  bash "$SRC_DIR/infra/bootstrap/gen-base-secrets.sh"

  if [ ! -f "$STATE_DIR/wizard-token.sha256" ] || [ "$FORCE_WIZARD" = 1 ]; then
    SETUP_TOKEN="$(od -vN 24 -An -tx1 /dev/urandom | tr -d ' \n')"
    printf '%s' "$SETUP_TOKEN" | sha256sum | awk '{print $1}' > "$STATE_DIR/wizard-token.sha256"
    chmod 600 "$STATE_DIR/wizard-token.sha256"
  fi
  stamp secrets
}

# =============================================================================
# Phase g — install + launch the wizard
# =============================================================================
phase_wizard() {
  # Already fully set up? Don't re-open anything without --force-wizard.
  if [ -f "$STATE_DIR/wizard.json" ] && [ "$FORCE_WIZARD" = 0 ] &&
     python3 -c 'import json,sys; sys.exit(0 if json.load(open("'"$STATE_DIR"'/wizard.json")).get("locked") else 1)' 2>/dev/null; then
    local dom
    dom="$(python3 -c 'import json; print(json.load(open("'"$STATE_DIR"'/wizard.json")).get("domain",""))' 2>/dev/null || true)"
    log "already set up — console at https://console.${dom:-<your-domain>} (use --force-wizard to re-run setup)"
    return 0
  fi

  log "phase g: install + launch the setup wizard"
  if [ "$DRY_RUN" = 1 ]; then
    cat <<EOF
  [plan] write /etc/systemd/system/vibebase-wizard.service (root, python3 stdlib)
  [plan] systemctl enable --now vibebase-wizard
  [plan] print banner: visit http://<IP>:${WIZARD_PORT}/?token=<one-time-token>
EOF
    return 0
  fi

  [ -f "$SRC_DIR/infra/bootstrap/wizard/wizard.py" ] || die "wizard source missing under $SRC_DIR"

  cat > /etc/systemd/system/vibebase-wizard.service <<EOF
[Unit]
Description=Vibe Base first-run setup wizard (transient; removed at lock-down)
After=network-online.target docker.service
Wants=network-online.target
[Service]
Environment=VIBE_HOME=$VIBE_HOME
Environment=WIZARD_PORT=$WIZARD_PORT
ExecStart=/usr/bin/python3 $SRC_DIR/infra/bootstrap/wizard/wizard.py
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vibebase-wizard.service

  # give it a moment, then verify it answers locally
  local ok=0 i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS -o /dev/null "http://127.0.0.1:${WIZARD_PORT}/healthz" 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" = 1 ] || warn "wizard did not answer on :${WIZARD_PORT} yet — check: journalctl -u vibebase-wizard"

  local public_ip
  # shellcheck source=/dev/null disable=SC2153
  public_ip="$(. "$STATE_DIR/facts.env" && echo "$PUBLIC_IP")"
  echo
  echo "  ============================================================="
  echo "   Vibe Base — server prepared."
  echo
  if [ -n "${SETUP_TOKEN:-}" ]; then
    echo "   Finish setup in your browser:"
    echo
    echo "     http://${public_ip}:${WIZARD_PORT}/?token=${SETUP_TOKEN}"
  else
    echo "   Wizard already initialized. Open:  http://${public_ip}:${WIZARD_PORT}/"
    echo "   (the setup token was printed when it was first minted;"
    echo "    rerun with --force-wizard to mint a new one)"
  fi
  echo
  echo "   The wizard walks you through: system review -> firewall review"
  echo "   -> admin account -> domain + DNS -> TLS -> full deploy -> lock-down."
  echo "   The port ${WIZARD_PORT} closes automatically when setup completes."
  echo "  ============================================================="
  echo
  stamp wizard
}

# =============================================================================
main() {
  if [ "$DRY_RUN" = 1 ]; then
    log "DRY RUN — printing the plan; nothing will be changed"
  fi
  [ "$DRY_RUN" = 1 ] || mkdir -p "$STATE_DIR"
  phase_preflight
  phase_sources
  phase_studio_src
  phase_docker
  phase_harden
  phase_networks
  phase_secrets
  phase_wizard
  log "done."
}
main
