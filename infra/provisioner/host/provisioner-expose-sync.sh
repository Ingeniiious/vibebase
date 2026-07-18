#!/bin/bash
# provisioner-expose-sync: reconcile host socat relays (dbexpose-<ref>.service)
# and ufw allows with /root/provisioner-expose.d/ (desired state written by the
# provisioner container). Docker-published ports BYPASS ufw (cutover/03 gotcha),
# so provisioner DBs publish on 127.0.0.1 only and public exposure happens here,
# on the host INPUT path, exactly like the seed projects.
#
# Template guard: refs ^[a-z][a-z0-9]{1,30}$, ports 5435-5999 only. Units it
# did not create (no 'provisioner-managed' marker) are never touched.
set -euo pipefail
DIR=/root/provisioner-expose.d
# PUBLIC_IP comes from /etc/default/vibebase (written by deploy-stack.sh).
# Fail-safe default: bind relays to loopback if it is missing.
BIND_IP=127.0.0.1
# shellcheck disable=SC1091
[ -f /etc/default/vibebase ] && . /etc/default/vibebase
BIND_IP="${PUBLIC_IP:-$BIND_IP}"
mkdir -p "$DIR"

declare -A WANT=()
shopt -s nullglob
for f in "$DIR"/*; do
  [ -f "$f" ] || continue
  ref="$(basename "$f")"
  [[ "$ref" =~ ^[a-z][a-z0-9]{1,30}$ ]] || continue
  port="$(tr -cd '0-9' < "$f")"
  [[ "$port" =~ ^[0-9]{4}$ ]] || continue
  [ "$port" -ge 5435 ] && [ "$port" -le 5999 ] || continue
  WANT[$ref]="$port"
done

changed=0
declare -a RESTART=()

for ref in "${!WANT[@]}"; do
  port="${WANT[$ref]}"
  unit="/etc/systemd/system/dbexpose-${ref}.service"
  body="[Unit]
Description=TLS-passthrough relay: public :${port} -> ${ref} DB (127.0.0.1:${port}) [provisioner-managed]
After=network-online.target docker.service
Wants=network-online.target
[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:${port},bind=${BIND_IP},fork,reuseaddr TCP:127.0.0.1:${port}
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
"
  if [ ! -f "$unit" ] || ! cmp -s <(printf '%s' "$body") "$unit"; then
    printf '%s' "$body" > "$unit"
    changed=1
    RESTART+=("dbexpose-${ref}.service")
  fi
  ufw allow "${port}/tcp" comment "provisioner-${ref}" >/dev/null 2>&1 || true
done

# Remove stale provisioner-managed units (ref no longer in the desired state).
for unit in /etc/systemd/system/dbexpose-*.service; do
  name="$(basename "$unit" .service)"
  ref="${name#dbexpose-}"
  if [ -z "${WANT[$ref]+x}" ]; then
    # only remove units we manage (marker in Description)
    grep -q 'provisioner-managed' "$unit" || continue
    port="$(grep -oE 'TCP-LISTEN:[0-9]+' "$unit" | head -1 | cut -d: -f2 || true)"
    systemctl disable --now "dbexpose-${ref}.service" >/dev/null 2>&1 || true
    rm -f "$unit"
    changed=1
    if [ -n "${port:-}" ] && [ "$port" -ge 5435 ] 2>/dev/null; then
      ufw --force delete allow "${port}/tcp" comment "provisioner-${ref}" >/dev/null 2>&1 \
        || ufw --force delete allow "${port}/tcp" >/dev/null 2>&1 || true
    fi
  fi
done

[ "$changed" = 1 ] && systemctl daemon-reload

for ref in "${!WANT[@]}"; do
  systemctl enable "dbexpose-${ref}.service" >/dev/null 2>&1 || true
  systemctl start "dbexpose-${ref}.service" >/dev/null 2>&1 || true
done
for u in "${RESTART[@]}"; do
  systemctl restart "$u" >/dev/null 2>&1 || true
done
exit 0
