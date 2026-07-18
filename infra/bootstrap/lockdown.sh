#!/usr/bin/env bash
# lockdown.sh — final wizard step: close the transient
# wizard port and remove the wizard itself. Run detached by the wizard via
# `systemd-run --on-active=10` so the done-page renders before the port dies.
#
# End state: ufw = default-deny + 22 + 80 + 443 + user-confirmed keeps
# (+ per-project DB ports managed by provisioner-expose-sync).
set -euo pipefail

VIBE_HOME="${VIBE_HOME:-/opt/vibebase}"
STATE_DIR="$VIBE_HOME/state"
WIZARD_PORT="${WIZARD_PORT:-8642}"

# 1. close the wizard port
ufw --force delete allow "${WIZARD_PORT}/tcp" >/dev/null 2>&1 || true

# 2. invalidate the setup token (wizard is gone, but belt-and-braces)
rm -f "$STATE_DIR/wizard-token.sha256"

# 3. stop + remove the wizard unit
systemctl disable --now vibebase-wizard.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/vibebase-wizard.service
systemctl daemon-reload

# 4. leave a breadcrumb for operators
DOMAIN="$(python3 -c 'import json;print(json.load(open("'"$STATE_DIR"'/wizard.json")).get("domain",""))' 2>/dev/null || true)"
{
  echo "Vibe Base — setup completed $(date -u +%FT%TZ)"
  echo "Console: https://console.${DOMAIN:-<domain>}"
  echo "Secrets: /root/*.env (0600) — BACK THESE UP off-box."
} > /etc/motd.d/50-vibebase 2>/dev/null || {
  mkdir -p /etc/update-motd.d
  {
    echo '#!/bin/sh'
    echo "echo 'Vibe Base: https://console.${DOMAIN:-<domain>} (secrets in /root/*.env — back them up)'"
  } > /etc/update-motd.d/50-vibebase
  chmod +x /etc/update-motd.d/50-vibebase
}

echo "lockdown complete: wizard port ${WIZARD_PORT} closed, wizard removed."
