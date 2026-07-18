#!/usr/bin/env bash
# gen-base-secrets.sh — generate the box-level base secrets for Vibe Base
# (install phase e). Contract:
# idempotent + ADDITIVE — existing values are never changed, only missing keys
# are appended, and secret values are never printed.
#
# Writes (0600):
#   /root/console.env        — shared control-plane secrets
#   /root/postgres-meta.env  — CRYPTO_KEY + PG_META_CRYPTO_KEY (SAME value;
#                              pg-meta reads CRYPTO_KEY, the studio reads
#                              PG_META_CRYPTO_KEY — pg-meta only honors CRYPTO_KEY)
#
# Usage: gen-base-secrets.sh [--dry-run]
set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

CONSOLE_ENV=/root/console.env
PGMETA_ENV=/root/postgres-meta.env

rand_hex() { # rand_hex <bytes>
  od -vN "$1" -An -tx1 /dev/urandom | tr -d ' \n'
}

# get_kv <file> <key> -> prints existing value or nothing
get_kv() {
  [ -f "$1" ] || return 0
  awk -F= -v k="$2" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$1"
}

# ensure_kv <file> <key> <value-if-missing>; appends only. Never echoes values.
ensure_kv() {
  local file="$1" key="$2" val="$3"
  if [ -n "$(get_kv "$file" "$key")" ]; then
    return 0
  fi
  if [ "$DRY_RUN" = 1 ]; then
    echo "would add: $key -> $file"
    return 0
  fi
  if [ ! -f "$file" ]; then
    (umask 177 && : > "$file")
  fi
  printf '%s=%s\n' "$key" "$val" >> "$file"
  chmod 600 "$file"
  echo "added: $key -> $file"
}

# --- /root/console.env ------------------------------------------------------
ensure_kv "$CONSOLE_ENV" BETTER_AUTH_SECRET "$(rand_hex 32)"
ensure_kv "$CONSOLE_ENV" CONSOLE_PROXY_HMAC_SECRET "$(rand_hex 32)"
# One crypto key, two names (gotcha: pg-meta only honors CRYPTO_KEY).
CRYPTO="$(get_kv "$CONSOLE_ENV" CRYPTO_KEY)"
if [ -z "$CRYPTO" ]; then
  CRYPTO="$(rand_hex 32)"
fi
ensure_kv "$CONSOLE_ENV" CRYPTO_KEY "$CRYPTO"
ensure_kv "$CONSOLE_ENV" PG_META_CRYPTO_KEY "$(get_kv "$CONSOLE_ENV" CRYPTO_KEY)"
ensure_kv "$CONSOLE_ENV" CONSOLE_MON_PASSWORD "$(rand_hex 24)"
ensure_kv "$CONSOLE_ENV" CONSOLE_META_POSTGRES_PASSWORD "$(rand_hex 24)"
ensure_kv "$CONSOLE_ENV" CONSOLE_META_PG_PASSWORD "$(rand_hex 24)"

# --- /root/postgres-meta.env (mirrors the crypto key) ------------------------
ensure_kv "$PGMETA_ENV" CRYPTO_KEY "$(get_kv "$CONSOLE_ENV" CRYPTO_KEY)"
ensure_kv "$PGMETA_ENV" PG_META_CRYPTO_KEY "$(get_kv "$CONSOLE_ENV" CRYPTO_KEY)"

# Consistency check: the two files must agree on the crypto key.
if [ "$DRY_RUN" = 0 ]; then
  if [ "$(get_kv "$CONSOLE_ENV" CRYPTO_KEY)" != "$(get_kv "$PGMETA_ENV" CRYPTO_KEY)" ] ||
     [ "$(get_kv "$CONSOLE_ENV" CRYPTO_KEY)" != "$(get_kv "$CONSOLE_ENV" PG_META_CRYPTO_KEY)" ]; then
    echo "ERROR: CRYPTO_KEY / PG_META_CRYPTO_KEY mismatch between $CONSOLE_ENV and $PGMETA_ENV" >&2
    echo "       (they must hold the same value — pg-meta only honors CRYPTO_KEY). Fix manually." >&2
    exit 1
  fi
fi

echo "base secrets OK ($CONSOLE_ENV, $PGMETA_ENV)"
