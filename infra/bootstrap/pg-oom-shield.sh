#!/usr/bin/env bash
# pg-oom-shield.sh — keep the kernel OOM killer away from project databases.
# Sets oom_score_adj=-800 on every postgres process belonging to a *-db or
# console-meta-db container. A 5-min systemd timer re-applies it because
# container restarts reset the adjustment.
set -euo pipefail

command -v docker >/dev/null 2>&1 || exit 0

docker ps --format '{{.Names}}' 2>/dev/null |
  grep -E -- '(-db$|^console-meta-db$)' |
  while read -r c; do
    pid="$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null || echo 0)"
    [ "$pid" -gt 0 ] || continue
    # the container's main pid plus all its descendants that are postgres
    for p in $pid $(pgrep -P "$pid" 2>/dev/null || true); do
      comm="$(cat "/proc/$p/comm" 2>/dev/null || true)"
      case "$comm" in
        postgres*) echo -800 > "/proc/$p/oom_score_adj" 2>/dev/null || true ;;
      esac
    done
    # postgres forks workers from the postmaster; catch the whole cgroup
    cg="/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' "$c" 2>/dev/null).scope/cgroup.procs"
    if [ -r "$cg" ]; then
      while read -r p; do
        comm="$(cat "/proc/$p/comm" 2>/dev/null || true)"
        case "$comm" in
          postgres*) echo -800 > "/proc/$p/oom_score_adj" 2>/dev/null || true ;;
        esac
      done < "$cg"
    fi
  done
exit 0
