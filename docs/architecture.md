# Architecture

End state of an installed box:

```
internet
  ├── :22  sshd (+ fail2ban)
  ├── :80  traefik — ACME HTTP-01 + redirect→https
  ├── :443 traefik — file provider only (no docker provider, no dashboard)
  │        ├── console.<base>    → studio-console:3000  (the dashboard)
  │        └── <ref>-api.<base>  → key-proxy → <ref>-{auth,rest,storage}; realtime direct
  └── :5435-5999 per-project socat relays (host units, ufw-allowed per port)
                 → 127.0.0.1:<port> → <ref>-db (TLS + SCRAM, hostssl-only)

docker networks
  coolify  (app):      traefik, studio-console, postgres-meta, console-meta-db,
                       key-proxy, svc-agent, provisioner, per-project stacks
  svcctl   (internal): svc-agent ↔ docker-socket-proxy   (start/stop/restart only)
  provctl  (internal): provisioner ↔ provisioner-proxy   (containers+volumes only;
                       IMAGES=0, NETWORKS=0 — images are pre-pulled on the host)

host (root): provisioner-expose-sync (.path watcher → socat units + ufw),
             pg-oom-shield.timer, earlyoom, unattended-upgrades, swap
```

Components:

- **studio-console** — the forked Supabase Studio dashboard (`studio-fork/`),
  admin login via Better Auth (scrypt + enforced TOTP), multi-project.
- **console-meta-db** — pgvector Postgres holding `console_meta`: admin
  users/sessions, the project registry, and encrypted project secrets. No
  published ports.
- **postgres-meta** — schema/table introspection API used by the dashboard.
  Gotcha honored everywhere: it reads `CRYPTO_KEY` (the studio reads
  `PG_META_CRYPTO_KEY`) — both are set to the same value.
- **provisioner** — template-enforced project create/delete. Only reachable
  via HMAC-signed requests from the console; talks to Docker only through its
  own locked-down socket proxy. Container names, images, and argv come from
  fixed templates — arbitrary containers cannot be created.
- **svc-agent** — start/stop/restart of per-project service containers,
  HMAC-signed, through a second socket proxy that allows nothing else.
- **key-proxy** — translates project API keys (`sb_publishable_…` /
  `sb_secret_…`) into role JWTs for the per-project Auth/REST/Storage
  services.
- **provisioner-expose-sync** — host-side reconciler that turns the
  provisioner's desired-state files into socat relay units + ufw allows.
  Docker-published ports bypass ufw, so DBs bind loopback and exposure
  happens only here.

Why the docker network is named `coolify` and Traefik's dynamic dir is
`/data/coolify/proxy/dynamic`: the platform originated on a Coolify-managed
host, and keeping the canonical names means a Coolify proxy can replace the
bundled Traefik (or vice versa) without touching any route template. Coolify
itself is not installed or required.
