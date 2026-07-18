# Vibe Base — Supabase's open-source studio, forked and improved for multi-project self-hosting

**Everything Supabase self-hosting is, improved: a fork of [Supabase's open-source studio](https://github.com/supabase/supabase) (Apache-2.0) turned into a multi-project database dashboard and Postgres platform you install on a fresh Ubuntu server with one command.** Where stock self-hosted Supabase runs one project per deployment, this fork adds self-service project creation, an admin login with enforced two-factor, a hardened installer, and per-project resource caps — create isolated Postgres projects from one web console, each with its own database, Auth, REST API, Storage, and Realtime, on hardware you control. Open source, self-hosted, no vendor lock-in.

Vibe Base is an independent, community-run fork. It is **not affiliated with, endorsed by, or sponsored by Supabase Inc.**, and it is not the hosted Supabase product — see [Attribution](#attribution--trademarks).

> **Status: v0 beta.** The stack — dashboard, Postgres, per-project Auth/REST/Storage/Realtime, provisioning — is production-tested. The one-command *fresh-server install flow* has not yet been verified end-to-end on a clean VM, so expect rough edges on your first install. Issues and PRs welcome.

## One-command install

On a fresh Ubuntu 22.04 / 24.04 server, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Ingeniiious/vibebase/main/install.sh | sudo bash
```

The installer prints a one-time URL. Open it in your browser and a first-run wizard walks you through the rest — about 20 minutes end to end, most of it a hands-off build. When it finishes, the wizard removes itself and closes its port.

Prefer to read before you run? `git clone` this repo and run `sudo ./install.sh --dry-run` — it prints everything the installer would do without changing anything.

## What you get

- **Multi-project dashboard** — a console at `https://console.<your-domain>` where you create and delete database projects on demand. Table editor, SQL editor, database advisors (security + performance lints), extensions, roles, backups view — the full studio experience, self-hosted.
- **A full stack per project** — each project gets its own Postgres 17 database (with pgvector and a rich extension set), plus optional Auth (GoTrue or a Neon-Auth-compatible service), REST (PostgREST), Storage, and Realtime — or just plain Postgres if that's all you need.
- **Real connection strings** — every project database is reachable directly at `<project>.<your-domain>:<port>` with TLS and SCRAM auth. Point any Postgres client or ORM at it.
- **Automatic HTTPS** — Let's Encrypt via Traefik: zero-config HTTP-01 per host, or a wildcard certificate via Cloudflare DNS-01 if you provide a scoped API token.
- **A hardened box by default** — default-deny firewall, fail2ban, unattended upgrades, OOM protection for your databases, and locked-down Docker socket proxies for every control-plane service. See [Security model](#security-model).
- **Honest capacity planning** — the installer measures your CPU (including shared-vCPU/steal detection), RAM, and disk, then tells you roughly how many projects the box can hold and recommends a swap size — with the assumptions shown, not magic numbers.

## What the installer does

1. **Preflight + spec scan** — checks OS, resources, and that the box isn't already hosting a console deployment; measures CPU/RAM/disk and prints a capacity estimate.
2. **Hardening** — snapshots every port that is already listening, then enables a default-deny firewall *without closing any of them* (you review keep/close per port in the wizard). Installs fail2ban, unattended-upgrades, and OOM shields.
3. **Docker + networks** — installs Docker and creates the app network plus two internal-only control networks.
4. **Secrets** — generates all control-plane secrets locally, `0600` under `/root`. Nothing is printed or sent anywhere.
5. **First-run wizard** — a transient, token-gated web wizard (Python stdlib only, removed at the end) that walks you through:
   system review → swap choice → firewall review → **admin account** (email + password; only a scrypt hash is stored; TOTP two-factor enrolls at first login) → base domain → DNS verification (checked via two independent DNS-over-HTTPS resolvers) → TLS → full stack deploy → lock-down.
6. **Lock-down** — the wizard closes its own port, invalidates the setup token, and removes itself. Final surface: SSH, HTTPS, and the per-project database ports you create.

Everything is idempotent and resumable: re-running `install.sh` is always safe, a crashed step retries just itself, and the wizard survives refreshes and reboots.

## Requirements

- A fresh **Ubuntu 22.04 or 24.04** server (bare metal or VM) with root access
- **≥ 2 vCPU** and **≥ 8 GiB RAM** recommended (3 GiB minimum — capacity scales with RAM; ~0.7 GiB per plain-Postgres project, ~1.4 GiB per full-stack project)
- **≥ 30 GB free disk**
- A **domain or subdomain** you control (e.g. `db.example.com`), ideally with a wildcard A record — the wizard shows you the exact records to create

## Security model

- The setup wizard is protected by a one-time token (only its SHA-256 touches disk) and disappears entirely after setup.
- The firewall is default-deny from the start; ports already in use on the box are never closed without your explicit per-port decision.
- No service gets the raw Docker socket: the provisioner and service-control agents talk to Docker only through [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) instances on internal-only networks, with images/networks/exec disabled and every create template-enforced.
- Project databases are never published straight through Docker (which would bypass the firewall); exposure goes through host-managed relays with per-port firewall rules.
- Traefik runs with no Docker provider and no dashboard — routes come only from files the platform writes.
- Admin passwords are stored as scrypt hashes; the admin account enrolls TOTP two-factor at first login; sign-up is disabled.
- All secrets live in `0600` files under `/root` on your server. Back them up; they never leave the box.

Found a vulnerability? Please open a private security advisory rather than a public issue.

## FAQ

**How does this relate to Supabase?** It's a fork of Supabase's open-source studio — the same self-hosted Supabase foundation, improved: multi-project provisioning from the dashboard, a one-command hardened install, enforced admin 2FA, per-project resource caps and network rules. It is an independent project, not affiliated with Supabase Inc.

**Is this a hosted service?** No. You rent a server, you run one command, you own everything: the data, the domain, the keys.

**Can it coexist with things already on the server?** It's designed for a dedicated fresh box, but it snapshots existing listeners and won't close their ports without asking. It refuses to run on a box that already hosts a console deployment it didn't install.

**What about backups?** Project data lives in Docker volumes under standard Postgres data directories; use your favorite Postgres backup tooling (`pg_dump`, WAL archiving, volume snapshots). A built-in backup story is on the roadmap.

**Why Ubuntu only?** The installer drives `apt`, `ufw`, and `systemd` directly. Debian likely works but is untested.

## Attribution & trademarks

- The dashboard is a fork of **Supabase Studio**, © Supabase Inc., licensed under the [Apache License 2.0](https://github.com/supabase/supabase/blob/master/LICENSE). This project also deploys other open-source Supabase components (GoTrue, Storage, Realtime) and [PostgREST](https://postgrest.org).
- **"Supabase" is a trademark of Supabase Inc.** This project is an independent, community-run work; the name is used only to describe compatibility and origin ("built with Supabase's open-source studio"), not as this project's identity, and the Apache-2.0 license grants no trademark rights.
- Vibe Base is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution details.
