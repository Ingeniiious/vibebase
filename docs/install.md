# Installing

## The one-liner

On a fresh Ubuntu 22.04/24.04 server, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Ingeniiious/vibebase/main/install.sh | sudo bash
```

Or from a checkout (lets you read everything first):

```bash
git clone https://github.com/Ingeniiious/vibebase.git && cd vibebase
sudo ./install.sh --dry-run   # print the full plan, change nothing
sudo ./install.sh
```

The installer ends by printing a one-time URL
(`http://<server-ip>:8642/?token=...`). Open it to finish setup in the
browser. The token is shown once; re-mint with
`sudo ./install.sh --force-wizard` if you lose it.

## Install phases

| Phase | What it does |
| --- | --- |
| a `preflight` | root/OS/resource checks, refuses boxes already hosting a console stack, spec scan + capacity estimate |
| b `sources` | syncs this repo to `/opt/vibebase/src` (checkout) or clones it (curl mode) |
| c `docker` | Docker Engine + compose plugin (get.docker.com), `live-restore` |
| d `harden` | port snapshot, ufw default-deny (pre-existing listeners auto-kept), fail2ban, unattended-upgrades, earlyoom, pg-oom-shield timer |
| e `networks` | docker networks: `coolify` (app), `svcctl` + `provctl` (internal-only) |
| f `secrets` | generates control-plane secrets to `/root/*.env` (0600) + the wizard token |
| g `wizard` | installs + starts the token-gated setup wizard, prints the banner URL |

Each phase stamps itself under `/opt/vibebase/state/` and re-checks
reality before skipping, so re-running `install.sh` at any point is safe.

## Wizard steps

System review (swap choice) → firewall review (keep/close per pre-existing
port) → admin account (email + password ≥ 12 chars; scrypt-hashed; TOTP
enrolls at first login) → base domain → DNS verification (both records must
resolve via Google + Cloudflare DoH) → TLS (HTTP-01 default, or Cloudflare
DNS-01 wildcard) → stack deploy (the studio image build takes 10–16 minutes)
→ lock-down (wizard port closes, wizard removes itself).

## Port lifecycle

| When | Publicly open |
| --- | --- |
| after `install.sh` | pre-existing ports (kept) + 22 + 8642 (wizard) |
| after the TLS step | + 80, 443 |
| after lock-down | 22, 80, 443 + your confirmed keeps |
| per project created | + one port in 5435–5999 (its Postgres endpoint) |

## After setup

- Console: `https://console.<your-base-domain>` — sign in with the admin
  account; first login enrolls TOTP.
- Create a project at `/new`; each project gets `<ref>.<base>` (database
  host) and `<ref>-api.<base>` (Auth/REST/Storage/Realtime).
- **Back up `/root/*.env`** — they hold every control-plane secret.
- Re-running `install.sh` after setup is a no-op that prints your console
  URL; `--force-wizard` re-opens the wizard for recovery.
