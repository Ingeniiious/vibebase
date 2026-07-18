# Security model

## Install-time

- **Nothing pre-existing is closed.** Before enabling the default-deny
  firewall, the installer snapshots every listening port and auto-allows it;
  you decide keep/close per port in the wizard. SSH (22) is always kept.
- **The wizard is token-gated and transient.** Access requires the one-time
  token from the install banner; only its SHA-256 touches disk; 10 bad
  attempts kill the process. At lock-down the wizard's port is closed, the
  token is invalidated, and the unit is deleted.
- **Secrets are generated on the box**, written `0600` under `/root`, never
  printed, never transmitted. The admin password is stored only as a
  Better Auth-compatible scrypt hash.

## Runtime

- **No raw Docker socket in any container.** The provisioner and svc-agent
  reach Docker only through dedicated `tecnativa/docker-socket-proxy`
  instances on internal-only networks:
  - svc-agent proxy: containers + start/stop/restart, nothing else.
  - provisioner proxy: containers + volumes only; `IMAGES=0`, `NETWORKS=0`
    (every image it launches is pre-pulled/built on the host at deploy time),
    no exec, no build.
- **Template-enforced provisioning.** The provisioner derives every container
  name, image, and argv from a regex-validated project ref and fixed
  templates; request bodies cannot inject containers, images, or flags.
- **HMAC-signed control plane.** The console signs every request to the
  provisioner and svc-agent with a shared secret; unsigned requests are
  rejected.
- **Firewall-honest exposure.** Docker-published ports bypass ufw, so
  project databases publish on `127.0.0.1` only; public exposure is a
  host-side socat relay plus an explicit ufw allow, both managed by a
  reconciler that touches only units it created.
- **Traefik hardened**: no docker provider (a compromised container cannot
  self-register a route), no dashboard/API, ACME storage `0600`.
- **Database TLS**: per-project Postgres runs TLS with SCRAM auth and
  `hostssl`-only pg_hba; connections use `sslmode=require`.
- **Console auth**: single admin account, sign-up disabled, TOTP two-factor
  enforced at first login, per-project IP allowlists and CORS origins
  configurable in Settings.
- **OOM resilience**: earlyoom plus a timer that keeps the kernel OOM killer
  away from Postgres processes (`oom_score_adj=-800`).

## Reporting

Please report vulnerabilities via a private security advisory on the
repository, not a public issue.
