#!/usr/bin/env python3
"""Vibe Base first-run setup wizard.

A transient, self-contained web app — Python stdlib only (http.server, urllib,
ssl, hashlib) — that runs as a root systemd unit (`vibebase-wizard.service`) on
WIZARD_PORT until setup completes, then removes itself (lockdown.sh).

Why a host process and not a container: steps must drive ufw, systemd, swap,
docker builds and /root secrets; a container doing that needs the raw docker
socket plus host mounts — a strictly bigger attack surface than a transient
root process that is deleted at lock-down.

Security:
- Access requires the one-time setup token from the install banner
  (?token=…). Only its SHA-256 is on disk. 10 bad attempts => process exits.
- State (/opt/vibebase/state/wizard.json, 0600) never stores the admin
  password — only a Better Auth-compatible scrypt hash.
- Secrets are never logged and never rendered back into HTML.

Resumable: every step records its completion in state; refreshes, restarts
and re-runs continue from the first incomplete step.
"""

import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from hashlib import scrypt, sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VIBE_HOME = os.environ.get("VIBE_HOME", "/opt/vibebase")
STATE_DIR = f"{VIBE_HOME}/state"
STATE_PATH = f"{STATE_DIR}/wizard.json"
TOKEN_HASH_PATH = f"{STATE_DIR}/wizard-token.sha256"
SRC = f"{VIBE_HOME}/src"
BOOT = f"{SRC}/infra/bootstrap"
PORT = int(os.environ.get("WIZARD_PORT", "8642"))

STEPS = ["system", "firewall", "admin", "domain", "dns", "tls", "deploy", "done"]
STEP_TITLES = {
    "system": "System review",
    "firewall": "Firewall review",
    "admin": "Admin account",
    "domain": "Base domain",
    "dns": "DNS verification",
    "tls": "TLS certificates",
    "deploy": "Deploy the stack",
    "done": "Lock down & finish",
}

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

_bad_attempts = 0


# ----------------------------------------------------------------- state ----

def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"done": {}}


def save_state(st):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(st, f, indent=1)
    os.replace(tmp, STATE_PATH)


def load_specs():
    try:
        with open(f"{STATE_DIR}/specs.json") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def load_ports_baseline():
    try:
        with open(f"{STATE_DIR}/ports-baseline.json") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def current_step(st):
    for s in STEPS:
        if not st.get("done", {}).get(s):
            return s
    return "done"


# ------------------------------------------------------------------ shell ---

def sh(args, timeout=120, input_=None, check=False):
    """Fixed argv, never shell. Returns CompletedProcess; never raises OSErr."""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, input=input_)
    except (OSError, subprocess.SubprocessError) as e:
        r = subprocess.CompletedProcess(args, 125, stdout="", stderr=str(e))
    if check and r.returncode != 0:
        raise RuntimeError(f"{args[0]} failed: {r.stderr.strip()[:300]}")
    return r


# -------------------------------------------------------- better-auth hash --

def better_auth_hash(password: str) -> str:
    """Better Auth credential hash: scrypt N=16384 r=16 p=1 dkLen=64 over the
    NFKC-normalized password, salt = 16 random bytes hex-encoded (the hex
    STRING is the salt input), stored as "<salt>:<key-hex>".
    VERIFY-VM: confirm a seeded login on a throwaway box before trusting."""
    import unicodedata
    salt = secrets.token_hex(16)
    key = scrypt(unicodedata.normalize("NFKC", password).encode(),
                 salt=salt.encode(), n=16384, r=16, p=1, dklen=64,
                 maxmem=64 * 1024 * 1024)
    return f"{salt}:{key.hex()}"


# ------------------------------------------------------------------- DoH ----

def doh_a_records(name):
    """Resolve A records via two independent public DoH resolvers.
    Returns {resolver: [ips] | error-string}."""
    out = {}
    urls = {
        "google": (f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type=A", {}),
        "cloudflare": (f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type=A",
                       {"Accept": "application/dns-json"}),
    }
    for resolver, (url, hdrs) in urls.items():
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.load(resp)
            out[resolver] = [a["data"] for a in data.get("Answer", [])
                             if a.get("type") == 1]
        except Exception as e:  # noqa: BLE001 — report, don't crash
            out[resolver] = f"error: {type(e).__name__}"
    return out


def check_dns(base, ip):
    """Verify console.<base> and a random wildcard label resolve to ip on both
    resolvers. Returns (ok, rows) where rows drive the results table."""
    rows = []
    ok = True
    names = [f"console.{base}", f"_vibe-{secrets.token_hex(4)}.{base}"]
    for name in names:
        res = doh_a_records(name)
        for resolver, ips in res.items():
            good = isinstance(ips, list) and ips == [ip] or (
                isinstance(ips, list) and ip in ips and len(set(ips)) == 1)
            ok = ok and bool(good)
            shown = ", ".join(ips) if isinstance(ips, list) and ips else (
                ips if isinstance(ips, str) else "no A record")
            rows.append({"name": name, "resolver": resolver,
                         "result": shown, "ok": bool(good)})
    return ok, rows


# ------------------------------------------------------------------- TLS ----

def write_traefik_config(st):
    base = st["domain"]
    tls = st["tls"]
    os.makedirs("/data/coolify/proxy/dynamic", exist_ok=True)
    with open(f"{BOOT}/traefik/traefik.yaml.tmpl") as f:
        tmpl = f.read()
    if tls["mode"] == "dns01":
        challenge = ("      dnsChallenge:\n"
                     "        provider: cloudflare\n"
                     "        delayBeforeCheck: 15\n")
    else:
        challenge = ("      httpChallenge:\n"
                     "        entryPoint: http\n")
    out = tmpl.replace("{acme_email}", tls["email"]).replace("{challenge_block}", challenge)
    with open("/data/coolify/proxy/traefik.yaml", "w") as f:
        f.write(out)
    shutil.copy(f"{BOOT}/traefik/00-base.yaml", "/data/coolify/proxy/dynamic/00-base.yaml")
    # console route now (even before studio runs): Traefik starts ACME for the
    # host as soon as the router exists; a 502 backend doesn't block issuance.
    with open(f"{BOOT}/traefik/console.yaml.tmpl") as f:
        ctmpl = f.read()
    domains = ""
    if tls["mode"] == "dns01":
        domains = (f"        domains:\n"
                   f"          - main: \"{base}\"\n"
                   f"            sans: [\"*.{base}\"]\n")
    with open("/data/coolify/proxy/dynamic/console.yaml", "w") as f:
        f.write(ctmpl.replace("{base_domain}", base).replace("{domains_block}", domains))
    # traefik.env: only ever contains the CF token; 0600.
    fd = os.open("/root/traefik.env", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        if tls["mode"] == "dns01" and tls.get("cf_token"):
            f.write(f"CF_DNS_API_TOKEN={tls['cf_token']}\n")
    # acme storage must pre-exist 0600
    if not os.path.exists("/data/coolify/proxy/acme.json"):
        fd = os.open("/data/coolify/proxy/acme.json", os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)


def run_traefik():
    sh(["ufw", "allow", "80/tcp"], check=False)
    sh(["ufw", "allow", "443/tcp"], check=False)
    sh(["docker", "rm", "-f", "coolify-proxy"])
    sh(["docker", "run", "-d", "--name", "coolify-proxy",
        "--restart", "unless-stopped", "--network", "coolify",
        "-p", "80:80", "-p", "443:443",
        "-v", "/data/coolify/proxy/traefik.yaml:/etc/traefik/traefik.yml:ro",
        "-v", "/data/coolify/proxy/dynamic:/data/coolify/proxy/dynamic:ro",
        "-v", "/data/coolify/proxy/acme.json:/acme.json",
        "--env-file", "/root/traefik.env",
        "traefik:v3.1"], timeout=300, check=True)


def cert_issued(base):
    """True when https://console.<base> serves a cert whose issuer is not
    Traefik's self-signed default (i.e. ACME succeeded)."""
    import socket
    import ssl
    host = f"console.{base}"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        # stdlib can't parse DER without verification; re-handshake verifying
        # against the system store — if it verifies AND matches the hostname,
        # a real CA (LE) issued it.
        ctx2 = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx2.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        return True, issuer.get("organizationName", "trusted CA")
    except ssl.SSLError as e:
        return False, f"not issued yet ({getattr(e, 'reason', 'TLS error')})"
    except OSError as e:
        return False, f"unreachable ({e})"


def traefik_acme_errors():
    r = sh(["docker", "logs", "--tail", "80", "coolify-proxy"])
    lines = [ln for ln in (r.stdout + r.stderr).splitlines()
             if "acme" in ln.lower() and ("error" in ln.lower() or "unable" in ln.lower())]
    return lines[-5:]


# ----------------------------------------------------------------- deploy ---

DEPLOY_UNIT = "vibebase-deploy"


def deploy_running():
    r = sh(["systemctl", "is-active", DEPLOY_UNIT])
    return r.stdout.strip() in ("active", "activating")


def deploy_finished_ok():
    return os.path.exists(f"{STATE_DIR}/deploy.verify.done")


def start_deploy(st):
    if deploy_running():
        return
    sh(["systemctl", "reset-failed", DEPLOY_UNIT])
    log = f"{STATE_DIR}/deploy.log"
    sh(["systemd-run", f"--unit={DEPLOY_UNIT}",
        "--property=Nice=5",
        f"--property=StandardOutput=append:{log}",
        f"--property=StandardError=append:{log}",
        "--setenv=VIBE_HOME=" + VIBE_HOME,
        "--setenv=DOMAIN_SUFFIX=" + st["domain"],
        "--setenv=PUBLIC_IP=" + st["public_ip"],
        "--setenv=TLS_MODE=" + st["tls"]["mode"],
        "/bin/bash", f"{BOOT}/deploy-stack.sh", "all"], check=True)


# ------------------------------------------------------------------- swap ---

def apply_swap(target_gib):
    """Create/extend /swapfile-vibebase to reach target_gib total swap. 0 = skip."""
    if target_gib <= 0:
        return "swap unchanged (you chose none)"
    existing_gib = 0
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("SwapTotal"):
                existing_gib = int(line.split()[1]) // (1024 * 1024)
    need = target_gib - existing_gib
    if need <= 0:
        return f"existing swap ({existing_gib} GiB) already >= target"
    path = "/swapfile-vibebase"
    if os.path.exists(path):
        sh(["swapoff", path])
        os.remove(path)
    r = sh(["fallocate", "-l", f"{need}G", path], timeout=120)
    if r.returncode != 0:  # fs without fallocate support
        sh(["dd", "if=/dev/zero", f"of={path}", "bs=1M", f"count={need * 1024}"],
           timeout=3600, check=True)
    os.chmod(path, 0o600)
    sh(["mkswap", path], check=True)
    sh(["swapon", path], check=True)
    with open("/etc/fstab") as f:
        fstab = f.read()
    if path not in fstab:
        with open("/etc/fstab", "a") as f:
            f.write(f"{path} none swap sw 0 0\n")
    sh(["sysctl", "-w", "vm.swappiness=10"])
    return f"added {need} GiB swap (total ~{target_gib} GiB), swappiness=10"


# ------------------------------------------------------------------- html ---

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Vibe Base setup</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
{refresh}
<style>
 body{{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
 .wrap{{max-width:860px;margin:0 auto;padding:24px}}
 h1{{font-size:20px}} h2{{font-size:17px;margin-top:0}}
 .card{{background:#181b22;border:1px solid #2a2f3a;border-radius:10px;padding:20px;margin:16px 0}}
 .steps{{display:flex;flex-wrap:wrap;gap:6px;font-size:12px}}
 .step{{padding:4px 10px;border-radius:20px;background:#232733;color:#9aa3b2}}
 .step.now{{background:#2f6feb;color:#fff}} .step.ok{{background:#1d3b2a;color:#7ee2a8}}
 table{{border-collapse:collapse;width:100%;font-size:14px}}
 td,th{{padding:6px 10px;border-bottom:1px solid #2a2f3a;text-align:left}}
 input[type=text],input[type=email],input[type=password],input[type=number]{{
   background:#0f1115;color:#e6e6e6;border:1px solid #2a2f3a;border-radius:6px;
   padding:8px;width:100%;max-width:420px;box-sizing:border-box}}
 button{{background:#2f6feb;color:#fff;border:0;border-radius:6px;padding:9px 18px;
   font-size:14px;cursor:pointer;margin-top:10px}}
 button.secondary{{background:#232733}}
 .ok{{color:#7ee2a8}} .bad{{color:#ff8f8f}} .warn{{color:#ffd479}}
 code,pre{{background:#0f1115;border:1px solid #2a2f3a;border-radius:6px;padding:2px 6px}}
 pre{{padding:12px;overflow-x:auto;font-size:12px;line-height:1.4}}
 .muted{{color:#9aa3b2;font-size:13px}}
 label{{display:block;margin-top:10px}}
</style></head><body><div class="wrap">
<h1>Vibe Base — first-run setup</h1>
<div class="steps">{stepbar}</div>
{body}
<p class="muted">State survives refreshes, restarts and reboots — you can
always come back. Wizard port closes automatically at the end.</p>
</div></body></html>"""


def stepbar(st):
    cur = current_step(st)
    out = []
    for s in STEPS:
        cls = "ok" if st.get("done", {}).get(s) else ("now" if s == cur else "")
        out.append(f'<span class="step {cls}">{html.escape(STEP_TITLES[s])}</span>')
    return "".join(out)


def page(st, body, refresh=0):
    r = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return PAGE.format(stepbar=stepbar(st), body=body, refresh=r)


def esc(v):
    return html.escape(str(v if v is not None else ""))


# ------------------------------------------------------------ step screens --

def screen_system(st, msg=""):
    sp = load_specs()
    steal = sp.get("steal_pct", 0)
    vcpu = sp.get("hypervisor") or "none detected (bare metal?)"
    steal_note = ' <span class="warn">— shared/oversold vCPU signal</span>' if steal and steal > 5 else ""
    rec = sp.get("swap_recommended_gib", 8)
    body = f"""
<div class="card"><h2>1 · System review</h2>
<table>
<tr><th>CPU</th><td>{esc(sp.get('cores'))} cores — {esc(sp.get('cpu_model'))}<br>
  <span class="muted">virtualization: {esc(vcpu)}; CPU steal {esc(steal)}%{steal_note}</span></td></tr>
<tr><th>RAM</th><td>{esc(sp.get('ram_gib'))} GiB (swap now: {esc(sp.get('swap_existing_gib'))} GiB)</td></tr>
<tr><th>Disk</th><td>{esc(sp.get('disk_total_gb'))} GB total, {esc(sp.get('disk_free_gb'))} GB free</td></tr>
</table></div>
<div class="card"><h2>Capacity estimate</h2>
<p><b>~{esc(sp.get('cap_plain'))}</b> plain-Postgres projects &nbsp;or&nbsp;
<b>~{esc(sp.get('cap_full'))}</b> full-stack projects (Auth+REST+Storage+Realtime).</p>
<p class="muted">Assumptions: plain project ≈ 0.7 GiB, full stack ≈ 1.4 GiB
(measured on the reference box), 3 GiB + 10% of RAM reserved for OS + console
+ control plane. Disk is rarely the limit early on; RAM is.</p></div>
<div class="card"><h2>Swap</h2>
<p class="muted">Recommended <b>{rec} GiB</b> = clamp(2×RAM, 8–64), capped at
30% of free disk (precedent: the 17 GiB reference box runs 44 GiB swap to
absorb build spikes). If you plan more projects than the estimate above,
choose more.</p>
{f'<p class="bad">{esc(msg)}</p>' if msg else ''}
<form method="post" action="/system">
<label>How many projects do you roughly plan to host? (optional)
<input type="number" name="planned" min="0" value="{esc(st.get('planned', ''))}"></label>
<label>Swap size in GiB (0 = none / keep current)
<input type="number" name="swap_gib" min="0" max="{esc(sp.get('swap_disk_cap_gib', 64))}" value="{rec}"></label>
<button>Apply &amp; continue</button></form></div>"""
    return body


def screen_firewall(st, msg=""):
    baseline = load_ports_baseline()
    rows = []
    for i, r in enumerate(baseline):
        port, proto, proc = r["port"], r["proto"], r.get("process") or "unknown"
        if port == 22 or port == PORT:
            continue
        rows.append(f"""<tr><td><code>{port}/{proto}</code></td><td>{esc(proc)}</td>
<td><label><input type="radio" name="p{i}" value="keep" checked> Keep</label>
<label><input type="radio" name="p{i}" value="close"> Close</label>
<input type="hidden" name="port{i}" value="{port}/{proto}"></td></tr>""")
    table = ("<table><tr><th>Port</th><th>Process</th><th>Decision (default: keep)</th></tr>"
             + "".join(rows) + "</table>") if rows else \
        "<p class='ok'>No pre-existing public listeners beyond SSH — nothing to review.</p>"
    body = f"""
<div class="card"><h2>2 · Firewall review — nothing gets closed without you</h2>
<p>These ports were already listening when the installer ran. This box may be
hosting other things — <b>keep</b> anything you're not sure about (fail-safe).
Assumed and not asked: <code>22</code> (SSH), <code>{PORT}</code> (this wizard,
closes automatically at the end). Required later: <code>80</code>/<code>443</code>
(TLS, opened at the TLS step).</p>
{f'<p class="bad">{esc(msg)}</p>' if msg else ''}
<form method="post" action="/firewall">{table}
<button>Apply decisions &amp; continue</button></form></div>"""
    return body


def screen_admin(st, msg=""):
    body = f"""
<div class="card"><h2>3 · Admin account</h2>
<p class="muted">This is the only account that can sign in to the console
(sign-up is disabled). First login will enroll two-factor (TOTP).</p>
{f'<p class="bad">{esc(msg)}</p>' if msg else ''}
<form method="post" action="/admin">
<label>Name <input type="text" name="name" value="{esc(st.get('admin', {}).get('name', ''))}"></label>
<label>Email <input type="email" name="email" required value="{esc(st.get('admin', {}).get('email', ''))}"></label>
<label>Password (min 12 chars) <input type="password" name="pw" required minlength="12"></label>
<label>Repeat password <input type="password" name="pw2" required minlength="12"></label>
<button>Save &amp; continue</button></form>
<p class="muted">Only a scrypt hash is stored; the password itself is never
written to disk or logs.</p></div>"""
    return body


def screen_domain(st, msg=""):
    ip = st.get("public_ip", "?")
    body = f"""
<div class="card"><h2>4 · Base domain</h2>
<p>Choose the base under which everything lives, e.g. <code>db.example.com</code>:
console at <code>console.&lt;base&gt;</code>, project APIs at
<code>&lt;ref&gt;-api.&lt;base&gt;</code>, database hosts at
<code>&lt;ref&gt;.&lt;base&gt;</code>.</p>
{f'<p class="bad">{esc(msg)}</p>' if msg else ''}
<form method="post" action="/domain">
<label>Base domain <input type="text" name="domain" required
 placeholder="db.example.com" value="{esc(st.get('domain', ''))}"></label>
<button>Save &amp; show DNS records</button></form></div>
<div class="card"><h2>DNS records you will create</h2>
<table><tr><th>Type</th><th>Name</th><th>Value</th></tr>
<tr><td>A</td><td><code>&lt;base&gt;</code></td><td><code>{esc(ip)}</code></td></tr>
<tr><td>A</td><td><code>*.&lt;base&gt;</code> (wildcard — recommended)</td><td><code>{esc(ip)}</code></td></tr>
</table>
<p class="muted">No wildcard? Then per-name: <code>console.&lt;base&gt;</code>
now, plus <code>&lt;ref&gt;.&lt;base&gt;</code> and
<code>&lt;ref&gt;-api.&lt;base&gt;</code> for every project you create later.
Cloudflare users: set records to <b>DNS only</b> (grey cloud) — raw Postgres
TCP cannot ride the Cloudflare proxy.</p></div>"""
    return body


def screen_dns(st, rows=None, msg=""):
    base, ip = st.get("domain", ""), st.get("public_ip", "")
    table = ""
    if rows:
        trs = "".join(
            f"<tr><td><code>{esc(r['name'])}</code></td><td>{esc(r['resolver'])}</td>"
            f"<td class=\"{'ok' if r['ok'] else 'bad'}\">{esc(r['result'])}"
            f"{' ✓' if r['ok'] else ' ✗'}</td></tr>" for r in rows)
        table = f"<table><tr><th>Name</th><th>Resolver</th><th>Answer</th></tr>{trs}</table>"
    body = f"""
<div class="card"><h2>5 · Verify DNS</h2>
<p>Create these records, then check:</p>
<table><tr><th>Type</th><th>Name</th><th>Value</th></tr>
<tr><td>A</td><td><code>{esc(base)}</code></td><td><code>{esc(ip)}</code></td></tr>
<tr><td>A</td><td><code>*.{esc(base)}</code></td><td><code>{esc(ip)}</code></td></tr></table>
<p class="muted">Checked against two independent public resolvers (Google +
Cloudflare DNS-over-HTTPS): <code>console.{esc(base)}</code> and a random
wildcard label. Propagation can take a few minutes.</p>
{f'<p class="bad">{esc(msg)}</p>' if msg else ''}
{table}
<form method="post" action="/dns"><button>Check now</button></form>
<form method="post" action="/back"><input type="hidden" name="to" value="domain">
<button class="secondary">Change domain</button></form></div>"""
    return body


def screen_tls(st, msg="", status=""):
    tls = st.get("tls", {})
    admin_email = st.get("admin", {}).get("email", "")
    body = f"""
<div class="card"><h2>6 · TLS certificates (Let's Encrypt)</h2>
{f'<p class="bad">{esc(msg)}</p>' if msg else ''}
{f'<p class="warn">{esc(status)}</p>' if status else ''}
<form method="post" action="/tls">
<label><input type="radio" name="mode" value="http01"
 {'checked' if tls.get('mode', 'http01') == 'http01' else ''}>
 <b>HTTP-01</b> (default) — zero credentials; per-host certs issued lazily as
 routes appear. Needs port 80 (opened now).</label>
<label><input type="radio" name="mode" value="dns01"
 {'checked' if tls.get('mode') == 'dns01' else ''}>
 <b>DNS-01 via Cloudflare</b> — one wildcard cert <code>*.{esc(st.get('domain', ''))}</code>
 covering all current and future subdomains. Needs a Cloudflare API token
 (Zone → DNS → Edit on this zone only).</label>
<label>Cloudflare API token (only for DNS-01)
<input type="password" name="cf_token" autocomplete="off"></label>
<label>ACME account email <input type="email" name="email" required
 value="{esc(tls.get('email') or admin_email)}"></label>
<button>Open 80/443, start Traefik &amp; request certificate</button></form>
<p class="muted">This opens ports 80 + 443 (ufw), writes the Traefik config,
starts the proxy, and waits for the certificate on
<code>console.{esc(st.get('domain', ''))}</code>. The token, if given, is
stored only in <code>/root/traefik.env</code> (0600).</p></div>"""
    if st.get("tls", {}).get("requested"):
        body += """<div class="card"><form method="post" action="/tls-check">
<button>Check certificate status</button></form></div>"""
    return body


def screen_deploy(st):
    log_tail = ""
    try:
        with open(f"{STATE_DIR}/deploy.log") as f:
            log_tail = "".join(f.readlines()[-40:])
    except OSError:
        pass
    running = deploy_running()
    finished = deploy_finished_ok()
    if finished:
        body = f"""<div class="card"><h2>7 · Deploy — <span class="ok">complete</span></h2>
<pre>{esc(log_tail)}</pre>
<form method="post" action="/deploy-ok"><button>Continue to lock-down</button></form></div>"""
        return body, 0
    if running:
        body = f"""<div class="card"><h2>7 · Deploying… (page refreshes itself)</h2>
<p class="muted">The studio image build takes 10–16 minutes and Next.js goes
silent during its optimize phase — a quiet log is NOT a hang.</p>
<pre>{esc(log_tail) or 'starting…'}</pre></div>"""
        return body, 5
    failed = os.path.exists(f"{STATE_DIR}/deploy.log") and log_tail
    body = f"""<div class="card"><h2>7 · Deploy the stack</h2>
<p>Deploys: console-meta DB → postgres-meta → key-proxy → service toggles
(svc-agent) → provisioner → studio build (~10–16 min) → studio → routes →
admin seed → health checks. Every substep is idempotent; retry re-runs only
what's missing.</p>
{f'<p class="bad">Previous run did not finish — check the log, then retry.</p><pre>{esc(log_tail)}</pre>' if failed else ''}
<form method="post" action="/deploy"><button>{'Retry deploy' if failed else 'Start deploy'}</button></form></div>"""
    return body, 0


def screen_done(st):
    base = st.get("domain", "")
    if st.get("locked"):
        return f"""<div class="card"><h2>8 · All done 🎉</h2>
<p>Your console: <a href="https://console.{esc(base)}">https://console.{esc(base)}</a></p>
<p>This wizard is shutting down and its port is closing. Bookmark the console.</p>
<ul class="muted"><li>Sign in as {esc(st.get('admin', {}).get('email', ''))} —
first login enrolls TOTP.</li>
<li>Create projects at <code>/new</code>; each gets its own DB + API subdomain.</li>
<li>Back up <code>/root/*.env</code> off-box — they hold every secret.</li></ul></div>"""
    return f"""<div class="card"><h2>8 · Lock down &amp; finish</h2>
<p>Final firewall: <code>22</code> (SSH), <code>80/443</code> (TLS){', plus the ports you chose to keep' if st.get('firewall', {}).get('kept') else ''}.
Project DB ports (5435–5999) open automatically per project.</p>
<p>This will close port <code>{PORT}</code> and remove the wizard itself.</p>
<form method="post" action="/lockdown"><button>Lock down now</button></form></div>"""


# ---------------------------------------------------------------- handlers --

def handle_post(path, form, st):
    """Returns (redirect_path | None, html | None, refresh)."""
    step = current_step(st)

    if path == "/back":
        to = form.get("to", [""])[0]
        if to in STEPS:
            for s in STEPS[STEPS.index(to):]:
                st["done"].pop(s, None)
            save_state(st)
        return "/", None, 0

    if path == "/system" and step == "system":
        try:
            swap = int(form.get("swap_gib", ["0"])[0] or 0)
        except ValueError:
            return None, page(st, screen_system(st, "swap size must be a number")), 0
        cap = load_specs().get("swap_disk_cap_gib", 64)
        if swap > cap:
            return None, page(st, screen_system(
                st, f"{swap} GiB exceeds the safe disk cap ({cap} GiB = 30% of free disk)")), 0
        planned = form.get("planned", [""])[0]
        if planned:
            st["planned"] = planned[:6]
        try:
            result = apply_swap(swap)
        except RuntimeError as e:
            return None, page(st, screen_system(st, f"swap setup failed: {e}")), 0
        st.setdefault("system", {})["swap_result"] = result
        st["done"]["system"] = True
        save_state(st)
        return "/", None, 0

    if path == "/firewall" and step == "firewall":
        decisions = {}
        closed = []
        kept = []
        for k, v in form.items():
            if k.startswith("port"):
                idx = k[4:]
                rule = v[0]
                choice = form.get(f"p{idx}", ["keep"])[0]
                decisions[rule] = choice
                if choice == "close":
                    sh(["ufw", "--force", "delete", "allow", rule])
                    closed.append(rule)
                else:
                    kept.append(rule)
        st["firewall"] = {"decisions": decisions, "closed": closed, "kept": kept}
        st["done"]["firewall"] = True
        save_state(st)
        return "/", None, 0

    if path == "/admin" and step == "admin":
        email = form.get("email", [""])[0].strip().lower()
        name = form.get("name", [""])[0].strip() or email
        pw, pw2 = form.get("pw", [""])[0], form.get("pw2", [""])[0]
        if "@" not in email or "." not in email.split("@")[-1]:
            return None, page(st, screen_admin(st, "enter a valid email")), 0
        if len(pw) < 12:
            return None, page(st, screen_admin(st, "password must be at least 12 characters")), 0
        if pw != pw2:
            return None, page(st, screen_admin(st, "passwords do not match")), 0
        st["admin"] = {"email": email, "name": name,
                       "password_hash": better_auth_hash(pw)}
        st["done"]["admin"] = True
        save_state(st)
        return "/", None, 0

    if path == "/domain" and step == "domain":
        dom = form.get("domain", [""])[0].strip().lower().rstrip(".")
        if not DOMAIN_RE.match(dom):
            return None, page(st, screen_domain(st, "that doesn't look like a valid domain")), 0
        try:
            ipaddress.ip_address(dom)
            return None, page(st, screen_domain(st, "enter a domain, not an IP")), 0
        except ValueError:
            pass
        st["domain"] = dom
        st["done"]["domain"] = True
        save_state(st)
        return "/", None, 0

    if path == "/dns" and step == "dns":
        ok, rows = check_dns(st["domain"], st["public_ip"])
        st["dns_last"] = {"ok": ok, "at": int(time.time())}
        if ok:
            st["done"]["dns"] = True
            save_state(st)
            return "/", None, 0
        save_state(st)
        return None, page(st, screen_dns(
            st, rows, "Not all records resolve to this server yet — fix/wait and retry.")), 0

    if path == "/tls" and step == "tls":
        mode = form.get("mode", ["http01"])[0]
        if mode not in ("http01", "dns01"):
            mode = "http01"
        email = form.get("email", [""])[0].strip()
        cf = form.get("cf_token", [""])[0].strip()
        if mode == "dns01" and not cf:
            return None, page(st, screen_tls(st, "DNS-01 needs a Cloudflare API token")), 0
        if "@" not in email:
            return None, page(st, screen_tls(st, "enter a valid ACME email")), 0
        st["tls"] = {"mode": mode, "email": email, "requested": True}
        if cf:
            st["tls"]["cf_token"] = cf  # state file is 0600; also in /root/traefik.env
        try:
            write_traefik_config(st)
            run_traefik()
        except RuntimeError as e:
            save_state(st)
            return None, page(st, screen_tls(st, str(e))), 0
        save_state(st)
        # first check after a short wait
        time.sleep(8)
        issued, detail = cert_issued(st["domain"])
        if issued:
            st["done"]["tls"] = True
            save_state(st)
            return "/", None, 0
        errs = "; ".join(traefik_acme_errors())
        return None, page(st, screen_tls(
            st, status=f"Certificate not issued yet: {detail}. "
                       f"{('Traefik: ' + errs) if errs else 'Issuance can take up to a minute — use the check button.'}")), 0

    if path == "/tls-check" and step == "tls":
        issued, detail = cert_issued(st["domain"])
        if issued:
            st["done"]["tls"] = True
            save_state(st)
            return "/", None, 0
        errs = "; ".join(traefik_acme_errors())
        return None, page(st, screen_tls(
            st, status=f"Still waiting: {detail}. {('Traefik: ' + errs) if errs else ''}")), 0

    if path == "/deploy" and step == "deploy":
        try:
            start_deploy(st)
        except RuntimeError as e:
            body, _ = screen_deploy(st)
            return None, page(st, f'<p class="bad">{esc(e)}</p>' + body), 0
        return "/", None, 0

    if path == "/deploy-ok" and step == "deploy":
        if deploy_finished_ok():
            st["done"]["deploy"] = True
            save_state(st)
        return "/", None, 0

    if path == "/lockdown" and step == "done" and not st.get("locked"):
        st["locked"] = True
        st["done"]["done"] = True
        save_state(st)
        # detached so this response can render before the port closes
        sh(["systemd-run", "--unit=vibebase-lockdown", "--on-active=10",
            f"--setenv=VIBE_HOME={VIBE_HOME}", f"--setenv=WIZARD_PORT={PORT}",
            "/bin/bash", f"{BOOT}/lockdown.sh"])
        return "/", None, 0

    return "/", None, 0  # stale form for a completed step: back to current


def render(st):
    step = current_step(st)
    if step == "system":
        return page(st, screen_system(st)), 200
    if step == "firewall":
        return page(st, screen_firewall(st)), 200
    if step == "admin":
        return page(st, screen_admin(st)), 200
    if step == "domain":
        return page(st, screen_domain(st)), 200
    if step == "dns":
        return page(st, screen_dns(st)), 200
    if step == "tls":
        return page(st, screen_tls(st)), 200
    if step == "deploy":
        body, refresh = screen_deploy(st)
        return page(st, body, refresh=refresh), 200
    return page(st, screen_done(st)), 200


# ------------------------------------------------------------------ server --

def token_ok(handler):
    """Setup-token gate: ?token=… or the session cookie must hash-match."""
    global _bad_attempts
    try:
        with open(TOKEN_HASH_PATH) as f:
            want = f.read().strip()
    except OSError:
        return False  # no token on disk => locked out (post-lockdown)
    q = urllib.parse.urlparse(handler.path).query
    supplied = urllib.parse.parse_qs(q).get("token", [""])[0]
    if not supplied:
        cookie = handler.headers.get("Cookie", "")
        m = re.search(r"vibebase_setup=([A-Za-z0-9]+)", cookie)
        supplied = m.group(1) if m else ""
    if supplied and secrets.compare_digest(sha256(supplied.encode()).hexdigest(), want):
        handler._grant = supplied
        return True
    if supplied:
        _bad_attempts += 1
        if _bad_attempts >= 10:
            # brute-force tripwire: die; systemd restarts us with attempts reset,
            # but the operator sees the crash loop in journalctl.
            os._exit(3)
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "vibebase-wizard/1"
    _grant = ""

    def log_message(self, fmt, *args):
        pass  # no request logging (URLs may carry the token)

    def _reply(self, code, body, extra_headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, to):
        self.send_response(303)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        if self._grant:
            self.send_header("Set-Cookie",
                             f"vibebase_setup={self._grant}; HttpOnly; SameSite=Strict; Path=/")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/healthz":
            return self._reply(200, "ok")
        if not token_ok(self):
            return self._reply(403, FORBIDDEN)
        st = load_state()
        if "public_ip" not in st:
            facts = {}
            try:
                with open(f"{STATE_DIR}/facts.env") as f:
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            facts[k] = v
            except OSError:
                pass
            st["public_ip"] = facts.get("PUBLIC_IP", "")
            save_state(st)
        body, code = render(st)
        hdrs = {}
        if self._grant:
            hdrs["Set-Cookie"] = f"vibebase_setup={self._grant}; HttpOnly; SameSite=Strict; Path=/"
        return self._reply(code, body, hdrs)

    def do_POST(self):
        if not token_ok(self):
            return self._reply(403, FORBIDDEN)
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode() if n else ""
        form = urllib.parse.parse_qs(raw, keep_blank_values=True)
        st = load_state()
        path = urllib.parse.urlparse(self.path).path
        redirect, body, _refresh = handle_post(path, form, st)
        if body is not None:
            return self._reply(200, body)
        return self._redirect(redirect or "/")


FORBIDDEN = """<!doctype html><html><body style="font-family:system-ui;
background:#0f1115;color:#e6e6e6;display:grid;place-items:center;height:100vh">
<div><h2>Setup token required</h2><p>Open the exact URL printed by the
installer (it contains <code>?token=…</code>), or re-run
<code>install.sh --force-wizard</code> on the server to mint a new one.</p>
</div></body></html>"""


if __name__ == "__main__":
    os.makedirs(STATE_DIR, exist_ok=True)
    print(f"vibebase-wizard listening on :{PORT} (state: {STATE_PATH})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
