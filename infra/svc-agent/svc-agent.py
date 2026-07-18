#!/usr/bin/env python3
"""Vibe Base service-control agent.

A deliberately tiny privileged surface: the ONLY thing it can do is
start/stop/status the whitelisted per-project Supabase aux containers.
It never execs arbitrary docker commands and never touches the DB
containers or anything else, so even a fully-compromised console can at
most bounce these 8 known containers.

Auth: HMAC-SHA256 over "<ts>.<method>.<path>.<body>" with CONSOLE_PROXY_HMAC_SECRET,
in the X-Console-Sig header; timestamp must be within 300s (replay guard).

Docker access: this agent NEVER touches /var/run/docker.sock. It talks to a
locked-down tecnativa/docker-socket-proxy (start/stop/restart + inspect only)
over tcp via DOCKER_HOST (default tcp://docker-socket-proxy:2375, honored
natively by the docker CLI). Runs as the `svc-agent` container on the
dedicated `svcctl` network (where the proxy lives) plus the `coolify` network
(where studio-console reaches it at http://svc-agent:8899). No published
ports; never public.
"""
import hashlib
import hmac
import re
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ["CONSOLE_PROXY_HMAC_SECRET"].encode()
# Never the raw socket: default every docker CLI call at the socket-proxy. An
# operator can point elsewhere explicitly, but absent config we fail closed to
# the proxy (if it's absent, docker calls just error — we never fall back to
# /var/run/docker.sock, which isn't mounted in this container anyway).
os.environ.setdefault("DOCKER_HOST", "tcp://docker-socket-proxy:2375")
# ref -> the exact containers the console may toggle. Nothing else is reachable.
# Toggleable containers: <ref>-<svc> for any regex-valid ref (seeds + provisioned
# projects), aux services only — never the *-db container. This is the security
# boundary: nothing outside this shape can be started/stopped.
CONTAINER_RE = re.compile(r"^([a-z][a-z0-9]{1,30})-(auth|rest|storage|realtime)$")

def is_allowed(name):
    return bool(CONTAINER_RE.match(name or ""))

def list_project_services():
    r = docker("ps", "-a", "--format", "{{.Names}}")
    out = {}
    if r.returncode == 0:
        for name in r.stdout.split():
            m = CONTAINER_RE.match(name)
            if m:
                out.setdefault(m.group(1), {})[name] = container_state(name)
    return out


def sign(ts, method, path, body):
    msg = f"{ts}.{method}.{path}.{body}".encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()


def docker(*args):
    # Fixed argv, never shell — args are only ever our own literals + whitelisted names.
    # Never raises: a missing CLI / timeout becomes a failed result so the HTTP
    # handler always answers instead of dropping the connection.
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(["docker", *args], 125, stdout="", stderr=str(e))


def container_state(name):
    r = docker("inspect", "-f", "{{.State.Status}}", name)
    return r.stdout.strip() if r.returncode == 0 else "absent"


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _verify(self, method, body):
        ts = self.headers.get("X-Console-Ts", "")
        sig = self.headers.get("X-Console-Sig", "")
        if not ts.isdigit() or abs(time.time() - int(ts)) > 300:
            return False
        expect = sign(ts, method, self.path, body)
        return hmac.compare_digest(expect, sig)

    def log_message(self, *a):
        pass  # quiet

    def do_GET(self):
        if not self._verify("GET", ""):
            return self._send(401, {"error": "bad signature"})
        if self.path == "/status":
            return self._send(200, {"services": list_project_services()})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode() if n else ""
        if not self._verify("POST", body):
            return self._send(401, {"error": "bad signature"})
        if self.path != "/control":
            return self._send(404, {"error": "not found"})
        try:
            req = json.loads(body or "{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        action = req.get("action")
        container = req.get("container")
        if not is_allowed(container):
            return self._send(403, {"error": "container not in whitelist"})
        if action not in ("start", "stop", "restart"):
            return self._send(400, {"error": "action must be start|stop|restart"})
        r = docker(action, container)
        ok = r.returncode == 0
        return self._send(200 if ok else 500, {
            "ok": ok, "container": container, "action": action,
            "state": container_state(container),
            "detail": (r.stderr or r.stdout).strip()[:300],
        })


if __name__ == "__main__":
    port = int(os.environ.get("SVC_AGENT_PORT", "8899"))
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
