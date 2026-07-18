#!/usr/bin/env python3
# key-proxy: translates Supabase new-format opaque API keys (sb_publishable_*,
# sb_secret_*) into this project's legacy anon/service_role JWTs, then forwards
# to the real service (PostgREST/GoTrue/storage). PostgREST only understands
# JWTs; in Supabase Cloud, Kong does this translation — self-hosted Traefik
# does not, hence this shim. stdlib only; runs on python:3.*-alpine unchanged.
#
# Routing contract (set by Traefik, per router):
#   X-Key-Proxy-Upstream: http://<ref>-rest:3000   (overwritten by Traefik's
#   headers middleware, so clients cannot spoof it; stripped before forwarding)
# Key maps (env):
#   KEY_PROXY_MAP = {"<public host>": "<REF>", ...}
#   <REF>_PUBLISHABLE_KEY -> <REF>_ANON_KEY      (anon role JWT)
#   <REF>_SECRET_KEY      -> <REF>_SERVICE_KEY   (service_role JWT)
#
# Pass-through guarantee: requests whose apikey/Authorization do NOT carry an
# sb_* key are forwarded with method, path, query, body and headers unmodified
# (minus hop-by-hop headers and X-Key-Proxy-Upstream). Unknown sb_* keys -> 401.
# Header lookup/replace is CASE-INSENSITIVE — Traefik canonicalises header names
# (apikey -> Apikey), so fixed-case matching would miss the sb_ key.
import hmac, json, os, sys
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOST_TO_REF = json.loads(os.environ["KEY_PROXY_MAP"])
# {host: [(sb_key, jwt), ...]}
KEYMAP = {}
for host, ref in HOST_TO_REF.items():
    pairs = []
    for sb_env, jwt_env in ((f"{ref}_PUBLISHABLE_KEY", f"{ref}_ANON_KEY"),
                            (f"{ref}_SECRET_KEY", f"{ref}_SERVICE_KEY")):
        sb, jwt = os.environ.get(sb_env, ""), os.environ.get(jwt_env, "")
        if sb and jwt:
            pairs.append((sb, jwt))
    KEYMAP[host.lower()] = pairs

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailer", "transfer-encoding", "upgrade", "x-key-proxy-upstream"}

def lookup(host, candidate):
    for sb, jwt in KEYMAP.get(host, ()):  # constant-time compare per entry
        if hmac.compare_digest(candidate.encode(), sb.encode()):
            return jwt
    return None

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "key-proxy/1"

    def log_message(self, fmt, *args):  # never log headers/keys
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _fail(self, code, msg):
        body = json.dumps({"message": msg}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _handle(self):
        if self.path == "/key-proxy-health":
            return self._fail(200, "ok")
        if "Upgrade" in self.headers:
            return self._fail(501, "websocket upgrade not supported by key-proxy")
        upstream = self.headers.get("X-Key-Proxy-Upstream", "")
        target = urlsplit(upstream)
        if target.scheme != "http" or not target.hostname:
            return self._fail(500, "key-proxy misrouted: missing upstream")

        host = (self.headers.get("Host") or "").split(":")[0].lower()
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        # Case-insensitive access/replace: Traefik title-cases header names.
        lc = {k.lower(): k for k in headers}

        def get_h(name):
            k = lc.get(name.lower())
            return headers.get(k, "") if k else ""

        def set_h(name, val):
            k = lc.get(name.lower())
            if k is None:
                k = name
                lc[name.lower()] = k
            headers[k] = val

        apikey = get_h("apikey")
        auth = get_h("authorization")
        bearer = auth[7:] if auth.lower().startswith("bearer ") else ""

        sb_key = apikey if apikey.startswith("sb_") else \
                 bearer if bearer.startswith("sb_") else ""
        if sb_key:
            jwt = lookup(host, sb_key)
            if jwt is None:
                return self._fail(401, "Invalid API key")
            if apikey.startswith("sb_"):
                set_h("apikey", jwt)
            # Keep a user access token intact; only swap the Authorization
            # header when it is absent or carries the sb_ key itself.
            if not bearer or bearer.startswith("sb_"):
                set_h("Authorization", "Bearer " + jwt)

        body = self._read_body()
        for k in [h for h in headers if h.lower() == "content-length"]:
            headers.pop(k, None)
        if body or self.command in ("POST", "PUT", "PATCH", "DELETE"):
            headers["Content-Length"] = str(len(body))
        headers["Connection"] = "close"

        try:
            conn = HTTPConnection(target.hostname, target.port or 80, timeout=60)
            conn.request(self.command, self.path, body=body or None, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
        except OSError:
            return self._fail(502, "upstream unreachable")

        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() not in HOP and k.lower() not in ("content-length", "date", "server"):
                self.send_header(k, v)
        if self.command == "HEAD" or resp.status in (204, 304):
            self.end_headers()
        else:
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        conn.close()

    # One implementation for every method.
    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)

if __name__ == "__main__":
    port = int(os.environ.get("KEY_PROXY_PORT", "8080"))
    print(f"key-proxy listening on :{port}; hosts: {sorted(KEYMAP)}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
