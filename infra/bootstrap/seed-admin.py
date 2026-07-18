#!/usr/bin/env python3
"""seed-admin.py — seed the wizard-collected admin account into console_meta.

Runs on the host (root) after console-meta-db is up. Reads the admin email /
name / Better Auth-compatible scrypt hash from the wizard state file (the
plaintext password is never persisted anywhere) and inserts the Better Auth
`user` + `account` rows via `docker exec … psql`, using psql variables so no
user-controlled value is ever interpolated into SQL.

Hash format (must match better-auth's credential provider —
VERIFY ON A THROWAWAY VM before trusting a fresh box's first login):
  scrypt N=16384 r=16 p=1 dkLen=64, salt = 16 random bytes hex-encoded,
  password NFKC-normalized, stored as "<salt-hex>:<key-hex>".
The hash itself is produced by the wizard (wizard.py better_auth_hash()).

Idempotent: ON CONFLICT on the unique email -> re-runs are no-ops (it will
NOT overwrite an existing user's password).
"""
import json
import os
import secrets
import subprocess
import sys

STATE = os.environ.get("VIBE_HOME", "/opt/vibebase") + "/state/wizard.json"
META_CONTAINER = "console-meta-db"

SQL = """
\\set ON_ERROR_STOP on
INSERT INTO "user" (id, name, email, "emailVerified", role, "createdAt", "updatedAt")
VALUES (:'uid', :'uname', :'uemail', true, 'admin', now(), now())
ON CONFLICT (email) DO NOTHING;

INSERT INTO account (id, "accountId", "providerId", "userId", password, "createdAt", "updatedAt")
SELECT :'aid', u.id, 'credential', u.id, :'phash', now(), now()
FROM "user" u
WHERE u.email = :'uemail'
  AND NOT EXISTS (
    SELECT 1 FROM account a WHERE a."userId" = u.id AND a."providerId" = 'credential'
  );

-- default org (harmless if the console plane ignores it; idempotent)
INSERT INTO orgs (id, name, slug)
SELECT gen_random_uuid()::text, 'Default Org', 'default-org-slug'
WHERE NOT EXISTS (SELECT 1 FROM orgs WHERE slug = 'default-org-slug');
"""


def main() -> int:
    with open(STATE) as f:
        st = json.load(f)
    admin = st.get("admin") or {}
    email, phash = admin.get("email"), admin.get("password_hash")
    name = admin.get("name") or email
    if not email or not phash:
        print("seed-admin: no admin in wizard state; nothing to do")
        return 0

    args = [
        "docker", "exec", "-i", META_CONTAINER,
        "psql", "-U", "postgres", "-d", "console_meta", "-q",
        "-v", f"uid={secrets.token_hex(16)}",
        "-v", f"aid={secrets.token_hex(16)}",
        "-v", f"uname={name}",
        "-v", f"uemail={email}",
        "-v", f"phash={phash}",
    ]
    # SQL via stdin, never -c (psql only interpolates :'var' in its input loop).
    r = subprocess.run(args, input=SQL, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        # stderr may not contain secrets (SQL uses variables), still keep it short
        print(f"seed-admin: FAILED: {r.stderr.strip()[:400]}", file=sys.stderr)
        return 1
    print(f"seed-admin: ok ({email})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
