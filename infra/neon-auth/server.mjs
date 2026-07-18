// Vibe Base — Neon-Auth-compatible auth service (Better Auth).
//
// Speaks the same HTTP contract as the CURRENT Neon Auth (which is a managed
// Better Auth, NOT Stack Auth — Stack Auth powered the legacy product):
//   {basePath}/sign-up/email, /sign-in/email, /sign-in/social, /get-session,
//   /token, /ok, ... (better-auth REST surface, which is what the
//   @neondatabase/auth SDK wraps)
//   {basePath}/.well-known/jwks.json — EdDSA/Ed25519 keys
//   JWTs: 15-min expiry, iss = aud = the base URL's ORIGIN (Neon's contract),
//   claims: sub, email, name, emailVerified, role, banned, createdAt, updatedAt.
//
// Apps that set NEON_AUTH_BASE_URL / NEON_AUTH_JWKS_URL repoint here with zero
// code changes. All state lives in the project DB's `neon_auth` schema — the
// exact table shapes Neon writes (see neon-auth-bootstrap.sql, captured from a
// live Neon project on 2026-07-17).
//
// Env:
//   NEON_AUTH_DATABASE_URL    required. postgres DSN; the role must have full
//                             rights on schema neon_auth (we use <ref>_app).
//                             sslmode=no-verify works (node-postgres).
//   NEON_AUTH_BASE_URL        required. Public base incl. path, e.g.
//                             https://myapp-api.db.example.com/myapp/auth
//   NEON_AUTH_SECRET          required. better-auth secret (cookie/state signing
//                             + private-key-at-rest encryption in neon_auth.jwks).
//   NEON_AUTH_TRUSTED_ORIGINS optional. Comma-separated browser origins allowed
//                             for CORS/CSRF (e.g. the app's public URL).
//   NEON_AUTH_ALLOW_SIGNUP    optional, default "true". "false" disables
//                             self-service email sign-up (existing users only).
//   GOOGLE_CLIENT_ID/SECRET   optional. Enables Google social login (Neon's
//                             shared OAuth client cannot be migrated — bring
//                             your own client).
//   PORT                      optional, default 3000.
import http from 'node:http'

import { betterAuth } from 'better-auth'
import { toNodeHandler } from 'better-auth/node'
import { admin, bearer, jwt, organization } from 'better-auth/plugins'
import pg from 'pg'

/**
 * Build the Better Auth instance. Exported so the offline verify harness
 * (verify-local.mjs) can inject a pg-mem pool; production main() below passes a
 * real node-postgres Pool. Everything contract-relevant lives HERE so the
 * harness exercises the same configuration that ships.
 */
export function buildAuth({ pool, baseURL, secret, trustedOrigins, allowSignup, google }) {
  const url = new URL(baseURL)
  const origin = url.origin
  const basePath = url.pathname.replace(/\/+$/, '') || '/'
  return {
    basePath,
    origin,
    auth: betterAuth({
      database: pool,
      baseURL: origin,
      basePath,
      secret,
      trustedOrigins,
      emailAndPassword: {
        enabled: true,
        disableSignUp: !allowSignup,
      },
      ...(google?.clientId
        ? {
            socialProviders: {
              google: { clientId: google.clientId, clientSecret: google.clientSecret },
            },
          }
        : {}),
      advanced: {
        // Matches Neon's cookie name: __Secure-neonauth.session_token
        cookiePrefix: 'neonauth',
        // Neon's tables use uuid PKs with DB-side gen_random_uuid() defaults.
        database: { generateId: false },
        defaultCookieAttributes: { sameSite: 'none', secure: true },
        // Neon-parity: server-side SDK calls (Node fetch) send
        // `sec-fetch-mode: cors` with NO Origin header; better-auth's origin
        // CSRF check 403s those (MISSING_OR_NULL_ORIGIN), which would break
        // every migrated app's server runtime. Neon's managed service accepts
        // them (its trusted_origins defaults to []). Browser cross-origin
        // access is still constrained by the CORS allowlist in
        // createRequestHandler (NEON_AUTH_TRUSTED_ORIGINS).
        disableCSRFCheck: true,
      },
      plugins: [
        // admin() supplies user.role/banned/banReason/banExpires and
        // session.impersonatedBy — columns present in Neon's schema.
        admin(),
        // organization() supplies organization/member/invitation and
        // session.activeOrganizationId — also present in Neon's schema.
        organization(),
        // bearer() lets the session token ride an Authorization header, the
        // way the @neondatabase/auth SDK talks to the service from servers.
        bearer(),
        jwt({
          jwks: {
            // EdDSA/Ed25519 is better-auth's default AND what Neon serves —
            // pinned anyway so an upstream default change can't break clients.
            keyPairConfig: { alg: 'EdDSA', crv: 'Ed25519' },
            // Neon serves the JWKS at {base}/.well-known/jwks.json (default /jwks).
            jwksPath: '/.well-known/jwks.json',
          },
          jwt: {
            // Neon contract: iss and aud are the base URL's ORIGIN (no path).
            issuer: origin,
            audience: origin,
            expirationTime: '15m',
            // Claim set observed in Neon Auth JWTs (docs/auth/guides/plugins/jwt).
            definePayload: ({ user }) => ({
              email: user.email,
              name: user.name,
              emailVerified: user.emailVerified,
              role: user.role ?? null,
              banned: user.banned ?? null,
              createdAt: user.createdAt,
              updatedAt: user.updatedAt,
            }),
          },
        }),
      ],
    }),
  }
}

/**
 * Wrap the better-auth node handler with CORS. Neon Auth is called cross-origin
 * from browser apps, so preflights + credentialed CORS must work. Only origins
 * in trustedOrigins are reflected (credentials forbid a wildcard).
 */
export function createRequestHandler({ auth, trustedOrigins }) {
  const authHandler = toNodeHandler(auth)
  const allowed = new Set(trustedOrigins)
  return (req, res) => {
    const origin = req.headers.origin
    if (origin && (allowed.has(origin) || allowed.has('*'))) {
      res.setHeader('Access-Control-Allow-Origin', origin)
      res.setHeader('Access-Control-Allow-Credentials', 'true')
      res.setHeader('Vary', 'Origin')
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, Cookie, X-Requested-With'
      )
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
      res.setHeader('Access-Control-Expose-Headers', 'set-auth-jwt, set-auth-token')
    }
    if (req.method === 'OPTIONS') {
      res.statusCode = 204
      return res.end()
    }
    return authHandler(req, res)
  }
}

function main() {
  const required = (name) => {
    const v = process.env[name]
    if (!v || v.trim() === '') {
      console.error(`FATAL: env ${name} is required`)
      process.exit(1)
    }
    return v.trim()
  }

  const databaseUrl = required('NEON_AUTH_DATABASE_URL')
  const baseURL = required('NEON_AUTH_BASE_URL')
  const secret = required('NEON_AUTH_SECRET')
  const trustedOrigins = (process.env.NEON_AUTH_TRUSTED_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  const allowSignup = (process.env.NEON_AUTH_ALLOW_SIGNUP ?? 'true') !== 'false'

  const pool = new pg.Pool({
    connectionString: databaseUrl,
    // All better-auth tables live in the project's neon_auth schema.
    options: '-c search_path=neon_auth',
    max: 5,
  })

  const { auth, basePath } = buildAuth({
    pool,
    baseURL,
    secret,
    trustedOrigins,
    allowSignup,
    google: process.env.GOOGLE_CLIENT_ID
      ? {
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
        }
      : undefined,
  })

  const port = Number(process.env.PORT ?? 3000)
  http
    .createServer(createRequestHandler({ auth, trustedOrigins }))
    .listen(port, '0.0.0.0', () => {
      console.log(`neon-auth listening on :${port} basePath=${basePath}`)
    })
}

// Run only when executed directly (node server.mjs), not when imported by the
// verify harness.
if (import.meta.url === `file://${process.argv[1]}`) {
  main()
}
