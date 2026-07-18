// Verify a JWT against a JWKS URL exactly the way a migrated app would
// (jose createRemoteJWKSet + jwtVerify, EdDSA, iss/aud = auth-URL origin).
//
//   node verify-jwt.mjs <jwks-url> <jwt> [expected-origin]
//
// Exits 0 and prints the payload when the token verifies; exits 1 otherwise.
// jose is a transitive dependency of better-auth, so this runs inside the
// vibe-neon-auth image with no extra installs:
//   docker run --rm vibe-neon-auth:v1 node verify-jwt.mjs <jwks-url> <jwt>
import { createRemoteJWKSet, jwtVerify } from 'jose'

const [jwksUrl, token, expectedOrigin] = process.argv.slice(2)
if (!jwksUrl || !token) {
  console.error('usage: node verify-jwt.mjs <jwks-url> <jwt> [expected-origin]')
  process.exit(1)
}

const origin = expectedOrigin ?? new URL(jwksUrl).origin
try {
  const jwks = createRemoteJWKSet(new URL(jwksUrl))
  const { payload, protectedHeader } = await jwtVerify(token, jwks, {
    issuer: origin,
    audience: origin,
  })
  console.log(JSON.stringify({ ok: true, header: protectedHeader, payload }, null, 2))
} catch (err) {
  console.error(JSON.stringify({ ok: false, error: String(err) }))
  process.exit(1)
}
