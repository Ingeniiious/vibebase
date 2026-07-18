# studio-fork/ (vendored at release)

This directory holds Vibe Base's web dashboard: a fork of
[Supabase Studio](https://github.com/supabase/supabase) (Apache-2.0) with the
multi-project console, Better Auth admin login (TOTP-enforced), the
provisioner UI, and self-hosted gating.

It is vendored here when this tree is split into its public repository
(source of truth: `studio-fork/` in the parent repo). The deploy step builds
it on the server with:

    docker build studio-fork -f apps/studio/Dockerfile --target production -t studio-console:v1

`install.sh` and `infra/bootstrap/deploy-stack.sh` expect it at
`<repo-root>/studio-fork/`. Until it is vendored, the deploy step's
`studio_build` substep will fail — nothing else in this tree depends on it.

## Branding checklist at vendor time

- `apps/studio/lib/brand.ts`: set `BRAND_NAME = "Vibe Base"` and
  `BRAND_SHORT = "VB"`.
- Site meta (title/description tags) and the studio `package.json`
  description: use the fork framing — "Supabase's open-source studio,
  forked and improved for multi-project self-hosting" — never
  "Supabase alternative", and never the Supabase name/logo as the
  product identity (Apache-2.0 grants no trademark rights).
