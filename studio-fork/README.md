# studio-fork/ (fetched from a release asset at install time)

This directory holds Vibe Base's web dashboard: a fork of
[Supabase Studio](https://github.com/supabase/supabase) (Apache-2.0) with the
multi-project console, Better Auth admin login (TOTP-enforced), the
provisioner UI, and self-hosted gating.

The source tree is **not committed to this repo** (it is a large pnpm
monorepo). Instead it ships as a GitHub **release asset** and is downloaded at
install time. `install.sh`'s `phase_studio_src`:

1. downloads `vibebase-studio-src.tar.gz` from the pinned release
   (tag `STUDIO_SRC_TAG`, default `v0.1.0-beta`),
2. verifies its `sha256` against the digest hardcoded in `install.sh`
   (a tampered or truncated download is rejected), and
3. extracts it here, into `<repo-root>/studio-fork/` (which on the server is
   `/opt/vibebase/src/studio-fork`).

`infra/bootstrap/deploy-stack.sh`'s `studio_build` step then builds it with:

    docker build studio-fork -f apps/studio/Dockerfile --target production -t studio-console:v1

Until `phase_studio_src` has run, this directory contains only this README —
nothing else in the tree depends on it being populated ahead of the build.

## What the release asset contains

The published tarball is the fork source with `.git`, `node_modules`,
`.next`, `.turbo`, and `.env` files excluded, plus these public-release
adjustments:

- `apps/studio/lib/brand.ts`: `BRAND_NAME = "Vibe Base"`, `BRAND_SHORT = "VB"`;
  `BRAND_ORG` / `BRAND_DOMAIN` read from `NEXT_PUBLIC_BRAND_ORG` /
  `NEXT_PUBLIC_BRAND_DOMAIN` at build time with neutral fallbacks, so each
  install self-brands.
- Test files (`*.test.ts` / `*.spec.ts`) and internal dev notes are stripped.
- Never present the Supabase name/logo as the product identity (Apache-2.0
  grants no trademark rights); `LICENSE` and `NOTICE` attribution stay intact.

To cut a new asset, rebuild the tarball, update `STUDIO_SRC_TAG` and
`STUDIO_SRC_SHA256` in `install.sh`, and publish the release.
