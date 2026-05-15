# Contributing to Gemma.Witness

## Lockfiles are the source of truth

Workspace `Cargo.toml` and per-package `package.json` files may declare
caret-range version requirements (`"^x.y.z"` in npm, default semver caret in
cargo). The lockfile pins the exact version that gets built, and CI enforces
that lockfile via `cargo --locked` and `pnpm install --frozen-lockfile`.

What that means for contributors:

- A PR that changes a dependency must also update the lockfile. Run
  `cargo build` and `pnpm install` locally first; commit the resulting
  `Cargo.lock` / `pnpm-lock.yaml` together with the manifest change.
- A PR that touches `Cargo.lock` or any `pnpm-lock.yaml` without a matching
  manifest change is suspicious. CODEOWNERS routes those changes through
  security review.
- Never edit a lockfile by hand to bypass a resolver disagreement; fix the
  manifests instead. Hand-edited integrity hashes have been the vector for
  multiple supply-chain incidents in the npm ecosystem.

CI runs `cargo audit`, `cargo deny check`, and `pnpm audit` on every push. A
PR cannot land if those jobs fail. Local equivalents:

```sh
cargo install cargo-audit cargo-deny
cargo audit --locked
cargo deny check advisories bans sources
( cd apps/verifier && pnpm audit --audit-level moderate )
( cd apps/capture && pnpm audit --audit-level moderate )
```

## Pinning GitHub Actions

Every action in `.github/workflows/*.yml` is pinned to a 40-character commit
SHA with a human-readable comment alongside it. Floating tags (`v4`,
`@stable`) are forbidden. Dependabot is configured to open PRs that bump the
SHA forward; review the diff between the old and new SHA before merging.

## Code style is non-negotiable

See `CLAUDE.md` for the full list. The highlights:

- TypeScript: no `any`, named exports only, kebab-case filenames.
- Rust: no `unwrap()` / `expect()` in production code paths. Use `?` with
  `thiserror`.
- 300-line hard cap per file.
- No em dashes anywhere. CI fails on a single em dash in tracked files.
