# Repository settings (maintainer operations)

GitHub settings that must be on for the security policy in
[`SECURITY.md`](../../SECURITY.md) and the trust anchors in
[`RELEASE.md`](../../RELEASE.md) to mean what they say. Re-check after
ownership transfers, settings audits, or anytime an unexpected merge
lands.

## Security tab

- **Private vulnerability reporting**: ON. Settings → Code security and
  analysis → Private vulnerability reporting → Enable. Without this,
  the "Report a vulnerability" button in the Security tab is hidden and
  channel 1 of `SECURITY.md` is inert.
- **Security advisories**: enable drafts. The maintainer creates a draft
  advisory the moment a private report is triaged in-scope, even if no
  CVE is assigned yet; this gives the reporter a shared workspace and
  a public-disclosure surface that goes live with one click.
- **Dependabot security updates**: ON.
- **Dependabot version updates**: configured via the in-tree
  `.github/dependabot.yml`. Weekly cadence is documented in the README
  §"Security and supply chain" section.
- **Code scanning**: optional. CodeQL on the Rust workspace is light
  signal because the cryptographic invariants live behind types
  CodeQL does not see into. Leave it on for the JavaScript verifier;
  turn it off for Rust if scan noise crowds out real findings.

## Branch protection (`main`)

- Required status checks: `rust-checks`, `rust-coverage`,
  `rust-supply-chain-audit`, `verifier-js`, `capture-js-audit`,
  `live-e2e-gate`. Each maps to a job in `.github/workflows/ci.yml` or
  `live-e2e.yml`.
- Require linear history: ON. The release identity assumption is that
  every commit on `main` was produced by a maintainer's clearly
  attributed push; merge commits with rewritten history defeat that.
- Restrict who can push: organisation admins only. Pull requests are
  the only path to merge.
- Required reviews: 1 (the maintainer is currently the only reviewer).
  Raise to 2 once a second maintainer is on-boarded.
- Allow force-pushes: OFF.
- Allow deletions: OFF.

## Workflow permissions

- Default `GITHUB_TOKEN` permissions: read-only.
- Each workflow declares the permissions it needs at the `permissions:`
  key, and never sets `permissions: write-all`.
- `id-token: write` is granted only to `release.yml` and
  `sign-fingerprints.yml`. Both use Sigstore keyless OIDC and need the
  token to mint the signing certificate.
- Workflows are pinned to commit SHAs, not version tags. Renovate /
  Dependabot bumps the pins; the maintainer reviews each bump.

## Tag protection

- Pattern `v*`: only the maintainer's account can push. Sigstore
  keyless cosign signs at workflow runtime using the GitHub OIDC token
  for the workflow file at the tag, so an unauthorized push would
  produce a signature with a wrong workflow path and fail every
  verifier.

## Secrets

The repository should hold exactly these secrets:

- `HF_TOKEN`: read access to Hugging Face for the `live-e2e.yml` Linux
  job. Granted to the `live-e2e` environment, not the repo-wide pool,
  so PR workflows from forks cannot read it.

There must be no other secrets. In particular, do not store cosign
private keys, code-signing certificates, or App Store credentials:
release signing is keyless, and the macOS / Windows code-signing flows
(when they land) will use platform-managed credential stores not
GitHub secrets.

## Audit cadence

- Quarterly: walk this document end-to-end and verify every setting
  matches.
- Before tagging a release: confirm branch protection has not loosened
  and `Private vulnerability reporting` is still ON.
- After any settings change pushed by a maintainer: file a one-line
  note in `docs/decisions.md` so the trail is reviewable later.
