# Release checklist

CI proves the wiring on three platforms on every push via the hermetic e2e against `witness-test-sidecar`. It does not prove the capture binary still drives a real Gemma 4 sidecar end-to-end; the GitHub macOS runner cannot host the model. The maintainer closes that gap manually before every tagged release.

## Pre-tag steps

Run on Apple Silicon with the pinned MLX model cached:

```bash
# 1. Bring up the live sidecar.
inference/mlx-sidecar/start.sh

# 2. Live e2e against the real model. Must pass, not skip.
cargo test -p witness-core --test day-4-e2e -- --nocapture

# 3. Full workspace tests once more for the record.
cargo test --workspace -- --test-threads=1

# 4. Clippy + fmt gate. Must be clean.
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# 5. Verifier build. Output should be a single HTML file.
cd apps/verifier && pnpm install && pnpm build && cd -

# 6. Spot-check the verifier with the bundle the live e2e produced.
#    Drag it into apps/verifier/dist/verify.html. Expect three green checks.
```

If any step fails or `day-4-e2e` hits its skip path instead of running, do not tag. The skip path exists for CI on hosts that cannot run the model; on a release host it is a bug.

## Tagging

```bash
git tag -s v0.X.Y -m "v0.X.Y"
git push origin v0.X.Y
```

## After tagging

- Confirm the GitHub Actions run for the tag is green.
- Update `apps/verifier/known-fingerprints.json` if any model fingerprint was added or rotated in this release; the verifier ships with the list embedded.
- File a release-notes entry naming the manifest version and any changes to the bundle layout. The manifest version did not change in this release unless explicitly noted.

## When the live e2e cannot run

A self-hosted Apple Silicon runner would make this automated. The maintenance burden of a Mac mini sitting in a closet is real, and the hermetic e2e already catches the schema-drift class of bugs on every push, so the live e2e stays as a release gate, not a per-push gate. If a self-hosted runner lands later, replace this checklist with a CI job; no migration cost beyond deleting this file.
