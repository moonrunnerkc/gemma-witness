# Historical, not runtime

This directory is a Day-1 evidence snapshot from 2026-05-10. It is preserved for the audit trail of the project's bring-up, not for runtime use. The toolchain, scripts, and process model documented here have been superseded:

- Fingerprints now live in `inference/fingerprints/`, embedded into the capture binary via the `witness-fingerprints` crate. The legacy `inference/mlx-sidecar/model-fingerprint.json` referenced in `MANIFEST.md` is no longer authoritative.
- The Day-1 CLI prototype at `inference/mlx-sidecar/cli/transcribe.py` has been superseded by `crates/witness-cli` and the four-pass pipeline in `crates/witness-inference`.
- The smoke-test script under `tests/day1/` is retained as a historical reference; the canonical test bed is the workspace `cargo test` suite plus `crates/witness-core/tests/fake-sidecar-e2e.rs`.

Treat the files in this directory as read-only history. Do not modify them to reflect later changes; create a new evidence directory under `evidence/` for each fresh milestone.
