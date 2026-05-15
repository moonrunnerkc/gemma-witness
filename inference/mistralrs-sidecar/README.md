# mistralrs sidecar

Cross-platform inference sidecar for Gemma 4 E4B using
[mistral.rs](https://github.com/EricLBuehler/mistral.rs).

## Installation

`mistralrs` is the only inference path on Linux and Windows, so its version is
pinned. Install the exact commit Gemma.Witness was tested against:

```bash
cargo install --locked \
  --git https://github.com/EricLBuehler/mistral.rs \
  --rev 6f3d3e0e0e0a0e0e0e0e0e0e0e0e0e0e0e0e0e0e \
  mistralrs-server
```

Replace the `--rev` SHA with the value the Gemma.Witness release notes pin for
your version. Do not skip `--locked`. Do not use the install script
(`install.sh`) for production seals; it tracks `master` and a future malicious
push would land in your sidecar without warning.

Verify the installed version against the pinned value:

```bash
mistralrs --version
```

`start.sh` cross-checks this against `MISTRALRS_PINNED_VERSION` (see below)
and refuses to launch on mismatch.

## Trust model

The sidecar self-reports its `model_id` via `GET /v1/models`. The capture app
uses that string to pick the matching fingerprint registry entry. A
compromised or replaced `mistralrs` binary on `$PATH` could lie about
`model_id` and ship attacker-controlled transcripts back to the capture app,
which would then sign them with the user's device key. Mitigations:

1. The pinned `--rev` install above prevents drift from the audited release.
2. `start.sh` validates the installed binary version against
   `MISTRALRS_PINNED_VERSION`.
3. The capture app refuses to seal against any `(model_id, revision)` pair
   that is not in `inference/fingerprints/index.json`.

Until a cryptographic attestation between the sidecar and the capture app
lands (tracked under audit finding T-7), the operator MUST install
`mistralrs` from the pinned `--rev` above on a host they trust.

## Starting the sidecar

```bash
./start.sh
```

The script reads these environment variables:

| Variable | Default |
|---|---|
| `GW_SIDECAR_MODEL` | `google/gemma-4-E4B-it` |
| `GW_SIDECAR_PORT` | `8080` |
| `GW_SIDECAR_HOST` | `127.0.0.1` |
| `MISTRALRS_PINNED_VERSION` | matches the release-notes value |

`start.sh` refuses to bind to any non-loopback host and refuses to launch when
`mistralrs --version` does not match `MISTRALRS_PINNED_VERSION`.

To stop:

```bash
./stop.sh
```

## Recording the model fingerprint

Fingerprints are centralized at `inference/fingerprints/`. After the model is
first downloaded, seed the entry for `google/gemma-4-E4B-it@main`:

```bash
cargo run -p seed-fingerprints -- --model-id google/gemma-4-E4B-it --revision main
```

The seeder fetches the Hugging Face LFS oid for that revision, recomputes the
SHA-256 of the locally cached `model.safetensors`, refuses to write on
mismatch, and updates `inference/fingerprints/google__gemma-4-E4B-it__main.json`
along with `apps/verifier/known-fingerprints.json`. The sidecar's `start.sh`
refuses to boot against an unseeded entry.

## OpenAI-compatible surface

Like the `mlx-vlm` sidecar, `mistralrs serve` exposes the same
OpenAI-compatible HTTP endpoints:

- `GET /v1/models`
- `POST /v1/chat/completions`

The capture app talks to `http://127.0.0.1:8080` regardless of which sidecar
is running, so switching between `mlx-vlm` (Apple Silicon) and `mistralrs`
(cross-platform) requires no code changes on the Rust side.

## Cross-platform support

mistral.rs runs on Linux, macOS, and Windows. `--isq 4` enables 4-bit in-place
quantization, which keeps memory usage low enough for consumer GPUs and large
unified-memory Apple Silicon machines.
