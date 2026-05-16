# Self-hosted Apple Silicon runner for live e2e

`.github/workflows/live-e2e.yml` runs the live capture-to-verify pipeline
against a real Gemma 4 sidecar before any release artifact is built.
Two jobs run in parallel:

- `live-e2e-linux` (transformers sidecar, `google/gemma-4-E4B-it`) runs
  on the GitHub-hosted `ubuntu-latest` pool. No maintainer hardware
  required; the only repository secret needed is `HF_TOKEN` with read
  access to the gated Gemma 4 repository.
- `live-e2e-macos` (mlx-vlm sidecar, `mlx-community/gemma-4-e4b-it-4bit`)
  requires Apple Silicon. GitHub does not currently offer a hosted
  Apple-Silicon runner large enough to keep the model resident, so this
  job runs on a self-hosted runner the maintainer registers from a Mac
  the project owns.

Until the runner is registered, jobs targeting it queue indefinitely on
the missing labels, so a release will sit in "queued" rather than passing
or silently bypassing the gate. That is intentional: the gate's
absence is visible in the Actions UI.

## One-time registration

Run on the Mac that will host the runner. The Mac must:

- Be Apple Silicon (`uname -m` returns `arm64`).
- Have `pnpm`, `node` 22+, `rustup`, `uv`, and the mlx-vlm Python
  environment available on the runner user's `$PATH`.
- Have the pinned mlx-community model present at
  `~/.cache/huggingface/hub/models--mlx-community--gemma-4-e4b-it-4bit/snapshots/cc3b666c01c20395e0dcebd53854504c7d9821f9/`.
  The workflow fails fast if it is missing, so seed it by running
  `inference/mlx-sidecar/start.sh` once before registering.

Pick a directory for the runner files (anywhere under the runner user's
home; the runner stages each job inside `_work/`):

```bash
mkdir -p ~/actions-runner && cd ~/actions-runner
```

Pull the latest runner tarball for `osx-arm64` from
`https://github.com/actions/runner/releases`. Verify its SHA-256 against
the checksum on that page, extract, then run the configure step. The
token is obtained from
`https://github.com/<owner>/gemma-witness/settings/actions/runners/new`
and is single-use; do not commit it.

```bash
./config.sh \
  --url https://github.com/<owner>/gemma-witness \
  --token <one-time-token> \
  --name gemma-witness-macos-1 \
  --labels self-hosted,macOS,apple-silicon \
  --runnergroup default \
  --work _work \
  --unattended
```

Install as a launchd service so it survives reboots and restarts on
failure:

```bash
./svc.sh install
./svc.sh start
./svc.sh status
```

The runner now appears under
`https://github.com/<owner>/gemma-witness/settings/actions/runners` with
the labels above. The next release tag, or any `workflow_dispatch` on
`Live e2e`, will pick it up.

## Repository secret

The Linux job needs `HF_TOKEN`. Create a personal Hugging Face token
with at least read access to `google/gemma-4-E4B-it`, then add it under
`https://github.com/<owner>/gemma-witness/settings/secrets/actions/new`
named `HF_TOKEN`. The macOS job does not need it because the
mlx-community mirror is not gated.

## Decommissioning

To retire the runner (planned or after a hardware change):

```bash
cd ~/actions-runner
./svc.sh stop
./svc.sh uninstall
./config.sh remove --token <one-time-removal-token>
```

The removal token is obtained from the same Actions runners settings
page. After it succeeds, future tagged releases queue indefinitely on
the missing label until a replacement is registered.

## Operational notes

- The runner user's keychain is in scope for any job that runs on this
  host. The live-e2e workflow does not touch the keychain (it uses
  ephemeral signing keys), but treat the host as if it did and limit
  the runner user's permissions accordingly.
- Workflow logs uploaded to GitHub include the mlx sidecar log
  (`/tmp/mlx-sidecar.log`). Confirm that log does not contain anything
  the maintainer would not want surfaced; the sidecar is configured to
  bind only to loopback and does not log prompts or completions.
- Runner updates land via the runner's auto-update channel. If the
  runner falls behind, GitHub will refuse new jobs and the runner shows
  as offline; `./svc.sh restart` usually clears it.
