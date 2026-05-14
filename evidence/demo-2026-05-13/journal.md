# Gemma.Witness real-world end-to-end demo journal

Date: 2026-05-13
Operator: Brad (with Claude Code assistance)
Plan: `/Users/brad/.claude/plans/create-a-plan-to-federated-sketch.md`

## Goal

Drive the full Gemma.Witness system end-to-end (sidecar -> CLI -> Tauri app -> static verifier),
prove each step works on the current commit, and produce a self-contained audit trail under this
directory.

## Sidecar selected

`inference/mlx-sidecar` (Apple Silicon). Model: `mlx-community/gemma-4-e4b-it-4bit`.

---

## Step 0 - Prepare evidence directory

- [ ] Directory tree created
- [ ] Journal seeded

## Step 1 - Start mlx sidecar

- [x] start.sh launches (pid 24807, log evidence/day1/sidecar.log)
- [x] /v1/models reachable (logs/v1-models.json captured)
- [x] Pinned fingerprint: mlx-community/gemma-4-e4b-it-4bit @ revision cc3b666c01c20395e0dcebd53854504c7d9821f9, sha256 339409bd18494955556e1fde6ccc15faaa9f707b911b74791fe290b9d722beed (per inference/mlx-sidecar/model-fingerprint.json)
- Note: /v1/models does NOT expose runtime sha256. The fingerprint is sealed into the manifest at capture time from model-fingerprint.json. Verifier checks against known-fingerprints.json.

## Step 2 - CLI pipeline pass (fixture)

- [x] Pipeline returns schema-valid PipelineResult (transcribe + structure + 2 image analyses + consistency)
- [x] Latency: total_latency_ms=10518 (transcribe 1945, structure 994, images 766+541, consistency 6217)
- [x] Output saved to logs/cli-pipeline.json
- Verdict: consistent. Reasoning trace captured verbatim including byte-level sha256.

## Step 3 - Day-4 Rust e2e control

- [x] cargo test -p witness-core --test day-4-e2e PASSED (9.39s)
- [x] stdout captured to logs/day-4-e2e.log
- Bundle id sealed: fe6e06a1-3613-4b01-b5ac-0d20909a33fb
- Clean verify: signature_valid + assets_untampered + model_fingerprint_known all true
- Tamper detected: "asset assets/audio.wav hash mismatch" with expected and recomputed sha256 in the message
- Conclusion: core capture-seal-verify-tamper path is healthy on this commit.

## Step 4 - Tauri capture app live run

Required four iterations of fix-launch-retry: bugs (1) and (2) blocked compile/launch, (3) blocked UI state advancement, (4) blocked sealing. After all four fixes:

- [x] App launches via pnpm tauri dev
- [x] Device initialised, real keychain key generated (id 6dac93251b6b7b6a…)
- [x] Live audio recorded via mic
- [x] Two real images picked
- [x] 4-pass pipeline completes; consistency verdict "consistent" between audio+images
- [x] Bundle sealed: id 8ff259e1-e975-46e2-bbe1-111456883093, ~592 KB
- [x] Bundle copied to evidence/demo-2026-05-13/bundles/demo.witness

## Step 5 - Independent CLI verification of live bundle

In-place fix (authorised by plan): added `witness verify --bundle <path> [--fingerprints <path>]` subcommand to `crates/witness-cli/src/main.rs`. It loads `apps/verifier/known-fingerprints.json` (or an override), calls `witness_core::verify_bundle`, prints a JSON report, and exits 0 only if all four checks pass.

- [x] Smoke-tested against tests/fixtures/day-4-fixture.witness: all checks green
- [x] Live bundle verified: signature=true, assets=true, fingerprint=true. Output saved to logs/cli-verify-live.json.

## Step 6 - Build static HTML verifier

- [x] pnpm build emits dist/verify.html (29417 bytes)
- [x] Build script confirmed no external src/href, no fetch/XHR/importScripts
- Log: logs/verifier-build.log

## Step 7 - Verify live bundle in browser

- [x] dist/verify.html opens via file:// (no server, no fetch)
- [x] Operator dropped demo.witness, all checks reported green (signature, asset hashes, model fingerprint)
- [x] Operator dropped demo-tampered.witness, audio asset hash flagged as expected
- Operator confirmation: "1 worked fine, and 2 was exactly what you expected"

## Step 8 - Tamper detection in browser

- [x] Tampered copy generated via `cargo run -p witness-core --example tamper_audio` (new one-off utility added at crates/witness-core/examples/tamper_audio.rs)
- [x] CLI control check: tampered bundle FAILS verification with `asset assets/audio.wav hash mismatch`, signature still valid, exit code 1
- [x] Browser verifier flags audio hash failure (operator confirmed)
- [ ] Screenshot not saved (operator did not capture; visual confirmation only)

## Step 9 - Issue triage

| Issue | Severity | Disposition | Reference |
|-------|----------|-------------|-----------|
| (1) Tauri app panics on startup: tauri-specta v2.0.0-rc.25 forbids u64/usize/i64/u128 at the TypeScript boundary (BigInt-style types lose precision in JS). Four `specta::Type`-derived boundary structs in `apps/capture/src-tauri/src/commands/` were affected: `RecordingStarted.maxDurationSeconds`, `RecordingFinished.durationMs`, `InferenceSummary.totalLatencyMs`, `PickedImages.count`. | P0 (blocks app launch) | Fixed in place. Narrowed all four to `u32` (values are bounded: durations <= 30 s, latency in ms, count <= 4). Used `u32::try_from(...).unwrap_or(u32::MAX)` for safe narrowing. | apps/capture/src-tauri/src/commands/{audio,image,inference}_commands.rs |
| (2) Svelte UI calls were snake_case (`commands.initialize_device()`) but tauri-specta v2 auto-generated bindings expose camelCase (`commands.initializeDevice()`). After commit 47950ae switched from the hand-written wrapper to auto-generation, the Svelte side was never updated. Every command call in `app.svelte` was undefined at runtime. | P0 (UI cannot reach Rust at all) | Fixed in place. Renamed six call sites in `apps/capture/src/app.svelte` to camelCase. Verified with `tsc --noEmit` (clean). | apps/capture/src/app.svelte:25,34,39,48,64,73 |
| (3) The auto-generated `commands.X()` functions return a Result *envelope* `{ status: "ok"; data: T } | { status: "error"; error: AppError }`, not the raw `T`. The Svelte code (written for the previous hand-written wrapper that unwrapped this) was binding the envelope object directly to fields typed as `T`, so the UI rendered but `phase` and `deviceKeyId` were never set to usable values. Symptom: buttons rendered, clicks fired the handlers, but state never advanced. Operator confirmed: "UI itself came up, but didn't register anything I did aside from the click events themselves". | P0 (UI silently inert after click) | Fixed in place. Added a typed `unwrap<T>` helper inside `<script>` and wrapped all six call sites. svelte-check reports 0 errors 0 warnings across 77 files. | apps/capture/src/app.svelte (single block) |
| (4) `keyring` crate compiled with **no backend feature**. keyring 3.x requires an explicit opt-in (`apple-native`, `windows-native`, `linux-native-*`) — without one, `cargo metadata` reports `resolved features: []` and the crate falls back to a stub that does not actually persist anything to the OS keychain. Symptom: `initialize_device` returns a fresh-looking key id (because the in-process key bytes are valid), but `sign_with_device_key` inside `seal_bundle` calls `load_signing_key` which finds nothing and returns `WitnessCoreError::NoDeviceKey`. `security find-generic-password -s "tech.aftermath.gemma-witness"` returns "not found" even immediately after a successful `initialize_device`. **This affects the core security invariant of the system** — without it, every "sealed" bundle from a Tauri app build would be unsealable. Tests passed because the stub happens to satisfy intra-test set/get roundtrips. | P0 (signing path silently broken, breaks security invariant) | Fixed in place. Updated workspace `Cargo.toml` to `keyring = { version = "3.6", features = ["apple-native", "windows-native", "linux-native-sync-persistent", "crypto-rust"] }` so each platform gets its real backend. Re-ran keystore tests: pass. Confirmed `cargo metadata` now reports the backend features as resolved. | Cargo.toml:38 |

## Step 10 - Close out

### Pass/fail by step

| Step | Outcome |
|------|---------|
| 0. Prepare evidence dir | PASS |
| 1. Start mlx sidecar | PASS |
| 2. CLI pipeline (fixture) | PASS, 10.5 s, consistent |
| 3. day-4-e2e Rust control | PASS, 9.4 s |
| 4. Tauri capture app live | PASS after 4 fixes |
| 5. CLI verify live bundle | PASS, all four checks green |
| 6. Build static verifier | PASS, dist/verify.html 29417 bytes, no external refs |
| 7. Browser verifier on live bundle | PASS (operator confirmed) |
| 8. Tamper detection | PASS in CLI + browser (operator confirmed) |
| 9. Issue triage | 4 issues filed |
| 10. Close out | this section |

All eight verification criteria from the plan's "Verification" section met. The demo is a PASS with caveat: four in-place fixes were required to make the Tauri surface functional. Without them, the system would not have sealed a bundle at all on this commit.

### Issues filed

- #1 https://github.com/moonrunnerkc/gemma-witness/issues/1 - tauri-specta v2 boundary structs use u64/usize, debug build panics at startup
- #2 https://github.com/moonrunnerkc/gemma-witness/issues/2 - Svelte UI calls snake_case command names after auto-bindings switched to camelCase
- #3 https://github.com/moonrunnerkc/gemma-witness/issues/3 - Auto-generated tauri-specta bindings return a Result envelope; Svelte expected raw T
- #4 https://github.com/moonrunnerkc/gemma-witness/issues/4 - keyring crate compiled without a backend feature, Tauri-app signing silently broken (P0 security invariant)

### In-place fixes (committed at journal close)

| Commit | Subject | Closes |
|--------|---------|--------|
| f4db3d1 | fix(capture): narrow tauri-specta boundary structs to u32 | #1 |
| 9368120 | fix(capture): reconcile Svelte UI with auto-generated tauri-specta bindings | #2, #3 |
| f252c14 | fix(deps): enable platform-native keyring backends so device keys persist | #4 |
| a5fb80d | feat(witness-cli): add verify subcommand for round-trip bundle validation | n/a |
| b787a9b | chore(witness-core): add tamper_audio example for tamper-detection demos | n/a |
| d554710 | chore(capture): commit pnpm lockfile to match verifier convention | n/a |

Six commits ahead of origin/main, not yet pushed.

### Artifacts produced

- `bundles/demo.witness` (591716 bytes, sealed by live Tauri run) **NOT in git, kept locally only; sha256 recorded in CHECKSUMS.txt**
- `bundles/demo-tampered.witness` (591716 bytes, audio byte 100 XOR 0x42) **NOT in git, kept locally only; sha256 recorded in CHECKSUMS.txt**
- `logs/cli-pipeline.json` - first CLI pipeline run output
- `logs/cli-verify-live.json` - CLI verify of live bundle (all green)
- `logs/day-4-e2e.log` - control test stdout
- `logs/sidecar-start.log`, `logs/v1-models.json` - sidecar handshake
- `logs/verifier-build.log` - static verifier build log
- `logs/tauri-dev*.log` - four Tauri launch attempts (with the failures that produced bugs 1, 2, 3, 4)
- `CHECKSUMS.txt` - SHA256 of every file above, including this journal

### Demo verdict

The complete Gemma.Witness pipeline (sidecar -> CLI -> Tauri UI -> sealed bundle -> static HTML verifier) works end to end on this commit, ONCE the four bugs found and patched today are addressed. The bugs are independent of each other and each blocked a different stage of the system. The cryptographic core (`witness-core`) was clean throughout: every test passed and the round-trip verification logic correctly flagged tampering at the asset-hash step in both the CLI and browser verifiers.

The single P0 finding (issue #4) is a security-relevant misconfiguration that existed in the workspace from before this session and was not caught by the existing tests. The other three findings are wiring drift from the recent tauri-specta auto-generation switch (commit 47950ae) and a stale type pattern.

---

## Event log

(append timestamped lines below as the demo proceeds)

