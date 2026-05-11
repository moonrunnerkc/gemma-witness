# Gemma.Witness Build Guide

Offline, multimodal, tamper-evident evidence-capture for civic accountability. One device, one button, one signed bundle that a third party can verify weeks later. Built on Gemma 4 E4B running entirely on-device.

This guide is the end-to-end build plan: architecture, decisions, risk, and the eight-day path to a submittable Kaggle entry. No filler.

---

## What you're actually building

Three pieces that ship together as one product:

1. **The capture app**. A Tauri 2.x desktop application that records audio, accepts images, runs Gemma 4 E4B locally to produce a structured incident report, signs the result, and emits a `.witness` bundle. Cross-platform (Linux/macOS/Windows), no network calls.
2. **The inference layer**. Gemma 4 E4B running locally via mistralrs (Rust-native, audio confirmed) with HuggingFace `transformers` as fallback. Produces transcript, structured report (function calling), reasoning trace, and an audio/image consistency check.
3. **The verifier**. A static web page (single HTML file plus WASM crypto) that drag-and-drops a `.witness` file and shows green/red on signature, hashes, and model fingerprint. Runs in any browser, no server.

The novelty sits in piece three combined with piece two. Bundle the AI reasoning trace, the inputs, the model fingerprint, and the device key into a single signed artifact that survives offline-to-courtroom. No existing project does this combination.

---

## Architecture decisions and why each one

### Model: Gemma 4 E4B at 8-bit

E4B sits in the sweet spot for this hackathon. It supports native audio input (E2B and E4B exclusively; the 26B and 31B do not), runs in roughly 5GB of RAM at 4-bit and 15GB at 16-bit, and fits a Raspberry Pi 5 (8GB) or any modern laptop. Unsloth's Gemma 4 documentation recommends 8-bit for the small models as the default quality-vs-size point, so that's what we ship.

E2B is the fallback if E4B is too slow on the demo device. E2B runs in 1.5GB at 4-bit and Google's published Pi 5 benchmarks show 133 tokens/sec prefill and 7.6 tokens/sec decode (independently confirmed at 128/7.2). 7.6 tok/s decode means a 200-token structured report takes about 26 seconds, which is acceptable for a non-interactive evidence-capture flow.

26B A4B is a Mixture of Experts model with 4B active parameters but 26B total memory footprint, so it doesn't fit on edge hardware. 31B is dense. Neither supports audio. Don't use them.

### Inference backend: mlx-vlm for dev and demo, mistralrs for cross-platform shipping, transformers as fallback

Dev hardware is a MacBook Pro M5 Max with 64GB unified memory. That changes the primary inference path. mlx-vlm shipped Day-0 Gemma 4 support including the audio leg on April 2, 2026, and a working CLI is documented: `mlx_vlm.generate --model google/gemma-4-e2b-it --audio file.wav --prompt "Transcribe this audio" --max-tokens 500`. MLX runs 10-20% faster than Ollama on Apple Silicon, talks directly to Metal, and benefits from unified memory so a 26B A4B model is fully resident with room to spare on the 64GB box. Use mlx-vlm as the primary inference backend for development and for the filmed demo.

Run mlx-vlm as a Python sidecar that the Tauri shell spawns and talks to over local HTTP (mlx-vlm exposes an OpenAI-compatible server via `mlx_vlm.server --port 8080`). This keeps the Tauri Rust code clean of Python deps and gives a clean swap point for the cross-platform backend later.

For cross-platform shipping (non-Apple hardware: Linux laptops, Windows machines, Pi 5 deployments), mistralrs is the production target. It's Rust-native, supports Gemma 4 audio (`mistralrs run -m google/gemma-4-E4B-it --isq 8 --audio audio.mp3 -i "Transcribe this fully."`), and produces a single binary. Document this as the v2 cross-platform path; don't burn hackathon days on it unless the M5 Max demo path breaks.

HuggingFace `transformers` is the fallback fallback. Use `AutoModelForMultimodalLM` with `torch`, `librosa`, and `accelerate`. The Gemma 4 model card explicitly documents this path. Heavier deps, slower, but proven everywhere. Set this up only if mlx-vlm somehow breaks on the demo machine.

Ollama is not in the picture. Its Gemma 4 model card lists text and image only, no audio. If that changes during the eight-day window, reconsider for the cross-platform path.

### Shell: Tauri 2.x, not Electron

Tauri 2.x has the smallest bundle, native Rust crypto, and integrates cleanly with both the mlx-vlm sidecar (HTTP) and mistralrs (subprocess or library). Cross-platform via Tauri's WebView abstraction.

The one historical sharp edge is Linux WebKit's lack of WebRTC for `getUserMedia`, which would block in-WebView microphone access on Linux. Dev on macOS sidesteps this for the build, but the shipped Linux binary needs the same workaround. We capture audio through `cpal` in Rust (exposed as a Tauri command) and accept images through the native file picker on every platform. No WebRTC required anywhere. The Tauri `dialog` plugin handles the file picker uniformly.

Electron would also work but ships ~150MB. Tauri 2.x is the right call.

### Audio capture: cpal directly, not the WebView

`cpal` is the cross-platform audio I/O crate in Rust. It records to WAV via host APIs (WASAPI on Windows, CoreAudio on macOS, ALSA on Linux). Expose a Tauri command `start_recording`/`stop_recording` that writes WAV to a temp path. Gemma 4 E4B accepts up to 30 seconds of audio input per turn at 16 kHz, so cap clip length client-side at 30 seconds and chunk longer recordings.

There's a third-party `tauri-plugin-audio-recorder` for Tauri 2.x that handles this, but rolling your own with `cpal` is fewer dependencies and you own the WAV format end-to-end (which matters because the bundle hashes the audio file byte-for-byte).

### Image capture: file picker for v1, camera for v2

In-WebView camera access is unreliable on Linux Tauri and finicky on macOS without correct entitlements. For the hackathon demo, accept image input through the Tauri `dialog` plugin (user picks photo files from disk: phone-transferred shots, screenshots, anything). This trades a small UX hit for a build-time guarantee that camera capture won't break across platforms.

If time permits on day six, add native camera via the `nokhwa` crate or the existing `crabcamera` Tauri plugin. Treat this as optional polish.

### Crypto: Ed25519 for signing, SHA-256 for hashing

Hashing: SHA-256. This matches C2PA's recommendation and aligns the bundle format with the broader provenance standard. Use the `sha2` crate.

Signing: Ed25519 via `ed25519-dalek`. Faster than ECDSA, smaller signatures, modern API. C2PA's signing layer is built on COSE which supports EdDSA, so this stays in-spec if you later want to claim formal C2PA conformance. ECDSA P-256 via the `p256` crate is the swap-in if strict C2PA Trust List conformance ever becomes a requirement; both keys are stored the same way.

The device generates a fresh Ed25519 keypair on first launch, stores the private key in the OS keychain (via `keyring` crate: Keychain on macOS, Secret Service on Linux, Credential Manager on Windows), and embeds the public key in every emitted bundle. This is "trust on first use" plus device-bound provenance. No CA, no PKI, no trust list required for the demo. Production deployment would add a trust list.

### Bundle format: ZIP of JSON manifest plus assets

The `.witness` file is a ZIP archive. The structure:

```
incident-{uuid}.witness/
├── manifest.json          (signed root: hashes, assertions, model fingerprint)
├── signature.json         (detached Ed25519 signature over canonicalized manifest)
├── public_key.pem         (device public key)
├── assets/
│   ├── audio.wav          (raw captured audio)
│   ├── images/
│   │   ├── img-0.jpg
│   │   └── img-1.jpg
│   └── reasoning.txt      (Gemma 4 chain-of-thought verbatim)
└── attestation/
    └── device.json        (optional: OS, hardware, software versions)
```

The manifest follows C2PA's JSON manifest pattern (used by the open-source CAI SDK) with custom assertions under a `gemma.witness.*` namespace. Each asset is referenced by SHA-256 hash. The signature covers the canonicalized JSON (RFC 8785 JCS) so reordering keys doesn't break verification.

Custom assertion types:
- `gemma.witness.model_fingerprint` (SHA-256 of model weights, plus model name and version)
- `gemma.witness.incident_report` (structured JSON from function calling: who, what, when, where, witness contact, severity, notes)
- `gemma.witness.reasoning_trace` (full Gemma 4 thinking-channel output, hashed)
- `gemma.witness.consistency_verdict` (Gemma 4's audio/image consistency assessment)
- `gemma.witness.capture_environment` (device hostname, OS, app version, timestamp, optional GPS)

This sits inside the C2PA manifest envelope, so a stricter C2PA verifier can validate the standard parts while the Gemma.Witness verifier handles the custom assertions.

### Inference pipeline: four passes, not one

Gemma 4 is asked to do four distinct things on each capture, in sequence:

**Pass 1: Transcribe and structure.** Audio goes in, Gemma 4 produces a transcript and fills the incident schema via function calling. Native function calling is a headline Gemma 4 feature, so this is the right place to use it. Multimodal input goes before text in the prompt (Gemma 4 docs are explicit about this).

**Pass 2: Image analysis.** Each image goes through with a prompt asking what's visible. Variable visual token budget: 280 tokens (Gemma 4 default) is fine; lower to 140 if speed matters more than detail. Output stored as per-image description.

**Pass 3: Consistency check.** The transcript, structured report, and image descriptions all go in. Gemma 4's thinking mode is enabled by prepending `<|think|>` to the system prompt. Output is a single boolean verdict (`consistent` or `inconsistent`) plus a reasoning trace. The reasoning trace is the entire content of the thinking channel, captured verbatim.

**Pass 4: Final review.** One more pass that takes everything above and produces a one-paragraph summary suitable for human review before signing. This is what the user sees in the UI before tapping "seal."

Each pass writes to a temporary working directory. Only after the user confirms does the app hash everything, build the manifest, sign, and emit the ZIP.

### Verifier: static HTML plus WASM crypto, zero server

The verifier is a single HTML file that loads `@noble/ed25519` (pure-JS Ed25519) and `@noble/hashes` (pure-JS SHA-256) for crypto in the browser. Drag a `.witness` file onto the page, the JS extracts the ZIP (via `fflate` or `jszip`), recomputes hashes of every asset, validates the signature against the embedded public key, and shows a per-assertion checklist.

No backend. No network calls (load all libs from same-origin or inline). The verifier itself can be hosted on GitHub Pages or distributed as a single HTML file with everything inlined. This matters: if the verifier requires infrastructure, the system fails its own privacy guarantee.

The verifier UI shows three rows:
- **Signature valid**: did the device key sign this manifest?
- **Assets untampered**: do recomputed hashes match the manifest claims?
- **Model fingerprint known**: does the model hash match a published Gemma 4 fingerprint? (This requires shipping a small JSON list of known good fingerprints with the verifier.)

If all three pass, the bundle is authentic. If any fails, show which.

---

## Eight-day plan

This is paced for a solo developer. Half-day buffer baked in.

### Day 1: model on the machine, audio in, text out

Goal: prove Gemma 4 E4B audio works end-to-end on the M5 Max.

Install mlx-vlm in a fresh Python 3.13 environment via uv: `uv pip install mlx_vlm torchvision`. Pull `mlx-community/gemma-4-e4b-it-4bit` (auto-downloads on first run, ~5GB). Run the documented audio CLI against a recorded WAV: `mlx_vlm.generate --model mlx-community/gemma-4-e4b-it-4bit --audio test.wav --prompt "Transcribe this audio" --max-tokens 500`. Confirm accurate English text out.

If that's clean, scaffold the sidecar: `mlx_vlm.server --model mlx-community/gemma-4-e4b-it-4bit --port 8080`. This is the OpenAI-compatible local endpoint the Tauri app will hit. Test with `curl` to confirm audio in the multimodal message format gets transcribed correctly.

Stop when you have: WAV in, accurate English text out, with the sidecar reachable on localhost:8080. End-of-day deliverable: a CLI script that hits the sidecar with an audio file and prints the transcript.

### Day 2: structured output and function calling

Goal: define the incident schema and prove Gemma 4 fills it reliably.

Write the function schema as a JSON Schema document (incident fields: timestamp, location, witness contact, incident type, narrative summary, severity 1-5, notes, evidence references). Build a system prompt that asks Gemma 4 to extract these from a transcript and emit them as a function call. Test on 10 sample transcripts (real ones from publicly available accident reports, OSHA complaints, anything textual that has incident structure).

Measure: how often does Gemma 4 produce valid JSON matching the schema? Target 95% or better. If lower, iterate the prompt. Native function calling on Gemma 4 is well-documented and reliable; if you're seeing schema drift, the prompt is the problem, not the model.

End-of-day deliverable: transcript in, valid structured JSON out, with a confusion matrix on the 10 test cases.

### Day 3: image leg and consistency check

Goal: add image input and the audio/image consistency verdict.

Image input through the same Gemma 4 E4B model. Per the Gemma 4 docs, place image content before text in the prompt. Set visual token budget to 280 (default).

The consistency check is the interesting piece. The prompt is roughly: "Given this transcript and these N image descriptions, are they consistent with each other? Output one of: consistent, partially-consistent, inconsistent, with a one-sentence reason." Enable thinking mode (`<|think|>` prefix) so the reasoning trace is captured.

End-of-day deliverable: full inference pipeline (audio + images in, structured report + consistency verdict + reasoning trace out), running against the mlx-vlm sidecar, three test scenarios captured.

### Day 4: Tauri shell, crypto, bundle emit

Goal: get the inference pipeline behind a real UI and emit a signed `.witness` file.

Scaffold the Tauri 2.x app (`cargo create-tauri-app`, vanilla TypeScript frontend or Svelte; skip React to avoid bundle bloat). Wire up the `cpal` audio command. Wire up the file dialog for images. Drive the inference pipeline by spawning the mlx-vlm sidecar as a child process on app start (Tauri's `Command` API in Rust) and communicating over HTTP to localhost:8080.

Implement the manifest builder in Rust: walk the assets, compute SHA-256, build the JSON manifest, canonicalize per RFC 8785, sign with Ed25519, write the ZIP. Use the `ed25519-dalek`, `sha2`, `serde_json`, and `zip` crates.

Store the Ed25519 private key in the OS keychain on first launch via the `keyring` crate.

End-of-day deliverable: a working app that captures audio, accepts images, runs inference, and emits a `.witness` file on disk.

### Day 5: verifier

Goal: a single HTML file that validates a `.witness` bundle.

Static HTML page with vanilla JavaScript. Load `@noble/ed25519`, `@noble/hashes`, and `fflate` from a same-origin path or inline as data URIs. Drag-and-drop file input. Extract the ZIP, parse the manifest, recompute all hashes, validate signature, render the three-row result table.

Ship the verifier as `verify.html`, single file, no build step. Host on GitHub Pages for the live demo, include the file in the repo so anyone can run it locally.

End-of-day deliverable: drop a bundle on `verify.html`, see green checks. Tamper with the ZIP (edit an image, change one byte in the manifest), see a red check pointing at the broken assertion.

### Day 6: real scenario capture and demo prep

Goal: film something convincing.

Pick a low-stakes simulated scenario. Two options that work for a solo dev:
- **Unsafe construction site**. Walk around a real construction site (public sidewalk view is fine), narrate the observed hazards into the app, snap two or three photos, seal. Show the verifier validating it.
- **Environmental observation**. Walk to a creek, narrate water turbidity or visible debris, snap photos, seal.

Don't fake a human rights or labor scenario you can't credibly perform. Use what's around you in Lakewood.

Film in two takes: a wide establishing shot, then the close-up on the laptop screen. Edit to under three minutes.

End-of-day deliverable: rough cut of the demo video.

### Day 7: writeup, repo polish, Kaggle assets

Goal: submission package.

Kaggle writeup is 1,500 words max. Structure:
1. Problem (2 paragraphs): chain of custody is broken for civic evidence; AI-mediated capture makes it worse; nobody can verify what an offline model said
2. Approach (3 paragraphs): four-pass Gemma 4 pipeline, signed bundle format, public verifier; specific Gemma 4 features used (audio, vision, function calling, thinking mode)
3. Architecture (2 paragraphs plus a diagram)
4. Novelty (2 paragraphs): comparison to ProofMode, eyeWitness, C2PA, CommitLLM (each adjacent, none equivalent)
5. Limitations (1 paragraph): trust-on-first-use device keys, no formal CA, no TEE attestation by default

Repo polish: clean README (use Brad's readme-craft skill rules), MIT license, working CI on push, end-to-end test that captures a fixture, signs it, and validates it.

End-of-day deliverable: submitted Kaggle entry minus the final polish pass.

### Day 8: buffer, polish, submit

Whatever broke during day 7. Final video edit. Final repo pass. Submit.

---

## Risks and what to do when they hit

**Risk: mlx-vlm sidecar breaks on the M5 Max for E4B audio.** Drop to E2B at 4-bit; Simon Willison's documented working recipe uses E2B specifically. If MLX itself misbehaves, fall back to HuggingFace transformers with `AutoModelForMultimodalLM` (proven path, documented on the Gemma 4 model card). Time cost: half a day, but you lose the MLX speed advantage.

**Risk: Gemma 4 function calling produces malformed JSON.** Post-process with a strict validator and a retry loop. Cap retries at three; on the fourth failure, fall back to free-text extraction and tag the assertion as `partial`. The verifier should treat `partial` as yellow, not red. Native function calling on Gemma 4 is reliable on clean prompts, so this should be rare.

**Risk: cross-platform shipping breaks the demo claim.** The shipped product needs to run on Linux and Windows, not just Apple Silicon. Mitigation: keep the inference layer behind a clean interface (the HTTP sidecar) so swapping mlx-vlm for mistralrs is a deployment-time choice, not an architecture rewrite. State in the writeup that the hackathon demo runs on Apple Silicon via MLX and that mistralrs is the cross-platform shipping path. Don't claim Linux/Windows binaries work if you haven't built them.

**Risk: bundle ZIP gets too large.** The audio is the heaviest piece. Cap at 30 seconds (matches Gemma 4 E4B's audio input limit anyway), encode as 16 kHz mono, that's ~1MB. Images compressed to 1080p JPEG, ~500KB each, allow up to four. Total bundle stays under 5MB.

**Risk: model fingerprint mismatches between dev and a future deployment machine.** Pin a specific HuggingFace revision SHA (the MLX-converted `mlx-community/gemma-4-e4b-it-4bit` repo), hash the actual `.safetensors` files (not just the model name), and ship the expected fingerprint inside the verifier's known-fingerprints JSON. Document the exact model URL and revision in the readme. If you also support the mistralrs path for v2, include both fingerprints in the known list.

**Risk: judges ask "what stops the user from faking the input?"** The honest answer: nothing at this layer. Gemma.Witness proves capture-time integrity, not real-world truth. The capture device asserts what it saw and heard. A malicious user with full device control can still feed it fabricated inputs. The system is one layer of a chain of custody, not the whole chain. Pair with hardware attestation (TPM, TEE) in a v2 to close the input-spoofing gap. State this explicitly in the writeup; judges respect honesty about limits more than they respect overclaims.

---

## What to put on Kaggle and YouTube

**Kaggle submission** needs three things: the working demo (link to a release with binaries for Linux/macOS/Windows), the public code repo (MIT or Apache 2.0 license), and the writeup (1,500 words max). All three under one Kaggle notebook or external links.

**YouTube video** structure:
- 0:00-0:20 problem framing (no music, just text on screen and a sentence: "In places where being believed is dangerous, evidence has to survive without the cloud")
- 0:20-2:00 the capture flow (real footage of you using the app)
- 2:00-2:30 the bundle, opened in a file browser, structure visible
- 2:30-3:00 the verifier in a browser, drag and drop, three green checks; then tamper, one red check
- 3:00 end card with repo URL

Three minutes, no padding, no music swells, no "Hi everyone." The hackathon judges have watched 600 of these.

---

## Tech stack summary

| Layer | Choice | Why |
|---|---|---|
| Model | Gemma 4 E4B at 8-bit (4-bit on Pi 5) | Native audio (E2B/E4B exclusive), fits 5GB RAM, runs on Pi 5 |
| Inference (dev + demo) | mlx-vlm sidecar | Day-0 Gemma 4 audio support, Apple Silicon native, 10-20% faster than Ollama, unified-memory friendly |
| Inference (cross-platform shipping) | mistralrs | Rust-native, audio confirmed, single-binary, runs anywhere |
| Inference (fallback) | transformers + Python sidecar | Documented, proven, AutoModelForMultimodalLM path |
| Shell | Tauri 2.x | Small bundle, Rust crypto, cross-platform |
| Audio capture | cpal (Rust) | Bypasses WebView, native APIs, cross-platform |
| Image input | Tauri dialog plugin | Sidesteps Linux WebRTC issues |
| Hashing | SHA-256 via `sha2` | C2PA-aligned |
| Signing | Ed25519 via `ed25519-dalek` | Fast, modern, COSE-compatible |
| Key storage | OS keychain via `keyring` | Native security, no plaintext on disk |
| Bundle | ZIP via `zip` crate | Universal format, easy verifier |
| Verifier | Static HTML + @noble/ed25519 | No server, no infra dependency |
| Manifest format | C2PA JSON with custom assertions | Standards-aligned, extensible |

---

## What this is not

It's not a zero-knowledge proof of inference. Active research (zkAgent, zkLLM) covers that lane; the proof systems are too heavy for an edge-AI demo in eight days. Gemma.Witness produces a cryptographic receipt that a specific signed device produced a specific output from specific inputs; it does not prove the model wasn't tampered with at the binary level. Hardware attestation (TEE, TPM) is the path to closing that gap and is called out as v2 work.

It's not blockchain-anchored. No chain is required for the demo. Optional anchoring of bundle hashes to a public timestamp service (OpenTimestamps, RFC 3161 TSA) is a small addition for v2 if needed.

It's not a clinical scribe or a journalism platform. It's evidence-capture infrastructure that those product categories can build on top of.

It's not a surveillance tool. The capture device generates the bundle and the user controls when and where it's shared. No upload, no automatic disclosure. The novel piece is that the bundle, when shared, can be independently verified.

---

## Sources

- Gemma 4 model card: https://ai.google.dev/gemma/docs/core/model_card_4
- Gemma 4 announcement: https://blog.google/innovation-and-ai/technology/developers-tools/gemma-4/
- Gemma 4 HuggingFace blog (audio examples for E2B/E4B): https://huggingface.co/blog/gemma4
- Gemma 4 E4B Ollama page (text/image only, no audio listed): https://ollama.com/library/gemma4:e4b
- Gemma 4 transformers integration (AutoModelForMultimodalLM): https://huggingface.co/google/gemma-4-31B
- mlx-vlm Gemma 4 day-0 release (audio + vision + MoE): https://medium.com/@borislavbankov/googles-gemma-4-just-made-cloud-ai-optional-30145cd35f62
- Simon Willison's documented MLX audio recipe: https://simonwillison.net/2026/Apr/12/mlx-audio/
- Google's official MLX integration docs for Gemma: https://ai.google.dev/gemma/docs/integrations/mlx
- mlx-community model repository (4-bit quantized Gemma 4 builds): https://huggingface.co/mlx-community
- mistralrs audio CLI example: https://huggingface.co/blog/gemma4
- Unsloth Gemma 4 hardware requirements: https://unsloth.ai/docs/models/gemma-4
- Gemma 4 hackathon details and tracks: https://www.kaggle.com/competitions/gemma-4-good-hackathon
- C2PA technical specification (SHA-256, ECC, JSON manifest): https://c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html
- C2PA implementation guidance (hashing and signing algorithms): https://spec.c2pa.org/specifications/specifications/1.2/guidance/Guidance.html
- Content Authenticity Initiative open-source SDK: https://opensource.contentauthenticity.org/docs/getting-started/
- Tauri 2.x audio recorder plugin: https://github.com/brenogonzaga/tauri-plugin-audio-recorder
- cpal Rust audio I/O: https://docs.rs/cpal
- ed25519-dalek: https://docs.rs/ed25519-dalek
- @noble/ed25519 (pure-JS for the verifier): https://github.com/paulmillr/noble-ed25519
- ProofMode (adjacent, photo-only): https://guardianproject.info/apps/org.witness.proofmode/
- eyeWitness to Atrocities (adjacent, media-only for ICC): https://www.eyewitness.global/
- CommitLLM (adjacent, hosted API receipts): https://commitllm.com/
