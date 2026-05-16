# `.witness` bundle format, v1

A `.witness` file is a ZIP archive. All entries are stored uncompressed (STORED) and emitted in lexicographic path order so that two captures of the same payload produce byte-identical archives.

## Layout

```
incident-{uuid}.witness/
├── manifest.json          RFC 8785 JCS canonical bytes are the signing payload.
├── signature.json         Detached Ed25519 signature plus signer metadata.
├── public_key.pem         PKCS#8 PEM of the device public key (also embedded in manifest.signer).
└── assets/
    ├── audio.wav          Raw captured audio (PCM, 16 kHz mono).
    ├── images/
    │   ├── img-0.jpg
    │   └── img-1.jpg
    └── reasoning.txt      Gemma thinking-channel output, captured verbatim (UTF-8, no normalization).
```

## Signing payload

The signature is over `serde_jcs::to_vec(&manifest)`, i.e., the RFC 8785 JSON Canonicalization Scheme bytes of the manifest object. Re-serializing the manifest with a different key order must still verify; serializing with non-canonical floats or non-JCS escapes must not.

## Asset hashing

The manifest's integrity is enforced by the signature, not by an entry in `assets[]`. The asset hash list covers only files under `assets/`. Each entry is hashed as `SHA-256(raw file bytes)`. Bytes are obtained via `std::fs::read` and the matching JS verifier reads the bytes out of the unzipped entry. No decoding, normalization, or re-encoding occurs between read and hash.

## signature.json

```json
{
  "algorithm": "ed25519",
  "key_id": "<lowercase hex SHA-256 of the 32-byte raw public key>",
  "signature_b64": "<base64-standard, no wrapping>",
  "signed_payload": "manifest.json",
  "canonicalization": "rfc8785"
}
```

## Versioning

`manifest.manifest_version` is an integer. The verifier reads it first and routes to the matching validator. Any change to the manifest layout that would break an older verifier requires bumping this number and shipping a new validator branch.

Two versions exist today:

- **v1**: Ed25519 software-key signing. `signer.algorithm` is always `"ed25519"`; `signer.attestation` is not permitted. Every bundle the capture app has emitted since launch is v1.
- **v2**: Adds `ecdsa-p256` as a permitted `signer.algorithm` value (Secure Enclave on macOS, TPM 2.0 on Linux, NCrypt on Windows are all P-256-native) and adds an optional `signer.attestation` blob carrying the hardware-key attestation document. v2 manifests may also use Ed25519 (a hardware-backed Ed25519 path would still emit v2). The seal path will start emitting v2 once a hardware-backed key provider is wired up; the verifier accepts v2 today so the format gate is not the bottleneck.

The verifier accepts every version in `crates/witness-core/src/verifier.rs::SUPPORTED_MANIFEST_VERSIONS` and rejects unknown versions with a clear "obtain a newer verifier" message.

## Canonicalization edges

`PassParameters.temperature` and `top_p` are unconstrained `number` fields in the schema today, because the inference pipeline already records values like `0.2` and `0.9` and tightening the schema would invalidate existing fixtures. RFC 8785 cross-language conformance is enforced via `tests/fixtures/canonicalization-conformance/`. If a future pass records a value whose canonical-bytes form diverges between `serde_jcs` (Rust) and `canonicalize` (npm), add a fixture case there before merging.

## Determinism

- ZIP entries written in sorted (`Ord` on the entry path) order.
- ZIP entries stored uncompressed; this avoids deflate version drift between platforms.
- ZIP modification times set to the Unix epoch (1980-01-01 in DOS time, the lowest the format allows).
- Manifest produced via `serde_jcs::to_vec`; signature is computed on those bytes; the same bytes are written into the ZIP.

## Trust anchors

Two distinct signing identities are load-bearing for a verifier deciding whether to trust a bundle.

### Per-bundle signer (the device key)

Each bundle's `signature.json` is produced by the capture app's device key. The signing algorithm is recorded in `signature.algorithm` (Ed25519 today); the public key is embedded both in `manifest.signer.public_key_pem` (covered by the signature) and, as documentation, in the verifier UI as a 16-character SHA-256 fingerprint. Verifiers MUST refuse a bundle whose `signature.key_id` does not match the SHA-256 of `manifest.signer.public_key_pem`'s raw key bytes. The trust decision for the signer is downstream: a verifier comparing the rendered fingerprint against `apps/verifier/trusted-signers.json` declares the bundle "signed by a known witness" or "signed by an unknown key". TOFU (treat the first key seen as authoritative) is acceptable for civic-accountability use but is not the same trust property as a registered signer.

### Registry-of-registries (the build identity)

The fingerprint registry under `inference/fingerprints/` is baked into the capture binary at compile time and inlined into the static verifier at build time. Its authenticity is tied to the build pipeline's signing identity, not to any one signer's device key. The integrity contract has two layers:

1. **Content gate.** `inference/fingerprints/registry-manifest.json` is the JCS-canonical envelope listing every file under the registry directory and its SHA-256. Both `crates/witness-fingerprints/build.rs` and `apps/verifier/build.mjs` recompute every hash and refuse to embed the registry on mismatch. A regression suite (`crates/witness-fingerprint-verify/tests/tamper-regression.rs`) walks tampered trees through this gate to keep it honest.
2. **Signature gate.** `inference/fingerprints/registry-manifest.sigstore` is the cosign `sign-blob --bundle` output covering the envelope. It is produced by `.github/workflows/sign-fingerprints.yml` under the same keyless OIDC identity that signs `SHASUMS256.txt` in `release.yml`. Verifiers MUST chain the bundle's certificate to the pinned Sigstore production trust root and MUST accept only certificate subjects whose SAN URI starts with the workflow-path prefix recorded in `RELEASE.md` §"Trust anchors". The Rust side enforces this at `witness-fingerprint-verify::signature::verify_signature`; the verifier-side enforcement happens at build time in `apps/verifier/build-verify-registry.mjs` and surfaces to the user as the "Registry signature" check row.

A placeholder envelope (`registry-manifest.json` with `placeholder: true`) is permitted during local development; both the Rust and JS build paths emit a loud warning and refuse to ship a production binary or verifier HTML against it. Once the signing workflow has run on a branch, every subsequent build either reproduces the same signature or fails.

Updates to the OIDC issuer or the workflow-path prefix MUST happen in lockstep across `RELEASE.md`, `crates/witness-fingerprint-verify/src/signature.rs`, and `apps/verifier/build-verify-registry.mjs`. The unit test `identity_prefix_pins_release_yml_workflow_path` catches a drift in the Rust constant; the equivalent JS constant is read from a literal string and surfaces in `apps/verifier/build-verify-registry.mjs`.
