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

## Canonicalization edges

`PassParameters.temperature` and `top_p` are unconstrained `number` fields in the schema today, because the inference pipeline already records values like `0.2` and `0.9` and tightening the schema would invalidate existing fixtures. RFC 8785 cross-language conformance is enforced via `tests/fixtures/canonicalization-conformance/`. If a future pass records a value whose canonical-bytes form diverges between `serde_jcs` (Rust) and `canonicalize` (npm), add a fixture case there before merging.

## Determinism

- ZIP entries written in sorted (`Ord` on the entry path) order.
- ZIP entries stored uncompressed; this avoids deflate version drift between platforms.
- ZIP modification times set to the Unix epoch (1980-01-01 in DOS time, the lowest the format allows).
- Manifest produced via `serde_jcs::to_vec`; signature is computed on those bytes; the same bytes are written into the ZIP.
