# Registered signers

This directory is the repo-root source of truth for the **signer registry**
that turns Gemma.Witness from a TOFU-style verifier into a CA-anchored one.
Each registered signer ships:

- `signer-<id>.pem` — the signer's public key in SubjectPublicKeyInfo PEM
  form. For software Ed25519 signers this is a PKCS#8 PEM; for
  hardware-backed ECDSA P-256 signers (Apple Secure Enclave, TPM 2.0,
  Windows NCrypt) this is the standard 91-byte SPKI PEM.
- `signer-<id>.json` — the metadata envelope (see schema below). Includes
  `name`, `affiliation`, optional `attestation_url`, optional
  `revoked_at`, and a cryptographic binding to the PEM via
  `public_key_pem_sha256`.

The aggregate `signers/manifest.json` is regenerated from the per-signer
files at release time and is meant to be signed by the same Sigstore
keyless identity that signs `inference/fingerprints/registry-manifest.json`
(see WS4). Until the first signing run lands, `signers/manifest.json`
ships with `placeholder: true` and the verifier's
[`verify-signer-identity.ts`](../apps/verifier/src/verify-signer-identity.ts)
falls back to the per-build `apps/verifier/trusted-signers.json` it
already inlines.

## How the verifier uses these files

At build time, `apps/verifier/build.mjs` reads `signers/manifest.json`
(when present) and projects each non-placeholder entry into
`trusted-signers.json`, which is inlined into the static HTML verifier
under `window.__TRUSTED_SIGNERS__`. The verifier then renders one of
three states per bundle:

| State | Trigger | Row |
|---|---|---|
| **Registered** | manifest's `signer.key_id` + PEM SHA-256 match an entry that is NOT revoked | green, passes the overall verdict |
| **Revoked** | matched entry carries `revoked_at` | red, fails the overall verdict even when every cryptographic check passes |
| **Unknown (TOFU)** | no matching entry | row fails so the reviewer is forced to pin the key out-of-band before trusting |

## Metadata schema (`signer-<id>.json`)

```json
{
  "schema_version": 1,
  "name": "Brad Kinnard",
  "affiliation": "Aftermath Technology",
  "key_id": "lowercase-hex-sha256-of-the-raw-public-key-point",
  "public_key_pem_sha256": "lowercase-hex-sha256-of-the-utf8-pem-bytes",
  "algorithm": "ecdsa-p256",
  "attestation_url": "https://example.org/brad-kinnard/signer-key.html",
  "added_at": "2026-05-16T00:00:00Z",
  "note": "free-text reviewer-visible context",
  "revoked_at": null,
  "revocation_reason": null
}
```

`revoked_at` is OPTIONAL and unset for active signers; when set to an
RFC 3339 timestamp the verifier flips the state to red and surfaces
`revocation_reason` in the row's drilldown.

## Submitting a new signer

See [`docs/signer-onboarding.md`](../docs/signer-onboarding.md) for the
full PR-based flow (CSR-like JSON, hardware-backed key recommended,
Rekor record per registration).

## Trust anchor for this directory

Two separate Sigstore-keyless identities sign the supply chain:

- The **per-bundle device key** (an SEP / TPM / NCrypt P-256 or software
  Ed25519 key) signs each `.witness` bundle.
- The **release identity** signs both
  `inference/fingerprints/registry-manifest.json` (WS4) and
  `signers/manifest.json` (WS5). The verifier validates both signatures
  at build time and refuses to ship a static HTML build whose Sigstore
  bundle does not verify under the pinned issuer / workflow-path prefix.

The release identity is the same maintainer-controlled GitHub Actions
workflow described in [`spec/bundle-format.md`](../spec/bundle-format.md);
turning on `signers/manifest.json` signing in CI is a maintainer step
that's tracked but not yet wired (the workflow exists for the
fingerprint registry; mirroring it for signers is a one-line extension).
