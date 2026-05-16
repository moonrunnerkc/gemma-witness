# Signer onboarding

This document describes how to add yourself (or another witness) to the
Gemma.Witness signer registry. Once your entry merges and the next
release tag lands, every static HTML verifier will recognize your bundles
as **Registered** rather than **Unknown (TOFU)**.

## Before you start

You need two things:

1. **A hardware-backed signing key.** On Apple Silicon (or any Mac with a
   T2 chip) the capture app generates this key in the Secure Enclave
   automatically on first launch; the key never leaves hardware. On
   Linux a TPM 2.0 backend is tracked but not yet wired up; on Windows
   the NCrypt backend is a stretch goal. A software Ed25519 key still
   works for registration, but the verifier cannot prove the key was
   minted on a specific device. Hardware-backed is strongly preferred.
2. **An out-of-band identity anchor.** This is anything your readers can
   reach independently: a personal homepage, a verified social profile,
   a published institutional staff page. The verifier will display your
   `name` and `affiliation` next to the green "Registered" row; the
   anchor URL goes in `attestation_url` so reviewers can cross-check.

## Step 1: produce your public key

After running the capture app once, the seal flow prints the signer's
public-key fingerprint on the "Bundle sealed" screen. You can also
extract the embedded PEM out of any bundle you've already sealed:

```sh
unzip -p path/to/your.witness manifest.json \
  | jq -r '.signer.public_key_pem' \
  > signer-<your-id>.pem
```

Compute the two digests the registry needs:

```sh
KEY_ID=$(unzip -p path/to/your.witness manifest.json | jq -r '.signer.key_id')
PEM_SHA=$(shasum -a 256 signer-<your-id>.pem | awk '{print $1}')
echo "key_id:               $KEY_ID"
echo "public_key_pem_sha256: $PEM_SHA"
```

`<your-id>` is a short kebab-case slug; the maintainer's id is
`brad-kinnard`.

## Step 2: write your registration JSON

Drop a new `signers/signer-<your-id>.json` with the following shape:

```json
{
  "schema_version": 1,
  "name": "Your Full Name",
  "affiliation": "Your organization, if any",
  "key_id": "<paste the key_id from step 1>",
  "public_key_pem_sha256": "<paste the PEM SHA-256 from step 1>",
  "algorithm": "ecdsa-p256",
  "attestation_url": "https://example.org/your-anchor-page",
  "added_at": "2026-05-16T00:00:00Z",
  "note": "Short reviewer-visible context. State the device, the location, anything you want a future reviewer to be able to cross-check."
}
```

For software Ed25519 signers set `"algorithm": "ed25519"`. Leave
`revoked_at` and `revocation_reason` out of the file until you
actually need to retire the key.

## Step 3: open a PR

Title: `feat(signers): register <Your Name>`.

The PR body must include:

1. A link to the `attestation_url` you put in the JSON.
2. The unique key_id and PEM SHA-256 in plaintext, so reviewers can
   diff against the JSON without parsing.
3. A short statement of intent: what kind of evidence you expect to
   produce with this key.

A maintainer reviews, cross-checks the anchor URL, confirms the
`public_key_pem_sha256` reproduces from the PEM bytes you committed,
and merges.

## Step 4: tag a release

The next release tag triggers `.github/workflows/sign-fingerprints.yml`
(extended to also sign `signers/manifest.json`) to:

1. Regenerate `signers/manifest.json` from the per-signer files.
2. Sign the canonicalized envelope with the maintainer's Sigstore
   keyless identity.
3. Publish a Rekor inclusion proof so a third party can independently
   verify the registration was made by the documented workflow.

The verifier then inlines the new entry into its static-HTML
`window.__TRUSTED_SIGNERS__` at the next build, and bundles signed by
your key render in green ("Signed by registered signer: <Your Name>")
from that release forward.

## Rotating or revoking a key

To rotate (planned key change, hardware replacement): add a new
`signer-<your-id>-v2.json` with the new key, then update the existing
entry's `revoked_at` to the rotation timestamp and set
`revocation_reason` to `"rotated to signer-<your-id>-v2"`. Bundles
signed by the old key will then render red as "Signed by a revoked
key", which is the desired behaviour: the rotation is the assertion
that you no longer endorse those bundles under that key.

To revoke under compromise: open an urgent PR setting `revoked_at` and
`revocation_reason` on the affected entry, with the maintainer's
contact info in the PR body so they can fast-track the merge.

## Why the row defaults to fail for unknown signers

Without this row, anyone could embed their own `public_key_pem` and
ship a bundle that passes "Signature valid" against that embedded key.
The cryptographic check would say "yes, the bundle is internally
consistent" while the bundle would still be unrooted in any real-world
identity. The "TOFU" framing comes from SSH's trust-on-first-use: a
reviewer who recognizes a signer on first encounter can pin them
manually, but the verifier's default position must be skeptical. The
registry is the standing list of pins the maintainer has reviewed.

## Why hardware-backed is preferred

A software-held key proves the bundle was signed by *something with
access to the key file*. A hardware-backed key proves the bundle was
signed by *this specific device's hardware*, because the private
material is never exfiltrable from the SEP / TPM / NCrypt token. Both
forms are valid registrations, but a registered hardware-backed signer
is a strictly stronger claim than a registered software signer, and
the registry surfaces the difference (`algorithm` field plus the
bundle's own `signer.attestation` block when present).
