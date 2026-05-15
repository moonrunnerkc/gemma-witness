import { sha256 } from "@noble/hashes/sha2";

import type { CheckOutcome, Manifest, TrustedSigners } from "./types";

/**
 * Verify the bundle's signer against the registry of known witnesses.
 *
 * Audit finding V-1: previously a bundle that simply embedded its own
 * `public_key_pem` passed the three cryptographic checks and rendered as
 * "All checks passed", because nothing tied the signing key to a real-world
 * identity. This check is mandatory: an unknown signer fails the row, fails
 * the overall verdict, and surfaces the bundle's `signer.key_id` plus a
 * 16-character public-key fingerprint so a reviewer can pin the new signer
 * out-of-band.
 *
 * The trust anchor is the verifier's `trusted-signers.json`, which the build
 * inlines into the static HTML via `window.__TRUSTED_SIGNERS__`. Each entry
 * pins both `key_id` (lowercase hex SHA-256 of the raw 32-byte public key,
 * matching what the manifest stores) and `public_key_pem_sha256` (lowercase
 * hex SHA-256 of the UTF-8 bytes of the PEM the signer actually embedded).
 * Both must match: a key_id collision is computationally infeasible, but
 * checking both is the cheap belt-and-braces.
 *
 * @param manifest - Parsed manifest object.
 * @param trusted - Parsed trusted-signers envelope.
 * @returns A {@link CheckOutcome}.
 */
export function verifySignerIdentity(
  manifest: Manifest,
  trusted: TrustedSigners,
): CheckOutcome {
  const keyId = manifest.signer.key_id;
  const pem = manifest.signer.public_key_pem;
  const pemSha256 = bytesToHex(sha256(utf8(pem)));
  const fingerprintShort = pemSha256.slice(0, 16);

  const match = trusted.signers.find(
    (s) => s.key_id === keyId && s.public_key_pem_sha256 === pemSha256,
  );
  if (match) {
    return {
      name: "Signed by a known witness",
      passed: true,
      details: [
        `signer "${match.label}" matched by key_id ${keyId}.`,
        `public-key fingerprint: ${fingerprintShort} (sha256 of PEM bytes).`,
      ],
    };
  }
  return {
    name: "Signed by a known witness",
    passed: false,
    details: [
      `bundle is signed by key_id ${keyId} which is NOT in the verifier's trusted-signers registry. ` +
        `the cryptographic signature is valid for the embedded public key, but the verifier has no out-of-band tie ` +
        `between this key and a real-world witness identity.`,
      `public-key fingerprint: ${fingerprintShort} (sha256 of PEM bytes). ` +
        `pin this fingerprint via the signer's published profile or an editor's signed announcement before trusting the bundle.`,
    ],
  };
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}
