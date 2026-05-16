import { sha256 } from "@noble/hashes/sha2";

import type { CheckOutcome, Manifest, TrustedSigners } from "./types";

/**
 * Verify the bundle's signer against the registry of known witnesses.
 *
 * Three terminal states, mirroring WS5's registered / TOFU / revoked design:
 *
 * - **Registered** (green): the bundle's `signer.key_id` and PEM SHA-256
 *   match an entry in `trusted-signers.json` and that entry is NOT
 *   revoked. Row passes; overall verdict can pass.
 * - **Revoked** (red): the matched entry carries `revoked_at`. The row
 *   fails and the overall verdict fails even if every cryptographic
 *   check passes. Existing bundles signed before the rotation should be
 *   re-verified against a fresh signature from the new key, not silently
 *   accepted.
 * - **Unknown (TOFU)** (amber-via-fail in the current row palette): no
 *   matching entry. The cryptographic signature is valid for the
 *   embedded public key, but the verifier has no out-of-band tie between
 *   this key and a real-world witness identity. Row fails so the
 *   reviewer is forced to pin the key out-of-band before trusting.
 *
 * Audit finding V-1 framing: previously a bundle that simply embedded
 * its own `public_key_pem` passed the cryptographic checks and rendered
 * as "All checks passed", because nothing tied the signing key to a
 * real-world identity. The row is therefore mandatory.
 *
 * The trust anchor is the verifier's `trusted-signers.json`, which the
 * build inlines into the static HTML via `window.__TRUSTED_SIGNERS__`.
 * Each entry pins both `key_id` (lowercase hex SHA-256 of the raw
 * public-key point or seed, matching what the manifest stores) and
 * `public_key_pem_sha256` (lowercase hex SHA-256 of the UTF-8 bytes of
 * the PEM the signer actually embedded). Both must match; a key_id
 * collision is computationally infeasible, but checking both is the
 * cheap belt-and-braces.
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
  if (match && match.revoked_at) {
    const reason = match.revocation_reason
      ? ` reason: ${match.revocation_reason}`
      : "";
    return {
      name: "Signed by a known witness",
      passed: false,
      details: [
        `signer "${match.label}" matched by key_id ${keyId}, but the registry marks this key as REVOKED at ${match.revoked_at}.${reason}`,
        `revoked keys never produce verifiable bundles. ask the signer to re-issue this evidence under their current key, or treat the bundle as untrusted.`,
        `public-key fingerprint: ${fingerprintShort} (sha256 of PEM bytes).`,
      ],
    };
  }
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
        `between this key and a real-world witness identity (TOFU state).`,
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
