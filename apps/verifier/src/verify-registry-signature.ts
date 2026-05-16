import type { CheckOutcome, RegistryVerification } from "./types";

/**
 * Surface the build-time Sigstore verification result of the
 * fingerprint registry envelope as a verifier check row.
 *
 * The verification itself happens at build time in
 * `apps/verifier/build-verify-registry.mjs`, where the Node-only
 * `@sigstore/verify` chain runs against the pinned cosign OIDC
 * identity. A `null` value here means the verifier was bundled
 * without build-time verification (an internal bug) and is treated as
 * a hard failure. A `placeholder: true` value means the signing
 * workflow has not produced a bundle yet and the row warns rather
 * than rejects so pre-1.0 builds can be inspected. A
 * `placeholder: false` value renders the verified identity and the
 * signing timestamp.
 *
 * @param verification - The inlined verification result, or null.
 * @returns A {@link CheckOutcome} describing the registry signature.
 */
export function verifyRegistrySignature(
  verification: RegistryVerification | null,
): CheckOutcome {
  if (verification === null) {
    return {
      name: "Registry signature",
      passed: false,
      details: [
        "verifier was built without build-time registry verification; this is an internal bug, rebuild via apps/verifier/build.mjs.",
      ],
    };
  }
  if (verification.placeholder) {
    return {
      name: "Registry signature",
      passed: false,
      details: [
        "fingerprint registry envelope is a placeholder; no Sigstore signature has been produced yet. " +
          "release builds must run sign-fingerprints.yml first. this verifier was built before the registry was signed and should not be used to validate production bundles.",
      ],
    };
  }
  return {
    name: "Registry signature",
    passed: true,
    details: [
      `registry envelope signed by cosign keyless identity ${verification.identity} ` +
        `(OIDC issuer ${verification.issuer}) at ${verification.signed_at_utc}. ` +
        `${verification.covered_files.length} fingerprint file(s) covered.`,
    ],
  };
}
