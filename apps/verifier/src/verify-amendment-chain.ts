import type { CheckOutcome, Manifest } from "./types";

/**
 * Verify the amendment chain when `manifest.amends` is present.
 *
 * `AmendsReference.original_signer_key_id` is the back-link to the original
 * bundle's signer. Without this check, anyone with their own valid keypair
 * could sign an "amendment" of any other person's bundle and the verifier
 * would render it as a continuation of the chain.
 *
 * Returns a passing outcome when `manifest.amends` is absent (no chain to
 * check) or when the amending bundle's `signer.key_id` matches the
 * back-linked `original_signer_key_id`. Returns a failing outcome with the
 * mismatched key IDs surfaced when they do not.
 *
 * @param manifest - Parsed manifest object.
 * @returns A {@link CheckOutcome}.
 */
export function verifyAmendmentChain(manifest: Manifest): CheckOutcome {
  if (!manifest.amends) {
    return {
      name: "Amendment chain consistent",
      passed: true,
      details: ["no amends pointer; this bundle is not an amendment."],
    };
  }
  const original = manifest.amends.original_signer_key_id;
  const amending = manifest.signer.key_id;
  if (original === amending) {
    return {
      name: "Amendment chain consistent",
      passed: true,
      details: [
        `amendment is signed by the same key_id as the original (${amending}).`,
      ],
    };
  }
  return {
    name: "Amendment chain consistent",
    passed: false,
    details: [
      `amendment was signed by key_id ${amending} but claims to amend a bundle signed by key_id ${original}. ` +
        "a reviewer should treat this as an independent claim rather than a continuation of the chain; out-of-band trust is required to confirm or refute the new signer's relationship to the original.",
    ],
  };
}
