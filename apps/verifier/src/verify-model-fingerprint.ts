import type { Manifest, CheckOutcome, KnownFingerprints } from "./types";

/**
 * Verify that the manifest's model fingerprint assertion matches an entry in
 * the known-fingerprints list shipped with the verifier.
 *
 * @param manifest - Parsed manifest object.
 * @param known - Parsed known-fingerprints envelope (from
 *   `window.__KNOWN_FINGERPRINTS__`).
 * @returns A {@link CheckOutcome} with `passed` true when the fingerprint is
 *   present in the list.
 */
export function verifyModelFingerprint(
  manifest: Manifest,
  known: KnownFingerprints,
): CheckOutcome {
  const claimed = manifest.assertions["gemma.witness.model_fingerprint"].sha256;
  const modelId = manifest.assertions["gemma.witness.model_fingerprint"].model_id;
  const revision = manifest.assertions["gemma.witness.model_fingerprint"].revision;

  const match = known.fingerprints.find((f) => f.sha256 === claimed);

  if (!match) {
    return {
      name: "Model fingerprint known",
      passed: false,
      details: [
        `model fingerprint ${claimed} for "${modelId}" (revision ${revision}) is not on the known-good list. update apps/verifier/known-fingerprints.json after publishing or approving this model revision.`,
      ],
    };
  }

  return {
    name: "Model fingerprint known",
    passed: true,
    details: [`matched "${match.model_id}" revision ${match.revision}.`],
  };
}
