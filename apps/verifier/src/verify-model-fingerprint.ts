import type { Manifest, CheckOutcome, KnownFingerprints } from "./types";

/**
 * Verify that the manifest's model fingerprint assertion matches an entry in
 * the known-fingerprints list shipped with the verifier.
 *
 * Audit finding V-4: previously the check matched on SHA-256 only, which
 * let a bundle claim `model_id: "evil/model"` with a real registered SHA-256
 * and still pass while the rendered row read `matched "<real-model_id>"`.
 * The fix matches the (model_id, revision, sha256) triple as a unit: a
 * mismatch in any one component fails the row.
 *
 * @param manifest - Parsed manifest object.
 * @param known - Parsed known-fingerprints envelope (from
 *   `window.__KNOWN_FINGERPRINTS__`).
 * @returns A {@link CheckOutcome}.
 */
export function verifyModelFingerprint(
  manifest: Manifest,
  known: KnownFingerprints,
): CheckOutcome {
  const claimed = manifest.assertions["gemma.witness.model_fingerprint"].sha256;
  const modelId = manifest.assertions["gemma.witness.model_fingerprint"].model_id;
  const revision = manifest.assertions["gemma.witness.model_fingerprint"].revision;

  const byHash = known.fingerprints.find((f) => f.sha256 === claimed);
  if (!byHash) {
    return {
      name: "Model fingerprint known",
      passed: false,
      details: [
        `model fingerprint ${claimed} for "${modelId}" (revision ${revision}) is not on the known-good list. update apps/verifier/known-fingerprints.json after publishing or approving this model revision.`,
      ],
    };
  }
  if (byHash.model_id !== modelId || byHash.revision !== revision) {
    return {
      name: "Model fingerprint known",
      passed: false,
      details: [
        `model fingerprint ${claimed} is registered but for "${byHash.model_id}" (revision ${byHash.revision}), ` +
          `not the manifest's claimed "${modelId}" (revision ${revision}). ` +
          `a registered SHA-256 must match the registered (model_id, revision) tuple to be trusted; ` +
          `a divergence indicates the bundle is claiming a model_id the registry does not own.`,
      ],
    };
  }
  return {
    name: "Model fingerprint known",
    passed: true,
    details: [
      `matched (model_id="${byHash.model_id}", revision=${byHash.revision}, sha256=${byHash.sha256}).`,
    ],
  };
}
