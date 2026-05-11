import {
  extractBundleEntries,
  readManifest,
  readSignatureDocument,
} from "./bundle-reader";
import { verifySignature } from "./verify-signature";
import { verifyAssetHashes } from "./verify-asset-hashes";
import { verifyModelFingerprint } from "./verify-model-fingerprint";
import type {
  Manifest,
  SignatureDocument,
  VerificationResult,
  CheckOutcome,
  KnownFingerprints,
} from "./types";

/**
 * Verify a `.witness` bundle from raw bytes.
 *
 * Performs three checks in order: signature validity, asset hash integrity,
 * and model fingerprint membership in the known-fingerprints list.
 *
 * @param buffer - Raw bytes of the `.witness` ZIP file.
 * @param knownFingerprints - Parsed known-fingerprints envelope.
 * @returns A {@link VerificationResult} with per-check outcomes and an overall
 *   `ok` flag.
 */
export async function verifyBundle(
  buffer: ArrayBuffer,
  knownFingerprints: KnownFingerprints,
): Promise<VerificationResult> {
  let manifest: Manifest;
  let sigDoc: SignatureDocument;
  let entries: Map<string, Uint8Array>;

  try {
    entries = extractBundleEntries(buffer);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      checks: [],
      manifest: null,
      error: `could not open bundle as ZIP: ${message}. ensure the file is a valid .witness archive and not corrupted.`,
    };
  }

  try {
    manifest = readManifest(entries);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      checks: [],
      manifest: null,
      error: `could not read manifest: ${message}`,
    };
  }

  try {
    sigDoc = readSignatureDocument(entries);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      checks: [],
      manifest,
      error: `could not read signature document: ${message}`,
    };
  }

  const versionCheck = routeVersion(manifest);
  if (!versionCheck.passed) {
    return {
      ok: false,
      checks: [versionCheck],
      manifest,
      error: null,
    };
  }

  const checks: CheckOutcome[] = [];

  const signatureCheck = await verifySignature(manifest, sigDoc);
  checks.push(signatureCheck);

  const assetCheck = verifyAssetHashes(manifest, entries);
  checks.push(assetCheck);

  const fingerprintCheck = verifyModelFingerprint(manifest, knownFingerprints);
  checks.push(fingerprintCheck);

  const ok = checks.every((c) => c.passed);
  return { ok, checks, manifest, error: null };
}

function routeVersion(manifest: Manifest): CheckOutcome {
  const supported = [1];
  if (!supported.includes(manifest.manifest_version)) {
    return {
      name: "Manifest version supported",
      passed: false,
      details: [
        `manifest_version ${manifest.manifest_version} is not supported by this verifier. supported versions are: ${supported.join(", ")}. obtain a newer verifier or regenerate the bundle with a compatible capture app.`,
      ],
    };
  }
  return {
    name: "Manifest version supported",
    passed: true,
    details: [],
  };
}
