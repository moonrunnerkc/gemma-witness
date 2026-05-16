import {
  extractBundleEntries,
  readManifest,
  readSignatureDocument,
} from "./bundle-reader";
import { verifySignature } from "./verify-signature";
import { verifyAssetHashes } from "./verify-asset-hashes";
import { verifyModelFingerprint } from "./verify-model-fingerprint";
import { verifyAmendmentChain } from "./verify-amendment-chain";
import { verifySignerIdentity } from "./verify-signer-identity";
import { verifyRegistrySignature } from "./verify-registry-signature";
import type {
  Manifest,
  SignatureDocument,
  VerificationResult,
  CheckOutcome,
  KnownFingerprints,
  TrustedSigners,
  RegistryVerification,
} from "./types";

/**
 * Verify a `.witness` bundle from raw bytes.
 *
 * Performs three checks in order: signature validity, asset hash integrity,
 * and model fingerprint membership in the known-fingerprints list.
 *
 * @param buffer - Raw bytes of the `.witness` ZIP file.
 * @param knownFingerprints - Parsed known-fingerprints envelope.
 * @param trustedSigners - Parsed trusted-signers envelope.
 * @param registryVerification - Build-time Sigstore verification result
 *   for the fingerprint registry. `null` indicates the verifier was built
 *   without it (treated as a hard failure).
 * @returns A {@link VerificationResult} with per-check outcomes and an overall
 *   `ok` flag.
 */
export async function verifyBundle(
  buffer: ArrayBuffer,
  knownFingerprints: KnownFingerprints,
  trustedSigners: TrustedSigners,
  registryVerification: RegistryVerification | null,
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

  checks.push(
    runCheckSync("Registry signature", () =>
      verifyRegistrySignature(registryVerification),
    ),
  );
  checks.push(await runCheck("Signature valid", () => verifySignature(manifest, sigDoc)));
  checks.push(runCheckSync("Assets untampered", () => verifyAssetHashes(manifest, entries)));
  checks.push(
    runCheckSync("Model fingerprint known", () =>
      verifyModelFingerprint(manifest, knownFingerprints),
    ),
  );
  checks.push(
    runCheckSync("Signed by a known witness", () =>
      verifySignerIdentity(manifest, trustedSigners),
    ),
  );
  if (manifest.amends) {
    checks.push(
      runCheckSync("Amendment chain consistent", () =>
        verifyAmendmentChain(manifest),
      ),
    );
  }

  const ok = checks.every((c) => c.passed);
  return { ok, checks, manifest, error: null };
}

/**
 * Run an async check function and convert any thrown error into a failing
 * {@link CheckOutcome}. Without this, a bug in any one check (or a malformed
 * but parseable bundle that trips an index-into-undefined) would bubble out
 * of `verifyBundleLogic` as an unhandled promise rejection, leaving the
 * previous render on screen.
 */
async function runCheck(
  name: string,
  fn: () => Promise<CheckOutcome>,
): Promise<CheckOutcome> {
  try {
    return await fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      name,
      passed: false,
      details: [
        `internal verifier error while running "${name}": ${message}. the bundle may be malformed in a way the verifier did not anticipate.`,
      ],
    };
  }
}

function runCheckSync(name: string, fn: () => CheckOutcome): CheckOutcome {
  try {
    return fn();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      name,
      passed: false,
      details: [
        `internal verifier error while running "${name}": ${message}. the bundle may be malformed in a way the verifier did not anticipate.`,
      ],
    };
  }
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
