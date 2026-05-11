import { verifyAsync } from "@noble/ed25519";

import type { Manifest, SignatureDocument, CheckOutcome } from "./types";
import { canonicalizeManifest } from "./canonicalize-manifest";
import { parsePublicKeyPem } from "./parse-public-key";

/**
 * Verify the Ed25519 signature over the canonicalized manifest.
 *
 * @param manifest - Parsed manifest object.
 * @param sigDoc - Parsed signature document from the bundle.
 * @returns A {@link CheckOutcome} with `passed` set when the signature is valid.
 */
export async function verifySignature(
  manifest: Manifest,
  sigDoc: SignatureDocument,
): Promise<CheckOutcome> {
  const details: string[] = [];

  if (sigDoc.algorithm !== "ed25519") {
    details.push(
      `unsupported signature algorithm "${sigDoc.algorithm}"; expected "ed25519". only Ed25519 bundles are supported by this verifier version.`,
    );
    return { name: "Signature valid", passed: false, details };
  }

  if (sigDoc.canonicalization !== "rfc8785") {
    details.push(
      `unsupported canonicalization "${sigDoc.canonicalization}"; expected "rfc8785". the manifest must be canonicalized per RFC 8785 for deterministic verification.`,
    );
    return { name: "Signature valid", passed: false, details };
  }

  let canonical: Uint8Array;
  try {
    canonical = canonicalizeManifest(manifest);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    details.push(`manifest canonicalization failed: ${message}`);
    return { name: "Signature valid", passed: false, details };
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64Decode(sigDoc.signature_b64);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    details.push(`signature_b64 decoding failed: ${message}`);
    return { name: "Signature valid", passed: false, details };
  }

  if (signatureBytes.length !== 64) {
    details.push(
      `signature was ${signatureBytes.length} bytes; expected 64. the bundle may be malformed or the signature truncated.`,
    );
    return { name: "Signature valid", passed: false, details };
  }

  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = parsePublicKeyPem(manifest.signer.public_key_pem);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    details.push(`public key PEM parsing failed: ${message}`);
    return { name: "Signature valid", passed: false, details };
  }

  const valid = await verifyAsync(signatureBytes, canonical, publicKeyBytes);
  if (!valid) {
    details.push(
      "signature does not verify against the embedded public key. the manifest was modified after signing, or the signature belongs to a different key.",
    );
    return { name: "Signature valid", passed: false, details };
  }

  if (sigDoc.key_id !== manifest.signer.key_id) {
    details.push(
      `signature key_id "${sigDoc.key_id}" does not match manifest signer.key_id "${manifest.signer.key_id}". the signature may have been copied from a different bundle.`,
    );
    return { name: "Signature valid", passed: false, details };
  }

  return { name: "Signature valid", passed: true, details };
}

function base64Decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
