import { verifyAsync } from "@noble/ed25519";
import { p256 } from "@noble/curves/nist.js";

import type { Manifest, SignatureDocument, CheckOutcome } from "./types";
import { canonicalizeManifest } from "./canonicalize-manifest";
import { parsePublicKeyPem } from "./parse-public-key";
import { parsePublicKeyPemP256 } from "./parse-public-key-p256";

const ALGORITHM_ED25519 = "ed25519";
const ALGORITHM_ECDSA_P256 = "ecdsa-p256";

/** Algorithms each manifest version may declare in `signer.algorithm` and
 *  `signature.algorithm`. The per-version restriction prevents a v1 verifier
 *  from being asked to render a field shape it does not understand. */
function algorithmsPermittedForVersion(version: number): readonly string[] {
  switch (version) {
    case 1:
      return [ALGORITHM_ED25519];
    case 2:
      return [ALGORITHM_ED25519, ALGORITHM_ECDSA_P256];
    default:
      return [];
  }
}

/**
 * Verify the manifest signature against the embedded public key, routing
 * by `signer.algorithm`. v1 manifests are restricted to Ed25519; v2 may
 * additionally use ECDSA P-256. This build only ships the Ed25519 backend,
 * so a v2 manifest declaring `ecdsa-p256` fails the row with a clear
 * "not yet implemented" detail rather than misverifying.
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

  const permitted = algorithmsPermittedForVersion(manifest.manifest_version);
  if (!permitted.includes(sigDoc.algorithm)) {
    details.push(
      `signature.algorithm is "${sigDoc.algorithm}"; manifest_version ${manifest.manifest_version} permits only ${JSON.stringify(permitted)}. the bundle may be malformed or produced by a verifier-incompatible capture app.`,
    );
    return { name: "Signature valid", passed: false, details };
  }
  if (!permitted.includes(manifest.signer.algorithm)) {
    details.push(
      `manifest.signer.algorithm is "${manifest.signer.algorithm}"; manifest_version ${manifest.manifest_version} permits only ${JSON.stringify(permitted)}. the bundle may be malformed or produced by a verifier-incompatible capture app.`,
    );
    return { name: "Signature valid", passed: false, details };
  }
  if (sigDoc.algorithm !== manifest.signer.algorithm) {
    details.push(
      `signature.algorithm "${sigDoc.algorithm}" does not match manifest.signer.algorithm "${manifest.signer.algorithm}". the two must agree; a mismatch indicates the signature was copied from a different bundle.`,
    );
    return { name: "Signature valid", passed: false, details };
  }
  if (manifest.manifest_version === 1 && manifest.signer.attestation !== undefined) {
    details.push(
      "manifest.signer.attestation is present on a v1 manifest. the attestation blob is a v2-only field; a v1 bundle that carries it is malformed.",
    );
    return { name: "Signature valid", passed: false, details };
  }

  if (sigDoc.canonicalization !== "rfc8785") {
    details.push(
      `unsupported canonicalization "${sigDoc.canonicalization}"; expected "rfc8785". the manifest must be canonicalized per RFC 8785 for deterministic verification.`,
    );
    return { name: "Signature valid", passed: false, details };
  }

  if (sigDoc.signed_payload !== "manifest.json") {
    details.push(
      `signature.signed_payload is "${sigDoc.signed_payload}"; expected "manifest.json". this verifier only signs over manifest.json.`,
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

  if (sigDoc.key_id !== manifest.signer.key_id) {
    details.push(
      `signature key_id "${sigDoc.key_id}" does not match manifest signer.key_id "${manifest.signer.key_id}". the signature may have been copied from a different bundle.`,
    );
    return { name: "Signature valid", passed: false, details };
  }

  if (manifest.signer.algorithm === ALGORITHM_ED25519) {
    return await verifyEd25519(manifest, signatureBytes, canonical, details);
  }
  if (manifest.signer.algorithm === ALGORITHM_ECDSA_P256) {
    return verifyEcdsaP256(manifest, signatureBytes, canonical, details);
  }
  details.push(
    `manifest.signer.algorithm "${manifest.signer.algorithm}" reached signature dispatch but no backend matches. this is a verifier bug; report it.`,
  );
  return { name: "Signature valid", passed: false, details };
}

function verifyEcdsaP256(
  manifest: Manifest,
  signatureBytes: Uint8Array,
  canonical: Uint8Array,
  details: string[],
): CheckOutcome {
  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = parsePublicKeyPemP256(manifest.signer.public_key_pem);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    details.push(`public key PEM parsing failed: ${message}`);
    return { name: "Signature valid", passed: false, details };
  }
  let valid: boolean;
  try {
    // `lowS: false` matches the Rust verifier's behavior (the `p256` crate
    // accepts both low-S and high-S signatures) and is required for
    // signatures produced by Apple's Secure Enclave, whose
    // `SecKeyCreateSignature` does not normalize S to the canonical low
    // half. ECDSA malleability is irrelevant to this verifier because
    // we anchor on `signature.json.signature_b64` byte-for-byte: a
    // mutated S yields a different `signature_b64`, which a bundle
    // consumer treats as a distinct (still valid) signature, not as
    // grounds for accepting two seal events for one manifest. The
    // @noble/curves default would reject SEP/TPM/NCrypt-emitted high-S
    // signatures even though both peers agree they verify.
    valid = p256.verify(signatureBytes, canonical, publicKeyBytes, {
      format: "der",
      lowS: false,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    details.push(
      `ECDSA P-256 signature decoding failed: ${message}. the signature must be ASN.1/DER-encoded over a SHA-256 digest of the canonicalized manifest.`,
    );
    return { name: "Signature valid", passed: false, details };
  }
  if (!valid) {
    details.push(
      "signature does not verify against the embedded public key. the manifest was modified after signing, or the signature belongs to a different key.",
    );
    return { name: "Signature valid", passed: false, details };
  }
  return { name: "Signature valid", passed: true, details };
}

async function verifyEd25519(
  manifest: Manifest,
  signatureBytes: Uint8Array,
  canonical: Uint8Array,
  details: string[],
): Promise<CheckOutcome> {
  if (signatureBytes.length !== 64) {
    details.push(
      `Ed25519 signature was ${signatureBytes.length} bytes; expected 64. the bundle may be malformed or the signature truncated.`,
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
