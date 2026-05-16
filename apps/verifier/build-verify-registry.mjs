import * as fs from "node:fs";
import * as path from "node:path";
import * as url from "node:url";
import { verify as sigstoreVerify } from "sigstore";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

/**
 * Build-time Sigstore verification of the inference/fingerprints/ registry
 * envelope. Mirrors the Rust build.rs gate in
 * `crates/witness-fingerprints/build.rs`: the verifier's static HTML is
 * built only against a registry whose signature chains to the pinned
 * cosign OIDC identity. A placeholder envelope (no signature yet) emits a
 * loud warning and returns `{ placeholder: true }`; a tampered or
 * malformed signature throws.
 *
 * The trust chain transfer at runtime:
 *   1. Release pipeline signs SHASUMS256.txt covering verify.html.
 *   2. verify.html embeds the verification result of this function.
 *   3. A user who pins the maintainer's cosign identity (RELEASE.md
 *      §"Trust anchors") transitively trusts the embedded result.
 *
 * @returns {Promise<{
 *   placeholder: true,
 *   covered_files: Array<{path: string, sha256: string}>
 * } | {
 *   placeholder: false,
 *   covered_files: Array<{path: string, sha256: string}>,
 *   identity: string,
 *   issuer: string,
 *   signed_at_utc: string,
 * }>}
 * @throws if signature verification fails or the bundle is malformed.
 */
export async function verifyRegistry() {
  const registryDir = path.join(__dirname, "..", "..", "inference", "fingerprints");
  const envelopePath = path.join(registryDir, "registry-manifest.json");
  const bundlePath = path.join(registryDir, "registry-manifest.sigstore");

  const envelopeBytes = fs.readFileSync(envelopePath);
  /** @type {{
   *   placeholder: boolean,
   *   covered_files: Array<{path: string, sha256: string}>,
   *   signed_at_utc?: string,
   * }} */
  const envelope = JSON.parse(envelopeBytes.toString("utf-8"));

  if (envelope.placeholder) {
    console.warn(
      "WARNING: inference/fingerprints/registry-manifest.json is a placeholder. " +
        "the Sigstore signature gate is not in effect on this verifier build. " +
        "release builds must run sign-fingerprints.yml first.",
    );
    return {
      placeholder: true,
      covered_files: envelope.covered_files,
    };
  }

  if (!fs.existsSync(bundlePath)) {
    throw new Error(
      `registry-manifest.json declares placeholder=false but ${bundlePath} is missing. ` +
        "either re-run the signing workflow or revert the envelope to placeholder=true.",
    );
  }
  const bundle = JSON.parse(fs.readFileSync(bundlePath, "utf-8"));

  // The cosign keyless OIDC identity that signs the envelope is the same
  // one that signs SHASUMS256.txt in release.yml. Updating this constant
  // requires updating RELEASE.md §"Trust anchors" and
  // crates/witness-fingerprint-verify/src/signature.rs in lockstep.
  const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
  const CERT_IDENTITY_PREFIX =
    "https://github.com/moonrunnerkc/gemma-witness/.github/workflows/release.yml@refs/tags/v";

  let signer;
  try {
    // sigstore.verify exact-matches identity strings, so we pass only the
    // issuer here and apply the workflow-path prefix check below. This
    // is the same shape as the Rust path in
    // crates/witness-fingerprint-verify/src/signature.rs.
    signer = await sigstoreVerify(bundle, envelopeBytes, {
      certificateIssuer: OIDC_ISSUER,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(
      `registry envelope signature did not verify: ${message}. ` +
        "either the envelope was tampered with after signing, or the pinned " +
        "OIDC identity has rotated and RELEASE.md is out of date.",
    );
  }

  const identity = signer.identity?.subjectAlternativeName;
  if (typeof identity !== "string" || identity.length === 0) {
    throw new Error(
      "registry envelope signature verified but the certificate did not surface a SAN identity. " +
        "the cosign sign-blob run that produced this envelope was not from a tagged release workflow.",
    );
  }
  if (!(identity.length > CERT_IDENTITY_PREFIX.length && identity.startsWith(CERT_IDENTITY_PREFIX))) {
    throw new Error(
      `registry envelope signature verified, but certificate identity ${identity} ` +
        `does not match the pinned release.yml workflow path. ` +
        `expected prefix ${CERT_IDENTITY_PREFIX}<tag>. ` +
        "update RELEASE.md and CERT_IDENTITY_PREFIX in lockstep if the repository moved.",
    );
  }
  if (typeof envelope.signed_at_utc !== "string" || envelope.signed_at_utc.length === 0) {
    throw new Error(
      "registry envelope signature verified but signed_at_utc is missing or empty. " +
        "run sign-fingerprints finalize before signing.",
    );
  }

  return {
    placeholder: false,
    covered_files: envelope.covered_files,
    identity,
    issuer: OIDC_ISSUER,
    signed_at_utc: envelope.signed_at_utc,
  };
}
