/// Types shared across the verifier modules.

/** One asset entry inside the manifest. */
export interface AssetEntry {
  path: string;
  media_type: string;
  sha256: string;
  bytes: number;
}

/** The model fingerprint assertion. */
export interface ModelFingerprint {
  model_id: string;
  revision: string;
  sha256: string;
}

/** The reasoning trace assertion. */
export interface ReasoningTrace {
  asset_path: string;
  sha256: string;
  bytes: number;
}

/** Consistency verdict labels. */
export type ConsistencyLabel = "consistent" | "inconsistent";

/** The consistency verdict assertion. */
export interface ConsistencyVerdict {
  verdict: ConsistencyLabel;
  summary?: string;
}

/** Capture environment assertion. */
export interface CaptureEnvironment {
  os: string;
  hostname?: string;
  app_version: string;
  captured_at: string;
}

/** Per-pass sampling parameters from the optional inference_parameters assertion. */
export interface PassParameters {
  temperature: number;
  top_p?: number;
  max_tokens: number;
  visual_token_budget?: number;
  prompt_sha256: string;
}

/** The optional inference_parameters assertion. */
export interface InferenceParameters {
  passes: Record<string, PassParameters>;
  sampling_seed: number | null;
  note: string;
}

/** The optional audio_fingerprint assertion. */
export interface AudioFingerprint {
  algorithm: string;
  value: string;
  note: string;
}

/** The optional manifest.amends reference. */
export interface AmendsReference {
  original_bundle_id: string;
  original_manifest_sha256: string;
  original_signer_key_id: string;
  reason: string;
}

/** The assertions block, namespaced per the manifest schema. */
export interface Assertions {
  "gemma.witness.model_fingerprint": ModelFingerprint;
  "gemma.witness.incident_report": unknown;
  "gemma.witness.reasoning_trace": ReasoningTrace;
  "gemma.witness.consistency_verdict": ConsistencyVerdict;
  "gemma.witness.capture_environment": CaptureEnvironment;
  "gemma.witness.inference_parameters"?: InferenceParameters;
  "gemma.witness.audio_fingerprint"?: AudioFingerprint;
}

/** Top-level manifest shape. */
export interface Manifest {
  manifest_version: number;
  bundle_id: string;
  created_at: string;
  signer: SignerInfo;
  assets: AssetEntry[];
  assertions: Assertions;
  amends?: AmendsReference;
}

/** Signer metadata embedded in the manifest. */
export interface SignerInfo {
  algorithm: string;
  public_key_pem: string;
  key_id: string;
}

/** Detached signature document inside the bundle. */
export interface SignatureDocument {
  algorithm: string;
  key_id: string;
  signature_b64: string;
  signed_payload: string;
  canonicalization: string;
}

/** Known fingerprint entry shipped with the verifier. */
export interface KnownFingerprint {
  model_id: string;
  revision: string;
  sha256: string;
  added_at: string;
  note: string;
  /** Storage format of the pinned artifact. Optional for back-compat with
   *  fingerprint lists generated before the format field existed; readers
   *  should treat absence as `"safetensors"`. */
  format?: "safetensors" | "gguf";
  /** Path of the file inside the model repo that the SHA-256 hashes. Optional
   *  for back-compat; readers should treat absence as `"model.safetensors"`. */
  primary_file?: string;
}

/** The parsed known-fingerprints.json envelope. */
export interface KnownFingerprints {
  schema_version: number;
  fingerprints: KnownFingerprint[];
}

/** A trusted-signers.json entry. */
export interface TrustedSigner {
  key_id: string;
  public_key_pem_sha256: string;
  label: string;
  added_at: string;
  note: string;
}

/** The parsed trusted-signers.json envelope. */
export interface TrustedSigners {
  schema_version: number;
  signers: TrustedSigner[];
}

/** One file covered by the registry envelope. */
export interface RegistryCoveredFile {
  path: string;
  sha256: string;
}

/**
 * Build-time Sigstore verification result for the fingerprint registry.
 * Inlined by apps/verifier/build.mjs from
 * `inference/fingerprints/registry-manifest.json` and
 * `registry-manifest.sigstore`. Surfaced at runtime via the
 * "Registry signature" check row. The trust chain transfer: the
 * verifier HTML is signed by SHASUMS256.txt via cosign keyless, so a
 * user who pins the maintainer's OIDC identity transitively trusts
 * this value without redoing the Sigstore dance in the browser.
 */
export type RegistryVerification =
  | {
      placeholder: true;
      covered_files: RegistryCoveredFile[];
    }
  | {
      placeholder: false;
      covered_files: RegistryCoveredFile[];
      identity: string;
      issuer: string;
      signed_at_utc: string;
    };

/** Outcome of a single verification check. */
export interface CheckOutcome {
  name: string;
  passed: boolean;
  details: string[];
}

/** Overall verification result surfaced to the UI. */
export interface VerificationResult {
  ok: boolean;
  checks: CheckOutcome[];
  manifest: Manifest | null;
  error: string | null;
}
