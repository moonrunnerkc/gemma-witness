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

/** The assertions block, namespaced per the manifest schema. */
export interface Assertions {
  "gemma.witness.model_fingerprint": ModelFingerprint;
  "gemma.witness.incident_report": unknown;
  "gemma.witness.reasoning_trace": ReasoningTrace;
  "gemma.witness.consistency_verdict": ConsistencyVerdict;
  "gemma.witness.capture_environment": CaptureEnvironment;
}

/** Top-level manifest shape. */
export interface Manifest {
  manifest_version: number;
  bundle_id: string;
  created_at: string;
  signer: SignerInfo;
  assets: AssetEntry[];
  assertions: Assertions;
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
}

/** The parsed known-fingerprints.json envelope. */
export interface KnownFingerprints {
  schema_version: number;
  fingerprints: KnownFingerprint[];
}

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
