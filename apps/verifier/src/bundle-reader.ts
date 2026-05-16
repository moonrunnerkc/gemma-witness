import { unzipSync, strFromU8 } from "fflate";

import type { Manifest, SignatureDocument } from "./types";

/**
 * Hard cap on the sum of all decompressed entries in a bundle. Mirrors the
 * Rust verifier's `MAX_BUNDLE_DECOMPRESSED_BYTES`. 200 MiB accommodates four
 * 10 MiB images plus the rest of a legitimate bundle with large headroom and
 * still bounds the worst-case zip-bomb a journalist might receive over a
 * shared link.
 */
export const MAX_BUNDLE_DECOMPRESSED_BYTES = 200 * 1024 * 1024;

/**
 * Hard cap on the uncompressed size of any single ZIP entry. 100 MiB is
 * orders of magnitude over the largest legitimate witness asset (a 30-s WAV
 * at 16 kHz mono is under 2 MiB; a JPEG capped to 10 MiB; reasoning trace is
 * tens of KB). Mirrors the Rust verifier's `MAX_ENTRY_DECOMPRESSED_BYTES`.
 */
export const MAX_ENTRY_DECOMPRESSED_BYTES = 100 * 1024 * 1024;

/**
 * Hard cap on the compressed input size as a backstop. fflate's `unzipSync`
 * decompresses every entry in one shot, so we also need an input-side cap;
 * 50 MiB is far over any realistic `.witness` file shipped to a journalist.
 */
export const MAX_BUNDLE_COMPRESSED_BYTES = 50 * 1024 * 1024;

/**
 * Extract the entries of a `.witness` ZIP from an ArrayBuffer.
 *
 * Enforces the following safety invariants against hostile input:
 * - Compressed input is bounded at {@link MAX_BUNDLE_COMPRESSED_BYTES}.
 * - Total decompressed bytes are bounded at
 *   {@link MAX_BUNDLE_DECOMPRESSED_BYTES}.
 * - No single entry exceeds {@link MAX_ENTRY_DECOMPRESSED_BYTES}.
 * - Entry names are validated against path traversal (`..`), absolute paths
 *   (`/...`), backslashes, embedded NUL bytes, and empty names.
 * - Duplicate entry names are rejected outright; different ZIP parsers
 *   resolve duplicates inconsistently and the ambiguity is unsafe.
 *
 * @param buffer - Raw bytes of the `.witness` file.
 * @returns A map of in-zip path to Uint8Array of raw bytes.
 * @throws If the buffer is not a valid ZIP, exceeds a size cap, contains an
 *   unsafe entry name, or contains duplicate entry names.
 */
export function extractBundleEntries(
  buffer: ArrayBuffer,
): Map<string, Uint8Array> {
  if (buffer.byteLength > MAX_BUNDLE_COMPRESSED_BYTES) {
    throw new Error(
      `bundle is ${buffer.byteLength} bytes compressed; cap is ${MAX_BUNDLE_COMPRESSED_BYTES}. refusing to read: bundle is implausibly large for a witness capture and may be a zip-bomb.`,
    );
  }
  const bytes = new Uint8Array(buffer);
  const entries = unzipSync(bytes);
  const out = new Map<string, Uint8Array>();
  let total = 0;
  for (const [path, data] of Object.entries(entries)) {
    validateEntryName(path);
    if (out.has(path)) {
      throw new Error(
        `ZIP contains duplicate entry name "${path}". refusing to read: different ZIP parsers resolve duplicates inconsistently and could verify the wrong copy.`,
      );
    }
    if (data.length > MAX_ENTRY_DECOMPRESSED_BYTES) {
      throw new Error(
        `ZIP entry "${path}" decompresses to ${data.length} bytes; per-entry cap is ${MAX_ENTRY_DECOMPRESSED_BYTES}. refusing to read: bundle may be a zip-bomb or otherwise malformed.`,
      );
    }
    total += data.length;
    if (total > MAX_BUNDLE_DECOMPRESSED_BYTES) {
      throw new Error(
        `ZIP total decompressed size exceeded the bundle cap of ${MAX_BUNDLE_DECOMPRESSED_BYTES} bytes. refusing to read: bundle may be a zip-bomb or otherwise malformed.`,
      );
    }
    out.set(path, data);
  }
  return out;
}

function validateEntryName(name: string): void {
  if (!name) {
    throw new Error("ZIP entry name is empty");
  }
  if (name.includes("\0")) {
    throw new Error(`ZIP entry name "${name}" contains a NUL byte`);
  }
  if (name.startsWith("/")) {
    throw new Error(
      `ZIP entry name "${name}" is an absolute path. conforming bundles use only relative POSIX paths.`,
    );
  }
  if (name.includes("\\")) {
    throw new Error(
      `ZIP entry name "${name}" contains a backslash. conforming bundles use only forward-slash POSIX paths.`,
    );
  }
  for (const segment of name.split("/")) {
    if (segment === "..") {
      throw new Error(
        `ZIP entry name "${name}" contains a parent-directory traversal. refusing to read: this would ZIP-slip any downstream extractor.`,
      );
    }
  }
}

/**
 * Decode `manifest.json` from raw ZIP bytes and validate that every assertion
 * the verifier subsequently indexes is present and well-typed.
 *
 * The verifier's check chain reads `assertions["gemma.witness.model_fingerprint"].sha256`
 * directly; a missing assertion would throw TypeError and crash the verifier
 * silently. Validating the structure up front turns the silent failure into a
 * named, rendered error.
 *
 * @param entries - Map produced by {@link extractBundleEntries}.
 * @returns Parsed manifest object.
 * @throws If the entry is missing, not valid JSON, or fails the structural
 *   validation (missing required fields, wrong types, missing required
 *   assertions).
 */
export function readManifest(entries: Map<string, Uint8Array>): Manifest {
  const raw = entries.get("manifest.json");
  if (!raw) {
    throw new Error(
      "bundle is missing manifest.json: not a valid .witness archive.",
    );
  }
  const text = strFromU8(raw);
  const parsed: unknown = JSON.parse(text);
  return validateManifest(parsed);
}

/**
 * Decode `signature.json` from raw ZIP bytes.
 *
 * @param entries - Map produced by {@link extractBundleEntries}.
 * @returns Parsed signature document.
 * @throws If the entry is missing or not valid JSON.
 */
export function readSignatureDocument(
  entries: Map<string, Uint8Array>,
): SignatureDocument {
  const raw = entries.get("signature.json");
  if (!raw) {
    throw new Error(
      "bundle is missing signature.json: not a valid .witness archive.",
    );
  }
  const text = strFromU8(raw);
  const parsed: unknown = JSON.parse(text);
  return validateSignatureDocument(parsed);
}

function isStringRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function requireString(
  parent: Record<string, unknown>,
  parentName: string,
  key: string,
): string {
  const value = parent[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(
      `manifest.${parentName}.${key} is missing or not a non-empty string. the bundle may have been produced by an incompatible capture app.`,
    );
  }
  return value;
}

function validateSignerAttestation(
  signer: Record<string, unknown>,
  manifestVersion: number,
): void {
  const attestation = signer.attestation;
  if (attestation === undefined) {
    return;
  }
  if (manifestVersion === 1) {
    throw new Error(
      "manifest.signer.attestation is present on a v1 manifest. the attestation blob is a v2-only field; a v1 bundle that carries it is malformed.",
    );
  }
  if (!isStringRecord(attestation)) {
    throw new Error(
      "manifest.signer.attestation is present but is not an object.",
    );
  }
  requireString(attestation, "signer.attestation", "format");
  requireString(attestation, "signer.attestation", "payload_b64");
  const chain = attestation.certificate_chain_b64;
  if (chain !== undefined) {
    if (!Array.isArray(chain)) {
      throw new Error(
        "manifest.signer.attestation.certificate_chain_b64 is present but is not an array.",
      );
    }
    for (const [i, item] of chain.entries()) {
      if (typeof item !== "string" || item.length === 0) {
        throw new Error(
          `manifest.signer.attestation.certificate_chain_b64[${i}] is not a non-empty string.`,
        );
      }
    }
  }
}

function requireNumber(
  parent: Record<string, unknown>,
  parentName: string,
  key: string,
): number {
  const value = parent[key];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(
      `manifest.${parentName}.${key} is missing or not a finite number. the bundle may have been produced by an incompatible capture app.`,
    );
  }
  return value;
}

function requireObject(
  parent: Record<string, unknown>,
  parentName: string,
  key: string,
): Record<string, unknown> {
  const value = parent[key];
  if (!isStringRecord(value)) {
    throw new Error(
      `manifest.${parentName}.${key} is missing or not an object. the bundle may have been produced by an incompatible capture app.`,
    );
  }
  return value;
}

/**
 * Validate the parsed manifest against the structural shape the verifier
 * relies on. Throws a named error on any failure rather than letting a later
 * index-into-undefined throw TypeError.
 *
 * This is a structural runtime check, not a schema validation. It enforces:
 * - top-level required fields (`manifest_version`, `bundle_id`, `created_at`,
 *   `signer`, `assets`, `assertions`)
 * - signer block has `algorithm`, `public_key_pem`, `key_id`
 * - every asset entry has `path`, `media_type`, `sha256`, `bytes`
 * - assertions block carries every required assertion the verifier reads
 */
export function validateManifest(parsed: unknown): Manifest {
  if (!isStringRecord(parsed)) {
    throw new Error("manifest.json is not a JSON object.");
  }
  const manifestVersion = requireNumber(parsed, "", "manifest_version");
  requireString(parsed, "", "bundle_id");
  requireString(parsed, "", "created_at");

  const signer = requireObject(parsed, "", "signer");
  requireString(signer, "signer", "algorithm");
  requireString(signer, "signer", "public_key_pem");
  requireString(signer, "signer", "key_id");
  validateSignerAttestation(signer, manifestVersion);

  const assets = parsed.assets;
  if (!Array.isArray(assets)) {
    throw new Error("manifest.assets is missing or not an array.");
  }
  for (const [i, entry] of assets.entries()) {
    if (!isStringRecord(entry)) {
      throw new Error(`manifest.assets[${i}] is not an object.`);
    }
    requireString(entry, `assets[${i}]`, "path");
    requireString(entry, `assets[${i}]`, "media_type");
    requireString(entry, `assets[${i}]`, "sha256");
    requireNumber(entry, `assets[${i}]`, "bytes");
  }

  const assertions = requireObject(parsed, "", "assertions");
  const required: ReadonlyArray<[string, ReadonlyArray<string>]> = [
    ["gemma.witness.model_fingerprint", ["model_id", "revision", "sha256"]],
    ["gemma.witness.incident_report", []],
    ["gemma.witness.reasoning_trace", ["asset_path", "sha256", "bytes"]],
    ["gemma.witness.consistency_verdict", ["verdict"]],
    [
      "gemma.witness.capture_environment",
      ["os", "app_version", "captured_at"],
    ],
  ];
  for (const [key, fields] of required) {
    const block = assertions[key];
    if (!isStringRecord(block)) {
      throw new Error(
        `manifest.assertions["${key}"] is missing or not an object. cannot verify a bundle that omits this assertion.`,
      );
    }
    for (const field of fields) {
      if (block[field] === undefined || block[field] === null) {
        throw new Error(
          `manifest.assertions["${key}"].${field} is missing. cannot verify a bundle that omits this field.`,
        );
      }
    }
  }

  if (parsed.amends !== undefined && parsed.amends !== null) {
    const amends = parsed.amends;
    if (!isStringRecord(amends)) {
      throw new Error("manifest.amends is present but is not an object.");
    }
    requireString(amends, "amends", "original_bundle_id");
    requireString(amends, "amends", "original_manifest_sha256");
    requireString(amends, "amends", "original_signer_key_id");
    requireString(amends, "amends", "reason");
  }

  return parsed as unknown as Manifest;
}

/**
 * Validate the parsed signature.json document against the structural shape
 * the verifier relies on.
 */
function validateSignatureDocument(parsed: unknown): SignatureDocument {
  if (!isStringRecord(parsed)) {
    throw new Error("signature.json is not a JSON object.");
  }
  requireString(parsed, "", "algorithm");
  requireString(parsed, "", "key_id");
  requireString(parsed, "", "signature_b64");
  requireString(parsed, "", "signed_payload");
  requireString(parsed, "", "canonicalization");
  return parsed as unknown as SignatureDocument;
}
