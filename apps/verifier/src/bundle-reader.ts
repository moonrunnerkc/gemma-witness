import { unzipSync, strFromU8 } from "fflate";

import type { Manifest, SignatureDocument } from "./types";

/**
 * Extract the entries of a `.witness` ZIP from an ArrayBuffer.
 *
 * @param buffer - Raw bytes of the `.witness` file.
 * @returns A map of in-zip path to Uint8Array of raw bytes.
 * @throws If the buffer is not a valid ZIP archive.
 */
export function extractBundleEntries(
  buffer: ArrayBuffer,
): Map<string, Uint8Array> {
  const bytes = new Uint8Array(buffer);
  const entries = unzipSync(bytes);
  const out = new Map<string, Uint8Array>();
  for (const [path, data] of Object.entries(entries)) {
    out.set(path, data);
  }
  return out;
}

/**
 * Decode `manifest.json` from raw ZIP bytes.
 *
 * @param entries - Map produced by {@link extractBundleEntries}.
 * @returns Parsed manifest object.
 * @throws If the entry is missing or not valid JSON.
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
  if (!isManifest(parsed)) {
    throw new Error(
      "manifest.json does not match the expected schema: verify the bundle was produced by a compatible Gemma.Witness capture app.",
    );
  }
  return parsed;
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
  if (!isSignatureDocument(parsed)) {
    throw new Error(
      "signature.json does not match the expected schema: verify the bundle was produced by a compatible Gemma.Witness capture app.",
    );
  }
  return parsed;
}

function isManifest(value: unknown): value is Manifest {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.manifest_version === "number" &&
    typeof v.bundle_id === "string" &&
    Array.isArray(v.assets) &&
    typeof v.assertions === "object" &&
    v.assertions !== null
  );
}

function isSignatureDocument(value: unknown): value is SignatureDocument {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.algorithm === "string" &&
    typeof v.key_id === "string" &&
    typeof v.signature_b64 === "string" &&
    typeof v.signed_payload === "string" &&
    typeof v.canonicalization === "string"
  );
}
