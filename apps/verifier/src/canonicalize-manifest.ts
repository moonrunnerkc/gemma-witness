import canonicalizeJson from "canonicalize";

import type { Manifest } from "./types";

/**
 * Produce the RFC 8785 JCS canonical bytes of a manifest.
 *
 * This is the exact byte sequence the signature was computed over in the
 * capture app. Reordering manifest keys must not change these bytes.
 *
 * @param manifest - Parsed manifest object.
 * @returns UTF-8 bytes of the canonical JSON string.
 * @throws If the manifest contains values that cannot be canonicalized.
 */
export function canonicalizeManifest(manifest: Manifest): Uint8Array {
  const text = canonicalizeJson(manifest);
  if (text === undefined) {
    throw new Error(
      "manifest could not be canonicalized: check for non-serializable values such as undefined, NaN, or circular references.",
    );
  }
  return new TextEncoder().encode(text);
}
