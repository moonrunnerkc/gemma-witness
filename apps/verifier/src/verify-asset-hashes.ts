import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

import type { Manifest, CheckOutcome } from "./types";

/**
 * Recompute SHA-256 of every asset listed in the manifest and compare against
 * the manifest claims.
 *
 * @param manifest - Parsed manifest object.
 * @param entries - Map of in-zip path to raw bytes.
 * @returns A {@link CheckOutcome} with `passed` true only when every asset
 *   hash and size matches.
 */
export function verifyAssetHashes(
  manifest: Manifest,
  entries: Map<string, Uint8Array>,
): CheckOutcome {
  const details: string[] = [];
  let allOk = true;

  for (const asset of manifest.assets) {
    const bytes = entries.get(asset.path);
    if (bytes === undefined) {
      details.push(
        `asset "${asset.path}" is listed in the manifest but missing from the bundle ZIP. the archive may be incomplete or the asset path may have changed after signing.`,
      );
      allOk = false;
      continue;
    }

    if (bytes.length !== asset.bytes) {
      details.push(
        `asset "${asset.path}" byte length ${bytes.length} does not match manifest claim ${asset.bytes}. the asset was likely replaced or re-encoded after signing.`,
      );
      allOk = false;
    }

    const actual = bytesToHex(sha256(bytes));
    if (actual !== asset.sha256) {
      details.push(
        `asset "${asset.path}" hash mismatch: manifest expected ${asset.sha256}, recomputed ${actual}. the bundle has been modified after signing, or the ZIP entry was rewritten with different bytes.`,
      );
      allOk = false;
    }
  }

  return {
    name: "Assets untampered",
    passed: allOk,
    details,
  };
}
