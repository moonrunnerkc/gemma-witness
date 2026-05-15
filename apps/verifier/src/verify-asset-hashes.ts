import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

import type { Manifest, CheckOutcome } from "./types";

/**
 * Recompute SHA-256 of every asset listed in the manifest and compare against
 * the manifest claims. Additionally reject any ZIP entry that is not bound by
 * the signature.
 *
 * The signed manifest only commits to `manifest.json` (via the signature) and
 * to each `assets[].path` (via the asset hash list). Anything else in the ZIP
 * - injected images, an `index.html` XSS payload, a substituted public key -
 * is not covered by the signature; accepting it would let an attacker append
 * arbitrary content to a legitimately signed bundle.
 *
 * @param manifest - Parsed manifest object.
 * @param entries - Map of in-zip path to raw bytes.
 * @returns A {@link CheckOutcome} with `passed` true only when every asset
 *   hash and size matches and no extra ZIP entries are present.
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

  const allowed = new Set<string>(["manifest.json", "signature.json"]);
  for (const asset of manifest.assets) {
    allowed.add(asset.path);
  }
  for (const name of entries.keys()) {
    if (!allowed.has(name)) {
      details.push(
        `ZIP entry "${name}" is not bound by the signature. conforming bundles contain only manifest.json, signature.json, and the asset paths listed in manifest.assets. extras may have been appended to a legitimately signed bundle and must not be trusted.`,
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
