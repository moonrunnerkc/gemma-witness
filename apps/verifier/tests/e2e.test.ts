// End-to-end tests for the Gemma.Witness static verifier.
//
// Uses the real JS verifier modules on real fixture bundles. Mutates ZIP
// entries to assert per-row pass/fail behavior.
//
// Run: cd apps/verifier && npx tsx tests/e2e.test.ts

import * as fs from "node:fs";
import * as path from "node:path";
import * as url from "node:url";
import { unzipSync, zipSync, strFromU8 } from "fflate";

import { verifyBundle } from "../src/verify-logic";
import type { KnownFingerprints } from "../src/types";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

const FIXTURE = path.join(
  __dirname,
  "../../..",
  "tests/fixtures/day-4-fixture.witness",
);

const KNOWN_WITH_FINGERPRINT: KnownFingerprints = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "known-fingerprints.json"),
    "utf-8",
  ),
);

const KNOWN_EMPTY: KnownFingerprints = {
  schema_version: 1,
  fingerprints: [],
};

function toArrayBuffer(buf: Buffer): ArrayBuffer {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function readFixture(): ArrayBuffer {
  return toArrayBuffer(fs.readFileSync(FIXTURE));
}

function mutateBundle(
  mutation: (entries: Map<string, Uint8Array>) => void,
): ArrayBuffer {
  const buf = fs.readFileSync(FIXTURE);
  const entriesMap = new Map<string, Uint8Array>();
  const rawEntries = unzipSync(new Uint8Array(buf));
  for (const [k, v] of Object.entries(rawEntries)) {
    entriesMap.set(k, v);
  }
  mutation(entriesMap);

  const files: Record<string, Uint8Array> = {};
  for (const [k, v] of entriesMap) {
    files[k] = v;
  }
  const zipped = zipSync(files, { level: 0 });
  return toArrayBuffer(Buffer.from(zipped));
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`ASSERTION FAILED: ${message}`);
  }
}

async function runTests(): Promise<void> {
  // T1: Positive.
  console.log("--- T1 (positive): valid fixture bundle");
  {
    const outcome = await verifyBundle(readFixture(), KNOWN_WITH_FINGERPRINT);
    assert(outcome.ok, "T1: overall should be OK");
    assert(outcome.checks.length >= 3, "T1: should have at least 3 checks");
    assert(outcome.checks[0].passed, "T1: signature row should pass");
    assert(outcome.checks[1].passed, "T1: asset row should pass");
    assert(outcome.checks[2].passed, "T1: fingerprint row should pass");
    console.log("PASS T1");
  }

  // T2: Flip one byte in assets/audio.wav.
  console.log("--- T2 (negative): flip byte in assets/audio.wav");
  {
    const mutated = mutateBundle((entries) => {
      const audio = entries.get("assets/audio.wav")!;
      audio[100] ^= 0x42;
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT);
    assert(!outcome.ok, "T2: overall should fail");
    assert(outcome.checks[0].passed, "T2: signature row should still pass");
    assert(!outcome.checks[1].passed, "T2: asset row should fail");
    assert(
      outcome.checks[1].details.some((d) => d.includes("assets/audio.wav")),
      "T2: asset row should name the modified asset",
    );
    assert(outcome.checks[2].passed, "T2: fingerprint row should still pass");
    console.log("PASS T2");
  }

  // T3: Replace signature bytes with random garbage.
  console.log("--- T3 (negative): corrupt signature");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("signature.json")!;
      const sigDoc = JSON.parse(strFromU8(raw));
      const garbage = new Uint8Array(64);
      for (let i = 0; i < 64; i++) {
        garbage[i] = Math.floor(Math.random() * 256);
      }
      sigDoc.signature_b64 = Buffer.from(garbage).toString("base64");
      entries.set(
        "signature.json",
        new TextEncoder().encode(JSON.stringify(sigDoc)),
      );
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT);
    assert(!outcome.ok, "T3: overall should fail");
    assert(!outcome.checks[0].passed, "T3: signature row should fail");
    assert(outcome.checks[1].passed, "T3: asset row should still pass");
    assert(outcome.checks[2].passed, "T3: fingerprint row should still pass");
    console.log("PASS T3");
  }

  // T4: Unknown model fingerprint using an empty known list.
  console.log("--- T4 (negative): unknown model fingerprint (empty registry)");
  {
    const outcome = await verifyBundle(readFixture(), KNOWN_EMPTY);
    assert(!outcome.ok, "T4: overall should fail");
    assert(outcome.checks[0].passed, "T4: signature row should still pass");
    assert(outcome.checks[1].passed, "T4: asset row should still pass");
    assert(!outcome.checks[2].passed, "T4: fingerprint row should fail");
    assert(
      outcome.checks[2].details.some((d) => d.includes("not on the known-good list")),
      "T4: fingerprint row should mention known-good list",
    );
    console.log("PASS T4");
  }

  // T4b: Unknown model fingerprint with the real shipped registry.
  // Mutate the manifest assertion to a hash not in known-fingerprints.json,
  // leave the signature and assets untouched. The signature row will also
  // fail because the manifest changed, but the critical assertion is that
  // the fingerprint row fails against the real registry.
  console.log("--- T4b (negative): unknown fingerprint against real registry");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      const fp = manifest.assertions["gemma.witness.model_fingerprint"];
      fp.sha256 = "a0".repeat(32);
      entries.set(
        "manifest.json",
        new TextEncoder().encode(JSON.stringify(manifest)),
      );
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT);
    assert(!outcome.ok, "T4b: overall should fail");
    // Signature fails because manifest bytes changed without re-signing.
    assert(!outcome.checks[0].passed, "T4b: signature row should fail (manifest mutated)");
    assert(outcome.checks[1].passed, "T4b: asset row should still pass");
    assert(!outcome.checks[2].passed, "T4b: fingerprint row should fail");
    assert(
      outcome.checks[2].details.some((d) => d.includes("not on the known-good list")),
      "T4b: fingerprint row should mention known-good list",
    );
    console.log("PASS T4b");
  }

  // T5: Reorder manifest keys without re-signing.
  // The proof is that the bytes on disk inside the ZIP have a different key
  // order than the original signed manifest, yet verification still succeeds
  // because the verifier canonicalizes per RFC 8785 before checking the signature.
  console.log("--- T5 (canonical): reorder manifest keys in ZIP bytes");
  {
    const originalBuf = fs.readFileSync(FIXTURE);
    const originalEntries = unzipSync(new Uint8Array(originalBuf));
    const originalManifestText = strFromU8(originalEntries["manifest.json"]);

    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      // Deliberately reorder top-level keys to a different order than serde
      // emitted during bundle creation.
      const reordered = {
        assertions: manifest.assertions,
        assets: manifest.assets,
        bundle_id: manifest.bundle_id,
        created_at: manifest.created_at,
        manifest_version: manifest.manifest_version,
        signer: manifest.signer,
      };
      const reorderedBytes = new TextEncoder().encode(
        JSON.stringify(reordered, null, 2),
      );
      entries.set("manifest.json", reorderedBytes);
    });

    // Verify that the mutated manifest bytes are actually different from the
    // original on-disk bytes. If they are identical, this test proves nothing.
    const mutatedEntries = unzipSync(new Uint8Array(Buffer.from(mutated)));
    const mutatedManifestText = strFromU8(mutatedEntries["manifest.json"]);
    assert(
      mutatedManifestText !== originalManifestText,
      "T5: mutated manifest bytes must differ from original; otherwise key reorder did not change the on-disk representation",
    );

    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT);
    assert(outcome.ok, "T5: overall should still be OK after key reorder");
    assert(
      outcome.checks[0].passed,
      "T5: signature must still pass (canonicalization invariant)",
    );
    assert(outcome.checks[1].passed, "T5: asset row should still pass");
    assert(outcome.checks[2].passed, "T5: fingerprint row should still pass");
    console.log("PASS T5");
  }

  // T6: Unknown manifest version.
  console.log("--- T6 (versioning): unknown manifest_version");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      manifest.manifest_version = 99;
      entries.set(
        "manifest.json",
        new TextEncoder().encode(JSON.stringify(manifest)),
      );
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT);
    assert(!outcome.ok, "T6: overall should fail");
    assert(
      outcome.checks.some(
        (c) => c.name.includes("Manifest version") && !c.passed,
      ),
      "T6: a version check should exist and fail",
    );
    assert(
      outcome.checks.some((c) =>
        c.details.some((d) => d.includes("not supported")),
      ),
      "T6: version failure should state 'not supported'",
    );
    console.log("PASS T6");
  }

  console.log("\n=== ALL E2E TESTS PASSED ===");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
