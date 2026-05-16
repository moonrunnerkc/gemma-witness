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
import { summarizeAttestation } from "../src/render-result";
import type {
  KnownFingerprints,
  TrustedSigners,
  RegistryVerification,
} from "../src/types";
import { sha256 } from "@noble/hashes/sha2";
import { p256 } from "@noble/curves/nist.js";
import canonicalizeJson from "canonicalize";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

const FIXTURE = path.join(
  __dirname,
  "../../..",
  "tests/fixtures/day-4-fixture.witness",
);

const SEP_FIXTURE = path.join(
  __dirname,
  "../../..",
  "tests/fixtures/secure-enclave-fixture.witness",
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

const TRUSTED_EMPTY: TrustedSigners = {
  schema_version: 1,
  signers: [],
};

/**
 * A passing build-time registry-verification result. In production the
 * verifier embeds the actual result of running `@sigstore/verify`
 * against the cosign bundle; these tests synthesize the success shape
 * so the registry-signature row passes by default. The
 * REGISTRY_PLACEHOLDER constant covers the failing path.
 */
const REGISTRY_VERIFIED: RegistryVerification = {
  placeholder: false,
  covered_files: [{ path: "index.json", sha256: "0".repeat(64) }],
  identity:
    "https://github.com/moonrunnerkc/gemma-witness/.github/workflows/release.yml@refs/tags/v0.4.0",
  issuer: "https://token.actions.githubusercontent.com",
  signed_at_utc: "2026-05-15T00:00:00Z",
};

const REGISTRY_PLACEHOLDER: RegistryVerification = {
  placeholder: true,
  covered_files: [{ path: "index.json", sha256: "0".repeat(64) }],
};

/**
 * Derive a trusted-signers registry that lists the day-4 fixture's signer as
 * trusted. The fixture's key_id and PEM-bytes hash are read out of its
 * manifest at test runtime so the registry stays in sync with whatever
 * fixture currently lives on disk.
 */
function trustedSignersFromFixture(): TrustedSigners {
  const buf = fs.readFileSync(FIXTURE);
  const entries = unzipSync(new Uint8Array(buf));
  const manifest = JSON.parse(strFromU8(entries["manifest.json"]));
  const keyId: string = manifest.signer.key_id;
  const pem: string = manifest.signer.public_key_pem;
  const pemSha256 = bytesToHex(sha256(new TextEncoder().encode(pem)));
  return {
    schema_version: 1,
    signers: [
      {
        key_id: keyId,
        public_key_pem_sha256: pemSha256,
        label: "day-4 fixture (test)",
        added_at: "2026-05-15T00:00:00Z",
        note: "synthesized at test time from tests/fixtures/day-4-fixture.witness",
      },
    ],
  };
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/** SPKI DER prefix for an ECDSA P-256 public key, terminated at the SEC1
 *  uncompressed marker (0x04). Append 64 raw X||Y bytes to reach 91 total. */
const P256_SPKI_PREFIX = new Uint8Array([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

function encodeP256Spki(uncompressedPoint: Uint8Array): string {
  if (uncompressedPoint.length !== 65 || uncompressedPoint[0] !== 0x04) {
    throw new Error(
      `expected a 65-byte SEC1 uncompressed point (leading 0x04); got ${uncompressedPoint.length} bytes`,
    );
  }
  const der = new Uint8Array(P256_SPKI_PREFIX.length + uncompressedPoint.length);
  der.set(P256_SPKI_PREFIX, 0);
  der.set(uncompressedPoint, P256_SPKI_PREFIX.length);
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/** Re-sign the day-4 fixture as a v2 ECDSA P-256 bundle: replace the signer
 *  with a fresh P-256 key, bump manifest_version, canonicalize, DER-sign, and
 *  rewrite signature.json. Returns the materials a test needs to assemble the
 *  bundle and a matching trusted-signers entry.
 *
 *  Pass `opts.attestation` to embed a `signer.attestation` blob (used by the
 *  WS3-8 attestation-rendering test). When omitted, no attestation field is
 *  written (matching what an unsigned dev SEP build produces today). */
function reSignAsP256(opts?: {
  attestation?: {
    format: string;
    payload_b64: string;
    certificate_chain_b64?: string[];
  };
}): {
  manifestText: string;
  sigDocText: string;
  keyId: string;
  pem: string;
} {
  const secretKey = p256.utils.randomSecretKey();
  const pointUncompressed = p256.getPublicKey(secretKey, false);
  const pem = encodeP256Spki(pointUncompressed);
  const keyId = bytesToHex(sha256(pointUncompressed));

  const buf = fs.readFileSync(FIXTURE);
  const entries = unzipSync(new Uint8Array(buf));
  const manifest = JSON.parse(strFromU8(entries["manifest.json"]));
  manifest.manifest_version = 2;
  manifest.signer = {
    algorithm: "ecdsa-p256",
    public_key_pem: pem,
    key_id: keyId,
  };
  if (opts?.attestation) {
    manifest.signer.attestation = opts.attestation;
  }
  const canonical = canonicalizeJson(manifest);
  if (canonical === undefined) {
    throw new Error("canonicalize returned undefined");
  }
  const canonicalBytes = new TextEncoder().encode(canonical);
  const signature = p256.sign(canonicalBytes, secretKey, { format: "der" });
  const signatureBytes: Uint8Array = signature as unknown as Uint8Array;
  const sigDoc = {
    algorithm: "ecdsa-p256",
    key_id: keyId,
    signature_b64: Buffer.from(signatureBytes).toString("base64"),
    signed_payload: "manifest.json",
    canonicalization: "rfc8785",
  };
  const sigDocText = canonicalizeJson(sigDoc);
  if (sigDocText === undefined) {
    throw new Error("canonicalize sigDoc returned undefined");
  }
  return { manifestText: canonical, sigDocText, keyId, pem };
}

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

/**
 * Look up a check row by name. Using name-based lookup keeps the tests
 * stable as new check rows are added or reordered in verify-logic.ts.
 */
function rowByName(
  outcome: { checks: { name: string; passed: boolean; details: string[] }[] },
  needle: string,
): { name: string; passed: boolean; details: string[] } {
  const row = outcome.checks.find((c) => c.name === needle);
  if (!row) {
    throw new Error(
      `no check row named "${needle}"; available rows: ${outcome.checks.map((c) => c.name).join(", ")}`,
    );
  }
  return row;
}

async function runTests(): Promise<void> {
  // T1: Positive.
  console.log("--- T1 (positive): valid fixture bundle");
  {
    const outcome = await verifyBundle(readFixture(), KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(outcome.ok, "T1: overall should be OK");
    assert(outcome.checks.length >= 4, "T1: should have at least 4 checks");
    assert(rowByName(outcome, "Registry signature").passed, "T1: registry-signature row should pass");
    assert(rowByName(outcome, "Signature valid").passed, "T1: signature row should pass");
    assert(rowByName(outcome, "Assets untampered").passed, "T1: asset row should pass");
    assert(rowByName(outcome, "Model fingerprint known").passed, "T1: fingerprint row should pass");
    console.log("PASS T1");
  }

  // T2: Flip one byte in assets/audio.wav.
  console.log("--- T2 (negative): flip byte in assets/audio.wav");
  {
    const mutated = mutateBundle((entries) => {
      const audio = entries.get("assets/audio.wav")!;
      audio[100] ^= 0x42;
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T2: overall should fail");
    assert(rowByName(outcome, "Signature valid").passed, "T2: signature row should still pass");
    const assetRow = rowByName(outcome, "Assets untampered");
    assert(!assetRow.passed, "T2: asset row should fail");
    assert(
      assetRow.details.some((d) => d.includes("assets/audio.wav")),
      "T2: asset row should name the modified asset",
    );
    assert(rowByName(outcome, "Model fingerprint known").passed, "T2: fingerprint row should still pass");
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
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T3: overall should fail");
    assert(!rowByName(outcome, "Signature valid").passed, "T3: signature row should fail");
    assert(rowByName(outcome, "Assets untampered").passed, "T3: asset row should still pass");
    assert(rowByName(outcome, "Model fingerprint known").passed, "T3: fingerprint row should still pass");
    console.log("PASS T3");
  }

  // T4: Unknown model fingerprint using an empty known list.
  console.log("--- T4 (negative): unknown model fingerprint (empty registry)");
  {
    const outcome = await verifyBundle(readFixture(), KNOWN_EMPTY, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T4: overall should fail");
    assert(rowByName(outcome, "Signature valid").passed, "T4: signature row should still pass");
    assert(rowByName(outcome, "Assets untampered").passed, "T4: asset row should still pass");
    const fpRow = rowByName(outcome, "Model fingerprint known");
    assert(!fpRow.passed, "T4: fingerprint row should fail");
    assert(
      fpRow.details.some((d) => d.includes("not on the known-good list")),
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
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T4b: overall should fail");
    // Signature fails because manifest bytes changed without re-signing.
    assert(!rowByName(outcome, "Signature valid").passed, "T4b: signature row should fail (manifest mutated)");
    assert(rowByName(outcome, "Assets untampered").passed, "T4b: asset row should still pass");
    const fpRow = rowByName(outcome, "Model fingerprint known");
    assert(!fpRow.passed, "T4b: fingerprint row should fail");
    assert(
      fpRow.details.some((d) => d.includes("not on the known-good list")),
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

    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(outcome.ok, "T5: overall should still be OK after key reorder");
    assert(
      rowByName(outcome, "Signature valid").passed,
      "T5: signature must still pass (canonicalization invariant)",
    );
    assert(rowByName(outcome, "Assets untampered").passed, "T5: asset row should still pass");
    assert(rowByName(outcome, "Model fingerprint known").passed, "T5: fingerprint row should still pass");
    console.log("PASS T5");
  }

  // T7 (V-1): Signer not in the trusted-signers registry.
  console.log("--- T7 (negative): unknown signer fails the signer-identity row");
  {
    const outcome = await verifyBundle(
      readFixture(),
      KNOWN_WITH_FINGERPRINT,
      TRUSTED_EMPTY,
      REGISTRY_VERIFIED,
    );
    assert(!outcome.ok, "T7: overall should fail when signer is unknown");
    const signerRow = outcome.checks.find((c) =>
      c.name.includes("known witness"),
    );
    assert(!!signerRow, "T7: a signer-identity row must exist");
    assert(!signerRow!.passed, "T7: signer row should fail");
    assert(
      signerRow!.details.some((d) => d.includes("NOT in the verifier's trusted-signers registry")),
      "T7: detail should explain the gap",
    );
    assert(
      signerRow!.details.some((d) => d.includes("fingerprint")),
      "T7: detail should print a public-key fingerprint for out-of-band pinning",
    );
    console.log("PASS T7");
  }

  // T8 (V-1): Signer present in the registry passes.
  console.log("--- T8 (positive): known signer passes the signer-identity row");
  {
    const outcome = await verifyBundle(
      readFixture(),
      KNOWN_WITH_FINGERPRINT,
      trustedSignersFromFixture(),
      REGISTRY_VERIFIED,
    );
    const signerRow = outcome.checks.find((c) =>
      c.name.includes("known witness"),
    );
    assert(!!signerRow, "T8: a signer-identity row must exist");
    assert(signerRow!.passed, "T8: signer row should pass for a registered signer");
    console.log("PASS T8");
  }

  // T9 (V-4): manifest claims a model_id the registry does not own.
  console.log("--- T9 (negative): fingerprint triple mismatch");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      // Keep the SHA-256 (so byHash succeeds) but change the model_id so
      // the registry's (model_id, revision, sha256) tuple no longer matches.
      manifest.assertions["gemma.witness.model_fingerprint"].model_id =
        "evil/model";
      entries.set(
        "manifest.json",
        new TextEncoder().encode(JSON.stringify(manifest)),
      );
    });
    const outcome = await verifyBundle(
      mutated,
      KNOWN_WITH_FINGERPRINT,
      trustedSignersFromFixture(),
      REGISTRY_VERIFIED,
    );
    assert(!outcome.ok, "T9: overall should fail");
    const fpRow = outcome.checks.find((c) => c.name === "Model fingerprint known");
    assert(!!fpRow, "T9: a fingerprint row must exist");
    assert(!fpRow!.passed, "T9: fingerprint row should fail on triple mismatch");
    assert(
      fpRow!.details.some((d) => d.includes("evil/model")),
      "T9: detail should mention the bogus claimed model_id",
    );
    console.log("PASS T9");
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
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
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

  // T10 (WS4): placeholder registry verification fails the registry row.
  console.log("--- T10 (negative): placeholder registry envelope fails the registry-signature row");
  {
    const outcome = await verifyBundle(
      readFixture(),
      KNOWN_WITH_FINGERPRINT,
      trustedSignersFromFixture(),
      REGISTRY_PLACEHOLDER,
    );
    assert(!outcome.ok, "T10: overall should fail when registry is a placeholder");
    const registryRow = rowByName(outcome, "Registry signature");
    assert(!registryRow.passed, "T10: registry-signature row should fail");
    assert(
      registryRow.details.some((d) => d.includes("placeholder")),
      "T10: detail should mention the placeholder state",
    );
    console.log("PASS T10");
  }

  // T11 (WS4): null registry verification (verifier built without
  // build-time check) fails the registry row.
  console.log("--- T11 (negative): null registry verification (verifier misbuilt) fails the registry-signature row");
  {
    const outcome = await verifyBundle(
      readFixture(),
      KNOWN_WITH_FINGERPRINT,
      trustedSignersFromFixture(),
      null,
    );
    assert(!outcome.ok, "T11: overall should fail when registry verification is missing");
    const registryRow = rowByName(outcome, "Registry signature");
    assert(!registryRow.passed, "T11: registry-signature row should fail");
    assert(
      registryRow.details.some((d) => d.includes("rebuild")),
      "T11: detail should ask the user to rebuild",
    );
    console.log("PASS T11");
  }

  // T12 (WS3-1): manifest_version=2 is accepted by the version router. The
  // signature row still fails because we mutated the manifest without
  // re-signing, but the failure must be a signature mismatch, not "version
  // not supported". This proves the verifier accepts v2 structurally.
  console.log("--- T12 (positive): manifest_version=2 routes past the version gate");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      manifest.manifest_version = 2;
      entries.set(
        "manifest.json",
        new TextEncoder().encode(JSON.stringify(manifest)),
      );
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T12: overall fails because the manifest was mutated without re-signing");
    assert(
      !outcome.checks.some((c) => c.name.includes("Manifest version") && !c.passed),
      "T12: there must be no failing version row; v2 is supported",
    );
    const sigRow = rowByName(outcome, "Signature valid");
    assert(!sigRow.passed, "T12: signature row fails because manifest bytes changed");
    console.log("PASS T12");
  }

  // T13 (WS3-3): A bundle that claims signer.algorithm=ecdsa-p256 but ships an
  // Ed25519 SPKI PEM under it fails the signature row at PEM parsing. The
  // P-256 dispatch is wired; the failure is now a shape-mismatch detail
  // rather than a "backend not in this build" message.
  console.log("--- T13 (negative): v2 + ecdsa-p256 over an Ed25519 PEM fails PEM parsing");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      manifest.manifest_version = 2;
      manifest.signer.algorithm = "ecdsa-p256";
      entries.set(
        "manifest.json",
        new TextEncoder().encode(JSON.stringify(manifest)),
      );
      const rawSig = entries.get("signature.json")!;
      const sigDoc = JSON.parse(strFromU8(rawSig));
      sigDoc.algorithm = "ecdsa-p256";
      entries.set(
        "signature.json",
        new TextEncoder().encode(JSON.stringify(sigDoc)),
      );
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T13: overall should fail");
    const sigRow = rowByName(outcome, "Signature valid");
    assert(!sigRow.passed, "T13: signature row should fail");
    assert(
      sigRow.details.some((d) => d.includes("public key PEM parsing failed")),
      `T13: detail must surface the P-256 PEM parsing failure; got ${JSON.stringify(sigRow.details)}`,
    );
    console.log("PASS T13");
  }

  // T13b (WS3-3): A bundle re-signed with a real P-256 software key
  // round-trips through the JS verifier. The signature row passes.
  console.log("--- T13b (positive): v2 + ecdsa-p256 signature verifies under @noble/curves p256");
  {
    const { manifestText: newManifestText, sigDocText, keyId, pem } = reSignAsP256();
    const mutated = mutateBundle((entries) => {
      entries.set("manifest.json", new TextEncoder().encode(newManifestText));
      entries.set("signature.json", new TextEncoder().encode(sigDocText));
    });
    const trusted: TrustedSigners = {
      schema_version: 1,
      signers: [
        {
          key_id: keyId,
          public_key_pem_sha256: bytesToHex(sha256(new TextEncoder().encode(pem))),
          label: "test P-256 signer",
          added_at: "2026-05-15T00:00:00Z",
          note: "ephemeral P-256 key synthesized at test time",
        },
      ],
    };
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trusted, REGISTRY_VERIFIED);
    const sigRow = rowByName(outcome, "Signature valid");
    assert(
      sigRow.passed,
      `T13b: signature row should pass for a real P-256-signed bundle; got ${JSON.stringify(sigRow.details)}`,
    );
    console.log("PASS T13b");
  }

  // T14 (WS3-1): A v1 manifest carrying signer.attestation is rejected at the
  // structural validation gate (bundle-reader), surfacing as a top-level error
  // rather than a check row. The attestation blob is a v2-only field.
  console.log("--- T14 (negative): v1 + signer.attestation is rejected at manifest validation");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      manifest.signer.attestation = {
        format: "apple-sep-v1",
        payload_b64: "QUFFQg==",
      };
      entries.set(
        "manifest.json",
        new TextEncoder().encode(JSON.stringify(manifest)),
      );
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T14: overall should fail");
    assert(
      outcome.error !== null && outcome.error.includes("attestation") && outcome.error.includes("v1"),
      `T14: top-level error must name the v1/attestation incompatibility; got ${outcome.error}`,
    );
    console.log("PASS T14");
  }

  // T15 (WS3-1): A v1 manifest declaring "ecdsa-p256" is rejected at the
  // signature row with a "permits only" detail. v1 manifests are restricted
  // to ed25519 even when the wire form is otherwise well-formed.
  console.log("--- T15 (negative): v1 + ecdsa-p256 fails the signature row with 'permits only'");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      manifest.signer.algorithm = "ecdsa-p256";
      entries.set(
        "manifest.json",
        new TextEncoder().encode(JSON.stringify(manifest)),
      );
      const rawSig = entries.get("signature.json")!;
      const sigDoc = JSON.parse(strFromU8(rawSig));
      sigDoc.algorithm = "ecdsa-p256";
      entries.set(
        "signature.json",
        new TextEncoder().encode(JSON.stringify(sigDoc)),
      );
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T15: overall should fail");
    const sigRow = rowByName(outcome, "Signature valid");
    assert(!sigRow.passed, "T15: signature row should fail");
    assert(
      sigRow.details.some((d) => d.includes("permits only") && d.includes("ed25519")),
      `T15: detail must name the permitted set for v1; got ${JSON.stringify(sigRow.details)}`,
    );
    console.log("PASS T15");
  }

  // T16 (WS3-8): A v2 + ecdsa-p256 manifest carrying signer.attestation
  // round-trips through the verifier. The signature row passes and the
  // returned manifest preserves the attestation blob so the renderer can
  // surface the "Signer attestation" advisory row.
  console.log("--- T16 (positive): v2 + ecdsa-p256 + signer.attestation round-trips with attestation preserved");
  {
    const { manifestText, sigDocText, keyId, pem } = reSignAsP256({
      attestation: {
        format: "apple-sep-v1",
        payload_b64: "ZGV2aWNlLWF0dGVzdGF0aW9uLWZpeHR1cmU=",
      },
    });
    const mutated = mutateBundle((entries) => {
      entries.set("manifest.json", new TextEncoder().encode(manifestText));
      entries.set("signature.json", new TextEncoder().encode(sigDocText));
    });
    const trusted: TrustedSigners = {
      schema_version: 1,
      signers: [
        {
          key_id: keyId,
          public_key_pem_sha256: bytesToHex(sha256(new TextEncoder().encode(pem))),
          label: "test SEP fixture signer",
          added_at: "2026-05-16T00:00:00Z",
          note: "ephemeral P-256 key with synthetic attestation",
        },
      ],
    };
    const outcome = await verifyBundle(
      mutated,
      KNOWN_WITH_FINGERPRINT,
      trusted,
      REGISTRY_VERIFIED,
    );
    assert(outcome.ok, `T16: overall should pass; got error=${outcome.error}`);
    const sigRow = rowByName(outcome, "Signature valid");
    assert(sigRow.passed, "T16: signature row should pass");
    assert(
      outcome.manifest !== null,
      "T16: outcome must include the parsed manifest",
    );
    assert(
      outcome.manifest.signer.attestation !== undefined &&
        outcome.manifest.signer.attestation !== null,
      "T16: signer.attestation must survive the verify pass for the renderer",
    );
    assert(
      outcome.manifest.signer.attestation!.format === "apple-sep-v1",
      `T16: attestation format must be preserved; got ${outcome.manifest.signer.attestation!.format}`,
    );
    assert(
      outcome.manifest.signer.attestation!.payload_b64 ===
        "ZGV2aWNlLWF0dGVzdGF0aW9uLWZpeHR1cmU=",
      "T16: attestation payload_b64 must round-trip byte-for-byte",
    );
    console.log("PASS T16");
  }

  // T17 (WS3-8c): The committed Secure Enclave fixture loads through the
  // JS verifier with `is_ok()`, surfaces `signer.attestation` for the
  // renderer, and the attestation summary helper formats the fixture's
  // deterministic payload correctly.
  console.log("--- T17 (positive): committed SEP fixture verifies end-to-end and renders its attestation");
  {
    const buf = fs.readFileSync(SEP_FIXTURE);
    const entries = unzipSync(new Uint8Array(buf));
    const manifest = JSON.parse(strFromU8(entries["manifest.json"]));
    const known: KnownFingerprints = {
      schema_version: 1,
      fingerprints: [
        {
          model_id: manifest.assertions["gemma.witness.model_fingerprint"].model_id,
          revision: manifest.assertions["gemma.witness.model_fingerprint"].revision,
          sha256: manifest.assertions["gemma.witness.model_fingerprint"].sha256,
        },
      ],
    };
    const trusted: TrustedSigners = {
      schema_version: 1,
      signers: [
        {
          key_id: manifest.signer.key_id,
          public_key_pem_sha256: bytesToHex(
            sha256(new TextEncoder().encode(manifest.signer.public_key_pem)),
          ),
          label: "SEP fixture signer",
          added_at: "2026-05-16T00:00:00Z",
          note: "ephemeral SEP key baked by generate_sep_fixture.rs",
        },
      ],
    };
    const outcome = await verifyBundle(
      toArrayBuffer(buf),
      known,
      trusted,
      REGISTRY_VERIFIED,
    );
    assert(outcome.ok, `T17: SEP fixture must verify; got error=${outcome.error}`);
    assert(
      outcome.manifest !== null && outcome.manifest.signer.attestation !== undefined &&
        outcome.manifest.signer.attestation !== null,
      "T17: fixture must surface signer.attestation for the renderer",
    );
    const att = outcome.manifest.signer.attestation!;
    assert(
      att.format === "apple-sep-v1-fixture",
      `T17: fixture attestation format must be apple-sep-v1-fixture; got ${att.format}`,
    );
    const summary = summarizeAttestation(att);
    assert(
      summary.includes("format:       apple-sep-v1-fixture"),
      `T17: summarizeAttestation must echo the fixture format tag; got:\n${summary}`,
    );
    assert(
      summary.includes("payload_size: 30 bytes"),
      `T17: fixture payload is 30 bytes ("secure-enclave-witness-fixture"); got:\n${summary}`,
    );
    console.log("PASS T17");
  }

  // T18 (WS5): A bundle signed by a registered-but-revoked signer fails
  // the signer-identity row with a "REVOKED" detail and fails the overall
  // verdict, even though every cryptographic check passes.
  console.log("--- T18 (negative): revoked signer fails the signer-identity row");
  {
    const buf = fs.readFileSync(FIXTURE);
    const entries = unzipSync(new Uint8Array(buf));
    const manifest = JSON.parse(strFromU8(entries["manifest.json"]));
    const trusted: TrustedSigners = {
      schema_version: 1,
      signers: [
        {
          key_id: manifest.signer.key_id,
          public_key_pem_sha256: bytesToHex(
            sha256(new TextEncoder().encode(manifest.signer.public_key_pem)),
          ),
          label: "compromised signer (test)",
          added_at: "2026-01-01T00:00:00Z",
          note: "previously trusted; revoked under WS5 fixture",
          revoked_at: "2026-05-16T00:00:00Z",
          revocation_reason: "test fixture: simulated key compromise",
        },
      ],
    };
    const outcome = await verifyBundle(
      readFixture(),
      KNOWN_WITH_FINGERPRINT,
      trusted,
      REGISTRY_VERIFIED,
    );
    assert(!outcome.ok, "T18: overall must fail when signer is revoked");
    const sigRow = rowByName(outcome, "Signed by a known witness");
    assert(!sigRow.passed, "T18: signer-identity row must fail");
    assert(
      sigRow.details.some((d) => d.includes("REVOKED")),
      `T18: details must surface the revocation state; got ${JSON.stringify(sigRow.details)}`,
    );
    assert(
      sigRow.details.some((d) => d.includes("simulated key compromise")),
      `T18: details must echo the revocation_reason; got ${JSON.stringify(sigRow.details)}`,
    );
    console.log("PASS T18");
  }

  // T19 (WS5): A bundle signed by a registered, non-revoked signer passes
  // the signer-identity row with no "REVOKED" wording.
  console.log("--- T19 (positive): registered signer passes the signer-identity row");
  {
    const outcome = await verifyBundle(
      readFixture(),
      KNOWN_WITH_FINGERPRINT,
      trustedSignersFromFixture(),
      REGISTRY_VERIFIED,
    );
    assert(outcome.ok, `T19: registered signer must pass overall; got error=${outcome.error}`);
    const sigRow = rowByName(outcome, "Signed by a known witness");
    assert(sigRow.passed, "T19: signer-identity row must pass for a registered signer");
    assert(
      !sigRow.details.some((d) => d.toLowerCase().includes("revoked")),
      `T19: registered-signer details must not contain "revoked"; got ${JSON.stringify(sigRow.details)}`,
    );
    console.log("PASS T19");
  }

  // T20 (WS5): A bundle whose key is not in the trusted-signers registry
  // fails the signer-identity row with a "TOFU" wording, distinguishing
  // it from the revoked path.
  console.log("--- T20 (negative): unknown signer fails with a TOFU detail");
  {
    const outcome = await verifyBundle(
      readFixture(),
      KNOWN_WITH_FINGERPRINT,
      TRUSTED_EMPTY,
      REGISTRY_VERIFIED,
    );
    assert(!outcome.ok, "T20: overall must fail when signer is unknown");
    const sigRow = rowByName(outcome, "Signed by a known witness");
    assert(!sigRow.passed, "T20: signer-identity row must fail");
    assert(
      sigRow.details.some((d) => d.includes("TOFU")),
      `T20: details must surface the TOFU state to distinguish from revoked; got ${JSON.stringify(sigRow.details)}`,
    );
    console.log("PASS T20");
  }

  // T21 (negative): signature.json with the canonicalization field stripped.
  // The verifier requires it to read "rfc8785"; a missing or different value
  // must fail the signature row before any crypto runs.
  console.log("--- T21 (negative): signature with wrong canonicalization value");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("signature.json")!;
      const sigDoc = JSON.parse(strFromU8(raw));
      sigDoc.canonicalization = "json-c14n";
      entries.set("signature.json", new TextEncoder().encode(JSON.stringify(sigDoc)));
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T21: overall must fail");
    const sigRow = rowByName(outcome, "Signature valid");
    assert(!sigRow.passed, "T21: signature row must fail");
    assert(
      sigRow.details.some((d) => d.includes("canonicalization") || d.includes("rfc8785")),
      `T21: details must name the canonicalization mismatch; got ${JSON.stringify(sigRow.details)}`,
    );
    console.log("PASS T21");
  }

  // T22 (negative): signature_b64 with structurally invalid base64 padding.
  // The decode step must fail with a recognizable error, not throw or pass.
  console.log("--- T22 (negative): signature_b64 with invalid base64 padding");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("signature.json")!;
      const sigDoc = JSON.parse(strFromU8(raw));
      sigDoc.signature_b64 = "AAAA=";
      entries.set("signature.json", new TextEncoder().encode(JSON.stringify(sigDoc)));
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T22: overall must fail");
    assert(!rowByName(outcome, "Signature valid").passed, "T22: signature row must fail");
    console.log("PASS T22");
  }

  // T23 (negative): signature.json with the wrong signed_payload value.
  // The verifier only signs over manifest.json; any other value must be
  // rejected even if the rest of the document looks valid.
  console.log("--- T23 (negative): signature with wrong signed_payload value");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("signature.json")!;
      const sigDoc = JSON.parse(strFromU8(raw));
      sigDoc.signed_payload = "assets/audio.wav";
      entries.set("signature.json", new TextEncoder().encode(JSON.stringify(sigDoc)));
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T23: overall must fail");
    const sigRow = rowByName(outcome, "Signature valid");
    assert(!sigRow.passed, "T23: signature row must fail");
    assert(
      sigRow.details.some((d) => d.includes("signed_payload") || d.includes("manifest")),
      `T23: details must name the signed_payload mismatch; got ${JSON.stringify(sigRow.details)}`,
    );
    console.log("PASS T23");
  }

  // T24 (negative): bumped manifest.created_at without re-signing. The
  // signature covers the canonicalized manifest, so any byte change in
  // the timestamp invalidates it; this confirms there is no time-based
  // replay window.
  console.log("--- T24 (negative): replay with bumped manifest.created_at");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("manifest.json")!;
      const manifest = JSON.parse(strFromU8(raw));
      manifest.created_at = "2099-01-01T00:00:00Z";
      entries.set("manifest.json", new TextEncoder().encode(JSON.stringify(manifest)));
    });
    const outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    assert(!outcome.ok, "T24: overall must fail");
    assert(!rowByName(outcome, "Signature valid").passed, "T24: signature row must fail after timestamp bump");
    console.log("PASS T24");
  }

  // T25 (negative): a structurally malformed signature document where
  // a required field is missing. The verifier must surface this as a
  // bundle-structure problem rather than silently passing.
  console.log("--- T25 (negative): signature.json missing required field");
  {
    const mutated = mutateBundle((entries) => {
      const raw = entries.get("signature.json")!;
      const sigDoc = JSON.parse(strFromU8(raw));
      delete sigDoc.canonicalization;
      entries.set("signature.json", new TextEncoder().encode(JSON.stringify(sigDoc)));
    });
    let outcome;
    let threw = false;
    try {
      outcome = await verifyBundle(mutated, KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    } catch {
      threw = true;
    }
    assert(
      threw || (outcome !== undefined && !outcome.ok),
      "T25: missing required signature field must either throw or fail the row",
    );
    console.log("PASS T25");
  }

  // T26 (negative): a bundle truncated to half its size. The unzip step
  // may either throw (central directory unreadable) or surface the gap
  // as a missing required entry; either is correct, the invariant is
  // that a truncated bundle never reaches a green verification.
  console.log("--- T26 (negative): truncated bundle (half the bytes lopped)");
  {
    const buf = fs.readFileSync(FIXTURE);
    const truncated = buf.subarray(0, Math.floor(buf.length / 2));
    let outcome;
    let threw = false;
    try {
      outcome = await verifyBundle(toArrayBuffer(truncated), KNOWN_WITH_FINGERPRINT, trustedSignersFromFixture(), REGISTRY_VERIFIED);
    } catch {
      threw = true;
    }
    assert(
      threw || (outcome !== undefined && !outcome.ok),
      "T26: a truncated bundle must never reach a green verification",
    );
    console.log("PASS T26");
  }

  console.log("\n=== ALL E2E TESTS PASSED ===");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
