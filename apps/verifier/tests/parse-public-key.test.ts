// Targeted unit tests for parsePublicKeyPem.
//
// These tests exercise edge cases the e2e bundle tests don't hit:
// wrong OIDs, truncated PEMs, and non-Ed25519 structures.
//
// Run: cd apps/verifier && npx tsx tests/parse-public-key.test.ts

import { parsePublicKeyPem } from "../src/parse-public-key";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`ASSERTION FAILED: ${message}`);
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// A valid Ed25519 PKCS#8 SPKI wrapper (44 bytes total).
// Extracted from a fixture bundle.
const VALID_ED25519_PEM =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MCowBQYDK2VwAyEAXtMcdiB8kV0cox8K/SD6R3XH9i7xtMyLBGsuL9WYnZE=\n" +
  "-----END PUBLIC KEY-----";

const VALID_RAW_32_HEX =
  "5ed31c76207c915d1ca31f0afd20fa4775c7f62ef1b4cc8b046b2e2fd5989d91";

async function runTests(): Promise<void> {
  // T1: valid 44-byte SPKI wrapper extracts the 32-byte raw key.
  console.log("--- PEM T1: valid Ed25519 SPKI wrapper");
  {
    const key = parsePublicKeyPem(VALID_ED25519_PEM);
    assert(key.length === 32, "T1: expected 32-byte raw key");
    assert(
      bytesToHex(key) === VALID_RAW_32_HEX,
      "T1: extracted key does not match expected raw bytes",
    );
    console.log("PASS PEM T1");
  }

  // T2: legacy 32-byte raw key form is rejected. Only the SPKI form produced
  // by the Rust capture app is accepted; accepting both would create
  // cross-implementation parsing drift.
  console.log("--- PEM T2: legacy 32-byte raw key is rejected");
  {
    const raw = Uint8Array.from(Buffer.from(VALID_RAW_32_HEX, "hex"));
    const b64 = Buffer.from(raw).toString("base64");
    const pem = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
    let threw = false;
    let message = "";
    try {
      parsePublicKeyPem(pem);
    } catch (err) {
      threw = true;
      message = err instanceof Error ? err.message : String(err);
    }
    assert(
      threw,
      "T2: expected parsePublicKeyPem to reject the legacy 32-byte raw form",
    );
    assert(
      message.includes("44") || message.includes("SPKI"),
      `T2: error should mention the required 44-byte SPKI form, got: ${message}`,
    );
    console.log("PASS PEM T2");
  }

  // T3: 44-byte wrapper with wrong OID is rejected.
  console.log("--- PEM T3: wrong OID in SPKI wrapper");
  {
    // Replace the Ed25519 OID prefix (0x2b 0x65 0x70) with secp256k1 (0x2b 0x81 0x04 0x00 0x0a).
    // Craft a 44-byte buffer: 0x30 0x2a ... then a different algorithm identifier.
    const bad = Uint8Array.from([
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x81, 0x04, 0x00, 0x03,
      0x21, 0x00,
    ]);
    // Pad to 44 bytes (13-byte prefix + 31 bytes of garbage key).
    const padded = new Uint8Array(44);
    padded.set(bad);
    for (let i = 13; i < 44; i++) padded[i] = i;
    const b64 = Buffer.from(padded).toString("base64");
    const pem = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
    let threw = false;
    let message = "";
    try {
      parsePublicKeyPem(pem);
    } catch (err) {
      threw = true;
      message = err instanceof Error ? err.message : String(err);
    }
    assert(threw, "T3: expected parsePublicKeyPem to throw on wrong OID");
    assert(
      message.includes("not Ed25519") || message.includes("OID"),
      `T3: error should mention OID mismatch, got: ${message}`,
    );
    console.log("PASS PEM T3");
  }

  // T4: truncated base64 throws.
  console.log("--- PEM T4: truncated PEM");
  {
    const badPem =
      "-----BEGIN PUBLIC KEY-----\n" +
      "MCowBQYDK2VwAyEAXtMcdiB8kV0cox8K/SD6R3XH\n" + // truncated
      "-----END PUBLIC KEY-----";
    let threw = false;
    try {
      parsePublicKeyPem(badPem);
    } catch {
      threw = true;
    }
    assert(threw, "T4: expected parsePublicKeyPem to throw on truncated PEM");
    console.log("PASS PEM T4");
  }

  // T5: PEM without headers still parses.
  console.log("--- PEM T5: bare base64 without headers");
  {
    const bare =
      "MCowBQYDK2VwAyEAXtMcdiB8kV0cox8K/SD6R3XH9i7xtMyLBGsuL9WYnZE=";
    const key = parsePublicKeyPem(bare);
    assert(key.length === 32, "T5: expected 32-byte raw key from bare base64");
    assert(
      bytesToHex(key) === VALID_RAW_32_HEX,
      "T5: bare base64 should yield same key",
    );
    console.log("PASS PEM T5");
  }

  // T6: Empty input throws.
  console.log("--- PEM T6: empty input");
  {
    let threw = false;
    try {
      parsePublicKeyPem("");
    } catch {
      threw = true;
    }
    assert(threw, "T6: expected parsePublicKeyPem to throw on empty string");
    console.log("PASS PEM T6");
  }

  // T7: Garbage inside base64 throws at decoding time.
  console.log("--- PEM T7: garbage base64");
  {
    let threw = false;
    try {
      parsePublicKeyPem("!!!not-valid-base64!!!");
    } catch {
      threw = true;
    }
    assert(threw, "T7: expected parsePublicKeyPem to throw on invalid base64");
    console.log("PASS PEM T7");
  }

  console.log("\n=== ALL PEM UNIT TESTS PASSED ===");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
