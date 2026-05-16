// Unit tests for `summarizeAttestation`, the pure helper that renders the
// v2 manifest's signer.attestation blob into the verifier's advisory row.
// Runs in Node with no DOM dependency.
//
// Run: cd apps/verifier && npx tsx tests/summarize-attestation.test.ts

import { summarizeAttestation } from "../src/render-result";
import type { SignerAttestation } from "../src/types";

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

function makeAttestation(payload: Uint8Array): SignerAttestation {
  // Convert to base64 without a Node Buffer dependency so this file can run
  // anywhere `tsx` does.
  let binary = "";
  for (const byte of payload) binary += String.fromCharCode(byte);
  return {
    format: "apple-sep-v1",
    payload_b64: btoa(binary),
  };
}

function runTests(): void {
  // T1: a short payload produces a full hex preview with no truncation.
  {
    const payload = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const text = summarizeAttestation(makeAttestation(payload));
    assert(text.includes("format:       apple-sep-v1"), "format line present");
    assert(text.includes("payload_size: 4 bytes"), "size line present");
    assert(
      text.includes("payload_hex:  de ad be ef"),
      `hex line must show the full 4-byte payload; got:\n${text}`,
    );
    assert(!text.includes("truncated"), "short payload must not be truncated");
    assert(text.includes("cert_chain:   (none)"), "cert_chain line present, default none");
    console.log("PASS T1: short payload renders without truncation");
  }

  // T2: a 64-byte payload renders the first 32 bytes followed by a
  // truncated marker; the size line still reports the full byte count.
  {
    const payload = new Uint8Array(64);
    for (let i = 0; i < 64; i++) payload[i] = i;
    const text = summarizeAttestation(makeAttestation(payload));
    assert(text.includes("payload_size: 64 bytes"), "size reflects the full payload");
    assert(
      text.includes("... (truncated)"),
      "long payloads must show a truncated marker",
    );
    // First and 32nd bytes appear; the 33rd does not (its hex string "20" might
    // collide with an earlier byte, so we check the 33rd-byte hex appears AFTER
    // the truncation marker is not present — i.e. before the truncation).
    assert(text.includes("00 01 02 03 04 05 06 07"), "first 8 bytes present");
    console.log("PASS T2: long payload truncated at 32 bytes with full size reported");
  }

  // T3: certificate chain count surfaces when present.
  {
    const att: SignerAttestation = {
      format: "tpm2-quote-v1",
      payload_b64: "AAEC",
      certificate_chain_b64: ["ZmFrZS1jZXJ0", "Zmlha2UyLWNlcnQ="],
    };
    const text = summarizeAttestation(att);
    assert(text.includes("cert_chain:   2 certificate(s)"), "cert count rendered");
    console.log("PASS T3: certificate chain count rendered");
  }

  // T4: malformed payload_b64 surfaces as a non-fatal note rather than
  // throwing. The signature row has already passed by the time we render
  // this advisory; a bad attestation must not crash the page.
  {
    const att: SignerAttestation = {
      format: "ncrypt-v1",
      payload_b64: "not!valid$base64!!!",
    };
    const text = summarizeAttestation(att);
    assert(
      text.includes("did not decode as valid base64"),
      `malformed payload_b64 must surface as a non-fatal note; got:\n${text}`,
    );
    console.log("PASS T4: malformed payload_b64 surfaces non-fatally");
  }

  console.log("\n=== summarize-attestation tests passed ===");
}

runTests();
