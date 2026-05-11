import fs from "node:fs";
import { unzipSync, strFromU8 } from "fflate";
import { verifyAsync } from "@noble/ed25519";
import canonicalize from "canonicalize";

const FIXTURE = "../../tests/fixtures/day-4-fixture.witness";
const buf = fs.readFileSync(FIXTURE);
const entries = unzipSync(new Uint8Array(buf));
const manifest = JSON.parse(strFromU8(entries["manifest.json"]));
const sigDoc = JSON.parse(strFromU8(entries["signature.json"]));
const sigBytes = Uint8Array.from(Buffer.from(sigDoc.signature_b64, "base64"));

const text = canonicalize(manifest);
const canonical = new TextEncoder().encode(text);
console.log("canonical length:", canonical.length);

function parsePk(pem: string): Uint8Array {
  const lines = pem.split(/\r?\n/);
  const filtered = lines.filter((l) => l.trim() && !l.startsWith("-----"));
  const b64 = filtered.join("").replace(/\s+/g, "");
  const raw = Buffer.from(b64, "base64");
  if (raw.length === 32) return new Uint8Array(raw);
  if (raw.length === 44) {
    const prefix = Array.from(raw.subarray(0, 12));
    const expected = [
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
      0x00,
    ];
    if (prefix.every((b, i) => b === expected[i])) {
      return new Uint8Array(raw.subarray(12));
    }
  }
  throw new Error("bad pem length " + raw.length);
}

const pk = parsePk(manifest.signer.public_key_pem);
console.log("pk length:", pk.length);

(async () => {
  const ok = await verifyAsync(sigBytes, canonical, pk);
  console.log("verify result:", ok);
})();
