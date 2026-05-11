/**
 * Parse an Ed25519 public key from a PKCS#8 PEM string.
 *
 * Accepts two forms:
 * 1. A 32-byte raw key (legacy form, not used by the capture app).
 * 2. A 44-byte PKCS#8 SubjectPublicKeyInfo wrapper where the
 *    AlgorithmIdentifier contains the Ed25519 OID (1.3.101.112).
 *
 * Any other OID or structure is rejected.
 *
 * @param pem - PEM-encoded public key, with or without headers.
 * @returns The 32-byte raw Ed25519 public key.
 * @throws If the PEM is malformed, truncated, or does not contain the Ed25519 OID.
 */
export function parsePublicKeyPem(pem: string): Uint8Array {
  const lines = pem.split(/\r?\n/);
  const filtered = lines.filter(
    (line) => line.trim() && !line.startsWith("-----"),
  );
  const b64 = filtered.join("").replace(/\s+/g, "");
  const raw = base64Decode(b64);

  if (raw.length === 32) {
    return raw;
  }

  if (raw.length === 44) {
    // PKCS#8 SubjectPublicKeyInfo:
    // SEQUENCE { AlgorithmIdentifier { OID 1.3.101.112 }, BIT STRING { 32-byte key } }
    // Prefix: 0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x03 0x21 0x00
    const prefix = Array.from(raw.slice(0, 12));
    const expectedPrefix = [
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
      0x00,
    ];
    if (prefix.every((b, i) => b === expectedPrefix[i])) {
      return raw.slice(12);
    }
    throw new Error(
      "PEM contains a 44-byte SPKI wrapper but the AlgorithmIdentifier OID is not Ed25519 (1.3.101.112). only Ed25519 public keys are accepted.",
    );
  }

  throw new Error(
    "PEM does not contain a recognized Ed25519 public key structure. expected 32 raw bytes or a 44-byte PKCS#8 SPKI wrapper with the Ed25519 OID.",
  );
}

function base64Decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
