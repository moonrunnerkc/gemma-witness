/**
 * Parse an ECDSA P-256 public key from a SubjectPublicKeyInfo PEM string.
 *
 * Accepts exactly one form: a 91-byte SPKI wrapper whose AlgorithmIdentifier
 * carries the ecPublicKey OID (1.2.840.10045.2.1) and the P-256 OID
 * (1.2.840.10045.3.1.7), followed by a BIT STRING wrapping the 65-byte
 * SEC1 uncompressed-point encoding (`0x04 || X || Y`). This is what
 * `openssl ec -pubout`, the Rust `p256::pkcs8::EncodePublicKey`
 * implementation, and the macOS `SecKeyCopyExternalRepresentation` path
 * all produce.
 *
 * Compressed-point or raw-point forms are intentionally rejected: only the
 * SPKI form is interoperable with the Rust verifier, and accepting other
 * envelopes invites cross-implementation drift.
 *
 * @param pem - PEM-encoded public key, with or without headers.
 * @returns The 65-byte SEC1 uncompressed-point public key (leading 0x04).
 * @throws If the PEM is malformed, truncated, the wrong length, or the
 *   AlgorithmIdentifier OIDs do not name ECDSA P-256.
 */
export function parsePublicKeyPemP256(pem: string): Uint8Array {
  const lines = pem.split(/\r?\n/);
  const filtered = lines.filter(
    (line) => line.trim() && !line.startsWith("-----"),
  );
  const b64 = filtered.join("").replace(/\s+/g, "");
  const raw = base64Decode(b64);

  if (raw.length !== 91) {
    throw new Error(
      `PEM body decoded to ${raw.length} bytes; expected exactly 91 (SPKI wrapper around a 65-byte uncompressed P-256 point). only the SPKI form produced by the capture app and standard tooling is accepted.`,
    );
  }

  // SubjectPublicKeyInfo for P-256 (RFC 5480):
  // 0x30 0x59             SEQUENCE, length 89
  // 0x30 0x13             SEQUENCE (AlgorithmIdentifier), length 19
  // 0x06 0x07 2a 86 48 ce 3d 02 01      OID 1.2.840.10045.2.1 (ecPublicKey)
  // 0x06 0x08 2a 86 48 ce 3d 03 01 07   OID 1.2.840.10045.3.1.7 (prime256v1)
  // 0x03 0x42 0x00        BIT STRING, length 66, 0 unused bits
  // 0x04                  SEC1 uncompressed marker, followed by 64 bytes X || Y
  const expectedPrefix = [
    0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00,
  ];
  for (let i = 0; i < expectedPrefix.length; i++) {
    if (raw[i] !== expectedPrefix[i]) {
      throw new Error(
        `PEM SPKI prefix does not match ECDSA P-256. mismatch at byte ${i}: expected 0x${expectedPrefix[i].toString(16).padStart(2, "0")}, got 0x${raw[i].toString(16).padStart(2, "0")}. only ecPublicKey + prime256v1 keys are accepted.`,
      );
    }
  }
  const point = raw.slice(expectedPrefix.length);
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new Error(
      `P-256 public key body must be a 65-byte SEC1 uncompressed point (0x04 || X || Y). got ${point.length} bytes starting with 0x${(point[0] ?? 0).toString(16).padStart(2, "0")}.`,
    );
  }
  return point;
}

function base64Decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
