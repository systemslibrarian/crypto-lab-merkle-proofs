/**
 * hash.ts — SHA-256 (WebCrypto) and the RFC 6962 domain-separated hashing
 * primitives that the whole Merkle tree is built from.
 *
 * Real primitive only: every digest goes through `crypto.subtle.digest`
 * (SubtleCrypto). Nothing here simulates or shortcuts the hash.
 *
 * Domain separation (RFC 6962 §2.1):
 *   leaf hash   = SHA-256( 0x00 || data        )
 *   node hash   = SHA-256( 0x01 || left || right )
 * The 0x00 / 0x01 prefixes make a leaf hash and an internal-node hash live in
 * disjoint input spaces. Without them a Merkle tree is vulnerable to a
 * second-preimage / leaf-node confusion attack (see src/merkle/security.ts).
 */

export const LEAF_PREFIX = 0x00;
export const NODE_PREFIX = 0x01;

const HEX = '0123456789abcdef';

/** Lowercase hex string of a byte array. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 0x0f];
  }
  return out;
}

/** Parse a hex string (even length, [0-9a-fA-F]) to bytes. Throws on malformed input. */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0) {
    throw new Error('hex string must have an even number of characters');
  }
  if (!/^[0-9a-f]*$/.test(clean)) {
    throw new Error('hex string contains non-hex characters');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** UTF-8 encode a string to bytes. */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Concatenate byte arrays into one. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** Constant-time-ish equality on two byte arrays (length + value). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Raw SHA-256 via WebCrypto. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // Cast to BufferSource: TS 5.7's generic Uint8Array<ArrayBufferLike> isn't
  // assignable to the digest signature, but the runtime value is always a plain
  // ArrayBuffer-backed view here.
  const digest = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource);
  return new Uint8Array(digest);
}

/**
 * Hash a leaf. With domain separation (the safe default) the leaf payload is
 * prefixed with 0x00 before hashing, per RFC 6962.
 */
export async function hashLeaf(data: Uint8Array, domainSep = true): Promise<Uint8Array> {
  return domainSep ? sha256(concatBytes(Uint8Array.of(LEAF_PREFIX), data)) : sha256(data);
}

/**
 * Hash an internal node from its two child hashes. With domain separation the
 * input is prefixed with 0x01, per RFC 6962. `left` and `right` are NOT sorted —
 * order is significant and is exactly what a proof's left/right flags encode.
 */
export async function hashNode(
  left: Uint8Array,
  right: Uint8Array,
  domainSep = true,
): Promise<Uint8Array> {
  return domainSep
    ? sha256(concatBytes(Uint8Array.of(NODE_PREFIX), left, right))
    : sha256(concatBytes(left, right));
}

/** Truncate a hex hash for compact display, e.g. "a1b2c3…d4e5f6". */
export function shortHex(hex: string, head = 6, tail = 6): string {
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}
