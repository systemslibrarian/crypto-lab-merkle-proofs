/**
 * rfc9162.ts — Inclusion-proof verification the way real logs ship it.
 *
 * The proofs elsewhere in this lab carry an explicit left/right flag per step.
 * Production logs (Certificate Transparency) don't send sides at all: the
 * verifier derives them from (leaf_index, tree_size) by walking the index bits.
 * This module implements that algorithm — RFC 9162 §2.1.3.2 — so the lab can
 * verify a REAL log entry byte-for-byte.
 */

import { bytesToHex, hashLeaf, hashNode } from './hash';
import type { Side } from './types';

/** One recompute step, with the side the verifier DERIVED from the index math. */
export interface IndexVerifyStep {
  readonly siblingHex: string;
  readonly side: Side;
  readonly outputHex: string;
}

export interface IndexVerifyResult {
  readonly ok: boolean;
  readonly computedRootHex: string;
  readonly expectedRootHex: string;
  readonly steps: readonly IndexVerifyStep[];
}

/**
 * Verify that the leaf whose RFC 6962 leaf hash is `SHA-256(0x00 ∥ leafInput)`
 * sits at `leafIndex` in the tree of `treeSize` leaves with root `rootHex`,
 * using only the `path` of sibling hashes (RFC 9162 §2.1.3.2).
 *
 * At each step: if the low bit of the leaf-index counter is set (we are a right
 * child), or we are the last node of the level, the sibling goes on the LEFT;
 * otherwise on the RIGHT. Promoted lone nodes show up as the extra shifts.
 */
export async function verifyInclusionAtIndex(
  leafInput: Uint8Array,
  leafIndex: number,
  treeSize: number,
  path: readonly Uint8Array[],
  rootHex: string,
): Promise<IndexVerifyResult> {
  const expectedRootHex = rootHex.toLowerCase();
  const steps: IndexVerifyStep[] = [];
  const fail = (): IndexVerifyResult => ({
    ok: false,
    computedRootHex: '',
    expectedRootHex,
    steps,
  });

  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) return fail();

  let r = await hashLeaf(leafInput, true);
  // fn walks the leaf index's bits; sn tracks the last index of the level.
  let fn = leafIndex;
  let sn = treeSize - 1;

  for (const p of path) {
    if (sn === 0) return fail();
    if (fn % 2 === 1 || fn === sn) {
      r = await hashNode(p, r, true);
      steps.push({ siblingHex: bytesToHex(p), side: 'left', outputHex: bytesToHex(r) });
      // A left-sibling step at an even index means we were a promoted lone
      // node: skip the levels it rose through unchanged.
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = await hashNode(r, p, true);
      steps.push({ siblingHex: bytesToHex(p), side: 'right', outputHex: bytesToHex(r) });
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  const computedRootHex = bytesToHex(r);
  // sn must be exhausted: a too-short path leaves levels unaccounted for.
  return { ok: sn === 0 && computedRootHex === expectedRootHex, computedRootHex, expectedRootHex, steps };
}

/**
 * Decode standard base64 to bytes. Hand-rolled (no atob) so the same code runs
 * in the browser and in the Node test environment.
 */
export function b64ToBytes(b64: string): Uint8Array {
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const clean = b64.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buf = 0;
  let bits = 0;
  let o = 0;
  for (const ch of clean) {
    const v = ALPHA.indexOf(ch);
    if (v === -1) throw new Error(`invalid base64 character: ${ch}`);
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buf >> bits) & 0xff;
    }
  }
  return out;
}
