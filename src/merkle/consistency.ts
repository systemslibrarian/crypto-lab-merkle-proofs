/**
 * consistency.ts — Merkle CONSISTENCY (append-only) proofs.
 *
 * An inclusion proof answers "is this leaf in the tree?". A consistency proof
 * answers a different, log-specific question: "is the tree of size m an exact
 * PREFIX of the tree of size n?" — i.e. the log only ever appended, never
 * rewrote history. This is the property Certificate Transparency relies on.
 *
 * Generation follows RFC 6962 §2.1.2 (the recursive SUBPROOF); verification
 * follows the iterative algorithm of RFC 9162 §2.1.4.2. Both assume RFC 6962
 * 'promote' odd-node semantics (the safe default), which is exactly what
 * buildTree produces.
 */

import { bytesToHex, hashNode, hexToBytes, sha256 } from './hash';
import type { MerkleTree } from './types';

export interface ConsistencyStep {
  readonly hash: Uint8Array;
  readonly hex: string;
}

export interface ConsistencyResult {
  readonly ok: boolean;
  readonly computedOldRootHex: string;
  readonly computedNewRootHex: string;
}

/** Merkle Tree Hash of leaf-hash slice [lo, hi) — RFC 6962 §2.1, recursive. */
async function mthRange(
  leafHashes: readonly Uint8Array[],
  lo: number,
  hi: number,
  domainSep: boolean,
): Promise<Uint8Array> {
  const n = hi - lo;
  if (n === 1) return leafHashes[lo]; // already a leaf hash
  let k = 1;
  while (k * 2 < n) k *= 2; // largest power of two strictly < n
  const left = await mthRange(leafHashes, lo, lo + k, domainSep);
  const right = await mthRange(leafHashes, lo + k, hi, domainSep);
  return hashNode(left, right, domainSep);
}

async function subproof(
  m: number,
  lo: number,
  hi: number,
  withRoot: boolean,
  leafHashes: readonly Uint8Array[],
  domainSep: boolean,
  out: Uint8Array[],
): Promise<void> {
  const n = hi - lo;
  if (m === n) {
    if (!withRoot) out.push(await mthRange(leafHashes, lo, hi, domainSep));
    return;
  }
  let k = 1;
  while (k * 2 < n) k *= 2;
  if (m <= k) {
    await subproof(m, lo, lo + k, withRoot, leafHashes, domainSep, out);
    out.push(await mthRange(leafHashes, lo + k, hi, domainSep));
  } else {
    await subproof(m - k, lo + k, hi, false, leafHashes, domainSep, out);
    out.push(await mthRange(leafHashes, lo, lo + k, domainSep));
  }
}

/**
 * Generate a consistency proof that the first `m` leaves of `tree` form a prefix
 * of the whole tree. `m` must satisfy 1 ≤ m ≤ n; m === n yields an empty proof.
 */
export async function generateConsistencyProof(
  tree: MerkleTree,
  m: number,
): Promise<ConsistencyStep[]> {
  const n = tree.leaves.length;
  if (m < 1 || m > n) {
    throw new RangeError(`old size m=${m} must be in 1..${n}`);
  }
  const leafHashes = tree.leaves.map((l) => l.hash);
  const out: Uint8Array[] = [];
  if (m < n) await subproof(m, 0, n, true, leafHashes, domainSep(tree), out);
  return out.map((hash) => ({ hash, hex: bytesToHex(hash) }));
}

function domainSep(tree: MerkleTree): boolean {
  return tree.domainSep;
}

/** Merkle Tree Hash of the first `m` leaves — the historical (old) root. */
export async function rootOfFirst(tree: MerkleTree, m: number): Promise<string> {
  if (m < 1 || m > tree.leaves.length) throw new RangeError(`m=${m} out of range`);
  const leafHashes = tree.leaves.map((l) => l.hash);
  if (m === 1) return bytesToHex(leafHashes[0]);
  return bytesToHex(await mthRange(leafHashes, 0, m, tree.domainSep));
}

/**
 * Verify a consistency proof (RFC 9162 §2.1.4.2). Confirms that the tree of size
 * `m` with root `oldRootHex` is a prefix of the tree of size `n` with root
 * `newRootHex`, using only the proof.
 */
export async function verifyConsistencyProof(
  m: number,
  n: number,
  oldRootHex: string,
  newRootHex: string,
  proof: readonly ConsistencyStep[],
  domainSeparation = true,
): Promise<ConsistencyResult> {
  const fail = (): ConsistencyResult => ({
    ok: false,
    computedOldRootHex: '',
    computedNewRootHex: '',
  });
  const old = oldRootHex.toLowerCase();
  const neu = newRootHex.toLowerCase();

  if (m > n) return fail();
  if (m === n) {
    return { ok: proof.length === 0 && old === neu, computedOldRootHex: old, computedNewRootHex: neu };
  }
  if (m === 0) {
    return { ok: proof.length === 0, computedOldRootHex: old, computedNewRootHex: neu };
  }

  const path = proof.map((s) => s.hash);
  let idx = 0;
  let node = m - 1;
  let last = n - 1;
  while (node & 1) {
    node >>= 1;
    last >>= 1;
  }

  let fn: Uint8Array;
  let sn: Uint8Array;
  if (node > 0) {
    if (idx >= path.length) return fail();
    fn = path[idx];
    sn = path[idx];
    idx += 1;
  } else {
    fn = hexToBytes(old);
    sn = hexToBytes(old);
  }

  while (node > 0) {
    if (node & 1) {
      if (idx >= path.length) return fail();
      const p = path[idx++];
      fn = await hashNode(p, fn, domainSeparation);
      sn = await hashNode(p, sn, domainSeparation);
    } else if (node < last) {
      if (idx >= path.length) return fail();
      const p = path[idx++];
      sn = await hashNode(sn, p, domainSeparation);
    }
    node >>= 1;
    last >>= 1;
  }

  while (last > 0) {
    if (idx >= path.length) return fail();
    const p = path[idx++];
    sn = await hashNode(sn, p, domainSeparation);
    last >>= 1;
  }

  const computedOldRootHex = bytesToHex(fn);
  const computedNewRootHex = bytesToHex(sn);
  return {
    ok: computedOldRootHex === old && computedNewRootHex === neu && idx === path.length,
    computedOldRootHex,
    computedNewRootHex,
  };
}

// [extension] point — sparse Merkle trees (non-membership proofs) and Verkle
// trees would slot in alongside this module without touching inclusion/proof.ts.

// Re-export for the empty-tree root if ever needed by callers.
export async function emptyRootHex(): Promise<string> {
  return bytesToHex(await sha256(new Uint8Array()));
}
