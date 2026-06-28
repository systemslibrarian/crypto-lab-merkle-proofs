/**
 * proof.ts — Inclusion (audit) proof generation and verification.
 *
 * A proof is the minimal set of sibling hashes on the path from a leaf to the
 * root. Its length is the tree height, so proof size grows as O(log n) in the
 * number of leaves — the property that makes Merkle proofs useful at scale.
 *
 * Verification recomputes the root from (leaf, proof) ALONE — it never needs the
 * rest of the tree — and accepts iff the recomputed root equals the trusted root.
 */

import { bytesToHex, hashLeaf, hashNode } from './hash';
import type {
  MerkleProof,
  MerkleTree,
  ProofStep,
  VerifyResult,
  VerifyStep,
} from './types';

/**
 * Generate the inclusion proof for the leaf at `leafIndex`.
 *
 * At each level we look at the sibling of the current index. If the index is the
 * lone promoted node of an odd level it has no sibling at that level, so no step
 * is emitted — it simply rises to the parent. This mirrors buildTree's promotion.
 */
export function generateProof(tree: MerkleTree, leafIndex: number): MerkleProof {
  if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
    throw new RangeError(`leafIndex ${leafIndex} out of range (0..${tree.leaves.length - 1})`);
  }

  const leaf = tree.leaves[leafIndex];
  const steps: ProofStep[] = [];
  let index = leafIndex;

  for (let level = 0; level < tree.levels.length - 1; level++) {
    const nodes = tree.levels[level];
    const isRightChild = index % 2 === 1;
    const siblingIndex = isRightChild ? index - 1 : index + 1;

    if (siblingIndex < nodes.length) {
      const sibling = nodes[siblingIndex];
      steps.push({
        siblingHash: sibling.hash,
        siblingHex: sibling.hashHex,
        // If we are the right child, the sibling is on our left, and vice versa.
        side: isRightChild ? 'left' : 'right',
      });
    }
    index = Math.floor(index / 2);
  }

  return {
    leafIndex,
    leafData: leaf.data ?? new Uint8Array(),
    leafLabel: leaf.label ?? '',
    steps,
  };
}

/**
 * Verify an inclusion proof against a trusted root hash.
 *
 * @param leafData         raw leaf payload bytes
 * @param steps            ordered sibling hashes (leaf level → root level)
 * @param expectedRootHex  the trusted root to check against
 * @param domainSep        must match how the tree was built
 */
export async function verifyProof(
  leafData: Uint8Array,
  steps: readonly ProofStep[],
  expectedRootHex: string,
  domainSep = true,
): Promise<VerifyResult> {
  let running = await hashLeaf(leafData, domainSep);
  const trace: VerifyStep[] = [];

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const inputHex = bytesToHex(running);
    running =
      step.side === 'left'
        ? await hashNode(step.siblingHash, running, domainSep)
        : await hashNode(running, step.siblingHash, domainSep);
    trace.push({
      index: i,
      inputHex,
      siblingHex: step.siblingHex,
      side: step.side,
      outputHex: bytesToHex(running),
    });
  }

  const computedRootHex = bytesToHex(running);
  return {
    ok: computedRootHex === expectedRootHex.toLowerCase(),
    computedRootHex,
    expectedRootHex: expectedRootHex.toLowerCase(),
    steps: trace,
  };
}

/** Theoretical proof length (number of sibling hashes) for n leaves. */
export function expectedProofLength(n: number): number {
  if (n <= 1) return 0;
  return Math.ceil(Math.log2(n));
}
