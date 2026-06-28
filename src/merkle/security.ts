/**
 * security.ts — The second-preimage (leaf-node confusion) attack, and the
 * domain-separation defense that stops it.
 *
 * THREAT: In a Merkle tree built WITHOUT domain separation, a leaf is hashed as
 * SHA-256(data) and an internal node as SHA-256(left || right). Those two hash
 * inputs live in the SAME space. So an attacker can take any internal node N with
 * children (A, B) and present the 64-byte string (A || B) as if it were a *leaf*:
 *   leafHash(A || B) = SHA-256(A || B) = N
 * The audit path from N up to the root then verifies — "proving" inclusion of a
 * leaf that was never in the tree.
 *
 * DEFENSE (RFC 6962): prefix leaves with 0x00 and nodes with 0x01. Now
 * leafHash(x) = SHA-256(0x00 || x) can never equal nodeHash(A,B) = SHA-256(0x01 || A || B),
 * so the forged leaf no longer collides with any internal node. The attack fails
 * to even get off the ground.
 *
 * This module is intentionally isolated and is only ever invoked from the
 * clearly-labeled "Security" panel; it is never on the default tree-building path.
 */

import { concatBytes } from './hash';
import type { MerkleTree, ProofStep } from './types';

export interface ForgeryAttempt {
  /** The fabricated "leaf" payload: the concatenation of two real child hashes. */
  readonly forgedLeafBytes: Uint8Array;
  /** Audit path from the targeted internal node up to the root. */
  readonly steps: ProofStep[];
  /** Hash of the internal node we are impersonating as a leaf. */
  readonly targetHashHex: string;
  readonly rootHex: string;
}

/**
 * Construct a second-preimage forgery attempt against `tree`.
 *
 * The same construction is built regardless of how `tree` was hashed; whether it
 * SUCCEEDS is what differs. Feed the result to `verifyProof(..., tree.domainSep)`:
 *   - domainSep === false → verification ACCEPTS the forged leaf (vulnerable)
 *   - domainSep === true  → verification REJECTS it (defended)
 *
 * Requires at least 2 leaves so that an internal node exists.
 */
export function buildSecondPreimageForgery(tree: MerkleTree): ForgeryAttempt {
  if (tree.levels.length < 2 || tree.levels[1].length === 0) {
    throw new Error('need at least 2 leaves to have an internal node to impersonate');
  }

  // Target the first genuine internal node (parent of leaves 0 and 1).
  const target = tree.levels[1][0];
  if (!target.left || !target.right) {
    throw new Error('targeted node is a promoted leaf, not a true internal node');
  }

  const forgedLeafBytes = concatBytes(target.left.hash, target.right.hash);

  // Audit path from level 1, index 0 up to the root — identical machinery to a
  // normal proof, just starting one level higher.
  const steps: ProofStep[] = [];
  let index = 0;
  for (let level = 1; level < tree.levels.length - 1; level++) {
    const nodes = tree.levels[level];
    const isRightChild = index % 2 === 1;
    const siblingIndex = isRightChild ? index - 1 : index + 1;
    if (siblingIndex < nodes.length) {
      const sibling = nodes[siblingIndex];
      steps.push({
        siblingHash: sibling.hash,
        siblingHex: sibling.hashHex,
        side: isRightChild ? 'left' : 'right',
      });
    }
    index = Math.floor(index / 2);
  }

  return {
    forgedLeafBytes,
    steps,
    targetHashHex: target.hashHex,
    rootHex: tree.root.hashHex,
  };
}
