/**
 * tree.ts — Build a Merkle tree from a list of leaf payloads.
 *
 * Odd-node handling is selectable (see OddMode):
 *  - 'promote'   (default) — RFC 6962: carry the lone node up UNCHANGED.
 *  - 'duplicate'           — Bitcoin: hash the lone node with a copy of itself.
 * The default is the safe RFC 6962 behavior; 'duplicate' exists so the Security
 * panel can demonstrate the CVE-2012-2459 block-malleability bug it caused.
 */

import { bytesToHex, hashLeaf, hashNode, sha256, utf8 } from './hash';
import type { MerkleNode, MerkleTree, OddMode } from './types';

export interface LeafInput {
  readonly bytes: Uint8Array;
  readonly label?: string;
}

/** Convenience: turn plain strings into leaf inputs (UTF-8 encoded). */
export function leavesFromStrings(items: readonly string[]): LeafInput[] {
  return items.map((s) => ({ bytes: utf8(s), label: s }));
}

async function makeLeaf(
  input: LeafInput,
  index: number,
  domainSep: boolean,
): Promise<MerkleNode> {
  const hash = await hashLeaf(input.bytes, domainSep);
  return {
    hash,
    hashHex: bytesToHex(hash),
    isLeaf: true,
    data: input.bytes,
    label: input.label ?? new TextDecoder().decode(input.bytes),
    leafIndex: index,
  };
}

/**
 * Build a Merkle tree. The empty tree's root is SHA-256("") per RFC 6962 §2.1.
 * A single leaf is its own root.
 */
export async function buildTree(
  inputs: readonly LeafInput[],
  domainSep = true,
  oddMode: OddMode = 'promote',
): Promise<MerkleTree> {
  if (inputs.length === 0) {
    const hash = await sha256(new Uint8Array());
    const root: MerkleNode = { hash, hashHex: bytesToHex(hash), isLeaf: false };
    return { root, leaves: [], levels: [[root]], domainSep, oddMode };
  }

  const leaves: MerkleNode[] = [];
  for (let i = 0; i < inputs.length; i++) {
    leaves.push(await makeLeaf(inputs[i], i, domainSep));
  }

  const levels: MerkleNode[][] = [leaves];
  let current: MerkleNode[] = leaves;

  while (current.length > 1) {
    const next: MerkleNode[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = current[i + 1];
      if (right === undefined) {
        if (oddMode === 'duplicate') {
          // Bitcoin: pair the lone node with a copy of itself, hash(x ‖ x).
          const hash = await hashNode(left.hash, left.hash, domainSep);
          next.push({ hash, hashHex: bytesToHex(hash), isLeaf: false, left, right: left });
        } else {
          // RFC 6962: promote the lone node unchanged, do not duplicate.
          next.push(left);
        }
        continue;
      }
      const hash = await hashNode(left.hash, right.hash, domainSep);
      next.push({ hash, hashHex: bytesToHex(hash), isLeaf: false, left, right });
    }
    levels.push(next);
    current = next;
  }

  return { root: current[0], leaves, levels, domainSep, oddMode };
}

/** Convenience builder from plain strings. */
export function buildTreeFromStrings(
  items: readonly string[],
  domainSep = true,
  oddMode: OddMode = 'promote',
): Promise<MerkleTree> {
  return buildTree(leavesFromStrings(items), domainSep, oddMode);
}
