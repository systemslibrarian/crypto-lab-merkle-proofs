/**
 * types.ts — Strict types for the Merkle tree, proofs, and verification traces.
 *
 * Leaf payloads are raw bytes (Uint8Array), never strings, so that the security
 * demos can feed arbitrary byte sequences (e.g. a 64-byte concatenation of two
 * child hashes) that are not valid UTF-8. A `label` carries the human-readable
 * text for display only.
 */

/** Which side of the running hash a proof sibling sits on. */
export type Side = 'left' | 'right';

/**
 * How a level with an odd number of nodes is handled:
 *  - 'promote'   — carry the lone node up unchanged (RFC 6962; safe)
 *  - 'duplicate' — pair the lone node with a copy of itself, hash(x‖x)
 *                  (Bitcoin; source of the CVE-2012-2459 malleability bug)
 */
export type OddMode = 'promote' | 'duplicate';

export interface MerkleNode {
  /** Raw 32-byte SHA-256 digest for this node. */
  readonly hash: Uint8Array;
  readonly hashHex: string;
  readonly isLeaf: boolean;
  /** Children — present only on internal nodes. */
  readonly left?: MerkleNode;
  readonly right?: MerkleNode;
  /** Leaf-only: original payload bytes and its position in the leaf list. */
  readonly data?: Uint8Array;
  readonly label?: string;
  readonly leafIndex?: number;
}

export interface MerkleTree {
  readonly root: MerkleNode;
  /** Leaves in original insertion order. */
  readonly leaves: readonly MerkleNode[];
  /** levels[0] = leaves, levels[last] = [root]. */
  readonly levels: readonly (readonly MerkleNode[])[];
  /** Whether RFC 6962 domain separation was used to build this tree. */
  readonly domainSep: boolean;
  /** How odd levels were handled. */
  readonly oddMode: OddMode;
}

/** One step of an inclusion (audit) path: a sibling hash and which side it's on. */
export interface ProofStep {
  readonly siblingHash: Uint8Array;
  readonly siblingHex: string;
  readonly side: Side;
}

export interface MerkleProof {
  readonly leafIndex: number;
  /** The leaf payload the proof is for (raw bytes). */
  readonly leafData: Uint8Array;
  readonly leafLabel: string;
  readonly steps: readonly ProofStep[];
}

/** A single recompute step recorded during verification, for visualization. */
export interface VerifyStep {
  readonly index: number;
  readonly inputHex: string;
  readonly siblingHex: string;
  readonly side: Side;
  readonly outputHex: string;
}

export interface VerifyResult {
  readonly ok: boolean;
  readonly computedRootHex: string;
  readonly expectedRootHex: string;
  readonly steps: readonly VerifyStep[];
}
