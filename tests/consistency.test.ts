import { describe, it, expect } from 'vitest';
import { buildTreeFromStrings } from '../src/merkle/tree';
import {
  generateConsistencyProof,
  verifyConsistencyProof,
  rootOfFirst,
} from '../src/merkle/consistency';

const items = (n: number): string[] => Array.from({ length: n }, (_, i) => `entry-${i}`);

describe('Merkle consistency (append-only) proofs', () => {
  it('rootOfFirst(tree, n) equals the full tree root', async () => {
    const tree = await buildTreeFromStrings(items(9));
    expect(await rootOfFirst(tree, 9)).toBe(tree.root.hashHex);
  });

  it('rootOfFirst(tree, m) equals an independently built m-leaf tree', async () => {
    const tree = await buildTreeFromStrings(items(13));
    for (const m of [1, 2, 3, 5, 8, 12]) {
      const sub = await buildTreeFromStrings(items(13).slice(0, m));
      expect(await rootOfFirst(tree, m), `m=${m}`).toBe(sub.root.hashHex);
    }
  });

  it('a valid proof verifies the old tree is a prefix of the new tree (all m≤n, n up to 12)', async () => {
    for (let n = 2; n <= 12; n++) {
      const tree = await buildTreeFromStrings(items(n));
      for (let m = 1; m <= n; m++) {
        const oldRoot = await rootOfFirst(tree, m);
        const proof = await generateConsistencyProof(tree, m);
        const res = await verifyConsistencyProof(m, n, oldRoot, tree.root.hashHex, proof);
        expect(res.ok, `n=${n} m=${m}`).toBe(true);
        expect(res.computedNewRootHex === '' || res.computedNewRootHex === tree.root.hashHex).toBe(true);
      }
    }
  });

  it('m === n yields an empty proof and verifies', async () => {
    const tree = await buildTreeFromStrings(items(7));
    const proof = await generateConsistencyProof(tree, 7);
    expect(proof.length).toBe(0);
    const res = await verifyConsistencyProof(7, 7, tree.root.hashHex, tree.root.hashHex, proof);
    expect(res.ok).toBe(true);
  });

  it('rejects a tampered old root', async () => {
    const tree = await buildTreeFromStrings(items(11));
    const m = 6;
    const oldRoot = await rootOfFirst(tree, m);
    const proof = await generateConsistencyProof(tree, m);
    const badOld = oldRoot.slice(0, -1) + (oldRoot.endsWith('0') ? '1' : '0');
    const res = await verifyConsistencyProof(m, 11, badOld, tree.root.hashHex, proof);
    expect(res.ok).toBe(false);
  });

  it('rejects a non-prefix history (the first m entries were rewritten)', async () => {
    // Old log: first 5 of A. New log: B, whose first 5 entries differ from A's.
    const treeA = await buildTreeFromStrings(items(5));
    const oldRoot = treeA.root.hashHex; // honest old root for A[0:5]
    const rewritten = ['HACKED', ...items(9).slice(1)]; // entry-0 replaced
    const treeB = await buildTreeFromStrings(rewritten);
    const proof = await generateConsistencyProof(treeB, 5); // proof for B's own prefix
    // Claiming A's old root is a prefix of B must fail.
    const res = await verifyConsistencyProof(5, rewritten.length, oldRoot, treeB.root.hashHex, proof);
    expect(res.ok).toBe(false);
  });

  it('rejects a tampered proof hash', async () => {
    const tree = await buildTreeFromStrings(items(14));
    const m = 9;
    const oldRoot = await rootOfFirst(tree, m);
    const proof = await generateConsistencyProof(tree, m);
    const tampered = proof.map((s, i) =>
      i === 0 ? { hash: ((): Uint8Array => { const b = s.hash.slice(); b[0] ^= 1; return b; })(), hex: '' } : s,
    );
    const res = await verifyConsistencyProof(m, 14, oldRoot, tree.root.hashHex, tampered);
    expect(res.ok).toBe(false);
  });
});
