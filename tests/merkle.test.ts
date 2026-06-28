import { describe, it, expect } from 'vitest';
import {
  bytesToHex,
  hexToBytes,
  utf8,
  sha256,
  hashLeaf,
  hashNode,
  concatBytes,
} from '../src/merkle/hash';
import { buildTree, buildTreeFromStrings, leavesFromStrings } from '../src/merkle/tree';
import { generateProof, verifyProof, expectedProofLength } from '../src/merkle/proof';
import { buildSecondPreimageForgery } from '../src/merkle/security';

const SAMPLE = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace'];

describe('hex helpers', () => {
  it('round-trips bytes ↔ hex', () => {
    const bytes = Uint8Array.from([0x00, 0x01, 0xff, 0xab, 0x10]);
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });
  it('rejects odd-length hex', () => {
    expect(() => hexToBytes('abc')).toThrow();
  });
  it('rejects non-hex characters', () => {
    expect(() => hexToBytes('zz')).toThrow();
  });
});

describe('RFC 6962 known-answer vectors', () => {
  it('empty tree root is SHA-256("")', async () => {
    const tree = await buildTree([]);
    expect(tree.root.hashHex).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('single empty leaf hash is SHA-256(0x00)', async () => {
    const tree = await buildTree([{ bytes: new Uint8Array() }]);
    expect(tree.root.hashHex).toBe(
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    );
  });

  it('leaf/node prefixes match RFC 6962 (0x00 / 0x01)', async () => {
    const data = utf8('x');
    expect(bytesToHex(await hashLeaf(data, true))).toBe(
      bytesToHex(await sha256(concatBytes(Uint8Array.of(0x00), data))),
    );
    const a = await sha256(utf8('a'));
    const b = await sha256(utf8('b'));
    expect(bytesToHex(await hashNode(a, b, true))).toBe(
      bytesToHex(await sha256(concatBytes(Uint8Array.of(0x01), a, b))),
    );
  });
});

describe('tree construction', () => {
  it('matches an independent hand recomputation for 4 leaves', async () => {
    const tree = await buildTreeFromStrings(['a', 'b', 'c', 'd']);
    const la = await hashLeaf(utf8('a'));
    const lb = await hashLeaf(utf8('b'));
    const lc = await hashLeaf(utf8('c'));
    const ld = await hashLeaf(utf8('d'));
    const nab = await hashNode(la, lb);
    const ncd = await hashNode(lc, ld);
    const root = await hashNode(nab, ncd);
    expect(tree.root.hashHex).toBe(bytesToHex(root));
  });

  it('is deterministic and order-sensitive', async () => {
    const t1 = await buildTreeFromStrings(['a', 'b', 'c']);
    const t2 = await buildTreeFromStrings(['a', 'b', 'c']);
    const t3 = await buildTreeFromStrings(['b', 'a', 'c']);
    expect(t1.root.hashHex).toBe(t2.root.hashHex);
    expect(t1.root.hashHex).not.toBe(t3.root.hashHex);
  });

  it('promotes a lone odd node instead of duplicating it', async () => {
    // 3 leaves: level1 = [hash(a,b), c-promoted]; root = hash(hash(a,b), leaf(c)).
    const tree = await buildTreeFromStrings(['a', 'b', 'c']);
    const la = await hashLeaf(utf8('a'));
    const lb = await hashLeaf(utf8('b'));
    const lc = await hashLeaf(utf8('c'));
    const nab = await hashNode(la, lb);
    const root = await hashNode(nab, lc); // c promoted, NOT hash(c,c)
    expect(tree.root.hashHex).toBe(bytesToHex(root));
  });
});

describe('proof generation + verification round-trip', () => {
  for (const n of [1, 2, 3, 4, 5, 7, 8, 16]) {
    it(`every leaf of an ${n}-leaf tree produces a verifying proof`, async () => {
      const items = Array.from({ length: n }, (_, i) => `item-${i}`);
      const tree = await buildTreeFromStrings(items);
      for (let i = 0; i < n; i++) {
        const proof = generateProof(tree, i);
        const res = await verifyProof(proof.leafData, proof.steps, tree.root.hashHex);
        expect(res.ok, `leaf ${i} of ${n}`).toBe(true);
        expect(res.computedRootHex).toBe(tree.root.hashHex);
        // proof never longer than the tree height
        expect(proof.steps.length).toBeLessThanOrEqual(expectedProofLength(n));
      }
    });
  }

  it('power-of-two trees give every leaf exactly log2(n) steps', async () => {
    const tree = await buildTreeFromStrings(Array.from({ length: 8 }, (_, i) => `${i}`));
    for (let i = 0; i < 8; i++) {
      expect(generateProof(tree, i).steps.length).toBe(3);
    }
  });

  it('out-of-range leaf index throws', async () => {
    const tree = await buildTreeFromStrings(['a', 'b']);
    expect(() => generateProof(tree, 5)).toThrow();
  });
});

describe('tamper detection', () => {
  it('rejects a modified leaf', async () => {
    const tree = await buildTreeFromStrings(SAMPLE);
    const proof = generateProof(tree, 2);
    const res = await verifyProof(utf8('mallory'), proof.steps, tree.root.hashHex);
    expect(res.ok).toBe(false);
  });

  it('rejects a flipped bit in a proof sibling', async () => {
    const tree = await buildTreeFromStrings(SAMPLE);
    const proof = generateProof(tree, 2);
    const steps = proof.steps.map((s) => ({ ...s, siblingHash: s.siblingHash.slice() }));
    steps[0].siblingHash[0] ^= 0x01;
    steps[0] = { ...steps[0], siblingHex: bytesToHex(steps[0].siblingHash) };
    const res = await verifyProof(proof.leafData, steps, tree.root.hashHex);
    expect(res.ok).toBe(false);
  });

  it('rejects a swapped sibling side', async () => {
    const tree = await buildTreeFromStrings(SAMPLE);
    const proof = generateProof(tree, 1);
    const steps = proof.steps.map((s, i) =>
      i === 0 ? { ...s, side: s.side === 'left' ? ('right' as const) : ('left' as const) } : s,
    );
    const res = await verifyProof(proof.leafData, steps, tree.root.hashHex);
    expect(res.ok).toBe(false);
  });

  it('rejects a proof against the wrong root', async () => {
    const tree = await buildTreeFromStrings(SAMPLE);
    const other = await buildTreeFromStrings(['x', 'y', 'z', 'w']);
    const proof = generateProof(tree, 0);
    const res = await verifyProof(proof.leafData, proof.steps, other.root.hashHex);
    expect(res.ok).toBe(false);
  });
});

describe('second-preimage attack (the reason domain separation exists)', () => {
  it('WITHOUT domain separation, a forged leaf verifies against the real root', async () => {
    const tree = await buildTree(leavesFromStrings(SAMPLE), /* domainSep */ false);
    const forgery = buildSecondPreimageForgery(tree);
    const res = await verifyProof(
      forgery.forgedLeafBytes,
      forgery.steps,
      tree.root.hashHex,
      /* domainSep */ false,
    );
    expect(res.ok).toBe(true); // attack succeeds — this is the vulnerability
    // and the forged "leaf" is not any real leaf payload
    const realLeafBytes = tree.leaves.map((l) => bytesToHex(l.data!));
    expect(realLeafBytes).not.toContain(bytesToHex(forgery.forgedLeafBytes));
  });

  it('WITH domain separation, the same construction is rejected', async () => {
    const tree = await buildTree(leavesFromStrings(SAMPLE), /* domainSep */ true);
    const forgery = buildSecondPreimageForgery(tree);
    const res = await verifyProof(
      forgery.forgedLeafBytes,
      forgery.steps,
      tree.root.hashHex,
      /* domainSep */ true,
    );
    expect(res.ok).toBe(false); // defended
  });
});
