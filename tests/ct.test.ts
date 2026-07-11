import { describe, it, expect } from 'vitest';
import { bytesToHex, utf8 } from '../src/merkle/hash';
import { buildTreeFromStrings } from '../src/merkle/tree';
import { generateProof } from '../src/merkle/proof';
import { b64ToBytes, verifyInclusionAtIndex } from '../src/merkle/rfc9162';
import { CT_FIXTURE } from '../src/merkle/ct-fixture';

describe('b64ToBytes', () => {
  it('decodes known vectors', () => {
    expect(bytesToHex(b64ToBytes('AAEC'))).toBe('000102');
    expect(bytesToHex(b64ToBytes('/w=='))).toBe('ff');
    expect(new TextDecoder().decode(b64ToBytes('aGVsbG8='))).toBe('hello');
  });
  it('rejects invalid characters', () => {
    expect(() => b64ToBytes('a!b')).toThrow();
  });
});

describe('index-based verification (RFC 9162 §2.1.3.2) agrees with side-flagged proofs', () => {
  it('every leaf of trees sized 1..12 verifies by index against the same root', async () => {
    for (let n = 1; n <= 12; n++) {
      const items = Array.from({ length: n }, (_, i) => `entry-${i}`);
      const tree = await buildTreeFromStrings(items);
      for (let i = 0; i < n; i++) {
        const proof = generateProof(tree, i);
        const path = proof.steps.map((s) => s.siblingHash);
        const res = await verifyInclusionAtIndex(utf8(items[i]), i, n, path, tree.root.hashHex);
        expect(res.ok, `n=${n} i=${i}`).toBe(true);
        // The derived sides must match the sides the generator recorded.
        expect(res.steps.map((s) => s.side)).toEqual(proof.steps.map((s) => s.side));
      }
    }
  });

  it('rejects the right proof at the wrong index', async () => {
    const tree = await buildTreeFromStrings(['a', 'b', 'c', 'd', 'e']);
    const proof = generateProof(tree, 2);
    const path = proof.steps.map((s) => s.siblingHash);
    const res = await verifyInclusionAtIndex(utf8('c'), 3, 5, path, tree.root.hashHex);
    expect(res.ok).toBe(false);
  });

  it('rejects out-of-range indexes and short paths', async () => {
    const tree = await buildTreeFromStrings(['a', 'b', 'c', 'd']);
    const proof = generateProof(tree, 1);
    const path = proof.steps.map((s) => s.siblingHash);
    expect((await verifyInclusionAtIndex(utf8('b'), 4, 4, path, tree.root.hashHex)).ok).toBe(false);
    expect((await verifyInclusionAtIndex(utf8('b'), -1, 4, path, tree.root.hashHex)).ok).toBe(false);
    expect(
      (await verifyInclusionAtIndex(utf8('b'), 1, 4, path.slice(0, 1), tree.root.hashHex)).ok,
    ).toBe(false);
  });
});

describe('the real Certificate Transparency fixture', () => {
  const leafInput = b64ToBytes(CT_FIXTURE.leafInputB64);
  const path = CT_FIXTURE.auditPathB64.map(b64ToBytes);
  const rootHex = bytesToHex(b64ToBytes(CT_FIXTURE.rootHashB64));

  it('proof length is ⌈log₂(2.8 billion)⌉ = 32 hashes', () => {
    expect(path.length).toBe(32);
    expect(Math.ceil(Math.log2(CT_FIXTURE.treeSize))).toBe(32);
  });

  it("verifies against the log's pinned signed-tree-head root", async () => {
    const res = await verifyInclusionAtIndex(
      leafInput,
      CT_FIXTURE.leafIndex,
      CT_FIXTURE.treeSize,
      path,
      rootHex,
    );
    expect(res.ok).toBe(true);
    expect(res.computedRootHex).toBe(rootHex);
    expect(res.steps.length).toBe(32);
  });

  it('rejects if any single byte of the certificate entry changes', async () => {
    const tampered = leafInput.slice();
    tampered[500] ^= 0x01; // one bit, deep inside the DER certificate
    const res = await verifyInclusionAtIndex(
      tampered,
      CT_FIXTURE.leafIndex,
      CT_FIXTURE.treeSize,
      path,
      rootHex,
    );
    expect(res.ok).toBe(false);
  });

  it('rejects a tampered audit-path hash and a wrong index', async () => {
    const badPath = path.map((p, i) => (i === 10 ? p.map((b, j) => (j === 0 ? b ^ 1 : b)) : p));
    expect(
      (
        await verifyInclusionAtIndex(
          leafInput,
          CT_FIXTURE.leafIndex,
          CT_FIXTURE.treeSize,
          badPath as unknown as Uint8Array[],
          rootHex,
        )
      ).ok,
    ).toBe(false);
    expect(
      (
        await verifyInclusionAtIndex(leafInput, CT_FIXTURE.leafIndex + 1, CT_FIXTURE.treeSize, path, rootHex)
      ).ok,
    ).toBe(false);
  });

  it('the MerkleTreeLeaf header parses as a v1 precert logged at the pinned time', () => {
    expect(leafInput[0]).toBe(0); // version v1
    expect(leafInput[1]).toBe(0); // leaf_type timestamped_entry
    let ts = 0;
    for (let i = 2; i < 10; i++) ts = ts * 256 + leafInput[i];
    expect(new Date(ts).toISOString().slice(0, 19) + 'Z').toBe(CT_FIXTURE.loggedAt);
    expect((leafInput[10] << 8) | leafInput[11]).toBe(1); // entry_type precert_entry
  });
});
