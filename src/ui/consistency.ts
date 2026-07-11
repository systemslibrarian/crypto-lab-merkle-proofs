/**
 * consistency.ts (UI) — Demonstrate Merkle CONSISTENCY (append-only) proofs:
 * proving an old log of size m is an exact prefix of a newer log of size n, and
 * catching a log that rewrote, deleted, or reordered history.
 *
 * The visualization renders the size-n tree with the old size-m prefix shaded,
 * and marks the nodes whose hashes make up the proof: every proof hash is the
 * root of a subtree that either sits entirely inside the old prefix (◆ — used
 * to rebuild the OLD root, then reused for the new one) or entirely in the
 * appended region (◇ — needed only to complete the NEW root). Seeing that the
 * old root is stitched together from subtrees that are still intact inside the
 * new tree IS the intuition for why the proof works.
 *
 * Honest color semantics: a verified append reads as success (green); a proof
 * that fails because history changed reads as a broken log (red).
 */

import { buildTreeFromStrings } from '../merkle/tree';
import {
  generateConsistencyProof,
  rootOfFirst,
  verifyConsistencyProof,
} from '../merkle/consistency';
import type { MerkleNode, MerkleTree } from '../merkle/types';
import { qs, esc } from './dom';
import { renderTree, type NodeDecor } from './tree-svg';

// A growing certificate-transparency-style log.
const LOG = ['cert-0', 'cert-1', 'cert-2', 'cert-3', 'cert-4', 'cert-5', 'cert-6', 'cert-7'];

type Tamper = 'rewrite' | 'delete' | 'reorder';

/** Leaf-index range [lo, hi) covered by each node, from a post-order walk. */
function leafRanges(tree: MerkleTree): Map<MerkleNode, { lo: number; hi: number }> {
  const ranges = new Map<MerkleNode, { lo: number; hi: number }>();
  function walk(node: MerkleNode): { lo: number; hi: number } {
    const cached = ranges.get(node);
    if (cached) return cached;
    let r: { lo: number; hi: number };
    if (node.isLeaf && node.leafIndex !== undefined) {
      r = { lo: node.leafIndex, hi: node.leafIndex + 1 };
    } else {
      const l = walk(node.left!);
      const h = node.right ? walk(node.right) : l;
      r = { lo: l.lo, hi: h.hi };
    }
    ranges.set(node, r);
    return r;
  }
  if (tree.leaves.length > 0) walk(tree.root);
  return ranges;
}

export function mountConsistency(): void {
  const oldSel = qs<HTMLSelectElement>('#cons-old');
  const newSel = qs<HTMLSelectElement>('#cons-new');
  const status = qs('#cons-status');
  const out = qs('#cons-output');
  const canvas = qs('#cons-canvas');

  function fillNew(): void {
    newSel.innerHTML = LOG.map((_, i) => i + 1)
      .filter((n) => n >= 2)
      .map((n) => `<option value="${n}">${n}</option>`)
      .join('');
    newSel.value = String(LOG.length);
  }
  function fillOld(): void {
    const n = Number(newSel.value);
    const prev = Number(oldSel.value) || 1;
    oldSel.innerHTML = Array.from({ length: n - 1 }, (_, i) => i + 1)
      .map((m) => `<option value="${m}">${m}</option>`)
      .join('');
    oldSel.value = String(Math.min(prev, n - 1));
  }

  // Guard against interleaved runs: hashing is async, so a slow honest run must
  // not overwrite the verdict of a tamper run started after it (and vice versa).
  let runToken = 0;

  /** Draw the size-n tree: old prefix shaded, proof-hash subtree roots marked. */
  function drawTree(tree: MerkleTree, m: number, proofHexes: readonly string[]): void {
    const ranges = leafRanges(tree);
    const proofSet = new Set(proofHexes);
    const decor = new Map<MerkleNode, NodeDecor>();
    let oldSide = 0;
    let newSide = 0;
    for (const [node, r] of ranges) {
      const inOld = r.hi <= m;
      const d: NodeDecor = {};
      if (inOld) d.cls = 'mt-node--old';
      if (proofSet.has(node.hashHex)) {
        d.cls = `${d.cls ?? ''} mt-node--consproof`.trim();
        d.marker = inOld ? '◆' : '◇';
        if (inOld) oldSide += 1;
        else newSide += 1;
      }
      if (d.cls || d.marker) decor.set(node, d);
    }
    renderTree(canvas, tree, undefined, {
      decor,
      ariaLabel:
        `New tree with ${tree.leaves.length} leaves. The first ${m} leaves (the old log) are shaded. ` +
        `The consistency proof hands over ${oldSide} subtree hash${oldSide === 1 ? '' : 'es'} inside the old prefix ` +
        `and ${newSide} in the appended region.`,
    });
  }

  async function show(
    token: number,
    oldRootHex: string,
    tree: MerkleTree,
    m: number,
    n: number,
  ): Promise<void> {
    const proof = await generateConsistencyProof(tree, m);
    const newRootHex = tree.root.hashHex;
    const res = await verifyConsistencyProof(m, n, oldRootHex, newRootHex, proof, true);
    if (token !== runToken) return; // a newer run superseded this one
    drawTree(tree, m, proof.map((s) => s.hex));

    if (res.ok) {
      status.className = 'mt-verdict mt-verdict--ok';
      status.innerHTML =
        '<span class="mt-verdict-icon" aria-hidden="true">✓</span> <strong>CONSISTENT</strong> — ' +
        `the size-${m} log is provably a prefix of the size-${n} log. The log only appended; nothing was rewritten.`;
    } else {
      status.className = 'mt-verdict mt-verdict--bad';
      status.innerHTML =
        '<span class="mt-verdict-icon" aria-hidden="true">✕</span> <strong>NOT CONSISTENT</strong> — ' +
        `the remembered old root cannot be rebuilt from the new log's subtrees. History was altered, not just appended.`;
    }

    const steps = proof.length
      ? `<ol class="mt-steps">${proof.map((s, i) => `<li class="mt-step"><span class="mt-step-i">${i + 1}</span><div class="mt-step-body"><code class="mt-mono mt-copy" title="Click to copy">${s.hex}</code></div></li>`).join('')}</ol>`
      : '<p class="mt-hint">Empty proof (the two sizes are equal).</p>';
    out.innerHTML =
      `<dl class="mt-sec-detail">` +
      `<dt>Old root (size ${m}) — the auditor REMEMBERS this</dt><dd><code class="mt-mono mt-wrap mt-copy" title="Click to copy">${oldRootHex}</code></dd>` +
      `<dt>New root (size ${n}) — the log CLAIMS this</dt><dd><code class="mt-mono mt-wrap mt-copy" title="Click to copy">${newRootHex}</code></dd>` +
      `</dl>` +
      `<h4 class="sub">Consistency proof (${proof.length} hash${proof.length === 1 ? '' : 'es'} ≈ log₂ ${n} — logarithmic, like inclusion proofs)</h4>` +
      steps;
  }

  async function runHonest(): Promise<void> {
    const token = ++runToken;
    const n = Number(newSel.value);
    const m = Number(oldSel.value);
    const tree = await buildTreeFromStrings(LOG.slice(0, n));
    const oldRoot = await rootOfFirst(tree, m);
    if (token !== runToken) return;
    renderLog(LOG.slice(0, n), m, null);
    await show(token, oldRoot, tree, m, n);
  }

  /** The operator alters history, then presents a proof for the altered log.
   *  The auditor still holds the old root from the ORIGINAL first m entries. */
  async function runTamper(kind: Tamper): Promise<void> {
    const token = ++runToken;
    const n = Number(newSel.value);
    const m = Number(oldSel.value);
    const original = await buildTreeFromStrings(LOG.slice(0, n));
    const honestOldRoot = await rootOfFirst(original, m);

    const rewritten = LOG.slice(0, n);
    if (kind === 'rewrite') {
      rewritten[0] = 'cert-0-FORGED';
    } else if (kind === 'delete') {
      // Delete an entry INSIDE the old prefix; everything after shifts left.
      // (A deletion is only detectable if it touches entries the old root
      // committed to — that caveat is called out in the page copy.)
      rewritten.splice(deleteIndex(m), 1);
    } else {
      // Swap the first two entries; same contents, different order.
      [rewritten[0], rewritten[1]] = [rewritten[1], rewritten[0]];
    }
    const badTree = await buildTreeFromStrings(rewritten);
    if (token !== runToken) return;
    renderLog(rewritten, m, kind);
    // After a deletion the new log may be shorter than the old claim; clamp so
    // the claim stays well-formed (m ≤ n) — it still fails, which is the point.
    await show(token, honestOldRoot, badTree, Math.min(m, rewritten.length), rewritten.length);
  }

  /** Delete entry 1 when the prefix covers it, else entry 0 — always inside
   *  the old prefix, so the attack is always detectable. */
  function deleteIndex(m: number): number {
    return m >= 2 ? 1 : 0;
  }

  function renderLog(entries: readonly string[], m: number, tamper: Tamper | null): void {
    const logEl = document.getElementById('cons-log');
    if (!logEl) return;
    logEl.innerHTML = entries
      .map((e, i) => {
        const old = i < m;
        const altered =
          (tamper === 'rewrite' && i === 0) ||
          (tamper === 'delete' && i >= deleteIndex(m)) ||
          (tamper === 'reorder' && i <= 1);
        return (
          `<span class="mt-chip${old ? ' mt-chip--old' : ''}${altered ? ' mt-chip--altered' : ''}">` +
          `<span class="mt-chip-idx">${i}</span>${esc(e)}${altered ? '<span class="mt-chip-warn" aria-hidden="true">≠</span>' : ''}` +
          `</span>`
        );
      })
      .join('');
  }

  fillNew();
  fillOld();
  newSel.addEventListener('change', () => {
    fillOld();
    void runHonest();
  });
  oldSel.addEventListener('change', () => void runHonest());
  qs('#cons-run').addEventListener('click', () => void runHonest());
  qs('#cons-tamper').addEventListener('click', () => void runTamper('rewrite'));
  qs('#cons-tamper-delete').addEventListener('click', () => void runTamper('delete'));
  qs('#cons-tamper-reorder').addEventListener('click', () => void runTamper('reorder'));
  void runHonest();
}
