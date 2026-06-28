/**
 * consistency.ts (UI) — Demonstrate Merkle CONSISTENCY (append-only) proofs:
 * proving an old log of size m is an exact prefix of a newer log of size n, and
 * catching a log that rewrote history instead of only appending.
 *
 * Honest color semantics: a verified append reads as success (green); a proof
 * that fails because early entries were altered reads as a broken log (red).
 */

import { buildTreeFromStrings } from '../merkle/tree';
import {
  generateConsistencyProof,
  rootOfFirst,
  verifyConsistencyProof,
} from '../merkle/consistency';
import { qs, esc } from './dom';

// A growing certificate-transparency-style log.
const LOG = ['cert-0', 'cert-1', 'cert-2', 'cert-3', 'cert-4', 'cert-5', 'cert-6', 'cert-7'];

export function mountConsistency(): void {
  const oldSel = qs<HTMLSelectElement>('#cons-old');
  const newSel = qs<HTMLSelectElement>('#cons-new');
  const status = qs('#cons-status');
  const out = qs('#cons-output');

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

  async function show(domainSepOk: boolean, oldRootHex: string, newRootHex: string, m: number, n: number, proof: { hex: string }[]): Promise<void> {
    const res = await verifyConsistencyProof(m, n, oldRootHex, newRootHex, proof as never, true);
    if (res.ok) {
      status.className = 'mt-verdict mt-verdict--ok';
      status.innerHTML =
        '<span class="mt-verdict-icon" aria-hidden="true">✓</span> <strong>CONSISTENT</strong> — ' +
        `the size-${m} log is provably a prefix of the size-${n} log. The log only appended; nothing was rewritten.`;
    } else {
      status.className = 'mt-verdict mt-verdict--bad';
      status.innerHTML =
        '<span class="mt-verdict-icon" aria-hidden="true">✕</span> <strong>NOT CONSISTENT</strong> — ' +
        `the old root is not a prefix of the new log. History was altered, not just appended.`;
    }
    void domainSepOk;
    const steps = proof.length
      ? `<ol class="mt-steps">${proof.map((s, i) => `<li class="mt-step"><span class="mt-step-i">${i + 1}</span><div class="mt-step-body"><code class="mt-mono mt-copy" title="Click to copy">${s.hex}</code></div></li>`).join('')}</ol>`
      : '<p class="mt-hint">Empty proof (the two sizes are equal).</p>';
    out.innerHTML =
      `<dl class="mt-sec-detail">` +
      `<dt>Old root (size ${m})</dt><dd><code class="mt-mono mt-wrap mt-copy" title="Click to copy">${oldRootHex}</code></dd>` +
      `<dt>New root (size ${n})</dt><dd><code class="mt-mono mt-wrap mt-copy" title="Click to copy">${newRootHex}</code></dd>` +
      `</dl>` +
      `<h4 class="sub">Consistency proof (${proof.length} hash${proof.length === 1 ? '' : 'es'})</h4>` +
      steps;
  }

  async function runHonest(): Promise<void> {
    const n = Number(newSel.value);
    const m = Number(oldSel.value);
    const tree = await buildTreeFromStrings(LOG.slice(0, n));
    const oldRoot = await rootOfFirst(tree, m);
    const proof = await generateConsistencyProof(tree, m);
    await show(true, oldRoot, tree.root.hashHex, m, n, proof);
  }

  async function runTamper(): Promise<void> {
    const n = Number(newSel.value);
    const m = Number(oldSel.value);
    // Auditor's remembered old root is from the ORIGINAL log's first m entries.
    const original = await buildTreeFromStrings(LOG.slice(0, n));
    const honestOldRoot = await rootOfFirst(original, m);
    // Operator secretly rewrote entry 0, then presents a proof for the new log.
    const rewritten = [...LOG];
    rewritten[0] = 'cert-0-FORGED';
    const badTree = await buildTreeFromStrings(rewritten.slice(0, n));
    const proof = await generateConsistencyProof(badTree, m);
    await show(false, honestOldRoot, badTree.root.hashHex, m, n, proof);
  }

  fillNew();
  fillOld();
  newSel.addEventListener('change', () => {
    fillOld();
    void runHonest();
  });
  oldSel.addEventListener('change', () => void runHonest());
  qs('#cons-run').addEventListener('click', () => void runHonest());
  qs('#cons-tamper').addEventListener('click', () => void runTamper());
  void runHonest();

  // Label the log for the page (read-only display).
  const logEl = document.getElementById('cons-log');
  if (logEl) {
    logEl.innerHTML = LOG.map((e, i) => `<span class="mt-chip"><span class="mt-chip-idx">${i}</span>${esc(e)}</span>`).join('');
  }
}
