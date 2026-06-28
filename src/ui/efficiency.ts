/**
 * efficiency.ts — Why Merkle proofs scale: proof size grows as the LOG of the
 * number of leaves. A slider drives the headline numbers; live build buttons
 * prove the claim against real SHA-256 trees of hundreds–thousands of leaves.
 */

import { buildTreeFromStrings } from '../merkle/tree';
import { generateProof, verifyProof } from '../merkle/proof';
import { qs } from './dom';

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

function fmtCount(n: number): string {
  return n.toLocaleString('en-US');
}

export function mountEfficiency(): void {
  const slider = qs<HTMLInputElement>('#eff-slider');
  const readout = qs('#eff-readout');
  const proofBar = qs('#eff-bar-proof');
  const fullBar = qs('#eff-bar-full');
  const expLabel = qs('#eff-exp-label');

  function update(): void {
    const exp = Number(slider.value); // 1..30
    const n = 2 ** exp;
    expLabel.textContent = String(exp);
    const proofHashes = exp; // ceil(log2 n) for power-of-two
    const proofBytes = proofHashes * 32;
    const fullBytes = n * 32; // all leaf hashes a naive verifier would need
    const ratio = fullBytes / proofBytes;

    readout.innerHTML =
      `<strong>${fmtCount(n)}</strong> leaves → a proof is just <strong>${proofHashes}</strong> ` +
      `sibling hashes (<strong>${fmtBytes(proofBytes)}</strong>).<br>` +
      `Sending every leaf hash instead would be <strong>${fmtBytes(fullBytes)}</strong> — ` +
      `the proof is <strong>${fmtCount(Math.round(ratio))}×</strong> smaller.`;

    // Bars use a log scale so both remain visible across 30 orders of magnitude.
    const logFull = Math.log2(fullBytes);
    const logProof = Math.log2(proofBytes);
    fullBar.style.width = '100%';
    proofBar.style.width = `${Math.max(2, (logProof / logFull) * 100)}%`;
  }

  slider.addEventListener('input', update);
  update();

  // Live build-and-verify against real SHA-256 trees.
  const out = qs('#eff-build-out');
  const buttons = qs('#eff-build-buttons');
  buttons.addEventListener('click', async (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-n]');
    if (!btn) return;
    const n = Number(btn.dataset.n);
    buttons.querySelectorAll('button').forEach((b) => (b.disabled = true));
    out.innerHTML = `<p class="mt-hint">Building a real ${fmtCount(n)}-leaf SHA-256 tree…</p>`;

    const items = Array.from({ length: n }, (_, i) => `block-${i}`);
    const t0 = performance.now();
    const tree = await buildTreeFromStrings(items, true);
    const t1 = performance.now();
    const idx = Math.floor(n / 2) + 1;
    const proof = generateProof(tree, idx);
    const res = await verifyProof(proof.leafData, proof.steps, tree.root.hashHex, true);
    const t2 = performance.now();

    out.innerHTML =
      `<table class="mt-eff-table"><tbody>` +
      `<tr><th scope="row">Leaves</th><td>${fmtCount(n)}</td></tr>` +
      `<tr><th scope="row">Tree built in</th><td>${(t1 - t0).toFixed(0)} ms (real SHA-256)</td></tr>` +
      `<tr><th scope="row">Proof for leaf ${fmtCount(idx)}</th><td>${proof.steps.length} hashes (${fmtBytes(proof.steps.length * 32)})</td></tr>` +
      `<tr><th scope="row">Verified in</th><td>${(t2 - t1).toFixed(2)} ms — ${proof.steps.length} hashes, not ${fmtCount(n)}</td></tr>` +
      `<tr><th scope="row">Result</th><td>${res.ok ? '<span class="mt-ok">✓ root matches</span>' : '<span class="mt-bad">✕ mismatch</span>'}</td></tr>` +
      `</tbody></table>`;
    buttons.querySelectorAll('button').forEach((b) => (b.disabled = false));
  });
}
