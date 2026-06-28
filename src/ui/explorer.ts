/**
 * explorer.ts — The shared interactive core: build a tree, pick a leaf, see its
 * proof, and verify it (honestly or after tampering). Sections 2–4 of the demo
 * all operate on this one tree + selection so the story stays continuous.
 */

import { utf8 } from '../merkle/hash';
import { buildTreeFromStrings } from '../merkle/tree';
import { generateProof, verifyProof, expectedProofLength } from '../merkle/proof';
import type { MerkleProof, MerkleTree, ProofStep } from '../merkle/types';
import { qs, esc, copyText } from './dom';
import { renderTree, findPath } from './tree-svg';

const MAX_LEAVES = 16;
const SAMPLE = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank'];
const TX_BLOCK = ['tx: A→B 0.5', 'tx: C→D 1.2', 'tx: E→F 0.1', 'tx: G→H 3.0', 'tx: I→J 0.7'];

interface State {
  leaves: string[];
  selected: number | null;
  tree: MerkleTree | null;
  proof: MerkleProof | null;
  // Verification working copy (may be tampered):
  vLeaf: string;
  vSteps: ProofStep[];
}

const state: State = {
  leaves: [...SAMPLE],
  selected: 0,
  tree: null,
  proof: null,
  vLeaf: '',
  vSteps: [],
};

let canvas: HTMLElement;
let leafList: HTMLElement;
let leafInput: HTMLInputElement;
let leafCount: HTMLElement;
let rootHash: HTMLElement;
let leafSelect: HTMLSelectElement;
let proofOut: HTMLElement;
let verifyLeaf: HTMLInputElement;
let verifySteps: HTMLElement;
let verifyTrace: HTMLElement;
let verifyVerdict: HTMLElement;
let srStatus: HTMLElement;

export function mountExplorer(): void {
  canvas = qs('#tree-canvas');
  leafList = qs('#leaf-list');
  leafInput = qs<HTMLInputElement>('#leaf-input');
  leafCount = qs('#leaf-count');
  rootHash = qs('#root-hash');
  leafSelect = qs<HTMLSelectElement>('#leaf-select');
  proofOut = qs('#proof-output');
  verifyLeaf = qs<HTMLInputElement>('#verify-leaf');
  verifySteps = qs('#verify-steps');
  verifyTrace = qs('#verify-trace');
  verifyVerdict = qs('#verify-verdict');
  srStatus = qs('#sr-status');

  // Builder controls
  qs('#leaf-add').addEventListener('click', addLeaf);
  leafInput.addEventListener('keydown', (e) => {
    if ((e as KeyboardEvent).key === 'Enter') addLeaf();
  });
  qs('#preset-sample').addEventListener('click', () => setLeaves([...SAMPLE]));
  qs('#preset-tx').addEventListener('click', () => setLeaves([...TX_BLOCK]));
  qs('#preset-clear').addEventListener('click', () => setLeaves([]));

  leafList.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-remove]');
    if (btn) removeLeaf(Number(btn.dataset.remove));
  });

  // Leaf selection: the <select> is the accessible/keyboard path; clicking a
  // leaf box in the SVG is a visual convenience for pointer users.
  canvas.addEventListener('click', onCanvasSelect);
  leafSelect.addEventListener('change', () => selectLeaf(Number(leafSelect.value)));

  // Verify controls
  qs('#verify-honest').addEventListener('click', resetVerify);
  qs('#verify-run').addEventListener('click', runVerify);
  qs('#verify-tamper-leaf').addEventListener('click', () => {
    verifyLeaf.value = verifyLeaf.value + '!';
    runVerify();
  });
  qs('#verify-flip').addEventListener('click', flipFirstStep);
  verifyLeaf.addEventListener('input', () => {
    state.vLeaf = verifyLeaf.value;
  });

  const copyRoot = (): void => {
    if (state.tree) void copyText(state.tree.root.hashHex);
  };
  rootHash.addEventListener('click', copyRoot);
  rootHash.addEventListener('keydown', (e) => {
    const key = (e as KeyboardEvent).key;
    if (key === 'Enter' || key === ' ') {
      e.preventDefault();
      copyRoot();
    }
  });

  void refresh();
}

function onCanvasSelect(e: Event): void {
  const target = (e.target as HTMLElement).closest<HTMLElement>('[data-leaf-index]');
  if (!target) return;
  e.preventDefault();
  selectLeaf(Number(target.dataset.leafIndex));
}

function addLeaf(): void {
  const v = leafInput.value.trim();
  if (!v) return;
  if (state.leaves.length >= MAX_LEAVES) {
    flashCount(`Max ${MAX_LEAVES} leaves in the visual builder — see the Efficiency section for scale.`);
    return;
  }
  state.leaves.push(v);
  leafInput.value = '';
  if (state.selected === null) state.selected = state.leaves.length - 1;
  void refresh();
}

function removeLeaf(i: number): void {
  state.leaves.splice(i, 1);
  if (state.leaves.length === 0) state.selected = null;
  else if (state.selected === null) state.selected = 0;
  else if (state.selected >= state.leaves.length) state.selected = state.leaves.length - 1;
  void refresh();
}

function setLeaves(leaves: string[]): void {
  state.leaves = leaves;
  state.selected = leaves.length ? 0 : null;
  void refresh();
}

function selectLeaf(i: number): void {
  if (i < 0 || i >= state.leaves.length) return;
  state.selected = i;
  syncSelection();
}

let countTimer: number | undefined;
function flashCount(msg: string): void {
  leafCount.textContent = msg;
  leafCount.classList.add('mt-note--warn');
  if (countTimer) clearTimeout(countTimer);
  countTimer = window.setTimeout(() => {
    leafCount.classList.remove('mt-note--warn');
    updateCount();
  }, 3500);
}

function updateCount(): void {
  const n = state.leaves.length;
  leafCount.textContent = `${n} leaf${n === 1 ? '' : 'ves'} · proof size ≤ ${expectedProofLength(n)} hashes`;
}

/** Rebuild the tree from leaves and refresh every dependent view. */
async function refresh(): Promise<void> {
  renderLeafChips();
  updateCount();
  state.tree = await buildTreeFromStrings(state.leaves, true);
  rootHash.textContent = state.tree.root.hashHex;
  if (state.leaves.length === 0) state.selected = null;
  else if (state.selected === null) state.selected = 0;
  renderLeafSelect(); // option list only changes when the leaf set changes
  syncSelection();
}

function renderLeafSelect(): void {
  if (state.leaves.length === 0) {
    leafSelect.innerHTML = '<option value="">No leaves yet</option>';
    leafSelect.disabled = true;
    return;
  }
  leafSelect.disabled = false;
  leafSelect.innerHTML = state.leaves
    .map((l, i) => `<option value="${i}"${i === state.selected ? ' selected' : ''}>Leaf ${i}: ${esc(l)}</option>`)
    .join('');
  if (state.selected !== null) leafSelect.value = String(state.selected);
}

/** Re-render tree highlight, proof, and reset verification to the honest proof. */
function syncSelection(): void {
  if (!state.tree) return;
  if (state.selected !== null) leafSelect.value = String(state.selected);
  const path = findPath(state.tree, state.selected);
  renderTree(canvas, state.tree, path);

  if (state.selected === null || state.tree.leaves.length === 0) {
    state.proof = null;
    proofOut.innerHTML = '<p class="mt-hint">Add at least one leaf, then select it to generate a proof.</p>';
    verifyTrace.innerHTML = '';
    verifyVerdict.className = 'mt-verdict';
    verifyVerdict.innerHTML = '';
    verifySteps.innerHTML = '';
    return;
  }

  state.proof = generateProof(state.tree, state.selected);
  renderProof();
  announce(
    `Selected leaf ${state.proof.leafIndex}, "${state.proof.leafLabel}". Proof is ${state.proof.steps.length} sibling hash${state.proof.steps.length === 1 ? '' : 'es'}.`,
  );
  resetVerify();
}

function announce(msg: string): void {
  if (srStatus) srStatus.textContent = msg;
}

function renderLeafChips(): void {
  if (state.leaves.length === 0) {
    leafList.innerHTML = '<span class="mt-hint">No leaves. Add data blocks below or load a preset.</span>';
    return;
  }
  leafList.innerHTML = state.leaves
    .map(
      (l, i) =>
        `<span class="mt-chip${i === state.selected ? ' mt-chip--selected' : ''}">` +
        `<span class="mt-chip-idx">${i}</span>${esc(l)}` +
        `<button type="button" class="mt-chip-x" data-remove="${i}" aria-label="Remove leaf ${i} (${esc(l)})">×</button>` +
        `</span>`,
    )
    .join('');
}

function sideLabel(side: 'left' | 'right'): string {
  return side === 'left'
    ? 'sibling on <strong>left</strong> → hash(sibling ∥ running)'
    : 'sibling on <strong>right</strong> → hash(running ∥ sibling)';
}

function renderProof(): void {
  const p = state.proof!;
  const total = state.tree!.leaves.length;
  const steps = p.steps
    .map(
      (s, i) =>
        `<li class="mt-step">` +
        `<span class="mt-step-i">${i + 1}</span>` +
        `<div class="mt-step-body"><code class="mt-mono">${s.siblingHex}</code>` +
        `<span class="mt-step-side mt-side--${s.side}">${sideLabel(s.side)}</span></div>` +
        `</li>`,
    )
    .join('');

  proofOut.innerHTML =
    `<div class="mt-proof-head">` +
    `<p>Proof for <strong>leaf ${p.leafIndex}</strong> (<code>${esc(p.leafLabel)}</code>): ` +
    `<strong>${p.steps.length}</strong> sibling hash${p.steps.length === 1 ? '' : 'es'}.</p>` +
    `<p class="mt-hint">A verifier needs only these ${p.steps.length} hash${p.steps.length === 1 ? '' : 'es'} + the leaf — ` +
    `not the other ${Math.max(0, total - 1)} leaf hash${total - 1 === 1 ? '' : 'es'} — to recompute the root.</p>` +
    `</div>` +
    (p.steps.length ? `<ol class="mt-steps">${steps}</ol>` : '<p class="mt-hint">Single-leaf tree: the leaf hash <em>is</em> the root, so the proof is empty.</p>');
}

function resetVerify(): void {
  if (!state.proof) return;
  state.vLeaf = state.proof.leafLabel;
  state.vSteps = state.proof.steps.map((s) => ({ ...s, siblingHash: s.siblingHash.slice() }));
  verifyLeaf.value = state.vLeaf;
  renderVerifySteps();
  void runVerify();
}

function renderVerifySteps(): void {
  if (state.vSteps.length === 0) {
    verifySteps.innerHTML = '<p class="mt-hint">No proof steps (single-leaf tree).</p>';
    return;
  }
  verifySteps.innerHTML = state.vSteps
    .map(
      (s, i) =>
        `<div class="mt-vstep">` +
        `<code class="mt-mono">${s.siblingHex}</code>` +
        `<span class="mt-side--${s.side}">${s.side}</span>` +
        `<button type="button" class="mt-btn mt-btn--ghost" data-flip="${i}">flip a bit</button>` +
        `</div>`,
    )
    .join('');
  verifySteps.querySelectorAll<HTMLElement>('[data-flip]').forEach((btn) => {
    btn.addEventListener('click', () => flipStep(Number(btn.dataset.flip)));
  });
}

function flipStep(i: number): void {
  const s = state.vSteps[i];
  if (!s) return;
  const bytes = s.siblingHash.slice();
  bytes[0] ^= 0x01;
  state.vSteps[i] = { siblingHash: bytes, siblingHex: hex(bytes), side: s.side };
  renderVerifySteps();
  void runVerify();
}

function flipFirstStep(): void {
  if (state.vSteps.length) flipStep(0);
  else runVerify();
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

async function runVerify(): Promise<void> {
  if (!state.tree || state.selected === null) return;
  state.vLeaf = verifyLeaf.value;
  const expected = state.tree.root.hashHex;
  const res = await verifyProof(utf8(state.vLeaf), state.vSteps, expected, true);

  const trace = res.steps
    .map(
      (s) =>
        `<li><span class="mt-trace-i">${s.index + 1}</span> ` +
        `hash(${s.side === 'left' ? `<code class="mt-mono">${short(s.siblingHex)}</code> ∥ <code class="mt-mono">${short(s.inputHex)}</code>` : `<code class="mt-mono">${short(s.inputHex)}</code> ∥ <code class="mt-mono">${short(s.siblingHex)}</code>`}) = <code class="mt-mono">${short(s.outputHex)}</code></li>`,
    )
    .join('');

  verifyTrace.innerHTML =
    `<ol class="mt-trace">` +
    `<li class="mt-trace-leaf"><span class="mt-trace-i">0</span> leaf hash of <code>${esc(state.vLeaf)}</code></li>` +
    trace +
    `</ol>` +
    `<div class="mt-roots">` +
    `<div><span class="mt-root-label">Recomputed root</span><code class="mt-mono ${res.ok ? 'mt-ok' : 'mt-bad'}">${res.computedRootHex}</code></div>` +
    `<div><span class="mt-root-label">Trusted root</span><code class="mt-mono">${res.expectedRootHex}</code></div>` +
    `</div>`;

  if (res.ok) {
    verifyVerdict.className = 'mt-verdict mt-verdict--ok';
    verifyVerdict.innerHTML = '<span class="mt-verdict-icon" aria-hidden="true">✓</span> <strong>INCLUDED</strong> — recomputed root matches the trusted root. The leaf is provably in the tree.';
  } else {
    verifyVerdict.className = 'mt-verdict mt-verdict--bad';
    verifyVerdict.innerHTML = '<span class="mt-verdict-icon" aria-hidden="true">✕</span> <strong>REJECTED</strong> — recomputed root does not match. The leaf or proof was altered, so inclusion cannot be proven.';
  }
}

function short(h: string): string {
  return h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h;
}
