/**
 * explorer.ts — The shared interactive core: build a tree, pick a leaf, see its
 * proof, and verify it (honestly or after tampering). Sections 2–4 of the demo
 * all operate on this one tree + selection so the story stays continuous.
 */

import { utf8, bytesToHex } from '../merkle/hash';
import { buildTreeFromStrings } from '../merkle/tree';
import { generateProof, verifyProof, expectedProofLength } from '../merkle/proof';
import type { MerkleProof, MerkleTree, ProofStep, VerifyResult } from '../merkle/types';
import { qs, esc, copyText } from './dom';
import { renderTree, findPath, type PathInfo } from './tree-svg';
import { toast } from './toast';

const prefersReducedMotion = (): boolean =>
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

const MAX_LEAVES = 16;
const SAMPLE = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank'];
const TX_BLOCK = ['tx: A→B 0.5', 'tx: C→D 1.2', 'tx: E→F 0.1', 'tx: G→H 3.0', 'tx: I→J 0.7'];

interface State {
  leaves: string[];
  selected: number | null;
  tree: MerkleTree | null;
  proof: MerkleProof | null;
  path: PathInfo | null;
  // Verification working copy (may be tampered):
  vLeaf: string;
  vSteps: ProofStep[];
  vResult: VerifyResult | null;
  reveal: number; // how many recompute steps are shown (step-through)
}

const state: State = {
  leaves: [...SAMPLE],
  selected: 0,
  tree: null,
  proof: null,
  path: null,
  vLeaf: '',
  vSteps: [],
  vResult: null,
  reveal: 0,
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
let stepStatus: HTMLElement;
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
  stepStatus = qs('#verify-step-status');
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
  qs('#verify-step').addEventListener('click', stepForward);
  qs('#verify-play').addEventListener('click', () => void playWalk());
  verifyLeaf.addEventListener('input', () => {
    state.vLeaf = verifyLeaf.value;
  });

  const copyRoot = (): void => {
    if (state.tree) void copyText(state.tree.root.hashHex).then((ok) => toast(ok ? 'Root hash copied' : 'Copy failed'));
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
let refreshToken = 0;
async function refresh(): Promise<void> {
  const token = ++refreshToken;
  renderLeafChips();
  updateCount();
  const tree = await buildTreeFromStrings(state.leaves, true);
  // A newer refresh started while we were hashing — discard this stale result.
  if (token !== refreshToken) return;
  state.tree = tree;
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
  state.path = findPath(state.tree, state.selected);
  renderTree(canvas, state.tree, state.path);

  if (state.selected === null || state.tree.leaves.length === 0) {
    state.proof = null;
    proofOut.innerHTML = '<p class="mt-hint">Add at least one leaf, then select it to generate a proof.</p>';
    verifyTrace.innerHTML = '';
    verifyVerdict.className = 'mt-verdict';
    verifyVerdict.innerHTML = '';
    verifySteps.innerHTML = '';
    stepStatus.textContent = '';
    return;
  }

  state.proof = generateProof(state.tree, state.selected);
  renderProof();
  announce(
    `Selected leaf ${state.proof.leafIndex}, "${state.proof.leafLabel}". Proof is ${state.proof.steps.length} sibling hash${state.proof.steps.length === 1 ? '' : 'es'}.`,
  );
  resetVerify();
}

/** Redraw the tree, optionally spotlighting the running node at the current step. */
function redrawTree(): void {
  if (!state.tree || !state.path) return;
  const current = state.path.chain[state.reveal] ?? null;
  renderTree(canvas, state.tree, { ...state.path, current });
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
      (l, i) => {
        const sel = i === state.selected;
        return (
          `<span class="mt-chip${sel ? ' mt-chip--selected' : ''}"${sel ? ' aria-current="true"' : ''}>` +
          (sel ? '<span class="mt-chip-sel" aria-hidden="true">✓</span>' : '') +
          `<span class="mt-chip-idx">${i}</span>${esc(l)}` +
          `<button type="button" class="mt-chip-x" data-remove="${i}" aria-label="Remove leaf ${i} (${esc(l)})">×</button>` +
          `</span>`
        );
      },
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

  const head =
    `<p>Proof for <strong>leaf ${p.leafIndex}</strong> (<code>${esc(p.leafLabel)}</code>): ` +
    `<strong>${p.steps.length}</strong> sibling hash${p.steps.length === 1 ? '' : 'es'}.</p>`;

  const others = total - 1;
  const body = p.steps.length
    ? `<p class="mt-hint">A verifier needs only these ${p.steps.length} hash${p.steps.length === 1 ? '' : 'es'} + the leaf — ` +
      `not the other ${others} leaf hash${others === 1 ? '' : 'es'} — to recompute the root.</p>` +
      `<ol class="mt-steps">${steps}</ol>`
    : `<p class="mt-hint">Single-leaf tree: the leaf hash <em>is</em> the root, so the proof is empty.</p>`;

  proofOut.innerHTML = `<div class="mt-proof-head">${head}</div>${body}`;
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
        `<button type="button" class="mt-btn mt-btn--ghost" data-flip="${i}" aria-label="Flip a bit in proof step ${i + 1}">flip a bit</button>` +
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

let verifyToken = 0;
/** Recompute the proof and fully reveal it (jump to the end). */
async function runVerify(): Promise<void> {
  if (!state.tree || state.selected === null) return;
  state.vLeaf = verifyLeaf.value;
  const expected = state.tree.root.hashHex;
  const token = ++verifyToken;
  const res = await verifyProof(utf8(state.vLeaf), state.vSteps, expected, true);
  // A newer verify started while we were hashing — discard this stale result.
  if (token !== verifyToken) return;
  state.vResult = res;
  state.reveal = res.steps.length; // fully revealed
  renderStep();
}

/** Render the recompute trace up to state.reveal, the tree spotlight, and the
 *  verdict (shown only once every step is revealed). `announceVerdict=false`
 *  leaves the live verdict region untouched (used during animation to avoid
 *  spamming a screen reader every tick). */
function renderStep(announceVerdict = true): void {
  const res = state.vResult;
  if (!res) return;
  const total = res.steps.length;
  state.reveal = Math.max(0, Math.min(state.reveal, total));
  const leafHex = bytesToHex(utf8(state.vLeaf));

  const lines: string[] = [
    `<li class="mt-trace-leaf"><span class="mt-trace-i">0</span> ` +
      `leaf hash of <code>${esc(state.vLeaf)}</code> = <code class="mt-mono">${short(res.steps[0]?.inputHex ?? res.computedRootHex)}</code>` +
      bytesDetail(`SHA-256( 00 ∥ ${leafHex} )`) +
      `</li>`,
  ];
  for (let i = 0; i < state.reveal; i++) {
    const s = res.steps[i];
    const combine =
      s.side === 'left'
        ? `<code class="mt-mono">${short(s.siblingHex)}</code> ∥ <code class="mt-mono">${short(s.inputHex)}</code>`
        : `<code class="mt-mono">${short(s.inputHex)}</code> ∥ <code class="mt-mono">${short(s.siblingHex)}</code>`;
    const preimage =
      s.side === 'left' ? `SHA-256( 01 ∥ ${s.siblingHex} ∥ ${s.inputHex} )` : `SHA-256( 01 ∥ ${s.inputHex} ∥ ${s.siblingHex} )`;
    lines.push(
      `<li${i === state.reveal - 1 ? ' class="mt-trace-now"' : ''}><span class="mt-trace-i">${i + 1}</span> ` +
        `hash(${combine}) = <code class="mt-mono">${short(s.outputHex)}</code>` +
        bytesDetail(preimage) +
        `</li>`,
    );
  }

  const fully = state.reveal === total;
  verifyTrace.innerHTML =
    `<ol class="mt-trace">${lines.join('')}</ol>` +
    (fully
      ? `<div class="mt-roots">` +
        `<div><span class="mt-root-label">Recomputed root</span><code class="mt-mono ${res.ok ? 'mt-ok' : 'mt-bad'}">${res.computedRootHex}</code></div>` +
        `<div><span class="mt-root-label">Trusted root</span><code class="mt-mono">${res.expectedRootHex}</code></div>` +
        `</div>`
      : '');

  stepStatus.textContent = total === 0 ? '' : `Step ${state.reveal} of ${total}`;

  redrawTree();
  if (!announceVerdict) return; // animation tick: don't touch the live verdict

  if (!fully) {
    verifyVerdict.className = 'mt-verdict mt-verdict--step';
    verifyVerdict.innerHTML = `<span class="mt-verdict-icon" aria-hidden="true">▸</span> Climbing the tree… step ${state.reveal} of ${total}.`;
  } else if (res.ok) {
    verifyVerdict.className = 'mt-verdict mt-verdict--ok';
    verifyVerdict.innerHTML = '<span class="mt-verdict-icon" aria-hidden="true">✓</span> <strong>INCLUDED</strong> — recomputed root matches the trusted root. The leaf is provably in the tree.';
  } else {
    verifyVerdict.className = 'mt-verdict mt-verdict--bad';
    verifyVerdict.innerHTML = '<span class="mt-verdict-icon" aria-hidden="true">✕</span> <strong>REJECTED</strong> — recomputed root does not match. The leaf or proof was altered, so inclusion cannot be proven.';
  }
}

function bytesDetail(preimage: string): string {
  return (
    `<details class="mt-bytes"><summary>show bytes</summary>` +
    `<code class="mt-mono mt-wrap">${preimage}</code></details>`
  );
}

/** Step-through: reveal one more recompute step. Wraps back to 0 at the end. */
function stepForward(): void {
  if (!state.vResult) return;
  const total = state.vResult.steps.length;
  state.reveal = state.reveal >= total ? 0 : state.reveal + 1;
  renderStep();
}

let playTimer: number | undefined;
/** Animate the walk from the leaf to the root (instant if reduced-motion). */
async function playWalk(): Promise<void> {
  if (!state.vResult) return;
  const total = state.vResult.steps.length;
  if (playTimer) clearInterval(playTimer);
  if (prefersReducedMotion() || total === 0) {
    state.reveal = total;
    renderStep();
    return;
  }
  state.reveal = 0;
  // One spoken cue for the whole animation; ticks update visuals silently.
  verifyVerdict.className = 'mt-verdict mt-verdict--step';
  verifyVerdict.innerHTML = '<span class="mt-verdict-icon" aria-hidden="true">▸</span> Animating the climb from leaf to root…';
  renderStep(false);
  playTimer = window.setInterval(() => {
    if (!state.vResult || state.reveal >= state.vResult.steps.length) {
      if (playTimer) clearInterval(playTimer);
      return;
    }
    state.reveal += 1;
    const last = state.reveal >= state.vResult.steps.length;
    renderStep(last); // announce only the final verdict
  }, 700);
}

function short(h: string): string {
  return h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h;
}
