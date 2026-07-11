/**
 * trust.ts (UI) — Confront the most common Merkle misconception head-on:
 * "the proof verified, so the leaf is real."
 *
 * Verification only ties a leaf to SOME root. If the prover also supplies the
 * root, a forger simply builds her own tree around the fake leaf and hands over
 * a perfectly self-consistent (leaf, proof, root) triple — it verifies, and it
 * proves nothing. ALL of the security lives in how the verifier obtained the
 * root: a block header mined into consensus, a signed tree head, a gossiped
 * checkpoint. Honest color semantics: the misleading "verifies" is an alarm.
 */

import { buildTreeFromStrings } from '../merkle/tree';
import { generateProof, verifyProof } from '../merkle/proof';
import { qs } from './dom';

// The ledger everyone agrees on — its root is what the block header commits to.
const LEDGER = ['tx: A→B 0.5', 'tx: C→D 1.2', 'tx: E→F 0.1', 'tx: G→H 3.0'];
const FORGED = 'tx: Mallory→Mallory 1,000,000';

export function mountTrust(): void {
  const status = qs('#trust-status');
  const out = qs('#trust-output');

  async function runHonest(): Promise<void> {
    // The verifier got the root out-of-band (think: block header), and the
    // prover can only supply a leaf + proof against THAT root.
    const ledger = await buildTreeFromStrings(LEDGER);
    const trustedRoot = ledger.root.hashHex;
    const proof = generateProof(ledger, 1);
    const res = await verifyProof(proof.leafData, proof.steps, trustedRoot);

    status.className = 'mt-verdict mt-verdict--ok';
    status.innerHTML =
      '<span class="mt-verdict-icon" aria-hidden="true">✓</span> <strong>INCLUDED, AND IT MEANS SOMETHING</strong> — ' +
      'the root came from a channel the attacker does not control, so matching it really does pin the leaf into the agreed-upon ledger.';

    out.innerHTML =
      `<dl class="mt-sec-detail">` +
      `<dt>Where the verifier got the root</dt><dd>out-of-band — a block header / signed tree head it already trusts</dd>` +
      `<dt>What the prover sent</dt><dd>leaf <code>${LEDGER[1]}</code> + ${proof.steps.length} sibling hashes (and nothing else)</dd>` +
      `<dt>Recomputed root equals the trusted root?</dt><dd>${res.ok ? '<span class="mt-ok">YES — inclusion in the real ledger proven</span>' : '<span class="mt-bad">NO</span>'}</dd>` +
      `</dl>`;
  }

  async function runAttack(): Promise<void> {
    // Mallory builds her OWN tree around the forged leaf and supplies all three
    // pieces herself. Everything is self-consistent — and worthless.
    const fake = await buildTreeFromStrings([FORGED, ...LEDGER.slice(1)]);
    const proof = generateProof(fake, 0);
    const res = await verifyProof(proof.leafData, proof.steps, fake.root.hashHex);

    status.className = 'mt-verdict mt-verdict--bad';
    status.innerHTML =
      '<span class="mt-verdict-icon" aria-hidden="true">⚠</span> <strong>VERIFIES — AND PROVES NOTHING</strong> — ' +
      'the recomputed root matches, because Mallory computed that root herself around her fake transaction. ' +
      'A proof only ties a leaf to <em>some</em> root; it says nothing about whether that root is the one everyone agreed on.';

    out.innerHTML =
      `<dl class="mt-sec-detail">` +
      `<dt>Where the verifier got the root</dt><dd><span class="mt-bad">from the prover</span> — the same person making the claim</dd>` +
      `<dt>What the prover sent</dt><dd>forged leaf <code>${FORGED}</code> + ${proof.steps.length} sibling hashes + <strong>her own root</strong></dd>` +
      `<dt>Recomputed root equals the supplied root?</dt><dd>${res.ok ? '<span class="mt-bad">YES — self-consistent, security-free</span>' : '<span class="mt-ok">NO</span>'}</dd>` +
      `<dt>The fix</dt><dd>the root must arrive over a channel the prover cannot influence: a mined block header, a log's signed tree head cross-checked by gossip, a checkpoint you fetched yourself</dd>` +
      `</dl>`;
  }

  qs('#trust-honest').addEventListener('click', () => void runHonest());
  qs('#trust-attack').addEventListener('click', () => void runAttack());
}
