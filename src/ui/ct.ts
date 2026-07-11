/**
 * ct.ts (UI) — Verify a REAL Certificate Transparency entry with the same code
 * path as everything else in the lab. The point for the learner: this is not a
 * toy construction that resembles the real thing — it IS the real thing. A
 * pinned entry from Google's Argon2026h1 log (2.8 billion certificates)
 * verifies here, offline, in 32 hashes.
 */

import { bytesToHex, shortHex } from '../merkle/hash';
import { b64ToBytes, verifyInclusionAtIndex } from '../merkle/rfc9162';
import { CT_FIXTURE } from '../merkle/ct-fixture';
import { qs } from './dom';

const fmt = (n: number): string => n.toLocaleString('en-US');

export function mountCT(): void {
  const status = qs('#ct-status');
  const out = qs('#ct-output');

  const leafInput = b64ToBytes(CT_FIXTURE.leafInputB64);
  const path = CT_FIXTURE.auditPathB64.map(b64ToBytes);
  const rootHex = bytesToHex(b64ToBytes(CT_FIXTURE.rootHashB64));

  // The pinned facts render once; the verdict + trace change per run.
  qs('#ct-facts').innerHTML =
    `<dl class="mt-sec-detail">` +
    `<dt>Log</dt><dd>${CT_FIXTURE.logName} — <code class="mt-mono">${CT_FIXTURE.logUrl}</code></dd>` +
    `<dt>Tree size when fetched (${CT_FIXTURE.fetchedOn})</dt><dd><strong>${fmt(CT_FIXTURE.treeSize)}</strong> certificates</dd>` +
    `<dt>Entry #${fmt(CT_FIXTURE.leafIndex)}</dt><dd>${CT_FIXTURE.entryKind} for <code>${CT_FIXTURE.certSubject}</code> (issuer: ${CT_FIXTURE.certIssuer}), logged ${CT_FIXTURE.loggedAt}</dd>` +
    `<dt>Leaf input</dt><dd>${fmt(leafInput.length)} bytes — the log's exact <code>MerkleTreeLeaf</code> structure, hashed as <code>SHA-256(0x00 ∥ bytes)</code> like every leaf in this lab</dd>` +
    `<dt>Audit path</dt><dd><strong>${path.length}</strong> hashes (${fmt(path.length * 32)} bytes) — ⌈log₂ ${fmt(CT_FIXTURE.treeSize)}⌉ = ${Math.ceil(Math.log2(CT_FIXTURE.treeSize))}</dd>` +
    `<dt>Trusted root (from the log's signed tree head)</dt><dd><code class="mt-mono mt-wrap mt-copy" title="Click to copy">${rootHex}</code></dd>` +
    `</dl>`;

  async function run(tamper: boolean): Promise<void> {
    const input = leafInput.slice();
    if (tamper) input[500] ^= 0x01; // one bit, deep inside the DER certificate

    status.className = 'mt-verdict mt-verdict--step';
    status.innerHTML =
      '<span class="mt-verdict-icon" aria-hidden="true">▸</span> Recomputing the root: 32 SHA-256 hashes…';

    const res = await verifyInclusionAtIndex(
      input,
      CT_FIXTURE.leafIndex,
      CT_FIXTURE.treeSize,
      path,
      rootHex,
    );

    if (res.ok) {
      status.className = 'mt-verdict mt-verdict--ok';
      status.innerHTML =
        '<span class="mt-verdict-icon" aria-hidden="true">✓</span> <strong>INCLUDED</strong> — ' +
        `this browser just proved a real certificate sits at position ${fmt(CT_FIXTURE.leafIndex)} ` +
        `of a ${fmt(CT_FIXTURE.treeSize)}-certificate log, using ${path.length} hashes instead of the log's terabytes.`;
    } else {
      status.className = 'mt-verdict mt-verdict--bad';
      status.innerHTML =
        '<span class="mt-verdict-icon" aria-hidden="true">✕</span> <strong>REJECTED</strong> — ' +
        'one flipped bit inside the certificate changed the leaf hash, and the recomputed root no longer matches the real log root. The same avalanche you saw in section 4, now at production scale.';
    }

    // Unlike the lab's own proofs, a CT audit path carries no left/right flags —
    // the verifier DERIVES each side from the entry index (RFC 9162 §2.1.3.2).
    const rows = res.steps
      .map(
        (s, i) =>
          `<li class="mt-step"><span class="mt-step-i">${i + 1}</span>` +
          `<div class="mt-step-body"><code class="mt-mono">${shortHex(s.siblingHex, 10, 10)}</code>` +
          `<span class="mt-step-side mt-side--${s.side}">sibling on <strong>${s.side}</strong> (derived from index bit ${i})</span></div></li>`,
      )
      .join('');
    out.innerHTML =
      `<details class="mt-bytes"><summary>show all ${res.steps.length} recompute steps (sides derived from the index, not sent)</summary>` +
      `<ol class="mt-steps">${rows}</ol>` +
      `<p class="mt-hint">Recomputed root: <code class="mt-mono mt-wrap ${res.ok ? 'mt-ok' : 'mt-bad'}">${res.computedRootHex}</code></p>` +
      `</details>` +
      `<details class="mt-bytes"><summary>show the raw ${fmt(input.length)}-byte leaf (MerkleTreeLeaf: version ∥ type ∥ timestamp ∥ the certificate)</summary>` +
      `<code class="mt-mono mt-wrap">${bytesToHex(input)}</code></details>`;
  }

  qs('#ct-run').addEventListener('click', () => void run(false));
  qs('#ct-tamper').addEventListener('click', () => void run(true));
}
