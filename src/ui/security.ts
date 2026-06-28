/**
 * security.ts (UI) — Demonstrate the second-preimage / leaf-node confusion
 * attack and the RFC 6962 domain-separation defense, with HONEST color
 * semantics: a forged leaf that is ACCEPTED is an ALARM (red), never a success.
 */

import { bytesToHex } from '../merkle/hash';
import { buildTreeFromStrings } from '../merkle/tree';
import { verifyProof } from '../merkle/proof';
import { buildSecondPreimageForgery } from '../merkle/security';
import { qs } from './dom';

const LEAVES = ['alice', 'bob', 'carol', 'dave'];

export function mountSecurity(): void {
  const toggle = qs<HTMLInputElement>('#sec-domainsep');
  const out = qs('#sec-output');
  const status = qs('#sec-status');

  async function run(): Promise<void> {
    const domainSep = toggle.checked;
    // Build the tree the way the toggle says, then attempt the SAME forgery.
    const tree = await buildTreeFromStrings(LEAVES, domainSep);
    const forgery = buildSecondPreimageForgery(tree);
    const res = await verifyProof(forgery.forgedLeafBytes, forgery.steps, forgery.rootHex, domainSep);

    // The attacker presents (hash(alice) ∥ hash(bob)) — 64 bytes — as a "leaf".
    const forgedHex = bytesToHex(forgery.forgedLeafBytes);

    if (res.ok) {
      // Forgery accepted: this is the vulnerability. Alarm semantics.
      status.className = 'mt-verdict mt-verdict--bad';
      status.innerHTML =
        '<span class="mt-verdict-icon" aria-hidden="true">⚠</span> <strong>FORGED LEAF ACCEPTED</strong> — ' +
        'the tree is vulnerable. A 64-byte value that was never a leaf just "proved" its own inclusion.';
    } else {
      status.className = 'mt-verdict mt-verdict--ok';
      status.innerHTML =
        '<span class="mt-verdict-icon" aria-hidden="true">✓</span> <strong>FORGERY REJECTED</strong> — ' +
        'domain separation holds. A leaf hash (0x00-prefixed) can never collide with an internal-node hash (0x01-prefixed).';
    }

    out.innerHTML =
      `<dl class="mt-sec-detail">` +
      `<dt>Mode</dt><dd>${domainSep ? 'RFC 6962 domain separation <strong>ON</strong> (leaf = 0x00‖data, node = 0x01‖L‖R)' : 'domain separation <strong>OFF</strong> (leaf = SHA-256(data), node = SHA-256(L‖R))'}</dd>` +
      `<dt>Internal node impersonated</dt><dd><code class="mt-mono">${forgery.targetHashHex}</code> (the parent of leaves <code>alice</code> & <code>bob</code>)</dd>` +
      `<dt>Forged "leaf" (64 bytes = two child hashes)</dt><dd><code class="mt-mono mt-wrap">${forgedHex}</code></dd>` +
      `<dt>Verifies against the real root?</dt><dd>${res.ok ? '<span class="mt-bad">YES — inclusion forged</span>' : '<span class="mt-ok">NO — attack blocked</span>'}</dd>` +
      `</dl>`;
  }

  toggle.addEventListener('change', run);
  qs('#sec-run').addEventListener('click', run);
  void run();
}
