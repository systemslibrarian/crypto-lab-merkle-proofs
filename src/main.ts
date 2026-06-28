/**
 * main.ts — Entry point for crypto-lab-merkle-proofs.
 *
 * The visible theme toggle lives in the shared Crypto Lab header, which owns the
 * click→flip→persist logic. This file only mounts the demo modules; it adds no
 * theme toggle of its own (per the standardization contract).
 */

import './merkle/index';
import { buildTreeFromStrings } from './merkle/tree';
import { renderTree } from './ui/tree-svg';
import { mountExplorer } from './ui/explorer';
import { mountEfficiency } from './ui/efficiency';
import { mountSecurity } from './ui/security';
import { mountConsistency } from './ui/consistency';
import { mountLearn } from './ui/learn';
import { copyText } from './ui/dom';
import { toast } from './ui/toast';

async function renderIntroDiagram(): Promise<void> {
  const el = document.getElementById('intro-diagram');
  if (!el) return;
  const tree = await buildTreeFromStrings(['data A', 'data B', 'data C', 'data D'], true);
  renderTree(el, tree);
}

/**
 * Status regions carry data-live in the HTML and are populated once during
 * mount. Promoting them to live regions AFTER that initial render means a
 * screen reader only announces state changes the user actually triggers, not
 * the content that was already there at page load.
 */
function activateLiveRegions(): void {
  for (const el of document.querySelectorAll<HTMLElement>('[data-live]')) {
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    el.removeAttribute('data-live');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  void renderIntroDiagram();
  mountExplorer();
  mountEfficiency();
  mountSecurity();
  mountConsistency();
  mountLearn();
  // Let the synchronous initial renders settle, then make the regions live.
  setTimeout(activateLiveRegions, 0);

  // Click any full hash to copy it.
  document.addEventListener('click', (e) => {
    const code = (e.target as HTMLElement).closest<HTMLElement>('.mt-copy');
    const value = code?.textContent ?? '';
    if (code && value && !value.includes('…')) {
      void copyText(value).then((ok) => toast(ok ? 'Hash copied' : 'Copy failed'));
    }
  });
});
