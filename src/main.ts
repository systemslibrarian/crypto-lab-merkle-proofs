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

async function renderIntroDiagram(): Promise<void> {
  const el = document.getElementById('intro-diagram');
  if (!el) return;
  const tree = await buildTreeFromStrings(['data A', 'data B', 'data C', 'data D'], true);
  renderTree(el, tree);
}

document.addEventListener('DOMContentLoaded', () => {
  void renderIntroDiagram();
  mountExplorer();
  mountEfficiency();
  mountSecurity();
});
