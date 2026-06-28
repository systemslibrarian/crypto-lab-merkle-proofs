/**
 * tree-svg.ts — Lay out and render a Merkle tree as an SVG, with optional
 * highlighting of a leaf's audit path and its sibling (proof) nodes.
 *
 * Layout works from the root via DFS, so an RFC 6962 "promoted" lone node simply
 * sits at a shallower depth, connected directly to the internal node that
 * eventually combines it — which is an honest picture of the unbalanced tree.
 */

import { shortHex } from '../merkle/hash';
import type { MerkleNode, MerkleTree } from '../merkle/types';
import { esc } from './dom';

const BOX_W = 104;
const BOX_H = 44;
const COL_GAP = 26; // horizontal gap between leaf columns
const ROW_GAP = 78; // vertical gap between depths
const PAD = 24;

export interface Placed {
  node: MerkleNode;
  x: number; // center x
  y: number; // center y
  depth: number;
}

export interface Layout {
  placed: Map<MerkleNode, Placed>;
  width: number;
  height: number;
  maxDepth: number;
}

function depthOf(node: MerkleNode, depths: Map<MerkleNode, number>, d: number): void {
  depths.set(node, d);
  if (node.left) depthOf(node.left, depths, d + 1);
  if (node.right) depthOf(node.right, depths, d + 1);
}

export function layoutTree(tree: MerkleTree): Layout {
  const depths = new Map<MerkleNode, number>();
  depthOf(tree.root, depths, 0);
  let maxDepth = 0;
  for (const d of depths.values()) maxDepth = Math.max(maxDepth, d);

  const xOf = new Map<MerkleNode, number>();
  let col = 0;
  const step = BOX_W + COL_GAP;

  // In-order traversal assigns each leaf a column; internals center over children.
  function assign(node: MerkleNode): number {
    // Memoize: in duplicate mode a node can be both children of its parent
    // (right === left). Without this guard it would be placed/counted twice.
    const cached = xOf.get(node);
    if (cached !== undefined) return cached;
    if (!node.left && !node.right) {
      const x = PAD + BOX_W / 2 + col * step;
      col += 1;
      xOf.set(node, x);
      return x;
    }
    const lx = node.left ? assign(node.left) : 0;
    const rx = node.right ? assign(node.right) : lx;
    const x = (lx + rx) / 2;
    xOf.set(node, x);
    return x;
  }
  assign(tree.root);

  const placed = new Map<MerkleNode, Placed>();
  for (const [node, depth] of depths) {
    placed.set(node, {
      node,
      x: xOf.get(node)!,
      y: PAD + BOX_H / 2 + depth * ROW_GAP,
      depth,
    });
  }

  const leafCount = Math.max(1, col);
  const width = PAD * 2 + leafCount * BOX_W + (leafCount - 1) * COL_GAP;
  const height = PAD * 2 + (maxDepth + 1) * BOX_H + maxDepth * ROW_GAP;
  return { placed, width, height, maxDepth };
}

export interface PathInfo {
  pathNodes: Set<MerkleNode>; // running-hash chain: leaf → root
  siblingNodes: Set<MerkleNode>; // proof inputs
  leaf: MerkleNode | null;
  /** Ordered running-hash chain, leaf (index 0) → root (last). */
  chain: MerkleNode[];
  /** The node the running hash currently sits on, for step-through. */
  current?: MerkleNode | null;
}

/** Walk root→leaf, recording ancestors (path) and the sibling taken at each step. */
export function findPath(tree: MerkleTree, leafIndex: number | null): PathInfo {
  const pathNodes = new Set<MerkleNode>();
  const siblingNodes = new Set<MerkleNode>();
  if (leafIndex === null) return { pathNodes, siblingNodes, leaf: null, chain: [] };

  let leaf: MerkleNode | null = null;
  let chain: MerkleNode[] = [];
  function dfs(node: MerkleNode, trail: MerkleNode[]): boolean {
    if (node.isLeaf && node.leafIndex === leafIndex) {
      leaf = node;
      for (const n of trail) pathNodes.add(n);
      pathNodes.add(node);
      // trail is root→parent; chain is leaf→root.
      chain = [node, ...[...trail].reverse()];
      return true;
    }
    if (node.left && dfs(node.left, [...trail, node])) {
      // Guard against duplicate mode (right === left): a node is not its own sibling.
      if (node.right && node.right !== node.left) siblingNodes.add(node.right);
      return true;
    }
    if (node.right && dfs(node.right, [...trail, node])) {
      if (node.left && node.left !== node.right) siblingNodes.add(node.left);
      return true;
    }
    return false;
  }
  dfs(tree.root, []);
  return { pathNodes, siblingNodes, leaf, chain };
}

function nodeClasses(node: MerkleNode, path: PathInfo): string {
  const cls = ['mt-node'];
  cls.push(node.isLeaf ? 'mt-node--leaf' : 'mt-node--internal');
  if (node === path.current) cls.push('mt-node--current');
  if (node === path.leaf) cls.push('mt-node--selected');
  else if (path.siblingNodes.has(node)) cls.push('mt-node--sibling');
  else if (path.pathNodes.has(node)) cls.push('mt-node--path');
  return cls.join(' ');
}

/**
 * Render `tree` into `container` as SVG. Leaves carry data-leaf-index for click
 * selection. Returns nothing; caller attaches a delegated click listener.
 */
export function renderTree(
  container: HTMLElement,
  tree: MerkleTree,
  path: PathInfo = { pathNodes: new Set(), siblingNodes: new Set(), leaf: null, chain: [] },
): void {
  if (tree.leaves.length === 0) {
    container.innerHTML =
      '<p class="mt-empty">Empty tree — its root is SHA-256 of the empty string. Add a leaf to begin.</p>';
    return;
  }

  const layout = layoutTree(tree);
  const edges: string[] = [];
  const boxes: string[] = [];

  for (const { node, x, y } of layout.placed.values()) {
    for (const child of [node.left, node.right]) {
      if (!child) continue;
      const c = layout.placed.get(child)!;
      const onPath = path.pathNodes.has(child) || path.siblingNodes.has(child);
      edges.push(
        `<line class="mt-edge${onPath ? ' mt-edge--active' : ''}" x1="${x}" y1="${y + BOX_H / 2}" x2="${c.x}" y2="${c.y - BOX_H / 2}" />`,
      );
    }
  }

  for (const { node, x, y } of layout.placed.values()) {
    const left = x - BOX_W / 2;
    const top = y - BOX_H / 2;
    const isRoot = node === tree.root;
    const tag = isRoot ? 'ROOT' : node.isLeaf ? `leaf ${node.leafIndex}` : 'node';
    const rawLabel = node.isLeaf && node.label ? node.label : '';
    const label = rawLabel ? esc(rawLabel.length > 10 ? rawLabel.slice(0, 9) + '…' : rawLabel) : '';
    // Non-color state marker so proof participation is conveyed by SHAPE+TEXT,
    // not color alone (WCAG 1.4.1). Legend in the page maps each glyph.
    const marker =
      node === path.leaf ? '●' : path.siblingNodes.has(node) ? '◆' : path.pathNodes.has(node) ? '↑' : '';
    const clickable = node.isLeaf ? ' mt-node--clickable' : '';
    // data-leaf-index drives mouse clicks as a visual convenience; the
    // <select> in section 3 is the accessible/keyboard path. We do NOT mark
    // these as role="button", because an SVG with role="img" hides descendants.
    const attrs = node.isLeaf ? ` data-leaf-index="${node.leafIndex}"` : '';
    boxes.push(
      `<g class="${nodeClasses(node, path)}${clickable}"${attrs}>` +
        `<rect class="mt-box" x="${left}" y="${top}" width="${BOX_W}" height="${BOX_H}" rx="8" />` +
        (marker ? `<text class="mt-marker" x="${left + BOX_W - 7}" y="${top + 13}">${marker}</text>` : '') +
        `<text class="mt-tag" x="${x}" y="${top + 14}">${tag}${label ? ': ' + label : ''}</text>` +
        `<text class="mt-hash" x="${x}" y="${top + 31}">${shortHex(node.hashHex, 7, 7)}</text>` +
        `</g>`,
    );
  }

  // Describe the whole figure (and current selection) for assistive tech, since
  // the textual proof list mirrors what the colors show.
  let aria = `Merkle tree with ${tree.leaves.length} leaf nodes`;
  if (path.leaf && path.leaf.leafIndex !== undefined) {
    aria += `. Leaf ${path.leaf.leafIndex}${path.leaf.label ? ' (' + path.leaf.label + ')' : ''} is selected; its proof is ${path.siblingNodes.size} sibling hashes shown with a diamond marker.`;
  }

  container.innerHTML =
    `<svg class="mt-svg" viewBox="0 0 ${layout.width} ${layout.height}" ` +
    `width="${layout.width}" height="${layout.height}" role="img" ` +
    `aria-label="${esc(aria)}">` +
    `<g class="mt-edges">${edges.join('')}</g>` +
    `<g class="mt-boxes">${boxes.join('')}</g>` +
    `</svg>`;
}
