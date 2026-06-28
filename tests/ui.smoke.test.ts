// @vitest-environment jsdom
/**
 * DOM smoke test — mounts the real index.html markup and drives the UI to catch
 * wiring bugs (missing/renamed element IDs, runtime errors) that the pure-logic
 * tests in merkle.test.ts can't see.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

// jsdom ships a Crypto without subtle; install Node's WebCrypto so the real
// SHA-256 path runs exactly as in the browser.
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
}

function loadBody(): void {
  const html = readFileSync('index.html', 'utf8');
  const m = html.match(/<body>([\s\S]*)<\/body>/);
  if (!m) throw new Error('could not find <body> in index.html');
  document.body.innerHTML = m[1];
}

/** Wait until `cond()` is true (async DOM updates), or fail after `tries`. */
async function until(cond: () => boolean, tries = 80): Promise<void> {
  for (let i = 0; i < tries; i++) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('condition not met in time');
}

const text = (sel: string): string => document.querySelector(sel)?.textContent ?? '';

beforeAll(async () => {
  loadBody();
  const { mountExplorer } = await import('../src/ui/explorer');
  const { mountEfficiency } = await import('../src/ui/efficiency');
  const { mountSecurity } = await import('../src/ui/security');
  // Should not throw — every qs() target must exist in index.html.
  mountExplorer();
  mountEfficiency();
  mountSecurity();
  await until(() => /^[0-9a-f]{64}$/.test(text('#root-hash')));
});

describe('builder + proof wiring', () => {
  it('renders a root hash and an SVG tree from the default leaves', () => {
    expect(text('#root-hash')).toMatch(/^[0-9a-f]{64}$/);
    expect(document.querySelector('#tree-canvas svg')).not.toBeNull();
  });

  it('populates the accessible leaf <select> with one option per leaf', () => {
    const opts = document.querySelectorAll('#leaf-select option');
    expect(opts.length).toBe(6); // SAMPLE has 6 leaves
  });

  it('selecting a leaf updates the proof and the screen-reader status', async () => {
    const select = document.querySelector<HTMLSelectElement>('#leaf-select')!;
    select.value = '2';
    select.dispatchEvent(new Event('change'));
    await until(() => text('#proof-output').includes('leaf 2'));
    expect(text('#sr-status')).toContain('Selected leaf 2');
  });
});

describe('verification wiring', () => {
  it('verifies the honest proof as INCLUDED', async () => {
    document.querySelector<HTMLButtonElement>('#verify-honest')!.click();
    await until(() => text('#verify-verdict').includes('INCLUDED'));
    expect(text('#verify-verdict')).toContain('INCLUDED');
  });

  it('flipping a proof bit flips the verdict to REJECTED', async () => {
    document.querySelector<HTMLButtonElement>('#verify-flip')!.click();
    await until(() => text('#verify-verdict').includes('REJECTED'));
    expect(text('#verify-verdict')).toContain('REJECTED');
  });

  it('tampering the leaf is also REJECTED', async () => {
    document.querySelector<HTMLButtonElement>('#verify-honest')!.click();
    await until(() => text('#verify-verdict').includes('INCLUDED'));
    document.querySelector<HTMLButtonElement>('#verify-tamper-leaf')!.click();
    await until(() => text('#verify-verdict').includes('REJECTED'));
    expect(text('#verify-verdict')).toContain('REJECTED');
  });
});

describe('security panel wiring', () => {
  it('rejects the forgery with domain separation on (default)', async () => {
    await until(() => text('#sec-status').length > 0);
    expect(text('#sec-status')).toContain('REJECTED');
  });

  it('accepts the forgery when domain separation is turned off', async () => {
    const toggle = document.querySelector<HTMLInputElement>('#sec-domainsep')!;
    toggle.checked = false;
    toggle.dispatchEvent(new Event('change'));
    await until(() => text('#sec-status').includes('ACCEPTED'));
    expect(text('#sec-status')).toContain('FORGED LEAF ACCEPTED');
  });
});

describe('efficiency panel wiring', () => {
  it('updates the readout when the slider moves', () => {
    const slider = document.querySelector<HTMLInputElement>('#eff-slider')!;
    slider.value = '20';
    slider.dispatchEvent(new Event('input'));
    expect(text('#eff-readout')).toContain('1,048,576'); // 2^20 leaves
    expect(slider.getAttribute('aria-valuetext')).toContain('1,048,576');
  });
});
