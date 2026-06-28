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
  const { mountLearn } = await import('../src/ui/learn');
  // Should not throw — every qs() target must exist in index.html.
  mountExplorer();
  mountEfficiency();
  mountSecurity();
  mountLearn();
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

describe('step-through + byte transparency', () => {
  it('the recompute trace exposes the exact SHA-256 preimage bytes', async () => {
    document.querySelector<HTMLButtonElement>('#verify-honest')!.click();
    await until(() => text('#verify-verdict').includes('INCLUDED'));
    const details = document.querySelectorAll('#verify-trace .mt-bytes');
    expect(details.length).toBeGreaterThan(0);
    expect(document.querySelector('#verify-trace .mt-bytes code')?.textContent).toContain('SHA-256');
  });

  it('Step ▸ walks the proof and shows step status / climbing state', async () => {
    document.querySelector<HTMLButtonElement>('#verify-honest')!.click();
    await until(() => text('#verify-verdict').includes('INCLUDED'));
    // From fully-revealed, a step wraps to 0 and enters "climbing" mode.
    document.querySelector<HTMLButtonElement>('#verify-step')!.click();
    expect(text('#verify-step-status')).toMatch(/Step \d+ of \d+/);
    expect(text('#verify-verdict').toLowerCase()).toContain('climbing');
  });
});

describe('CVE-2012-2459 duplication demo', () => {
  it('Bitcoin duplication makes two lists collide on one root', async () => {
    await until(() => text('#dup-status').length > 0);
    expect(text('#dup-status')).toContain('COLLIDE');
  });

  it('RFC 6962 promotion keeps the roots distinct', async () => {
    const promote = document.querySelector<HTMLInputElement>('#dup-mode input[value="promote"]')!;
    promote.click(); // proper radio-group selection + change event
    await until(() => text('#dup-status').includes('DIFFER'));
    expect(text('#dup-status')).toContain('DIFFER');
  });
});

describe('active-learning wiring', () => {
  it('glossary terms become accessible disclosures with a definition', () => {
    const term = document.querySelector<HTMLElement>('[data-term="merkle-root"]')!;
    expect(term.classList.contains('glossary')).toBe(true);
    expect(term.getAttribute('role')).toBe('button');
    expect(term.getAttribute('aria-expanded')).toBe('false');
    expect(term.getAttribute('aria-label')).toMatch(/commits to every leaf/);
    // clicking opens the shared tooltip and toggles aria-expanded
    term.click();
    expect(term.getAttribute('aria-expanded')).toBe('true');
    const tip = document.querySelector<HTMLElement>('#glossary-tip')!;
    expect(tip.hidden).toBe(false);
    expect(tip.textContent).toMatch(/commits to every leaf/);
    term.click();
    expect(term.getAttribute('aria-expanded')).toBe('false');
  });

  it('predict-then-reveal toggles the answer', () => {
    const reveal = document.querySelector<HTMLButtonElement>('.predict-reveal')!;
    const answer = reveal.parentElement!.querySelector<HTMLElement>('.predict-answer')!;
    expect(answer.hidden).toBe(true);
    reveal.click();
    expect(answer.hidden).toBe(false);
  });

  it('a wrong quiz answer shows the corrective explanation', () => {
    const card = document.querySelector<HTMLElement>('.quiz-card')!;
    const wrong = card.querySelector<HTMLInputElement>('input[type="radio"]')!; // first option
    wrong.checked = true;
    card.querySelector<HTMLButtonElement>('.quiz-check')!.click();
    const explain = card.querySelector<HTMLElement>('.quiz-explain')!;
    expect(explain.hidden).toBe(false);
    expect(explain.className).toContain('quiz-explain');
  });
});
