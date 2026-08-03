import { expect, test as base, type Page } from '@playwright/test';

/**
 * Functional gate on the claims this lab makes on screen.
 *
 * The a11y suite proves the page is reachable and the Vitest suite proves the
 * hashing matches RFC 6962; neither proves the *page* reaches the states it
 * advertises. This suite drives the real sections and re-derives each verdict
 * from what the page itself printed: INCLUDED only when the recomputed root it
 * shows equals the trusted root it shows, ROOTS COLLIDE only when the two roots
 * it printed are equal, the efficiency headline from its own arithmetic, and
 * every tamper path asserted to reach rejection *and* name the cause.
 */

const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(`console.error: ${message.text()}`);
      });
      await use(errors);
      expect(errors, 'uncaught page errors').toEqual([]);
    },
    { auto: true },
  ],
});

/** Load the lab and wait for the initial tree build to finish. */
async function open(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#root-hash')).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.locator('#verify-verdict')).toContainText('INCLUDED');
}

async function flat(page: Page, selector: string): Promise<string> {
  return (await page.locator(selector).innerText()).replace(/\s+/g, ' ').trim();
}

function grab(source: string, pattern: RegExp): RegExpMatchArray {
  const match = source.match(pattern);
  expect(match, `expected ${pattern} in: ${source}`).not.toBeNull();
  return match as RegExpMatchArray;
}

/** The lab's own abbreviation of a full hash in the recompute trace. */
const short = (hex: string): string => `${hex.slice(0, 8)}…${hex.slice(-8)}`;

/** Both roots the verify panel prints, as full hex. */
async function roots(page: Page): Promise<{ computed: string; trusted: string }> {
  const trace = await flat(page, '#verify-trace');
  const m = grab(trace, /Recomputed root ([0-9a-f]{64}) Trusted root ([0-9a-f]{64})/i);
  return { computed: m[1]!, trusted: m[2]! };
}

async function openDetails(page: Page, selector: string): Promise<void> {
  await page.locator(selector).evaluate((root) => {
    for (const d of Array.from(root.querySelectorAll('details'))) d.open = true;
  });
}

// ---------------------------------------------------------------------------
// Sections 2-4: build, prove, verify
// ---------------------------------------------------------------------------

test('explorer: the honest proof recomputes exactly the root the tree published', async ({ page }) => {
  await open(page);

  const root = await page.locator('#root-hash').innerText();

  // The leaf tally and the proof-size bound it advertises.
  const count = grab(await flat(page, '#leaf-count'), /^(\d+) leaves · proof size ≤ (\d+) hashes$/);
  const leaves = Number(count[1]);
  const bound = Number(count[2]);
  expect(leaves).toBe(6);
  expect(await page.locator('#leaf-list .mt-chip').count()).toBe(leaves);
  expect(bound).toBe(Math.ceil(Math.log2(leaves)));

  // The proof header, the rendered steps, and the verify rows are one proof.
  const proofText = await flat(page, '#proof-output');
  const header = grab(proofText, /Proof for leaf (\d+) \(([^)]+)\): (\d+) sibling hashes\./);
  const steps = Number(header[3]);
  expect(steps).toBeLessThanOrEqual(bound);
  expect(await page.locator('#proof-output .mt-step').count()).toBe(steps);
  expect(await page.locator('#verify-steps .mt-vstep').count()).toBe(steps);

  // The saving claimed is against the other leaves, not an invented number.
  expect(proofText).toContain(`not the other ${leaves - 1} leaf hashes`);

  // Verdict, checked against the two roots the panel printed.
  const { computed, trusted } = await roots(page);
  expect(trusted).toBe(root);
  expect(computed).toBe(trusted);
  await expect(page.locator('#verify-verdict')).toContainText(
    'INCLUDED — recomputed root matches the trusted root',
  );
  await expect(page.locator('#verify-verdict')).toHaveClass(/mt-verdict--ok/);

  // The last line of the recompute trace IS that root.
  const traceLines = await page.locator('#verify-trace .mt-trace > li').allInnerTexts();
  expect(traceLines).toHaveLength(steps + 1);
  expect(traceLines.at(-1)!.replace(/\s+/g, ' ')).toContain(short(computed));
  await expect(page.locator('#verify-step-status')).toHaveText(`Step ${steps} of ${steps}`);
});

test('explorer tamper: changing the leaf or flipping a proof bit is rejected, and recoverable', async ({
  page,
}) => {
  await open(page);
  const root = await page.locator('#root-hash').innerText();

  // 1. Tamper the leaf.
  await page.locator('#verify-tamper-leaf').click();
  await expect(page.locator('#verify-verdict')).toContainText('REJECTED');
  await expect(page.locator('#verify-verdict')).toHaveClass(/mt-verdict--bad/);
  await expect(page.locator('#verify-verdict')).toContainText(
    'recomputed root does not match. The leaf or proof was altered',
  );
  let printed = await roots(page);
  expect(printed.trusted, 'the tree itself must not move when the claim is tampered').toBe(root);
  expect(printed.computed).not.toBe(printed.trusted);
  await expect(page.locator('#verify-leaf')).toHaveValue(/!$/);

  // 2. Reset restores the honest proof — the failure state is recoverable.
  await page.locator('#verify-honest').click();
  await expect(page.locator('#verify-verdict')).toContainText('INCLUDED');
  printed = await roots(page);
  expect(printed.computed).toBe(root);

  // 3. Tamper a proof step instead: same rejection, from the other input.
  await page.locator('#verify-flip').click();
  await expect(page.locator('#verify-verdict')).toContainText('REJECTED');
  printed = await roots(page);
  expect(printed.trusted).toBe(root);
  expect(printed.computed).not.toBe(root);

  // The flipped step differs from the proof the generator published, in exactly
  // the first byte.
  const published = await page.locator('#proof-output .mt-step code').first().innerText();
  const tamperedRow = await page.locator('#verify-steps .mt-vstep code').first().innerText();
  expect(tamperedRow).not.toBe(published);
  expect(tamperedRow.slice(2)).toBe(published.slice(2));

  // 4. Per-step flip button on a later step, when the tree has one.
  await page.locator('#verify-honest').click();
  await expect(page.locator('#verify-verdict')).toContainText('INCLUDED');
  await page.locator('#verify-steps [data-flip="1"]').click();
  await expect(page.locator('#verify-verdict')).toContainText('REJECTED');
});

test('explorer step-through: the trace reveals one hash at a time and withholds the verdict until the top', async ({
  page,
}) => {
  await open(page);
  const total = Number(
    grab(await flat(page, '#proof-output'), /: (\d+) sibling hashes\./)[1],
  );
  expect(total).toBeGreaterThan(1);

  // The button wraps from "fully revealed" back to 0, then climbs.
  await page.locator('#verify-step').click();
  await expect(page.locator('#verify-step-status')).toHaveText(`Step 0 of ${total}`);

  for (let revealed = 1; revealed <= total; revealed += 1) {
    await page.locator('#verify-step').click();
    await expect(page.locator('#verify-step-status')).toHaveText(`Step ${revealed} of ${total}`);
    // leaf line + one line per revealed step
    await expect(page.locator('#verify-trace .mt-trace > li')).toHaveCount(revealed + 1);
    if (revealed < total) {
      // Mid-climb the verdict must not claim anything yet.
      await expect(page.locator('#verify-verdict')).toContainText(
        `Climbing the tree… step ${revealed} of ${total}`,
      );
      await expect(page.locator('#verify-verdict')).not.toContainText('INCLUDED');
      await expect(page.locator('#verify-verdict')).not.toContainText('REJECTED');
      // The roots are only shown once the climb finishes.
      await expect(page.locator('#verify-trace .mt-roots')).toHaveCount(0);
    }
  }
  await expect(page.locator('#verify-verdict')).toContainText('INCLUDED');
  const { computed, trusted } = await roots(page);
  expect(computed).toBe(trusted);
});

test('explorer builder: editing the leaf set moves the root and re-proves the selected leaf', async ({
  page,
}) => {
  await open(page);
  const before = await page.locator('#root-hash').innerText();

  await page.locator('#preset-clear').click();
  await expect(page.locator('#leaf-count')).toHaveText(/^0 leaves · /);
  await expect(page.locator('#proof-output')).toContainText('Add at least one leaf');

  await page.locator('#preset-sample').click();
  await expect(page.locator('#leaf-count')).toHaveText(/^6 leaves · /);
  await expect(page.locator('#root-hash')).toHaveText(before);

  // Add a seventh leaf: the root must change and the bound must follow log2.
  await page.locator('#leaf-input').fill('grace');
  await page.locator('#leaf-add').click();
  await expect(page.locator('#leaf-count')).toHaveText(/^7 leaves · proof size ≤ 3 hashes$/);
  const after = await page.locator('#root-hash').innerText();
  expect(after).not.toBe(before);

  // Select the new leaf and verify it against the new root.
  await page.locator('#leaf-select').selectOption('6');
  await expect(page.locator('#proof-output')).toContainText('Proof for leaf 6');
  await expect(page.locator('#verify-leaf')).toHaveValue('grace');
  await expect(page.locator('#verify-verdict')).toContainText('INCLUDED');
  const { computed, trusted } = await roots(page);
  expect(trusted).toBe(after);
  expect(computed).toBe(after);
  const steps = Number(grab(await flat(page, '#proof-output'), /: (\d+) sibling hash/)[1]);
  expect(steps).toBeLessThanOrEqual(3);
});

// ---------------------------------------------------------------------------
// Trust model
// ---------------------------------------------------------------------------

test('trust model: a self-supplied root verifies and the page says it proves nothing', async ({
  page,
}) => {
  await open(page);

  await page.locator('#trust-honest').click();
  await expect(page.locator('#trust-status')).toContainText('INCLUDED, AND IT MEANS SOMETHING');
  await expect(page.locator('#trust-status')).toHaveClass(/mt-verdict--ok/);
  let detail = await flat(page, '#trust-output');
  expect(detail).toContain('out-of-band');
  expect(detail).toContain('YES — inclusion in the real ledger proven');

  await page.locator('#trust-attack').click();
  // The forgery verifies — and the panel must flag that as an alarm, not a pass.
  await expect(page.locator('#trust-status')).toContainText('VERIFIES — AND PROVES NOTHING');
  await expect(page.locator('#trust-status')).toHaveClass(/mt-verdict--bad/);
  detail = await flat(page, '#trust-output');
  expect(detail).toContain('from the prover');
  expect(detail).toContain('YES — self-consistent, security-free');
  expect(detail).toContain('tx: Mallory→Mallory 1,000,000');
});

// ---------------------------------------------------------------------------
// Section 6: domain separation and CVE-2012-2459
// ---------------------------------------------------------------------------

test('domain separation: the second-preimage forgery is blocked with 0x00/0x01 and succeeds without', async ({
  page,
}) => {
  await open(page);

  const readSecurity = async () => {
    const detail = await flat(page, '#sec-output');
    return {
      status: await flat(page, '#sec-status'),
      detail,
      mode: grab(detail, /Mode (RFC 6962 domain separation ON|domain separation OFF)/i)[1]!,
      impersonated: grab(detail, /Internal node impersonated ([0-9a-f]{64})/i)[1]!,
      forged: grab(detail, /two child hashes\) ([0-9a-f]{128})/i)[1]!,
      verifies: grab(detail, /Verifies against the real root\? (YES — inclusion forged|NO — attack blocked)/i)[1]!,
    };
  };

  // Default: domain separation on.
  await expect(page.locator('#sec-domainsep')).toBeChecked();
  const on = await readSecurity();
  expect(on.mode).toBe('RFC 6962 domain separation ON');
  expect(on.status).toContain('FORGERY REJECTED');
  expect(on.verifies).toBe('NO — attack blocked');
  await expect(page.locator('#sec-status')).toHaveClass(/mt-verdict--ok/);
  // The forged "leaf" is the two child hashes concatenated: 64 bytes, and it
  // begins and ends with 32-byte halves that are not the node it impersonates.
  expect(on.forged).toHaveLength(128);
  expect(on.forged).not.toContain(on.impersonated);

  // Turn it off: the same forgery now succeeds, and the page must call that an
  // alarm rather than a success.
  await page.locator('#sec-domainsep').uncheck();
  await expect(page.locator('#sec-status')).toContainText('FORGED LEAF ACCEPTED');
  const off = await readSecurity();
  expect(off.mode).toBe('domain separation OFF');
  expect(off.verifies).toBe('YES — inclusion forged');
  await expect(page.locator('#sec-status')).toHaveClass(/mt-verdict--bad/);
  expect(off.status).toContain('the tree is vulnerable');
  expect(off.forged).toHaveLength(128);
  // Without the prefixes the whole tree hashes differently, so the impersonated
  // node is a different hash than in the defended build.
  expect(off.impersonated).not.toBe(on.impersonated);

  // And back: the defence is not one-way.
  await page.locator('#sec-domainsep').check();
  await expect(page.locator('#sec-status')).toContainText('FORGERY REJECTED');
});

test('CVE-2012-2459: the collide/differ verdict matches the two roots it prints', async ({ page }) => {
  await open(page);

  const readDup = async () => {
    const detail = await flat(page, '#dup-output');
    return {
      status: await flat(page, '#dup-status'),
      rule: grab(detail, /Odd-node rule (Bitcoin duplication|RFC 6962 promotion)/i)[1]!,
      rootA: grab(detail, /List A — \[tx-a, tx-b, tx-c\] ([0-9a-f]{64})/i)[1]!,
      rootB: grab(detail, /List B — \[tx-a, tx-b, tx-c, tx-c\] ([0-9a-f]{64})/i)[1]!,
    };
  };

  // Bitcoin's duplication rule is the default: the two different lists collide.
  const dup = await readDup();
  expect(dup.rule).toBe('Bitcoin duplication');
  expect(dup.rootA, 'the CVE is that these two lists share a root').toBe(dup.rootB);
  expect(dup.status).toContain('ROOTS COLLIDE');
  expect(dup.status).toContain('CVE-2012-2459');
  await expect(page.locator('#dup-status')).toHaveClass(/mt-verdict--bad/);

  // RFC 6962 promotion: same two lists, different roots.
  await page.locator('#dup-mode input[value="promote"]').check();
  await expect(page.locator('#dup-status')).toContainText('ROOTS DIFFER');
  const promote = await readDup();
  expect(promote.rule).toBe('RFC 6962 promotion');
  expect(promote.rootA).not.toBe(promote.rootB);
  await expect(page.locator('#dup-status')).toHaveClass(/mt-verdict--ok/);

  // The 4-leaf list is unaffected by the rule (no odd node), so only list A moves.
  expect(promote.rootB).toBe(dup.rootB);
  expect(promote.rootA).not.toBe(dup.rootA);
});

// ---------------------------------------------------------------------------
// Section 7: consistency proofs
// ---------------------------------------------------------------------------

test('consistency: an honest append proves consistent with a logarithmic proof', async ({ page }) => {
  await open(page);

  await page.locator('#cons-new').selectOption('8');
  await page.locator('#cons-old').selectOption('5');
  await expect(page.locator('#cons-status')).toContainText('CONSISTENT');

  const status = await flat(page, '#cons-status');
  expect(status).toContain('the size-5 log is provably a prefix of the size-8 log');
  await expect(page.locator('#cons-status')).toHaveClass(/mt-verdict--ok/);

  const detail = await flat(page, '#cons-output');
  const oldRoot = grab(detail, /Old root \(size 5\).*?([0-9a-f]{64})/i)[1]!;
  const newRoot = grab(detail, /New root \(size 8\).*?([0-9a-f]{64})/i)[1]!;
  expect(oldRoot).not.toBe(newRoot);

  // The header's hash count is the number of hashes it actually listed, and it
  // is logarithmic in the new size.
  const claimed = Number(grab(detail, /Consistency proof \((\d+) hashes/i)[1]);
  expect(await page.locator('#cons-output .mt-step').count()).toBe(claimed);
  expect(claimed).toBeLessThanOrEqual(Math.ceil(Math.log2(8)) + 1);

  // The log strip shades exactly the old prefix.
  expect(await page.locator('#cons-log .mt-chip').count()).toBe(8);
  expect(await page.locator('#cons-log .mt-chip--old').count()).toBe(5);
  expect(await page.locator('#cons-log .mt-chip--altered').count()).toBe(0);

  // The drawing marks the proof's subtree roots inside and outside the prefix.
  expect(await page.locator('#cons-canvas .mt-node--consproof').count()).toBeGreaterThan(0);
});

test('consistency tampers: rewrite, delete and reorder are each caught and each recover', async ({
  page,
}) => {
  await open(page);
  await page.locator('#cons-new').selectOption('8');
  await page.locator('#cons-old').selectOption('4');
  await expect(page.locator('#cons-status')).toContainText('CONSISTENT');

  const attacks: Array<[string, string]> = [
    ['#cons-tamper', 'cert-0-FORGED'],
    ['#cons-tamper-delete', ''],
    ['#cons-tamper-reorder', ''],
  ];

  for (const [button, marker] of attacks) {
    await page.locator(button).click();
    await expect(page.locator('#cons-status'), `${button} must be caught`).toContainText(
      'NOT CONSISTENT',
    );
    await expect(page.locator('#cons-status')).toHaveClass(/mt-verdict--bad/);
    const status = await flat(page, '#cons-status');
    // The rejection must name the cause, not just fail.
    expect(status).toContain('the remembered old root cannot be rebuilt');
    expect(status).toContain('History was altered, not just appended');
    // The altered entries are marked in the log strip.
    expect(
      await page.locator('#cons-log .mt-chip--altered').count(),
      `${button} must mark the altered entries`,
    ).toBeGreaterThan(0);
    if (marker) await expect(page.locator('#cons-log')).toContainText(marker);

    // Re-running honestly restores the consistent verdict.
    await page.locator('#cons-run').click();
    await expect(page.locator('#cons-status')).toContainText('CONSISTENT');
    expect(await page.locator('#cons-log .mt-chip--altered').count()).toBe(0);
  }
});

// ---------------------------------------------------------------------------
// Section 8: the pinned real Certificate Transparency entry
// ---------------------------------------------------------------------------

test('CT: the pinned real log entry verifies in 32 hashes, and one flipped bit breaks it', async ({
  page,
}) => {
  await open(page);

  const facts = await flat(page, '#ct-facts');
  const treeSize = Number(grab(facts, /Tree size when fetched \([\d-]+\) ([\d,]+) certificates/i)[1]!.replace(/,/g, ''));
  const pathLen = Number(grab(facts, /Audit path (\d+) hashes \(([\d,]+) bytes\)/i)[1]);
  const pathBytes = Number(grab(facts, /Audit path \d+ hashes \(([\d,]+) bytes\)/i)[1]!.replace(/,/g, ''));
  const trustedRoot = grab(facts, /signed tree head\) ([0-9a-f]{64})/i)[1]!;

  // The advertised proof size is log2 of the advertised tree size, and the byte
  // count is 32 bytes per hash.
  expect(pathLen).toBe(Math.ceil(Math.log2(treeSize)));
  expect(pathBytes).toBe(pathLen * 32);

  await page.locator('#ct-run').click();
  await expect(page.locator('#ct-status')).toContainText('INCLUDED', { timeout: 30_000 });
  await expect(page.locator('#ct-status')).toHaveClass(/mt-verdict--ok/);
  const okStatus = await flat(page, '#ct-status');
  expect(okStatus).toContain(`using ${pathLen} hashes`);
  expect(okStatus).toContain(treeSize.toLocaleString('en-US'));

  await openDetails(page, '#ct-output');
  const okDetail = await flat(page, '#ct-output');
  expect(await page.locator('#ct-output .mt-step').count()).toBe(pathLen);
  expect(grab(okDetail, /Recomputed root: ([0-9a-f]{64})/)[1]).toBe(trustedRoot);

  // One flipped bit deep inside the certificate must break it, and the page must
  // say why.
  await page.locator('#ct-tamper').click();
  await expect(page.locator('#ct-status')).toContainText('REJECTED', { timeout: 30_000 });
  await expect(page.locator('#ct-status')).toHaveClass(/mt-verdict--bad/);
  expect(await flat(page, '#ct-status')).toContain(
    'one flipped bit inside the certificate changed the leaf hash',
  );
  await openDetails(page, '#ct-output');
  const badDetail = await flat(page, '#ct-output');
  expect(grab(badDetail, /Recomputed root: ([0-9a-f]{64})/)[1]).not.toBe(trustedRoot);

  // And it recovers: the honest run still verifies afterwards.
  await page.locator('#ct-run').click();
  await expect(page.locator('#ct-status')).toContainText('INCLUDED', { timeout: 30_000 });
});

// ---------------------------------------------------------------------------
// Section 5: logarithmic scaling
// ---------------------------------------------------------------------------

test('efficiency: the headline numbers are the arithmetic of the size the slider names', async ({
  page,
}) => {
  await open(page);

  for (const exp of ['1', '10', '20', '30']) {
    await page.locator('#eff-slider').fill(exp);
    await expect(page.locator('#eff-exp-label')).toHaveText(exp);

    const readout = await flat(page, '#eff-readout');
    const parsed = grab(
      readout,
      /^([\d,]+) leaves → a proof is just (\d+) sibling hashes \(([\d.]+) ([A-Za-z]+)\)\. Sending every leaf hash instead would be ([\d.]+) ([A-Za-z]+) — the proof is ([\d,]+)× smaller\.$/,
    );
    const n = Number(parsed[1]!.replace(/,/g, ''));
    const hashes = Number(parsed[2]);
    const ratio = Number(parsed[7]!.replace(/,/g, ''));

    const unit = (value: string, suffix: string): number =>
      Number(value) * ({ B: 1, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3 }[suffix] ?? NaN);
    const proofBytes = unit(parsed[3]!, parsed[4]!);
    const fullBytes = unit(parsed[5]!, parsed[6]!);

    // Every number in the sentence follows from the exponent it names.
    expect(n).toBe(2 ** Number(exp));
    expect(hashes).toBe(Number(exp));
    expect(proofBytes).toBeCloseTo(hashes * 32, 0);
    expect(fullBytes / (n * 32)).toBeCloseTo(1, 1);
    expect(ratio).toBe(Math.round((n * 32) / (hashes * 32)));

    // The bar for the proof is never wider than the bar for every leaf hash.
    const widths = await page.evaluate(() => ({
      proof: document.querySelector<HTMLElement>('#eff-bar-proof')!.style.width,
      full: document.querySelector<HTMLElement>('#eff-bar-full')!.style.width,
    }));
    expect(widths.full).toBe('100%');
    expect(Number.parseFloat(widths.proof)).toBeLessThanOrEqual(100);
  }
});

test('efficiency: a real 256-leaf tree verifies from 8 hashes', async ({ page }) => {
  await open(page);

  await page.locator('#eff-build-buttons button[data-n="256"]').click();
  await expect(page.locator('#eff-build-out')).toContainText('Result', { timeout: 60_000 });

  const out = await flat(page, '#eff-build-out');
  const n = Number(grab(out, /Leaves ([\d,]+)/i)[1]!.replace(/,/g, ''));
  const hashes = Number(grab(out, /Proof for leaf [\d,]+ (\d+) hashes \((\d+) B\)/i)[1]);
  const bytes = Number(grab(out, /Proof for leaf [\d,]+ \d+ hashes \((\d+) B\)/i)[1]);
  const verified = grab(out, /Verified in [\d.]+ ms — (\d+) hashes, not ([\d,]+)/i);

  expect(n).toBe(256);
  // A real tree of this size, so the proof really is log2(n) hashes.
  expect(hashes).toBe(Math.log2(n));
  expect(bytes).toBe(hashes * 32);
  expect(Number(verified[1])).toBe(hashes);
  expect(Number(verified[2]!.replace(/,/g, ''))).toBe(n);
  expect(out).toContain('✓ root matches');
  expect(out).not.toContain('✕ mismatch');
});
