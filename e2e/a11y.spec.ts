import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate. Scans the full page with every <details>
 * expanded and every class-toggled / [hidden] panel revealed, in both the
 * dark (default) and light themes. Any WCAG 2.0/2.1 A/AA violation fails.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealEverything(page: Page): Promise<void> {
  // Kill animations/transitions/opacity so nothing is mid-flight during scan.
  await page.addStyleTag({
    content: `*, *::before, *::after {
      transition: none !important;
      animation: none !important;
      opacity: 1 !important;
    }`,
  });
  await page.evaluate(() => {
    // Expand every <details>.
    for (const d of Array.from(document.querySelectorAll('details'))) {
      (d as HTMLDetailsElement).open = true;
    }
    // Reveal anything hidden via the [hidden] attribute (e.g. quiz explanations)
    // or class-toggled panels, so their contents are scanned too.
    for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
      el.removeAttribute('hidden');
    }
    for (const el of Array.from(
      document.querySelectorAll<HTMLElement>('.open, .active, .is-active, .quiz-explain'),
    )) {
      el.classList.add('open', 'active');
      el.style.display = '';
      el.style.visibility = 'visible';
    }
  });
  // Give dynamically-rendered content a beat to settle.
  await page.waitForTimeout(100);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await revealEverything(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await scan(page);
});
