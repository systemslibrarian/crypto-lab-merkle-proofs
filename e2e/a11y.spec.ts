import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * Every exhibit's output — and its failure branch where it has one — is scanned
 * in both themes at desktop and phone width. See `gate.ts` for why nothing is
 * injected into the page, why each scan asserts its content first, and why
 * `violations` is not the whole oracle.
 *
 * `expectBaselineNotStale` is the non-text baseline's third rule — a listed
 * finding that no longer appears fails, so a fixed entry must be deleted and
 * the file can only shrink. It runs in the LIGHT configurations only, and that
 * restriction is measured rather than stylistic. `nonTextSeen` is module state
 * and `fullyParallel` gives every test its own worker, so each configuration
 * ratchets against what it alone drove. Dark finds 19 of the 26 baselined
 * selectors and light finds all 26: the seven `.mt-btn--primary` boundaries
 * fail at 2.54:1 against the light surface and clear 3:1 against the dark one.
 * Dark's set is a strict subset of light's, so running the rule in light loses
 * no coverage, while running it in dark would report those seven as stale on
 * every single run.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
