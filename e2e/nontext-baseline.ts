/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|a.cl-btn": { ratio: 2.05, required: 3.0, unverified: false },
  "control-boundary|button#cons-run.mt-btn.mt-btn--primary": { ratio: 2.54, required: 3.0, unverified: false },
  "control-boundary|button#cons-tamper-delete.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#cons-tamper-reorder.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#cons-tamper.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#ct-run.mt-btn.mt-btn--primary": { ratio: 2.54, required: 3.0, unverified: false },
  "control-boundary|button#ct-tamper.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#dup-run.mt-btn.mt-btn--primary": { ratio: 2.54, required: 3.0, unverified: false },
  "control-boundary|button#leaf-add.mt-btn.mt-btn--primary": { ratio: 2.54, required: 3.0, unverified: false },
  "control-boundary|button#preset-clear.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#preset-sample.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#preset-tx.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#sec-run.mt-btn.mt-btn--primary": { ratio: 2.54, required: 3.0, unverified: false },
  "control-boundary|button#share-link.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#trust-attack.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#trust-honest.mt-btn.mt-btn--primary": { ratio: 2.54, required: 3.0, unverified: false },
  "control-boundary|button#verify-flip.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#verify-honest.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#verify-play.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#verify-run.mt-btn.mt-btn--primary": { ratio: 2.54, required: 3.0, unverified: false },
  "control-boundary|button#verify-step.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#verify-tamper-leaf.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button.predict-reveal.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button.quiz-check.mt-btn.mt-btn--ghost": { ratio: 1.35, required: 3.0, unverified: false }
};
