/**
 * learn.ts — Active-learning helpers, all data-driven from the HTML so the
 * markup stays the single source of truth:
 *   - glossary tooltips   ([data-term])
 *   - predict-then-reveal (.predict / .predict-reveal / .predict-answer)
 *   - self-check quizzes  (.quiz-card[data-correct][data-why-correct][data-why-wrong])
 */

import { qsa } from './dom';

const GLOSSARY: Record<string, string> = {
  'merkle-root': 'The single hash at the top of the tree. It commits to every leaf at once.',
  'inclusion-proof':
    'The minimal set of sibling hashes on the path from a leaf to the root — also called an audit path.',
  preimage: 'An input that hashes to a given output. SHA-256 is preimage-resistant.',
  'second-preimage':
    'A DIFFERENT input that hashes to the same output as a given one. Hard for SHA-256 — the basis of Merkle security.',
  'collision-resistance':
    'The hardness of finding any two different inputs with the same hash.',
  'domain-separation':
    'Tagging leaf inputs with 0x00 and node inputs with 0x01 so a leaf hash can never be mistaken for a node hash.',
  spv:
    'Simplified Payment Verification — a light client that confirms a transaction is in a block using only a short Merkle proof.',
};

function mountGlossary(): void {
  // One shared tooltip element, appended to <body> so it can never be clipped by
  // an overflow container, and viewport-clamped on open.
  const tip = document.createElement('div');
  tip.className = 'glossary-def';
  tip.id = 'glossary-tip';
  tip.setAttribute('role', 'tooltip');
  tip.hidden = true;
  document.body.appendChild(tip);

  let openTerm: HTMLElement | null = null;

  const close = (): void => {
    if (!openTerm) return;
    openTerm.setAttribute('aria-expanded', 'false');
    openTerm = null;
    tip.hidden = true;
  };

  const open = (el: HTMLElement, def: string): void => {
    tip.textContent = def;
    tip.hidden = false;
    openTerm = el;
    el.setAttribute('aria-expanded', 'true');
    // Position below the term, clamped to the viewport.
    const r = el.getBoundingClientRect();
    const w = tip.offsetWidth;
    const left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8));
    tip.style.left = `${left}px`;
    tip.style.top = `${Math.min(r.bottom + 6, window.innerHeight - tip.offsetHeight - 8)}px`;
  };

  for (const el of qsa<HTMLElement>('[data-term]')) {
    const def = GLOSSARY[el.dataset.term ?? ''];
    if (!def) continue;
    el.classList.add('glossary');
    el.tabIndex = 0;
    el.setAttribute('role', 'button');
    el.setAttribute('aria-expanded', 'false');
    el.setAttribute('aria-describedby', tip.id);
    el.setAttribute('aria-label', `${el.textContent}: ${def}`);

    const toggle = (): void => (openTerm === el ? close() : open(el, def));
    el.addEventListener('click', toggle);
    el.addEventListener('keydown', (e) => {
      const key = (e as KeyboardEvent).key;
      if (key === 'Enter' || key === ' ') {
        e.preventDefault();
        toggle();
      } else if (key === 'Escape') {
        close();
      }
    });
    // Discoverable on hover/focus; dismissed when both are lost.
    el.addEventListener('mouseenter', () => open(el, def));
    el.addEventListener('mouseleave', () => {
      if (document.activeElement !== el) close();
    });
    el.addEventListener('blur', close);
  }

  // Escape anywhere, and scroll, dismiss the tooltip.
  document.addEventListener('keydown', (e) => {
    if ((e as KeyboardEvent).key === 'Escape') close();
  });
  window.addEventListener('scroll', close, { passive: true });
}

function mountPredict(): void {
  for (const btn of qsa<HTMLButtonElement>('.predict-reveal')) {
    const answer = btn.parentElement?.querySelector<HTMLElement>('.predict-answer');
    if (!answer) continue;
    answer.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    btn.addEventListener('click', () => {
      const open = answer.hidden;
      answer.hidden = !open;
      btn.setAttribute('aria-expanded', String(open));
      btn.textContent = open ? 'Hide answer' : 'Reveal answer';
    });
  }
}

function mountQuizzes(): void {
  for (const card of qsa<HTMLElement>('.quiz-card')) {
    const correct = card.dataset.correct ?? '';
    const whyCorrect = card.dataset.whyCorrect ?? '';
    const whyWrong = card.dataset.whyWrong ?? '';
    const explain = card.querySelector<HTMLElement>('.quiz-explain');
    const check = card.querySelector<HTMLButtonElement>('.quiz-check');
    if (!explain || !check) continue;

    check.addEventListener('click', () => {
      const chosen = card.querySelector<HTMLInputElement>('input[type="radio"]:checked');
      if (!chosen) {
        explain.hidden = false;
        explain.className = 'quiz-explain quiz-explain--wrong';
        explain.textContent = 'Pick an answer first.';
        return;
      }
      const isRight = chosen.value === correct;
      explain.hidden = false;
      explain.className = `quiz-explain ${isRight ? 'quiz-explain--right' : 'quiz-explain--wrong'}`;
      explain.innerHTML = `<strong>${isRight ? '✓ Correct.' : '✕ Not quite.'}</strong> ${isRight ? whyCorrect : whyWrong}`;
    });
  }
}

export function mountLearn(): void {
  mountGlossary();
  mountPredict();
  mountQuizzes();
}
