/** Tiny non-blocking toast for copy/confirmation feedback. */

let el: HTMLElement | null = null;
let timer: number | undefined;

function ensure(): HTMLElement {
  if (el) return el;
  el = document.createElement('div');
  el.className = 'mt-toast';
  el.setAttribute('role', 'status');
  el.setAttribute('aria-live', 'polite');
  document.body.appendChild(el);
  return el;
}

export function toast(message: string): void {
  const node = ensure();
  node.textContent = message;
  node.classList.add('mt-toast--show');
  if (timer) clearTimeout(timer);
  timer = window.setTimeout(() => node.classList.remove('mt-toast--show'), 1600);
}
