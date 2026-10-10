/* theme-init.js — sets the `.dark` class before first paint.
 *
 * Loaded from index.html as a classic blocking script. Three constraints, all
 * load bearing:
 *
 *   1. It must be this separate same-origin FILE, not an inline <script>.
 *      SecurityHeadersMiddleware sets `script-src 'self'` with no
 *      'unsafe-inline', so the usual inline snippet is blocked by CSP. 'self'
 *      permits this file, so no CSP relaxation is needed.
 *   2. It must NOT be type="module" and must NOT carry defer. Both run after
 *      the document is parsed, which is after first paint, which reintroduces
 *      the flash of the wrong theme this file exists to prevent.
 *   3. The storage key and the seeding rule are duplicated from src/lib/theme.ts
 *      because this runs before any module loads and cannot import. Keep the two
 *      in sync.
 */
(function () {
  try {
    var saved = localStorage.getItem('diar-theme');
    var dark =
      saved === 'dark' ||
      saved === 'light'
        ? saved === 'dark'
        : window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (dark) {
      document.documentElement.classList.add('dark');
    }
  } catch {
    /* Storage or matchMedia unavailable (private mode, ancient browser).
       Fall through to light, which is the default the stylesheet already
       assumes, so there is nothing to undo. */
  }
})();
