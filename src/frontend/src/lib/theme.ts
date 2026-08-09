// theme.ts — the only writer of the `.dark` class on <html>.
//
// The class is the single source of truth for the theme: Tailwind's `class`
// strategy reads it, and features/dashboard/lib/useIsDark observes it so SVG
// charts stay in lockstep with the page they sit on.
//
// Seeding the initial class is NOT this module's job. public/theme-init.js does
// it before first paint, reading the OS preference exactly once; it has to run
// as a plain blocking script (the CSP forbids inline script), so it cannot
// import from here. That leaves exactly one thing shared between the two files,
// the storage key below, and it MUST stay in sync. Deliberately no copy of the
// seeding rule lives here: a second, uncalled copy could drift from the real one
// without any symptom.

export type Theme = 'light' | 'dark';

/** localStorage key. Mirrored as a literal in public/theme-init.js. */
export const THEME_STORAGE_KEY = 'diar-theme';

/** The theme currently applied to the document. */
export function getTheme(): Theme {
  if (typeof document === 'undefined') return 'light';
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
}

/** Applies a theme to the document and persists it. */
export function setTheme(theme: Theme): void {
  document.documentElement.classList.toggle('dark', theme === 'dark');

  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Preference cannot be persisted; the theme still applies for this session.
  }
}

/** Flips the theme and returns the one now applied. */
export function toggleTheme(): Theme {
  const next: Theme = getTheme() === 'dark' ? 'light' : 'dark';
  setTheme(next);
  return next;
}
