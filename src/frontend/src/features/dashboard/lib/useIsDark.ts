import { useEffect, useState } from 'react';

/**
 * Reactively reports whether the dashboard is in dark mode, so SVG charts can
 * pick the right (non-class) colors. Driven solely by Tailwind's `class`
 * strategy (a `.dark` class on <html>), so the charts always stay in lockstep
 * with the page.
 *
 * The class is written by `lib/theme.ts` (the header toggle) and seeded before
 * first paint by `public/theme-init.js`. Do not reintroduce a
 * `prefers-color-scheme` fallback here: the OS preference is read once, at
 * seeding time, and a live media query is what would let these charts render
 * dark on a light page.
 */
export function useIsDark(): boolean {
  const read = () => {
    if (typeof document === 'undefined') return false;
    return document.documentElement.classList.contains('dark');
  };

  const [dark, setDark] = useState(read);

  useEffect(() => {
    const update = () => setDark(read());

    const mo = new MutationObserver(update);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

    return () => mo.disconnect();
  }, []);

  return dark;
}
