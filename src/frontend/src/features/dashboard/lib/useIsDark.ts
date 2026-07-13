import { useEffect, useState } from 'react';

/**
 * Reactively reports whether the dashboard is in dark mode, so SVG charts can
 * pick the right (non-class) colors. Driven solely by Tailwind's `class`
 * strategy (a `.dark` class on <html>), so the charts always stay in lockstep
 * with the page. There is no dark mode toggle in this MVP, so this is false in
 * practice; the OS preference fallback was removed to avoid dark charts on a
 * light page (a dark toggle is tracked in the delta doc).
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
