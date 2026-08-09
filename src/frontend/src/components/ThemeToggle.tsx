import { useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import { getTheme, toggleTheme, type Theme } from '@/lib/theme';

/**
 * Header control that switches the application between light and dark.
 *
 * State is seeded from the class already on <html> (put there before first
 * paint by public/theme-init.js) and `toggleTheme` is the sole writer, so local
 * state cannot drift from the document.
 *
 * Accessibility: a native <button> for keyboard reach and focus handling, with
 * `aria-pressed` carrying the on/off state. `aria-pressed` is preferred over
 * role="switch" here for wider assistive technology support, and the label is
 * fixed rather than describing the action so the announced state stays
 * unambiguous ("Dark mode, pressed" rather than "Switch to light mode").
 */
export function ThemeToggle() {
  const [theme, setThemeState] = useState<Theme>(getTheme);
  const isDark = theme === 'dark';

  return (
    <button
      type="button"
      onClick={() => setThemeState(toggleTheme())}
      aria-pressed={isDark}
      aria-label="Dark mode"
      title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      className="ml-1 grid h-9 w-9 place-items-center rounded-[10px] text-[#AEBAD0]
                 transition-colors hover:bg-white/10 hover:text-white
                 focus-visible:outline-none focus-visible:ring-2
                 focus-visible:ring-certus-400 focus-visible:ring-offset-2
                 focus-visible:ring-offset-nav-bg"
    >
      {isDark ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
    </button>
  );
}
