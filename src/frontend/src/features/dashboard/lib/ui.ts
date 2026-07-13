// ui.ts — shared Tailwind className tokens, so every widget renders the
// canonical surface/text treatment without repeating long class strings.
//
// Requires Tailwind's class-based dark mode:  darkMode: 'class'  (see README).

/** Tiny classnames joiner (avoids a clsx dependency). */
export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/** Card shell: white / deep-navy surface, hairline border, soft shadow, 16px radius. */
export const card = cn(
  'rounded-2xl border bg-white shadow-[0_1px_2px_rgba(15,23,42,.04),0_6px_20px_rgba(15,23,42,.05)]',
  'border-slate-900/[0.08] dark:border-slate-400/[0.16]',
  'dark:bg-[#131C2E] dark:shadow-[0_1px_2px_rgba(0,0,0,.4),0_8px_24px_rgba(0,0,0,.28)]',
);

/** Lift-on-hover for interactive cards (stat cards, quick actions). */
export const cardHover =
  'transition-[box-shadow,transform,border-color] duration-200 hover:-translate-y-0.5 ' +
  'hover:shadow-[0_10px_28px_rgba(15,23,42,.10)] dark:hover:shadow-[0_6px_22px_rgba(0,0,0,.45)]';

/** Canonical inner padding (comfortable density = 18px). */
export const cardPad = 'p-[18px]';

// Text ramp — light values are exact slate-scale; dark values are brand-tuned.
export const textInk = 'text-slate-900 dark:text-slate-100';
export const textInkSoft = 'text-slate-700 dark:text-slate-300';
export const textMuted = 'text-slate-500 dark:text-[#8595AD]';
export const textFaint = 'text-slate-400 dark:text-[#5B6B86]';

/** JetBrains Mono with tabular figures (font wired in dashboard-theme.css). */
export const mono = 'md-mono';
