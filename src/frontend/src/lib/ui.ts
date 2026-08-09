// ui.ts — shared Tailwind className tokens, so every surface renders the
// canonical treatment without repeating long class strings.
//
// These used to carry explicit `dark:` pairs and lived under
// features/dashboard. They now resolve through the semantic color tokens in
// index.css, which the `.dark` class flips, so a single class covers both
// themes and the same tokens serve the whole application rather than just the
// dashboard.
//
// Requires Tailwind's class-based dark mode: darkMode: 'class'.

/** Tiny classnames joiner (avoids a clsx dependency). */
export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/** Card shell: themed surface, hairline border, soft shadow, 16px radius. */
export const card = cn(
  'rounded-2xl border bg-surface border-card-border',
  'shadow-[0_1px_2px_rgba(15,23,42,.04),0_6px_20px_rgba(15,23,42,.05)]',
  'dark:shadow-[0_1px_2px_rgba(0,0,0,.4),0_8px_24px_rgba(0,0,0,.28)]',
);

/** Lift-on-hover for interactive cards (stat cards, quick actions). */
export const cardHover =
  'transition-[box-shadow,transform,border-color] duration-200 hover:-translate-y-0.5 ' +
  'hover:shadow-[0_10px_28px_rgba(15,23,42,.10)] dark:hover:shadow-[0_6px_22px_rgba(0,0,0,.45)]';

/** Canonical inner padding (comfortable density = 18px). */
export const cardPad = 'p-[18px]';

// Text ramp. Each token maps to one semantic color, flipped by the `.dark`
// class; the light values are the exact slate steps these replaced.
export const textInk = 'text-ink';
export const textInkSoft = 'text-ink-soft';
export const textMuted = 'text-muted';
export const textFaint = 'text-faint';

/** JetBrains Mono with tabular figures (font wired in dashboard-theme.css). */
export const mono = 'md-mono';
