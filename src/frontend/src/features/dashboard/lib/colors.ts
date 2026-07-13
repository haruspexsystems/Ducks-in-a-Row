// colors.ts — single source of truth for the dashboard's color system.
//
// Tailwind utility classes (in lib/ui.ts) handle surfaces / text / borders.
// But SVG charts need *real* color values, not class names — so the chart
// colors live here and are kept in lockstep with the Tailwind tokens.
//
// Light mode neutrals map 1:1 onto Tailwind's `slate` scale:
//   slate-900 #0F172A  slate-700 #334155  slate-500 #64748B
//   slate-400 #94A3B8  slate-300 #CBD5E1  slate-100 #F1F5F9

export type Hex = string;

/** Fixed semantic status palette — identical in light & dark. */
export const STATUS = {
  brand: { solid: '#FFCF00', deep: '#B8860B' }, // brand yellow (logo only)
  total: { solid: '#6366F1' }, //  indigo — neutral inventory
  success: { solid: '#10B981', deep: '#047857' },
  warning: { solid: '#F59E0B', deep: '#B45309' },
  danger: { solid: '#DC2626', deep: '#991B1B' },
  revoked: { solid: '#8B5CF6', deep: '#6D28D9' }, // violet, matches the table's revoked badge
} as const;

export type StatusTone = keyof typeof STATUS;

/** Canonical brand accent (drives nav active state, registrations bars, etc.). */
export const ACCENT = '#14B8A6'; //        teal-500
export const ACCENT_TEXT_LIGHT = '#0F766E'; // teal-700, legible on white
export const RENEW = '#6366F1'; //          renewals line (indigo)

/** Deep slate nav bar — same in both themes (intentional brand chrome). */
export const NAV_BG = '#0C1322';
export const NAV_BORDER = 'rgba(148,163,184,0.14)';

/** hex (#rgb / #rrggbb) → rgba() string. */
export function alpha(hex: string, a: number): string {
  const h = hex.replace('#', '');
  const full = h.length === 3 ? h.split('').map((x) => x + x).join('') : h;
  const n = parseInt(full, 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}

/** Tint = alpha-over-transparent of any color. Alias for readability in charts. */
export const tint = alpha;

export interface ChartColors {
  dark: boolean;
  accent: string;
  accentText: string;
  ink: string;
  inkSoft: string;
  muted: string;
  faint: string;
  border: string;
  surface: string;
  /** faint horizontal gridlines */
  grid: string;
  /** registrations bar fill (accent @ low alpha) */
  barFill: string;
  /** donut track */
  ringTrack: string;
  /** river water gradient + wave stroke */
  water1: string;
  water2: string;
  waveLine: string;
  /** dark tooltip surface */
  tooltipBg: string;
}

/** Resolve the full chart palette for the current theme. */
export function getChartColors(dark: boolean): ChartColors {
  return {
    dark,
    accent: ACCENT,
    accentText: dark ? ACCENT : ACCENT_TEXT_LIGHT,
    ink: dark ? '#F1F5F9' : '#0F172A',
    inkSoft: dark ? '#CBD5E1' : '#334155',
    muted: dark ? '#8595AD' : '#64748B',
    faint: dark ? '#5B6B86' : '#94A3B8',
    border: dark ? 'rgba(148,163,184,0.16)' : 'rgba(15,23,42,0.08)',
    surface: dark ? '#131C2E' : '#FFFFFF',
    grid: dark ? 'rgba(148,163,184,.14)' : 'rgba(15,23,42,.07)',
    barFill: alpha(ACCENT, dark ? 0.45 : 0.32),
    ringTrack: dark ? 'rgba(148,163,184,.12)' : '#EEF1F5',
    water1: dark ? '#0C2236' : '#E6F4FD',
    water2: dark ? '#0A1B2C' : '#CDE9FB',
    waveLine: dark ? 'rgba(56,189,248,.30)' : 'rgba(56,189,248,.55)',
    tooltipBg: dark ? '#0B1220' : '#0F172A',
  };
}
