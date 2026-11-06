// audit.ts: the words the Audit page makes of the trail (issue #634). The
// server records a stable dotted action name and the raw before and after
// values; this file turns the name into a sentence fragment and the counts
// into the summary line, which is why it is testable without a page.

/**
 * "settings.allowed-domains.changed" reads as "Settings: allowed domains
 * changed". The first segment is the area, the rest the noun and the verb,
 * with hyphens opened into spaces. An unknown shape falls back to the raw
 * name, so a new action on the server never renders as nothing.
 */
export function describeAction(action: string): string {
  const segments = action.split('.').filter((s) => s.length > 0);
  if (segments.length < 2) return action;
  const [area, ...rest] = segments;
  const words = rest
    .flatMap((s) => s.split('-'))
    .map((w) => ACRONYMS.has(w) ? w.toUpperCase() : w)
    .join(' ');
  return `${AREAS[area] ?? capitalize(area)}: ${words}`;
}

/** The first segment of an action name, as the page labels it. */
const AREAS: Record<string, string> = {
  acme: 'ACME',
  alerts: 'Alerts',
  certificate: 'Certificates',
  certificates: 'Certificates',
  licence: 'Licence',
  settings: 'Settings',
  setup: 'Setup',
};

/** Words that stay upper case when the name is opened into a sentence. */
const ACRONYMS = new Set(['eab', 'https', 'url', 'ca']);

function capitalize(word: string): string {
  return word.length === 0 ? word : word[0].toUpperCase() + word.slice(1);
}

/** "No refused sign ins in the last 30 days", or the count and the sources. */
export function describeSignInFailures(total: number, sources: number, days: number): string {
  const window = days === 1 ? 'the last day' : `the last ${days} days`;
  if (total === 0) return `No refused sign ins in ${window}.`;
  const attempts = total === 1 ? '1 refused sign in' : `${total} refused sign ins`;
  const from = sources === 1 ? '1 source address' : `${sources} source addresses`;
  return `${attempts} from ${from} in ${window}.`;
}

/**
 * The change column: before and after when both are known, after alone when
 * the action has no earlier value (a revocation, a test send), and a dash
 * when the row says nothing beyond the action itself.
 */
export function describeChange(before?: string | null, after?: string | null): string {
  if (before && after) return `${before} → ${after}`;
  if (after) return after;
  if (before) return `was ${before}`;
  return '—';
}
