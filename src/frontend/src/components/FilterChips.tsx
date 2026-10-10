import { CERTIFICATE_STATES, type CertificateState } from '@/types';

interface FilterChipsProps {
  /** The selected state, or undefined for "All". */
  value?: CertificateState;
  /** Called with the new state, or undefined when "All" is chosen. */
  onChange: (state: CertificateState | undefined) => void;
  /** The operator's configured warning window, for the Expiring soon tooltip. */
  warningDays: number;
}

/**
 * The visible label per state. Exported so the filtered empty state names the
 * active chip with the exact wording the chip itself shows (issue #157).
 */
// The export is deliberate and CertificateListPage depends on it, so the cost
// is accepted rather than removed: this one file reloads instead of hot
// patching when edited in the dev host. Undoing that means a separate module
// for the labels and a changed import, a refactor rather than part of making
// the lint script real (issue #254).
// eslint-disable-next-line react-refresh/only-export-components
export const STATE_LABELS: Record<CertificateState, string> = {
  valid: 'Valid',
  expiring: 'Expiring soon',
  expired: 'Expired',
  revoked: 'Revoked',
};

/**
 * Colours per state. The colours track ExpiryCell and StatusBadge so a chip
 * and the rows it returns read as the same thing.
 */
const CHIP_STYLES: Record<CertificateState, { active: string; idle: string }> = {
  valid: {
    active: 'bg-emerald-600 text-white border-emerald-600',
    idle: 'bg-surface text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/30 hover:bg-emerald-50 dark:bg-emerald-500/10',
  },
  expiring: {
    active: 'bg-amber-500 text-white border-amber-500',
    idle: 'bg-surface text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/30 hover:bg-amber-50 dark:bg-amber-500/10',
  },
  expired: {
    active: 'bg-red-600 text-white border-red-600',
    idle: 'bg-surface text-red-700 dark:text-red-300 border-red-200 dark:border-red-500/30 hover:bg-red-50 dark:bg-red-500/10',
  },
  revoked: {
    active: 'bg-slate-700 text-white border-slate-700',
    idle: 'bg-surface text-ink-soft border-hairline-strong hover:bg-sunken',
  },
};

const CHIP_BASE =
  'px-3 py-1.5 rounded-full border text-sm font-medium transition-colors ' +
  'focus:outline-none focus:ring-2 focus:ring-certus-500 focus:ring-offset-1';

/**
 * Single select chips for the four certificate lifecycle states (issue #155).
 *
 * Selecting a chip replaces the current one; the leading "All" chip clears it.
 * The states are mutually exclusive by construction on the server, so any two
 * of them together would return nothing, and a multi select would only offer
 * empty views.
 */
export function FilterChips({ value, onChange, warningDays }: FilterChipsProps) {
  return (
    <div role="group" aria-label="Filter by certificate state" className="flex flex-wrap items-center gap-2">
      <button
        type="button"
        onClick={() => onChange(undefined)}
        aria-pressed={value === undefined}
        className={`${CHIP_BASE} ${
          value === undefined
            ? 'bg-certus-600 text-white border-certus-600'
            : 'bg-surface text-ink-soft border-hairline-strong hover:bg-sunken'
        }`}
      >
        All
      </button>

      {CERTIFICATE_STATES.map((state) => {
        const { active, idle } = CHIP_STYLES[state];
        const label = STATE_LABELS[state];
        const isActive = value === state;
        return (
          <button
            key={state}
            type="button"
            // Clicking the active chip clears it, so the filter can be undone
            // without reaching for "All" or "Clear filters".
            onClick={() => onChange(isActive ? undefined : state)}
            aria-pressed={isActive}
            // A title becomes the accessible name, so it has to open with the
            // visible label or a voice control user asking for "Expiring soon"
            // no longer matches the chip (WCAG 2.5.3, Label in Name).
            title={state === 'expiring' ? `${label}: within ${warningDays} days` : undefined}
            className={`${CHIP_BASE} ${isActive ? active : idle}`}
          >
            {label}
          </button>
        );
      })}
    </div>
  );
}
