import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CalendarRange, ChevronDown, ChevronRight } from 'lucide-react';
import {
  fetchEabCredentials,
  type AcmeAccountActivityFilter,
  type AcmeAccountBindingFilter,
  type AcmeAccountStatusFilter,
} from '@/api/acme';
import { SearchBar } from '@/components/SearchBar';

/** The status chips, in triage order. */
const STATUS_CHIPS: { value: AcmeAccountStatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'valid', label: 'Valid' },
  { value: 'deactivated', label: 'Deactivated' },
];

const BINDING_OPTIONS: { value: AcmeAccountBindingFilter; label: string }[] = [
  { value: 'all', label: 'All accounts' },
  { value: 'bound', label: 'Bound' },
  { value: 'unbound', label: 'Unbound' },
  { value: 'boundToRevoked', label: 'Bound to a revoked credential' },
];

const ACTIVITY_OPTIONS: { value: AcmeAccountActivityFilter; label: string }[] = [
  { value: 'any', label: 'Any activity' },
  { value: 'never', label: 'Never ordered' },
  { value: 'idle30', label: 'No order in 30 days' },
  { value: 'idle90', label: 'No order in 90 days' },
  { value: 'idle180', label: 'No order in 180 days' },
  { value: 'active7', label: 'Ordered in last 7 days' },
  { value: 'active30', label: 'Ordered in last 30 days' },
];

/** The four absolute date bounds, as local YYYY-MM-DD days. */
export interface AcmeAccountDateFilters {
  registeredAfter?: string;
  registeredBefore?: string;
  lastOrderAfter?: string;
  lastOrderBefore?: string;
}

export type AcmeAccountDateKey = keyof AcmeAccountDateFilters;

const SELECT_CLASS =
  'px-3 py-2 border border-hairline-strong rounded-lg text-sm bg-surface text-ink-soft ' +
  'focus:outline-none focus:ring-2 focus:ring-certus-500 focus:border-certus-500';

const DATE_INPUT_CLASS =
  'px-2 py-1.5 border border-hairline-strong rounded-md text-sm bg-surface text-ink-soft ' +
  'focus:outline-none focus:ring-2 focus:ring-certus-500 disabled:opacity-50 ' +
  'disabled:cursor-not-allowed';

interface AcmeAccountFiltersProps {
  search: string;
  onSearchChange: (value: string) => void;
  status: AcmeAccountStatusFilter;
  onStatusChange: (value: AcmeAccountStatusFilter) => void;
  binding: AcmeAccountBindingFilter;
  onBindingChange: (value: AcmeAccountBindingFilter) => void;
  credentialId?: number;
  onCredentialChange: (value: number | undefined) => void;
  activity: AcmeAccountActivityFilter;
  onActivityChange: (value: AcmeAccountActivityFilter) => void;
  dates: AcmeAccountDateFilters;
  onDateChange: (key: AcmeAccountDateKey, value: string) => void;
  hasFilters: boolean;
  onClear: () => void;
}

/**
 * The account inventory filter bar. Status, binding, credential, and activity
 * are four independent axes that combine with AND, so "valid and still
 * unbound" is one query rather than an impossible one; that is the whole
 * reason status is not folded into the binding select.
 *
 * The absolute date ranges live behind a disclosure because most sessions use
 * none of them, and the relative Activity presets cover the common questions.
 */
export function AcmeAccountFilters({
  search,
  onSearchChange,
  status,
  onStatusChange,
  binding,
  onBindingChange,
  credentialId,
  onCredentialChange,
  activity,
  onActivityChange,
  dates,
  onDateChange,
  hasFilters,
  onClear,
}: AcmeAccountFiltersProps) {
  const hasDateFilter = Boolean(
    dates.registeredAfter || dates.registeredBefore ||
    dates.lastOrderAfter || dates.lastOrderBefore
  );

  // Open on mount when a bookmarked URL already carries a date, so a filter
  // that is narrowing the list is never invisible. Later toggles are the
  // administrator's, so this only ever forces the panel open, never shut.
  const [datesOpen, setDatesOpen] = useState(hasDateFilter);
  useEffect(() => {
    if (hasDateFilter) setDatesOpen(true);
  }, [hasDateFilter]);

  // Shares the credentials tab's cache entry; one fetch serves both. A
  // failure here leaves the select with just "Any credential" rather than
  // breaking the page: the other filters still work.
  const { data: credentials } = useQuery({
    queryKey: ['acme', 'eab-credentials'],
    queryFn: fetchEabCredentials,
    staleTime: 30_000,
    retry: false,
  });

  // Activity is a rolling window on the last order date and the Last order
  // range is an absolute one on the same field. Two controls over one axis
  // would fight, so Activity wins outright: it is the one on the always
  // visible row, and while it is set the range is both disabled here and
  // dropped when the page reads the URL, so it cannot reach the API by any
  // route. The relationship is deliberately one directional; the range never
  // clears Activity.
  const lastOrderRangeDisabled = activity !== 'any';

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {STATUS_CHIPS.map((chip) => {
          const active = status === chip.value;
          return (
            <button
              key={chip.value}
              type="button"
              onClick={() => onStatusChange(chip.value)}
              aria-pressed={active}
              className={`px-3 py-1.5 rounded-full text-sm font-medium border transition-colors ${
                active
                  ? 'bg-certus-600 border-certus-600 text-white'
                  : 'bg-surface border-hairline-strong text-ink-soft hover:bg-sunken'
              }`}
            >
              {chip.label}
            </button>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-[240px] max-w-md">
          <SearchBar
            value={search}
            onChange={onSearchChange}
            placeholder="Search account id, contact, or credential…"
          />
        </div>

        <select
          value={binding}
          onChange={(e) => onBindingChange(e.target.value as AcmeAccountBindingFilter)}
          aria-label="Filter by EAB binding"
          className={SELECT_CLASS}
        >
          {BINDING_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        <select
          value={credentialId ?? ''}
          onChange={(e) =>
            onCredentialChange(e.target.value === '' ? undefined : Number(e.target.value))
          }
          aria-label="Filter by EAB credential"
          className={SELECT_CLASS}
        >
          <option value="">Any credential</option>
          {credentials?.map((credential) => (
            <option key={credential.id} value={credential.id}>
              {credential.name}
              {credential.status === 'revoked' ? ' (revoked)' : ''}
            </option>
          ))}
        </select>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <select
          value={activity}
          onChange={(e) => onActivityChange(e.target.value as AcmeAccountActivityFilter)}
          aria-label="Filter by order activity"
          className={SELECT_CLASS}
        >
          {ACTIVITY_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        <button
          type="button"
          onClick={() => setDatesOpen((open) => !open)}
          aria-expanded={datesOpen}
          className="inline-flex items-center gap-1.5 text-sm font-medium text-ink-soft
                     hover:text-ink transition-colors"
        >
          {datesOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <CalendarRange className="h-4 w-4" />
          Dates
          {hasDateFilter && (
            <span className="ml-1 inline-flex h-1.5 w-1.5 rounded-full bg-certus-600" aria-hidden />
          )}
        </button>

        {hasFilters && (
          <button
            type="button"
            onClick={onClear}
            className="text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300 font-medium"
          >
            Clear filters
          </button>
        )}
      </div>

      {datesOpen && (
        <div className="rounded-lg border border-hairline bg-sunken p-4 space-y-3">
          <DateRangeRow
            label="Registered"
            fromKey="registeredAfter"
            toKey="registeredBefore"
            dates={dates}
            onDateChange={onDateChange}
          />
          <DateRangeRow
            label="Last order"
            fromKey="lastOrderAfter"
            toKey="lastOrderBefore"
            dates={dates}
            onDateChange={onDateChange}
            disabled={lastOrderRangeDisabled}
          />

          {/* The same filter as the Activity select's "Never ordered", not a
              second one: both read and write activity=never. It belongs here
              too because it is the null case of the range directly above,
              which is exactly why ticking it disables that range. */}
          <label className="flex items-center gap-2 text-sm text-ink-mid">
            <input
              type="checkbox"
              checked={activity === 'never'}
              onChange={(e) => onActivityChange(e.target.checked ? 'never' : 'any')}
              className="h-4 w-4 rounded border-hairline-strong text-certus-600
                         focus:ring-2 focus:ring-certus-500"
            />
            Never ordered
          </label>

          {activity === 'never' ? (
            <p className="text-xs text-muted">
              Showing accounts with no orders at all. They have no last order
              date, so that range does not apply.
            </p>
          ) : lastOrderRangeDisabled ? (
            <p className="text-xs text-muted">
              The activity filter above already constrains the last order date.
              Set it back to "Any activity" to pick exact dates.
            </p>
          ) : (
            <p className="text-xs text-muted">
              Both bounds include the whole day picked. An account that has
              never ordered has no last order date, so it matches neither
              bound; tick the box above to find those.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function DateRangeRow({
  label,
  fromKey,
  toKey,
  dates,
  onDateChange,
  disabled,
}: {
  label: string;
  fromKey: AcmeAccountDateKey;
  toKey: AcmeAccountDateKey;
  dates: AcmeAccountDateFilters;
  onDateChange: (key: AcmeAccountDateKey, value: string) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className={`text-sm w-24 ${disabled ? 'text-faint' : 'text-ink-mid'}`}>{label}</span>
      <input
        type="date"
        value={dates[fromKey] ?? ''}
        disabled={disabled}
        onChange={(e) => onDateChange(fromKey, e.target.value)}
        aria-label={`${label} from`}
        className={DATE_INPUT_CLASS}
      />
      <span className={`text-sm ${disabled ? 'text-faint' : 'text-muted'}`}>to</span>
      <input
        type="date"
        value={dates[toKey] ?? ''}
        disabled={disabled}
        onChange={(e) => onDateChange(toKey, e.target.value)}
        aria-label={`${label} to`}
        className={DATE_INPUT_CLASS}
      />
    </div>
  );
}
