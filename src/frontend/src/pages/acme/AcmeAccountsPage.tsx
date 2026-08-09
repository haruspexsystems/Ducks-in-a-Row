import { useCallback, useMemo, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { AlertTriangle } from 'lucide-react';
import {
  deactivateAcmeAccount,
  fetchAcmeAccounts,
  fetchEabEnforcement,
  type AcmeAccountActivityFilter,
  type AcmeAccountBindingFilter,
  type AcmeAccountsQuery,
  type AcmeAccountStatusFilter,
} from '@/api/acme';
import { AcmeAccountsTable } from '@/components/AcmeAccountsTable';
import { Pagination } from '@/components/Pagination';
import {
  AcmeAccountFilters,
  type AcmeAccountDateFilters,
  type AcmeAccountDateKey,
} from './AcmeAccountFilters';

/**
 * The page sizes the selector offers. Only these values may reach the API
 * through the take param; anything else reads as the default. Same set as the
 * certificate inventory, so the two lists offer the same choices.
 */
const PAGE_SIZE_OPTIONS = [25, 50, 100, 200];
const DEFAULT_PAGE_SIZE = 25;

const BINDING_VALUES: AcmeAccountBindingFilter[] = ['all', 'bound', 'unbound', 'boundToRevoked'];
const STATUS_VALUES: AcmeAccountStatusFilter[] = ['all', 'valid', 'deactivated'];
const ACTIVITY_VALUES: AcmeAccountActivityFilter[] = [
  'any', 'never', 'idle30', 'idle90', 'idle180', 'active7', 'active30',
];

const ACTIVITY_LABELS: Record<AcmeAccountActivityFilter, string> = {
  any: '',
  never: 'never ordered',
  idle30: 'no order in 30 days',
  idle90: 'no order in 90 days',
  idle180: 'no order in 180 days',
  active7: 'ordered in last 7 days',
  active30: 'ordered in last 30 days',
};

const BINDING_LABELS: Record<AcmeAccountBindingFilter, string> = {
  all: '',
  bound: 'bound',
  unbound: 'unbound',
  boundToRevoked: 'bound to a revoked credential',
};

/** A YYYY-MM-DD day, the shape an <input type="date"> reads and writes. */
const DAY_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * Turns a picked local day into the UTC instant the API compares against.
 * dayOffset 0 is the start of that day, 1 the start of the next one, which is
 * how an exclusive upper bound still includes the whole day picked. Returns
 * undefined for anything that is not a real day, so a hand edited URL cannot
 * put an unparseable value on the wire.
 */
function localDayToUtcInstant(day: string | undefined, dayOffset: number): string | undefined {
  if (!day) return undefined;
  const match = DAY_PATTERN.exec(day);
  if (!match) return undefined;
  // The Date constructor rolls a day past the end of a month or year over for
  // us, so an offset never needs its own calendar arithmetic.
  const parsed = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]) + dayOffset);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

/** Reads a param only when it names a known value, else undefined. */
function readEnum<T extends string>(raw: string | null, allowed: T[]): T | undefined {
  return raw !== null && (allowed as string[]).includes(raw) ? (raw as T) : undefined;
}

/** Reads a param only when it is a YYYY-MM-DD day, else undefined. */
function readDay(raw: string | null): string | undefined {
  return raw !== null && DAY_PATTERN.test(raw) ? raw : undefined;
}

/**
 * The ACME account inventory (issue #129), the default tab of the ACME
 * section. Every part of the query lives in the URL rather than component
 * state, so a filtered view is a link an administrator can bookmark or paste
 * into a ticket, and the back button walks the filters.
 *
 * Status, binding, credential, and activity are four independent axes that
 * combine with AND. That is the point of the layout: "which accounts are
 * still valid but unbound", the set the enforcement policy grandfathers, is
 * one question rather than an unaskable one.
 */
export function AcmeAccountsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();

  const [confirmId, setConfirmId] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // The URL is the single source of truth. Every read is guarded, because a
  // hand edited or stale link must never put a value on the wire the API
  // would refuse: the control would then sit on "All" while the list below it
  // was filtered, or the page would show an error for a filter nobody set.
  const urlQuery = useMemo(() => {
    const skipRaw = Number(searchParams.get('skip'));
    const skip = Number.isFinite(skipRaw) && skipRaw > 0 ? Math.floor(skipRaw) : 0;

    const takeRaw = Number(searchParams.get('take'));
    const take = PAGE_SIZE_OPTIONS.includes(takeRaw) ? takeRaw : DEFAULT_PAGE_SIZE;

    const credentialRaw = Number(searchParams.get('credentialId'));
    const credentialId =
      Number.isFinite(credentialRaw) && credentialRaw > 0 ? Math.floor(credentialRaw) : undefined;

    const activity = readEnum(searchParams.get('activity'), ACTIVITY_VALUES) ?? 'any';

    // Activity and the last order range constrain the same field, one
    // relatively and one absolutely, so only one of them may reach the API.
    // handleActivity already clears the range, but that only covers the two
    // controls; a hand edited or stale link can still carry both, and the
    // server would AND them into a query that is unsatisfiable by
    // construction (no order since May, and one since August) and answer it
    // with an unexplained empty list. Dropping the range on read makes the
    // rule a property of the URL rather than of the disabled attribute on
    // the inputs, so the greyed out fields are honestly inert.
    const lastOrderSuppressed = activity !== 'any';

    return {
      search: searchParams.get('search') ?? '',
      status: readEnum(searchParams.get('status'), STATUS_VALUES) ?? 'all',
      binding: readEnum(searchParams.get('binding'), BINDING_VALUES) ?? 'all',
      activity,
      credentialId,
      registeredAfter: readDay(searchParams.get('registeredAfter')),
      registeredBefore: readDay(searchParams.get('registeredBefore')),
      lastOrderAfter: lastOrderSuppressed ? undefined : readDay(searchParams.get('lastOrderAfter')),
      lastOrderBefore: lastOrderSuppressed ? undefined : readDay(searchParams.get('lastOrderBefore')),
      sortBy: searchParams.get('sortBy') ?? undefined,
      sortDesc: searchParams.get('sortDesc') === 'true',
      skip,
      take,
    };
  }, [searchParams]);

  // The URL carries local days because that is what a person reads and what
  // the date input round trips; the API takes instants. Converting here keeps
  // one object as both the query key and the request, so the cache key and
  // the request can never describe different sets.
  const apiQuery: AcmeAccountsQuery = useMemo(
    () => ({
      search: urlQuery.search || undefined,
      status: urlQuery.status,
      binding: urlQuery.binding,
      activity: urlQuery.activity,
      credentialId: urlQuery.credentialId,
      registeredAfter: localDayToUtcInstant(urlQuery.registeredAfter, 0),
      registeredBefore: localDayToUtcInstant(urlQuery.registeredBefore, 1),
      lastOrderAfter: localDayToUtcInstant(urlQuery.lastOrderAfter, 0),
      lastOrderBefore: localDayToUtcInstant(urlQuery.lastOrderBefore, 1),
      sortBy: urlQuery.sortBy,
      sortDesc: urlQuery.sortDesc,
      skip: urlQuery.skip,
      take: urlQuery.take,
    }),
    [urlQuery]
  );

  const { data, isLoading, isError, isPlaceholderData } = useQuery({
    queryKey: ['acme', 'accounts', apiQuery],
    queryFn: () => fetchAcmeAccounts(apiQuery),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
    retry: false,
  });

  // Shares the policy tab's cache entry; one fetch serves both.
  const { data: enforcement } = useQuery({
    queryKey: ['acme', 'eab-enforcement'],
    queryFn: fetchEabEnforcement,
    staleTime: 30_000,
    retry: false,
  });
  const requiredMode = enforcement?.mode === 'required';

  const updateParams = useCallback(
    (updates: Record<string, string | undefined>) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        for (const [key, value] of Object.entries(updates)) {
          if (value === undefined || value === '') {
            next.delete(key);
          } else {
            next.set(key, value);
          }
        }
        return next;
      });
    },
    [setSearchParams]
  );

  // Every filter change also drops skip: the old offset points at a different
  // row window once the filtered set changes underneath it.
  const handleSearch = useCallback(
    (value: string) => updateParams({ search: value || undefined, skip: undefined }),
    [updateParams]
  );

  const handleStatus = useCallback(
    (value: AcmeAccountStatusFilter) =>
      updateParams({ status: value === 'all' ? undefined : value, skip: undefined }),
    [updateParams]
  );

  const handleBinding = useCallback(
    (value: AcmeAccountBindingFilter) =>
      updateParams({ binding: value === 'all' ? undefined : value, skip: undefined }),
    [updateParams]
  );

  const handleCredential = useCallback(
    (value: number | undefined) =>
      updateParams({ credentialId: value === undefined ? undefined : String(value), skip: undefined }),
    [updateParams]
  );

  // Activity is a rolling window on the last order date and the last order
  // range is an absolute one on the same field. Rather than let the two build
  // a query that means nothing, setting an activity clears the range. The
  // read side above suppresses the range as well, so this only keeps the URL
  // tidy; it is not what enforces the rule.
  const handleActivity = useCallback(
    (value: AcmeAccountActivityFilter) =>
      updateParams({
        activity: value === 'any' ? undefined : value,
        lastOrderAfter: undefined,
        lastOrderBefore: undefined,
        skip: undefined,
      }),
    [updateParams]
  );

  const handleDate = useCallback(
    (key: AcmeAccountDateKey, value: string) =>
      updateParams({ [key]: value || undefined, skip: undefined }),
    [updateParams]
  );

  const handleSort = useCallback(
    (column: string) => {
      if (urlQuery.sortBy === column) {
        // Ascending, then descending, then back to the server's default.
        if (!urlQuery.sortDesc) {
          updateParams({ sortBy: column, sortDesc: 'true' });
        } else {
          updateParams({ sortBy: undefined, sortDesc: undefined });
        }
      } else {
        updateParams({ sortBy: column, sortDesc: undefined });
      }
    },
    [urlQuery.sortBy, urlQuery.sortDesc, updateParams]
  );

  const handlePageChange = useCallback(
    (skip: number) => updateParams({ skip: skip > 0 ? String(skip) : undefined }),
    [updateParams]
  );

  // A size change also returns to the first page: the old offset points at a
  // different row window under the new size. The default size is omitted from
  // the URL, the same canonical form skip takes at 0.
  const handlePageSizeChange = useCallback(
    (take: number) =>
      updateParams({
        take: take === DEFAULT_PAGE_SIZE ? undefined : String(take),
        skip: undefined,
      }),
    [updateParams]
  );

  // Drops the tab parameter along with the filters, which is deliberate: the
  // accounts tab is the default, so an empty query string is the canonical
  // URL for this view, the same way the default page size is omitted.
  const clearFilters = useCallback(() => setSearchParams({}), [setSearchParams]);

  const hasFilters = Boolean(
    urlQuery.search || urlQuery.status !== 'all' || urlQuery.binding !== 'all' ||
    urlQuery.activity !== 'any' || urlQuery.credentialId !== undefined ||
    urlQuery.registeredAfter || urlQuery.registeredBefore ||
    urlQuery.lastOrderAfter || urlQuery.lastOrderBefore
  );

  const dates: AcmeAccountDateFilters = useMemo(
    () => ({
      registeredAfter: urlQuery.registeredAfter,
      registeredBefore: urlQuery.registeredBefore,
      lastOrderAfter: urlQuery.lastOrderAfter,
      lastOrderBefore: urlQuery.lastOrderBefore,
    }),
    [urlQuery]
  );

  // Names for the active filters, in the words the controls themselves use,
  // for the filtered empty state.
  const activeFilterLabels = useMemo(() => {
    const labels: string[] = [];
    if (urlQuery.search) labels.push(`search "${urlQuery.search}"`);
    if (urlQuery.status !== 'all') labels.push(`status ${urlQuery.status}`);
    if (urlQuery.binding !== 'all') labels.push(BINDING_LABELS[urlQuery.binding]);
    if (urlQuery.credentialId !== undefined) labels.push('a single credential');
    if (urlQuery.activity !== 'any') labels.push(ACTIVITY_LABELS[urlQuery.activity]);
    if (urlQuery.registeredAfter) labels.push(`registered from ${urlQuery.registeredAfter}`);
    if (urlQuery.registeredBefore) labels.push(`registered to ${urlQuery.registeredBefore}`);
    if (urlQuery.lastOrderAfter) labels.push(`last order from ${urlQuery.lastOrderAfter}`);
    if (urlQuery.lastOrderBefore) labels.push(`last order to ${urlQuery.lastOrderBefore}`);
    return labels;
  }, [urlQuery]);

  const handleDeactivate = useCallback(
    async (id: number) => {
      setBusyId(id);
      setActionError(null);
      setConfirmId(null);
      try {
        await deactivateAcmeAccount(id);
        // The grandfathered count on the policy tab counts valid unbound
        // accounts, so a deactivation can change it. The two refetches are
        // independent; run them in parallel.
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ['acme', 'accounts'] }),
          queryClient.invalidateQueries({ queryKey: ['acme', 'eab-enforcement'] }),
        ]);
      } catch (err) {
        setActionError(err instanceof Error ? err.message : 'Deactivating failed');
      } finally {
        setBusyId(null);
      }
    },
    [queryClient]
  );

  // Which empty state the table shows. The server does the filtering, so with
  // no filters a zero total means there are no accounts at all, and with
  // filters it means the filters excluded everything. Placeholder data
  // belongs to the previous filter set (keepPreviousData), so it must not
  // pick a state for the current one: clearing a no match filter would
  // otherwise flash "No ACME accounts yet" over a populated list.
  let emptyState: ReactNode | undefined;
  if (data && !isPlaceholderData) {
    if (data.totalCount === 0) {
      emptyState = hasFilters ? (
        <FilteredEmptyState filters={activeFilterLabels} onClear={clearFilters} />
      ) : (
        <p className="font-medium text-ink-mid">
          No ACME accounts yet. An account appears when a client registers.
        </p>
      );
    } else if (data.items.length === 0) {
      // A skip past the end of the list (hand edited URL, or the list shrank
      // since the link was made). Neither of the two states above applies.
      emptyState = <PastEndState onFirstPage={() => handlePageChange(0)} />;
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-sm font-semibold text-ink">ACME Accounts</h2>
        <p className="text-sm text-muted mt-1">
          Every account registered with this server, across all templates. An
          account is a client key; the credential column shows which EAB
          credential it registered with, if any.
        </p>
      </div>

      <AcmeAccountFilters
        search={urlQuery.search}
        onSearchChange={handleSearch}
        status={urlQuery.status}
        onStatusChange={handleStatus}
        binding={urlQuery.binding}
        onBindingChange={handleBinding}
        credentialId={urlQuery.credentialId}
        onCredentialChange={handleCredential}
        activity={urlQuery.activity}
        onActivityChange={handleActivity}
        dates={dates}
        onDateChange={handleDate}
        hasFilters={hasFilters}
        onClear={clearFilters}
      />

      {actionError && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">{actionError}</p>
        </div>
      )}

      {isError ? (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">
            The accounts could not be loaded.
          </p>
        </div>
      ) : (
        <>
          <AcmeAccountsTable
            accounts={data?.items ?? []}
            requiredMode={requiredMode}
            sortBy={urlQuery.sortBy}
            sortDesc={urlQuery.sortDesc}
            onSort={handleSort}
            isLoading={isLoading}
            emptyState={emptyState}
            confirmId={confirmId}
            onConfirmChange={setConfirmId}
            busyId={busyId}
            onDeactivate={handleDeactivate}
          />

          {/* Rendered whenever a response exists, including an empty one, so
              the row count and the page size selector do not vanish exactly
              when an administrator is trying to widen a filter. */}
          {data && (
            <Pagination
              skip={data.skip}
              take={data.take}
              totalCount={data.totalCount}
              onPageChange={handlePageChange}
              itemsLabel="accounts"
              pageSizeOptions={PAGE_SIZE_OPTIONS}
              onPageSizeChange={handlePageSizeChange}
              pageSize={urlQuery.take}
            />
          )}
        </>
      )}
    </div>
  );
}

/**
 * Empty state for an over narrow filter: name the active filters in the words
 * the controls use, and offer the one action that resolves it.
 */
function FilteredEmptyState({ filters, onClear }: { filters: string[]; onClear: () => void }) {
  return (
    <div className="space-y-3">
      <p className="font-medium text-ink-mid">No accounts match the active filters</p>
      <p className="text-sm">Active: {filters.join(', ')}</p>
      <button
        type="button"
        onClick={onClear}
        className="text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300 font-medium"
      >
        Clear filters
      </button>
    </div>
  );
}

/** A skip past the end of the list: not an empty inventory, just out of range. */
function PastEndState({ onFirstPage }: { onFirstPage: () => void }) {
  return (
    <div className="space-y-3">
      <p className="font-medium text-ink-mid">This page is past the end of the list</p>
      <button
        type="button"
        onClick={onFirstPage}
        className="text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300 font-medium"
      >
        Go to first page
      </button>
    </div>
  );
}
