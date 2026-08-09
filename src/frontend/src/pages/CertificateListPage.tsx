import { useCallback, useMemo, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import type { SyncStatus } from '@/api/client';
import { useCertificates, useTemplates } from '@/hooks/useCertificates';
import { useExpiryWarningDays } from '@/hooks/useExpiryWarningDays';
import { useManualSync, useSyncStatus } from '@/hooks/useSyncStatus';
import {
  formatDate,
  parseCertificateState,
  relativeTime,
  type CertificateQuery,
  type CertificateState,
} from '@/types';
import { CertificateTable } from '@/components/CertificateTable';
import { FilterChips, STATE_LABELS } from '@/components/FilterChips';
import { HeaderSyncStatus } from '@/components/HeaderSyncStatus';
import { SearchBar } from '@/components/SearchBar';
import { SyncErrorNotice } from '@/components/SyncErrorNotice';
import { Pagination } from '@/components/Pagination';

/**
 * The page sizes the selector offers. Only these values may reach the API
 * through the take param; anything else reads as the default.
 */
const PAGE_SIZE_OPTIONS = [25, 50, 100, 200];
const DEFAULT_PAGE_SIZE = 25;

/**
 * The request states the dropdown can display. A status it cannot show must not
 * survive into the query, or the control would sit on "All Requests" while the
 * list below it was filtered.
 */
const REQUEST_STATUSES = ['Pending', 'Denied', 'Failed'];

export function CertificateListPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  // Parse query params into typed object
  const query: CertificateQuery = useMemo(() => {
    // Guard against a hand edited, non numeric skip so we never send skip=NaN.
    const skipRaw = Number(searchParams.get('skip'));
    const skip = Number.isFinite(skipRaw) && skipRaw > 0 ? Math.floor(skipRaw) : 0;

    // Same stance as skip: only the sizes the selector offers may reach the
    // API, so a hand edited take reads as the default.
    const takeRaw = Number(searchParams.get('take'));
    const take = PAGE_SIZE_OPTIONS.includes(takeRaw) ? takeRaw : DEFAULT_PAGE_SIZE;

    // Links made before the state chips existed carry a certificate status in
    // the status parameter, which the dropdown no longer offers. Revoked has an
    // exact chip, so it keeps its meaning. Issued spans three chips and has
    // none, so it falls back to the unfiltered list, which is where the
    // dashboard's View Certificates card now points anyway.
    const rawStatus = searchParams.get('status');
    return {
      search: searchParams.get('search') ?? undefined,
      template: searchParams.get('template') ?? undefined,
      status: REQUEST_STATUSES.includes(rawStatus ?? '') ? rawStatus! : undefined,
      // Same stance as skip above: a hand edited state never reaches the API,
      // which would answer it with a 400.
      state:
        parseCertificateState(searchParams.get('state')) ??
        (rawStatus === 'Revoked' ? 'revoked' : undefined),
      expiringBefore: searchParams.get('expiringBefore') ?? undefined,
      expiringAfter: searchParams.get('expiringAfter') ?? undefined,
      sortBy: searchParams.get('sortBy') ?? undefined,
      sortDesc: searchParams.get('sortDesc') === 'true',
      skip,
      take,
    };
  }, [searchParams]);

  const { data, isLoading, isFetching, isPlaceholderData, refetch } = useCertificates(query);
  const { data: templates } = useTemplates();
  // Label only. The server decides which certificates the "expiring" chip
  // returns, so this cannot drift the filter, only the caption on it.
  const warningDays = useExpiryWarningDays();
  const { data: syncStatus } = useSyncStatus();

  // Refresh = pull the inventory from the CA, then refetch. A failure surfaces
  // as a dismissible notice and in the header instead of being swallowed, and
  // never blocks the refetch of what is already local (issue #157).
  const { syncing, syncError, runSync, dismissSyncError } = useManualSync(refetch);

  // Update URL search params
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

  const handleSearch = useCallback(
    (value: string) => updateParams({ search: value || undefined, skip: undefined }),
    [updateParams]
  );

  const handleSort = useCallback(
    (column: string) => {
      const currentSort = query.sortBy;
      const currentDesc = query.sortDesc;

      if (currentSort === column) {
        // Toggle direction, then remove
        if (!currentDesc) {
          updateParams({ sortBy: column, sortDesc: 'true' });
        } else {
          updateParams({ sortBy: undefined, sortDesc: undefined });
        }
      } else {
        updateParams({ sortBy: column, sortDesc: undefined });
      }
    },
    [query.sortBy, query.sortDesc, updateParams]
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

  const handleTemplateFilter = useCallback(
    (template: string) => updateParams({ template: template || undefined, skip: undefined }),
    [updateParams]
  );

  // The chips and the dropdown are two controls over the same axis: a chip
  // pins a certificate status, the dropdown picks a request status. Each
  // clears the other, so the pair can never build a query that is empty by
  // construction (state=revoked plus status=Pending matches nothing).
  const handleStatusFilter = useCallback(
    (status: string) =>
      updateParams({ status: status || undefined, state: undefined, skip: undefined }),
    [updateParams]
  );

  const handleStateFilter = useCallback(
    (state: CertificateState | undefined) =>
      updateParams({ state, status: undefined, skip: undefined }),
    [updateParams]
  );

  const clearFilters = useCallback(
    () => setSearchParams({}),
    [setSearchParams]
  );

  const hasFilters =
    query.search || query.template || query.status || query.state ||
    query.expiringBefore || query.expiringAfter;

  // Names for the active filters, in the words the controls themselves use,
  // for the filtered empty state.
  const activeFilterLabels = useMemo(() => {
    const labels: string[] = [];
    if (query.search) labels.push(`search "${query.search}"`);
    if (query.template) labels.push(`template ${query.template}`);
    if (query.status) labels.push(`request state ${query.status}`);
    if (query.state) labels.push(STATE_LABELS[query.state]);
    if (query.expiringBefore) labels.push(`expiring before ${formatDate(query.expiringBefore)}`);
    if (query.expiringAfter) labels.push(`expiring after ${formatDate(query.expiringAfter)}`);
    return labels;
  }, [query]);

  // Which empty state the table shows (issue #157). The server does the
  // filtering, so with no filters a zero total means the inventory itself is
  // empty, and with filters it means the filters excluded everything. The two
  // states are mutually unreachable by construction. Placeholder data belongs
  // to the previous filter set (keepPreviousData), so it must not pick a
  // state for the current one: clearing a no match filter would otherwise
  // flash "No certificates in the inventory yet" over a populated inventory
  // until the unfiltered fetch lands.
  let emptyState: ReactNode | undefined;
  if (data && !isPlaceholderData) {
    if (data.totalCount === 0) {
      emptyState = hasFilters ? (
        <FilteredEmptyState filters={activeFilterLabels} onClear={clearFilters} />
      ) : (
        <InventoryEmptyState syncStatus={syncStatus} onSync={runSync} syncing={syncing} />
      );
    } else if (data.items.length === 0) {
      // A skip past the end of the list (hand edited URL, or the list shrank
      // since the link was made). Neither of the two states above applies.
      emptyState = <PastEndState onFirstPage={() => handlePageChange(0)} />;
    }
  }

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink">Certificates</h1>
          <HeaderSyncStatus lead="Full certificate inventory" />
        </div>
        <button
          onClick={runSync}
          disabled={syncing || isFetching}
          className="inline-flex items-center gap-2 px-3 py-2 border border-hairline-strong rounded-lg
                     text-sm font-medium text-ink-soft bg-surface hover:bg-sunken
                     disabled:opacity-50 transition-colors"
        >
          <RefreshCw className={`h-4 w-4 ${syncing || isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* A failed manual sync, with the problem detail and its remediation */}
      {syncError != null && (
        <SyncErrorNotice error={syncError} onDismiss={dismissSyncError} />
      )}

      {/* Lifecycle state chips */}
      <FilterChips value={query.state} onChange={handleStateFilter} warningDays={warningDays} />

      {/* Filters bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-[240px] max-w-md">
          <SearchBar
            value={query.search ?? ''}
            onChange={handleSearch}
            placeholder="Search by subject, serial, SAN..."
          />
        </div>

        {/* Template filter */}
        <select
          value={query.template ?? ''}
          onChange={(e) => handleTemplateFilter(e.target.value)}
          className="px-3 py-2 border border-hairline-strong rounded-lg text-sm bg-surface
                     focus:outline-none focus:ring-2 focus:ring-certus-500"
        >
          <option value="">All Templates</option>
          {templates?.map((t) => (
            <option key={t.oid || t.name} value={t.displayName || t.name}>
              {t.displayName || t.name}
            </option>
          ))}
        </select>

        {/* Request state filter. Issued and Revoked moved to the chips above,
            which say more precisely where in its life a certificate is; what is
            left here are the requests that never produced one. */}
        <select
          value={query.status ?? ''}
          onChange={(e) => handleStatusFilter(e.target.value)}
          aria-label="Filter by request state"
          className="px-3 py-2 border border-hairline-strong rounded-lg text-sm bg-surface
                     focus:outline-none focus:ring-2 focus:ring-certus-500"
        >
          <option value="">All Requests</option>
          <option value="Pending">Pending</option>
          <option value="Denied">Denied</option>
          <option value="Failed">Failed</option>
        </select>

        {hasFilters && (
          <button
            onClick={clearFilters}
            className="text-sm text-certus-600 hover:text-certus-800 dark:text-certus-300 font-medium"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <CertificateTable
        certificates={data?.items ?? []}
        sortBy={query.sortBy}
        sortDesc={query.sortDesc}
        onSort={handleSort}
        isLoading={isLoading}
        emptyState={emptyState}
      />

      {/* Pagination */}
      {data && (
        <Pagination
          skip={data.skip}
          take={data.take}
          totalCount={data.totalCount}
          onPageChange={handlePageChange}
          pageSizeOptions={PAGE_SIZE_OPTIONS}
          onPageSizeChange={handlePageSizeChange}
          pageSize={query.take}
        />
      )}
    </div>
  );
}

/**
 * Empty state for an over narrow filter: name the active filters in the words
 * the controls use, and offer the one action that resolves it (issue #157).
 */
function FilteredEmptyState({ filters, onClear }: { filters: string[]; onClear: () => void }) {
  return (
    <div className="space-y-3">
      <p className="font-medium text-ink-mid">No certificates match the active filters</p>
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

/**
 * Empty state for an inventory with nothing in it: say where the sync stands,
 * honestly (never a fabricated time), and offer the sync action (issue #157).
 */
function InventoryEmptyState({
  syncStatus,
  onSync,
  syncing,
}: {
  syncStatus: SyncStatus | undefined;
  onSync: () => void;
  syncing: boolean;
}) {
  let context = 'Nothing has been synced from the CA yet.';
  if (syncStatus?.failed && syncStatus.lastAttemptAt) {
    const kind =
      syncStatus.lastOutcome === 'caUnavailable' ? ' because the CA could not be reached'
      : syncStatus.lastOutcome === 'caAccessDenied' ? ' because the CA denied view access'
      : '';
    context = `The last sync attempt failed ${relativeTime(syncStatus.lastAttemptAt)}${kind}.`;
  } else if (syncStatus?.lastSuccess) {
    context = `Last synced ${relativeTime(syncStatus.lastSuccess.completedAtUtc)}; the CA returned no certificates.`;
  }

  return (
    <div className="space-y-3">
      <p className="font-medium text-ink-mid">No certificates in the inventory yet</p>
      <p className="text-sm">{context}</p>
      <button
        type="button"
        onClick={onSync}
        disabled={syncing}
        className="inline-flex items-center gap-2 px-3 py-2 border border-hairline-strong rounded-lg
                   text-sm font-medium text-ink-soft bg-surface hover:bg-sunken
                   disabled:opacity-50 transition-colors"
      >
        <RefreshCw className={`h-4 w-4 ${syncing ? 'animate-spin' : ''}`} />
        Sync now
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
