import { useCallback, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import { triggerSync } from '@/api/client';
import { useCertificates, useTemplates } from '@/hooks/useCertificates';
import type { CertificateQuery } from '@/types';
import { CertificateTable } from '@/components/CertificateTable';
import { SearchBar } from '@/components/SearchBar';
import { Pagination } from '@/components/Pagination';

const PAGE_SIZE = 25;

export function CertificateListPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  // Parse query params into typed object
  const query: CertificateQuery = useMemo(() => {
    // Guard against a hand edited, non numeric skip so we never send skip=NaN.
    const skipRaw = Number(searchParams.get('skip'));
    const skip = Number.isFinite(skipRaw) && skipRaw > 0 ? Math.floor(skipRaw) : 0;
    return {
      search: searchParams.get('search') ?? undefined,
      template: searchParams.get('template') ?? undefined,
      status: searchParams.get('status') ?? undefined,
      expiringBefore: searchParams.get('expiringBefore') ?? undefined,
      expiringAfter: searchParams.get('expiringAfter') ?? undefined,
      sortBy: searchParams.get('sortBy') ?? undefined,
      sortDesc: searchParams.get('sortDesc') === 'true',
      skip,
      take: PAGE_SIZE,
    };
  }, [searchParams]);

  const { data, isLoading, isFetching, refetch } = useCertificates(query);
  const { data: templates } = useTemplates();
  const [syncing, setSyncing] = useState(false);

  // Refresh = pull the inventory from the CA, then refetch. A sync failure
  // (CA unreachable) must not block the refetch of what is already local.
  const handleRefresh = useCallback(async () => {
    setSyncing(true);
    try {
      await triggerSync();
    } catch {
      // Sync errors surface in the service log; still refetch below.
    } finally {
      setSyncing(false);
    }
    refetch();
  }, [refetch]);

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

  const handleTemplateFilter = useCallback(
    (template: string) => updateParams({ template: template || undefined, skip: undefined }),
    [updateParams]
  );

  const handleStatusFilter = useCallback(
    (status: string) => updateParams({ status: status || undefined, skip: undefined }),
    [updateParams]
  );

  const clearFilters = useCallback(
    () => setSearchParams({}),
    [setSearchParams]
  );

  const hasFilters =
    query.search || query.template || query.status || query.expiringBefore || query.expiringAfter;

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Certificates</h1>
          <p className="text-sm text-slate-500 mt-1">
            Full certificate inventory synced from your ADCS CA
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={syncing || isFetching}
          className="inline-flex items-center gap-2 px-3 py-2 border border-slate-300 rounded-lg
                     text-sm font-medium text-slate-700 bg-white hover:bg-slate-50
                     disabled:opacity-50 transition-colors"
        >
          <RefreshCw className={`h-4 w-4 ${syncing || isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

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
          className="px-3 py-2 border border-slate-300 rounded-lg text-sm bg-white
                     focus:outline-none focus:ring-2 focus:ring-certus-500"
        >
          <option value="">All Templates</option>
          {templates?.map((t) => (
            <option key={t.oid || t.name} value={t.displayName || t.name}>
              {t.displayName || t.name}
            </option>
          ))}
        </select>

        {/* Status filter */}
        <select
          value={query.status ?? ''}
          onChange={(e) => handleStatusFilter(e.target.value)}
          className="px-3 py-2 border border-slate-300 rounded-lg text-sm bg-white
                     focus:outline-none focus:ring-2 focus:ring-certus-500"
        >
          <option value="">All Statuses</option>
          <option value="Issued">Issued</option>
          <option value="Revoked">Revoked</option>
          <option value="Pending">Pending</option>
          <option value="Denied">Denied</option>
          <option value="Failed">Failed</option>
        </select>

        {hasFilters && (
          <button
            onClick={clearFilters}
            className="text-sm text-certus-600 hover:text-certus-800 font-medium"
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
      />

      {/* Pagination */}
      {data && (
        <Pagination
          skip={data.skip}
          take={data.take}
          totalCount={data.totalCount}
          onPageChange={handlePageChange}
        />
      )}
    </div>
  );
}
