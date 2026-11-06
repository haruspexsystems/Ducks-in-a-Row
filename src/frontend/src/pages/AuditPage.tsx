import { useCallback, useMemo, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { ShieldAlert, ScrollText } from 'lucide-react';
import { fetchAuditActors, fetchAuditEntries, fetchSignInFailures } from '@/api/audit';
import { ApiErrorNotice } from '@/components/ApiErrorNotice';
import { Pagination } from '@/components/Pagination';
import { describeAction, describeChange, describeSignInFailures } from '@/lib/audit';
import { formatDateTime } from '@/types';

/** The page sizes the selector offers; anything else in the URL reads as the default. */
const PAGE_SIZE_OPTIONS = [25, 50, 100, 200];
const DEFAULT_PAGE_SIZE = 50;

/** The windows the refused sign ins card offers. */
const WINDOW_OPTIONS = [1, 7, 30, 90];
const DEFAULT_WINDOW_DAYS = 30;

/**
 * The administrator audit trail (issue #634): who changed what, and when,
 * plus the refused sign ins the server counted. Read only: the server has no
 * route that edits or deletes a row, so this page offers none either. The
 * actor filter and the page live in the URL, so a view is a link that can be
 * pasted into a ticket.
 */
export function AuditPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  const query = useMemo(() => {
    const skipRaw = Number(searchParams.get('skip'));
    const takeRaw = Number(searchParams.get('take'));
    const daysRaw = Number(searchParams.get('days'));
    return {
      actor: searchParams.get('actor') ?? '',
      skip: Number.isFinite(skipRaw) && skipRaw > 0 ? Math.floor(skipRaw) : 0,
      take: PAGE_SIZE_OPTIONS.includes(takeRaw) ? takeRaw : DEFAULT_PAGE_SIZE,
      days: WINDOW_OPTIONS.includes(daysRaw) ? daysRaw : DEFAULT_WINDOW_DAYS,
    };
  }, [searchParams]);

  const updateParams = useCallback(
    (updates: Record<string, string | undefined>) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        for (const [key, value] of Object.entries(updates)) {
          if (value === undefined || value === '') next.delete(key);
          else next.set(key, value);
        }
        return next;
      });
    },
    [setSearchParams],
  );

  const entries = useQuery({
    queryKey: ['audit', 'entries', query.actor, query.skip, query.take],
    queryFn: () => fetchAuditEntries({ actor: query.actor || undefined, skip: query.skip, take: query.take }),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
    retry: false,
  });

  const actors = useQuery({
    queryKey: ['audit', 'actors'],
    queryFn: fetchAuditActors,
    staleTime: 60_000,
    retry: false,
  });

  const failures = useQuery({
    queryKey: ['audit', 'sign-in-failures', query.days],
    queryFn: () => fetchSignInFailures(query.days),
    staleTime: 30_000,
    retry: false,
  });

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-ink">Audit</h1>
        <p className="text-sm text-muted mt-1">
          Every administrator action, with the value before and after, and the sign ins the
          server refused. The trail cannot be edited or turned off; it is kept for the
          retention period and removed only by the daily retention pass.
        </p>
      </div>

      <section className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-muted" />
            <h2 className="text-lg font-semibold text-ink">Refused sign ins</h2>
          </div>
          <label className="flex items-center gap-2 text-sm text-muted">
            Window
            <select
              value={query.days}
              onChange={(e) => updateParams({ days: e.target.value })}
              className="px-2 py-1.5 border border-hairline-strong rounded-md text-sm bg-surface text-ink
                         focus:outline-none focus:ring-2 focus:ring-certus-500"
            >
              {WINDOW_OPTIONS.map((d) => (
                <option key={d} value={d}>
                  {d === 1 ? 'Last day' : `Last ${d} days`}
                </option>
              ))}
            </select>
          </label>
        </div>

        {failures.isError ? (
          <ApiErrorNotice error={failures.error} title="Failed to load refused sign ins" />
        ) : failures.data ? (
          <>
            <p className="text-sm text-ink" data-testid="sign-in-failures-summary">
              {describeSignInFailures(failures.data.total, failures.data.sources.length, failures.data.days)}
            </p>
            {failures.data.sources.length > 0 && (
              <div className="overflow-x-auto border border-hairline rounded-lg">
                <table className="min-w-full divide-y divide-hairline text-sm">
                  <thead className="bg-sunken">
                    <tr>
                      <Th>Source address</Th>
                      <Th align="right">Refused</Th>
                      <Th align="right">Credentials refused</Th>
                      <Th align="right">Not an administrator</Th>
                      <Th>First</Th>
                      <Th>Last</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-hairline-soft">
                    {failures.data.sources.map((s) => (
                      <tr key={s.sourceAddress} className="hover:bg-sunken transition-colors">
                        <td className="px-4 py-2 md-mono text-ink">{s.sourceAddress}</td>
                        <td className="px-4 py-2 text-right tabular-nums text-ink">{s.count}</td>
                        <td className="px-4 py-2 text-right tabular-nums text-ink-soft">{s.unauthorized}</td>
                        <td className="px-4 py-2 text-right tabular-nums text-ink-soft">{s.forbidden}</td>
                        <td className="px-4 py-2 text-muted whitespace-nowrap">{formatDateTime(s.firstAt)}</td>
                        <td className="px-4 py-2 text-muted whitespace-nowrap">{formatDateTime(s.lastAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="text-xs text-faint">
              A refused credential is a 401 after the browser offered one; not an administrator is a
              signed in account outside the admin group. Counts are per source address and hour, so a
              repeated attempt grows a count rather than the table.
            </p>
          </>
        ) : (
          <p className="text-sm text-faint">Loading refused sign ins...</p>
        )}
      </section>

      <section className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <ScrollText className="h-5 w-5 text-muted" />
            <h2 className="text-lg font-semibold text-ink">Administrator actions</h2>
          </div>
          <label className="flex items-center gap-2 text-sm text-muted">
            Actor
            <select
              value={query.actor}
              onChange={(e) => updateParams({ actor: e.target.value, skip: undefined })}
              aria-label="Filter by actor"
              className="px-2 py-1.5 border border-hairline-strong rounded-md text-sm bg-surface text-ink
                         focus:outline-none focus:ring-2 focus:ring-certus-500"
            >
              <option value="">All actors</option>
              {(actors.data ?? []).map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </label>
        </div>

        {entries.isError ? (
          <ApiErrorNotice error={entries.error} title="Failed to load the audit trail" />
        ) : (
          <>
            <div className={`overflow-x-auto border border-hairline rounded-lg ${entries.isPlaceholderData ? 'opacity-60' : ''}`}>
              <table className="min-w-full divide-y divide-hairline text-sm">
                <thead className="bg-sunken">
                  <tr>
                    <Th>When</Th>
                    <Th>Actor</Th>
                    <Th>Action</Th>
                    <Th>Target</Th>
                    <Th>Change</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline-soft">
                  {entries.isLoading ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-12 text-center text-faint">Loading the audit trail...</td>
                    </tr>
                  ) : (entries.data?.items.length ?? 0) === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-12 text-center text-faint">
                        {query.actor ? 'No actions by this actor.' : 'No administrator actions recorded yet.'}
                      </td>
                    </tr>
                  ) : (
                    entries.data!.items.map((e) => (
                      <tr key={e.id} className="hover:bg-sunken transition-colors align-top">
                        <td className="px-4 py-2 text-muted whitespace-nowrap">{formatDateTime(e.occurredAt)}</td>
                        <td className="px-4 py-2 text-ink whitespace-nowrap">{e.actor}</td>
                        <td className="px-4 py-2 text-ink" title={e.action}>{describeAction(e.action)}</td>
                        <td className="px-4 py-2 text-ink-soft break-words max-w-xs">{e.target ?? '—'}</td>
                        <td className="px-4 py-2 text-ink-soft break-words max-w-xl">{describeChange(e.before, e.after)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            {entries.data && (
              <Pagination
                skip={entries.data.skip}
                take={entries.data.take}
                totalCount={entries.data.totalCount}
                onPageChange={(skip) => updateParams({ skip: skip > 0 ? String(skip) : undefined })}
                itemsLabel="actions"
                pageSizeOptions={PAGE_SIZE_OPTIONS}
                pageSize={query.take}
                onPageSizeChange={(take) => updateParams({ take: String(take), skip: undefined })}
              />
            )}
          </>
        )}
      </section>
    </div>
  );
}

function Th({ children, align }: { children: ReactNode; align?: 'right' }) {
  return (
    <th
      scope="col"
      className={`px-4 py-2.5 text-xs font-semibold uppercase tracking-wide text-muted ${
        align === 'right' ? 'text-right' : 'text-left'
      }`}
    >
      {children}
    </th>
  );
}
