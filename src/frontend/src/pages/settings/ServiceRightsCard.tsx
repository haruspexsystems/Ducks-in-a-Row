import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, KeyRound, Loader2, RefreshCw } from 'lucide-react';
import { ApiError } from '@/api/client';
import { fetchServiceRights, recheckServiceRights } from '@/api/serviceRights';
import { ServiceRightsReportView } from '@/components/ServiceRightsReport';

/**
 * Settings card with the service rights check for the configured CA and the
 * templates enabled for ACME (issue #440). The wizard proves the rights before
 * first use and never reopens; rights change afterwards, so this is where an
 * administrator looks again.
 *
 * Opening the page serves the kept report while it is fresh, because every
 * check reads from the CA and the directory. "Check again" always runs one.
 */
export function ServiceRightsCard() {
  const queryClient = useQueryClient();
  const queryKey = ['settings', 'service-rights'];

  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: fetchServiceRights,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  });

  const recheck = useMutation({
    mutationFn: recheckServiceRights,
    onSuccess: (report) => queryClient.setQueryData(queryKey, report),
  });

  const unconfigured = error instanceof ApiError && error.status === 409;
  const failure = recheck.error ?? (unconfigured ? null : error);

  return (
    <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-certus-600" />
          <h3 className="text-sm font-semibold text-ink">Service rights on the CA</h3>
        </div>
        {!unconfigured && (
          <button
            type="button"
            onClick={() => recheck.mutate()}
            disabled={recheck.isPending || isLoading}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-ink-soft
                       border border-hairline-strong rounded-lg hover:bg-sunken disabled:opacity-50 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${recheck.isPending ? 'animate-spin' : ''}`} />
            Check again
          </button>
        )}
      </div>
      <p className="text-sm text-muted">
        What this server's account may do on the CA and on each template enabled for ACME,
        as the service itself found it. Proven means the right was used and worked; Inferred
        means it was read from a permission list or reported by the CA, and has not been used yet.
      </p>

      {(isLoading || recheck.isPending) && !data && (
        <div className="flex items-center gap-2 text-sm text-faint py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Checking…
        </div>
      )}

      {unconfigured && (
        <p className="text-xs text-muted">No CA is configured yet. Complete the setup wizard first.</p>
      )}

      {failure != null && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
          <p className="text-xs text-red-700 dark:text-red-300">
            The rights check could not run. Check the service log.
          </p>
        </div>
      )}

      {data && (
        <>
          <ServiceRightsReportView report={data} />
          <p className="text-xs text-faint border-t border-hairline-soft pt-3">
            Checked {new Date(data.checkedAt).toLocaleString()}
          </p>
        </>
      )}
    </div>
  );
}
