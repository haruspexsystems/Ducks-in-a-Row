import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  FlaskConical,
  HelpCircle,
  Info,
  Loader2,
  MinusCircle,
  RefreshCw,
  XCircle,
} from 'lucide-react';
import {
  checkSetupServiceRights,
  type RightsGroup,
  type ServiceRightsReport,
  type ServiceRightsRow,
} from '@/api/serviceRights';
import { neededForText, rowsIn, statusLabel, statusPresentation } from '@/lib/serviceRights';

/**
 * The service rights check (issue #440): what this server's own account may do
 * on the CA and on each template, as the service itself found it.
 *
 * The icons follow the template checklist's, with one deliberate difference:
 * an Inferred row, read from a permission list or reported by the CA, gets an
 * information icon and never the green check. Only an exercised right is shown
 * as a pass.
 */
export function StatusIcon({ row }: { row: ServiceRightsRow }) {
  switch (statusPresentation(row.status).tone) {
    case 'pass':
      return <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 shrink-0" aria-hidden="true" />;
    case 'reading':
      return <Info className="h-4 w-4 text-sky-500 mt-0.5 shrink-0" aria-hidden="true" />;
    case 'fail':
      return row.optional
        ? <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" aria-hidden="true" />
        : <XCircle className="h-4 w-4 text-red-600 mt-0.5 shrink-0" aria-hidden="true" />;
    case 'skipped':
      return <MinusCircle className="h-4 w-4 text-faint mt-0.5 shrink-0" aria-hidden="true" />;
    default:
      // Fainter than text-faint as an opacity step, as the template checklist
      // does, so "not proven" reads as de-emphasised in both themes.
      return <HelpCircle className="h-4 w-4 text-faint/60 mt-0.5 shrink-0" aria-hidden="true" />;
  }
}

function StatusWord({ row }: { row: ServiceRightsRow }) {
  const tone = statusPresentation(row.status).tone;
  const colours: Record<string, string> = {
    pass: 'text-emerald-700 dark:text-emerald-300',
    reading: 'text-sky-700 dark:text-sky-300',
    fail: row.optional ? 'text-amber-700 dark:text-amber-300' : 'text-red-700 dark:text-red-300',
    skipped: 'text-faint',
    unknown: 'text-muted',
  };
  return (
    <span className={`text-[11px] font-semibold uppercase tracking-wide ${colours[tone]}`}>
      {statusLabel(row)}
    </span>
  );
}

/** Whose rights these are: the check never runs as the administrator at the browser. */
function IdentityLine({ report }: { report: ServiceRightsReport }) {
  const account = report.identity.accountName ?? report.identity.processIdentity;
  return (
    <p className="text-xs text-muted">
      Checked as <span className="font-mono text-ink-soft">{account}</span>
      {report.identity.isMachineIdentity ? ", this server's computer account, which is what the CA sees." : '.'}
    </p>
  );
}

export function ServiceRightsReportView({
  report,
  groups,
}: {
  report: ServiceRightsReport;
  groups?: RightsGroup[];
}) {
  const rows = rowsIn(report, groups);
  return (
    <div className="space-y-3">
      <IdentityLine report={report} />
      {report.simulated && (
        <div className="flex items-start gap-2 rounded-lg border border-hairline bg-sunken p-2.5">
          <FlaskConical className="h-4 w-4 text-faint mt-0.5 shrink-0" />
          <p className="text-xs text-muted">
            Simulated: the demo CA answers for an example estate, so these results say nothing about a real CA.
          </p>
        </div>
      )}
      <ul className="divide-y divide-hairline-soft">
        {rows.map((row) => (
          <li key={row.id} className="flex items-start gap-2.5 py-2.5">
            <StatusIcon row={row} />
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <p className="text-sm font-medium text-ink">{row.title}</p>
                <StatusWord row={row} />
              </div>
              <p className="text-xs text-muted">{row.detail}</p>
              {row.remedy && (
                <p className="text-xs text-ink-soft">
                  <span className="font-semibold">What to ask for: </span>
                  {row.remedy}
                </p>
              )}
              {row.neededFor.length > 0 && (
                <p className="text-[11px] text-faint">{neededForText(row.neededFor)}.</p>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The wizard's panel: runs the check against the candidate CA and the given
 * templates, and shows the rows of the given groups. It never blocks anything;
 * `onReport` hands the result, or null when the check could
 * not be loaded, to a step that needs to know.
 */
export function ServiceRightsPanel({
  caConnectionString,
  templates,
  groups,
  onReport,
}: {
  caConnectionString: string;
  templates: string[];
  groups?: RightsGroup[];
  onReport?: (report: ServiceRightsReport | null) => void;
}) {
  const { data, isFetching, error, refetch } = useQuery({
    queryKey: ['setup', 'service-rights', caConnectionString, templates.join('|')],
    queryFn: () => checkSetupServiceRights(caConnectionString, templates),
    // A check reads from the CA and the directory, so it runs when the panel
    // appears and when asked again, never on a timer or a window focus.
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    retry: false,
  });

  useEffect(() => {
    if (!onReport || isFetching) return;
    onReport(error ? null : data ?? null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, error, isFetching]);

  return (
    <div className="bg-surface border border-hairline rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-ink">Service rights on the CA</h3>
        <button
          type="button"
          onClick={() => void refetch()}
          disabled={isFetching}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-ink-soft
                     border border-hairline-strong rounded-lg hover:bg-sunken disabled:opacity-50 transition-colors"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
          Check again
        </button>
      </div>

      {isFetching && !data && (
        <div className="flex items-center gap-2 text-sm text-muted py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Asking the CA and the directory what this server's account may do…
        </div>
      )}

      {!isFetching && error != null && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
          <p className="text-xs text-red-700 dark:text-red-300">
            The rights check could not run: {error instanceof Error ? error.message : 'unknown error'}.
            Nothing below is known, so treat every right as unproven.
          </p>
        </div>
      )}

      {data && <ServiceRightsReportView report={data} groups={groups} />}
    </div>
  );
}
