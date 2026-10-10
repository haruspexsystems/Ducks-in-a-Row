import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Loader2, ShieldAlert } from 'lucide-react';
import {
  fetchCrlStatus,
  type CrlSourceStatus,
  type CrlStatusGroup,
} from '@/api/settings';
import { extractCN } from '@/types';

/**
 * Settings card showing every certificate revocation list the product watches
 * (issue #447).
 *
 * A CRL expiring is not like a certificate expiring: it breaks revocation
 * checking for everything its CA ever signed, at once, and for an offline root
 * nothing automatic replaces it. So the card leads with when each one expires
 * and shows every place it is published, because the copies can disagree and
 * that disagreement is the commonest way a root CRL renewal goes wrong.
 *
 * It reads stored state. The monitor does the fetching on its own timer, so
 * opening this page costs nothing at the CA or at a distribution point.
 */
export function CrlStatusCard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['settings', 'crl-status'],
    queryFn: fetchCrlStatus,
    staleTime: 60_000,
    retry: false,
  });

  return (
    <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-ink">Revocation lists</h3>
      </div>
      <p className="text-sm text-muted">
        Every certificate revocation list in the chain of the connected CA,
        including the ones published by a CA above it. When one of these
        expires, every certificate that CA ever signed stops validating on
        clients that check revocation.
      </p>

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-faint py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading revocation list status…
        </div>
      )}

      {!isLoading && error != null && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">
            The revocation list status could not be loaded. Check the service log.
          </p>
        </div>
      )}

      {!isLoading && !error && data && data.crls.length === 0 && (
        <p className="text-xs text-muted">
          Nothing has been read yet. The first check runs shortly after the
          service starts.
        </p>
      )}

      {!isLoading && !error && data && data.crls.length > 0 && (
        <>
          <ul className="divide-y divide-hairline-soft">
            {data.crls.map((group) => (
              <CrlGroupRow
                key={`${group.scope}-${group.issuerName}-${group.kind}`}
                group={group}
              />
            ))}
          </ul>
          {data.lastCheckedAt && (
            <p className="text-xs text-faint border-t border-hairline-soft pt-3">
              Last checked {new Date(data.lastCheckedAt).toLocaleString()}
            </p>
          )}
        </>
      )}
    </div>
  );
}

function CrlGroupRow({ group }: { group: CrlStatusGroup }) {
  return (
    <li className="py-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-ink truncate">
          {extractCN(group.issuerName)}
        </span>
        <span className="text-[10px] font-semibold uppercase tracking-wide border rounded px-1.5 py-0.5 bg-sunken text-ink-mid border-hairline">
          {group.kind === 'delta' ? 'Delta CRL' : 'Base CRL'}
        </span>
        {group.scope === 'parent' && (
          <span className="text-[10px] font-semibold uppercase tracking-wide border rounded px-1.5 py-0.5 bg-certus-50 dark:bg-certus-500/10 text-certus-700 dark:text-certus-300 border-certus-200 dark:border-certus-500/30">
            Published by hand
          </span>
        )}
      </div>

      <ul className="space-y-1">
        {group.sources.map((source) => (
          <SourceRow key={source.source} source={source} autoPublished={group.autoPublished} />
        ))}
      </ul>
    </li>
  );
}

function SourceRow({
  source,
  autoPublished,
}: {
  source: CrlSourceStatus;
  autoPublished: boolean;
}) {
  const state = describe(source, autoPublished);

  return (
    <li className="text-xs flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
      <span className={`font-medium ${state.classes}`}>{state.label}</span>
      <span className="text-muted font-mono truncate max-w-full">
        {source.source === 'ca' ? 'the certificate authority' : source.source}
      </span>
      {source.crlNumber && <span className="text-faint">number {source.crlNumber}</span>}
      {source.signatureStatus === 'unsupported' && (
        <span className="text-faint">signature not verified</span>
      )}
      {source.lastError && <span className="text-faint truncate">{source.lastError}</span>}
    </li>
  );
}

/**
 * What to say about one copy. The thresholds are the ones the alert rules use
 * in spirit rather than in fact: this is a colour on a page, and an operator
 * reading it wants to know which copy to look at first.
 */
function describe(
  source: CrlSourceStatus,
  autoPublished: boolean,
): { label: string; classes: string } {
  const red = 'text-red-600 dark:text-red-400';
  const amber = 'text-amber-600 dark:text-amber-400';
  const green = 'text-emerald-600 dark:text-emerald-400';
  const grey = 'text-faint';

  if (!source.nextUpdate) {
    return source.lastError
      ? { label: 'Not readable', classes: red }
      : { label: 'Never read', classes: grey };
  }

  const hours = (new Date(source.nextUpdate).getTime() - Date.now()) / 3_600_000;
  if (hours <= 0) return { label: 'Expired', classes: red };
  if (hours <= 24) return { label: `Expires in ${Math.floor(hours)} h`, classes: red };

  const days = Math.floor(hours / 24);
  // A CA replaces its own CRL on a timer, so days in hand mean nothing until
  // the timer is missed. A CRL somebody publishes by hand is the opposite.
  if (autoPublished) {
    const overdue =
      source.nextPublish != null && new Date(source.nextPublish).getTime() < Date.now();
    return overdue
      ? { label: `Not replaced on schedule, expires in ${days} d`, classes: amber }
      : { label: `Current, expires in ${days} d`, classes: green };
  }

  if (days <= 30) return { label: `Expires in ${days} d`, classes: amber };
  return { label: `Expires in ${days} d`, classes: green };
}
