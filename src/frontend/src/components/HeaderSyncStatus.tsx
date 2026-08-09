import type { ReactNode } from 'react';
import { useSyncStatus } from '@/hooks/useSyncStatus';
import { relativeTime } from '@/types';

/**
 * Page header subtitle with sync context (issue #157): which CA the inventory
 * comes from, and how the most recent sync went. Self contained and degrading
 * on purpose: while the status query has no data the line falls back to a
 * plain "{lead} from your ADCS CA" with no sync phrase, so a failing status
 * endpoint can never blank or distort a page. The mock CA is named in plain
 * text here; the amber banner in the layout stays the single warning about it.
 */
export function HeaderSyncStatus({ lead }: { lead: string }) {
  const { data: status } = useSyncStatus();

  const caLabel =
    status === undefined ? 'your ADCS CA'
    : status.caMode === 'mock' ? 'the mock CA'
    : status.caMode === 'unconfigured' ? 'no connected CA'
    : status.caName ?? 'your ADCS CA';

  // Omitted entirely while the status is unknown; never a fabricated time.
  let syncPhrase: ReactNode = null;
  if (status) {
    if (status.failed && status.lastAttemptAt) {
      syncPhrase = (
        <span className="text-red-600" title={status.lastMessage ?? undefined}>
          Sync failed {relativeTime(status.lastAttemptAt)}
          {status.lastSuccess && (
            <> (last good sync {relativeTime(status.lastSuccess.completedAtUtc)})</>
          )}
        </span>
      );
    } else if (status.lastSuccess) {
      syncPhrase = <span>Synced {relativeTime(status.lastSuccess.completedAtUtc)}</span>;
    } else {
      syncPhrase = <span>Not synced yet</span>;
    }
  }

  return (
    <p className="text-sm text-muted mt-1">
      {lead} from {caLabel}
      {syncPhrase && <> · {syncPhrase}</>}
    </p>
  );
}
