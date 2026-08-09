import { BellRing } from 'lucide-react';
import type { AlertCoverage, CertificateAlertHistory as History } from '@/api/alerts';
import { useCertificateAlerts } from '@/hooks/useCertificateAlerts';
import { AlertHistoryEntry } from './AlertHistoryEntry';

/**
 * Whether anybody was told this certificate is expiring (issue #160).
 *
 * The whole configured threshold ladder, not just the alerts that happen to
 * exist. A list of what exists cannot show the case that matters: a certificate
 * five days from expiry should have warned at 30, 14 and 7, and if the service
 * was down across the last two crossings, the 30 day row alone still reads as
 * healthy while two warnings were silently skipped.
 *
 * The coverage line above the ladder answers the other half. A certificate with
 * no alerts is not evidence of a problem on its own, and the four reasons it can
 * legitimately have none are indistinguishable from the rows alone.
 */
export function CertificateAlertHistory({ certificateId }: { certificateId: number }) {
  const { data, isLoading, error } = useCertificateAlerts(certificateId);

  return (
    <div className="bg-surface border border-hairline rounded-lg">
      <div className="px-4 py-3 border-b border-hairline-soft flex items-center gap-2">
        <BellRing className="h-4 w-4 text-faint" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-ink">Expiry warnings</h2>
      </div>

      {isLoading && (
        <p className="px-4 py-3 text-sm text-faint">Loading expiry warnings...</p>
      )}

      {/* Said plainly rather than swallowed. An empty block here is exactly the
          "nothing has been sent" answer, and a failed request must never be
          mistaken for one. */}
      {error && (
        <p className="px-4 py-3 text-sm text-red-600">
          The alert history could not be loaded, so this is not a statement that
          no warnings were sent.
        </p>
      )}

      {data && <Body history={data} />}
    </div>
  );
}

function Body({ history }: { history: History }) {
  const { tone, text } = coverageNote(history);

  // Named here rather than inside each failed entry, because it is the ladder
  // that knows what is left, not the rung that failed.
  const remaining = history.thresholds
    .filter((t) => t.state === 'pending')
    .map((t) => t.thresholdDays);
  const anyFailed = history.thresholds.some((t) => t.state === 'failed');

  return (
    <>
      <div className={`px-4 py-3 text-sm border-b border-hairline-soft ${tone}`}>
        <p>{text}</p>
        {anyFailed && <p className="mt-1">{whatIsLeft(remaining)}</p>}
      </div>

      {history.thresholds.length === 0 ? (
        <p className="px-4 py-3 text-sm text-muted">
          No expiry thresholds are configured, so no warnings are scheduled.
        </p>
      ) : (
        <ul className="divide-y divide-hairline-soft">
          {history.thresholds.map((entry) => (
            <AlertHistoryEntry key={entry.thresholdDays} entry={entry} />
          ))}
        </ul>
      )}
    </>
  );
}

/**
 * What a failure does and does not cost, said once for the whole ladder. Shown
 * only alongside a failure, because a recorded failure is permanent: the expiry
 * monitor's duplicate check ignores the success flag, so that rung will not fire
 * again and the warnings still ahead are all the operator has left.
 */
function whatIsLeft(remaining: number[]): string {
  if (remaining.length === 0) {
    return 'No further warnings are scheduled for this certificate.';
  }

  const days = remaining.join(', ');
  return remaining.length === 1
    ? `The remaining warning at ${days} ${remaining[0] === 1 ? 'day' : 'days'} is unaffected and will still be sent.`
    : `The remaining warnings at ${days} days are unaffected and will still be sent.`;
}

/**
 * One sentence saying whether this certificate is being watched at all, and if
 * not, why.
 *
 * noChannelsConfigured is the one worth reading twice. Monitoring switched on
 * with no recipient and no webhook produces no delivery and no recorded row, so
 * it is indistinguishable from a healthy quiet install by looking at the alert
 * table. It gets amber, not neutral.
 */
function coverageNote(history: History): { tone: string; text: string } {
  const neutral = 'bg-sunken text-ink-mid';
  const warn = 'bg-amber-50 dark:bg-amber-500/10 text-amber-900 dark:text-amber-200';

  const channels = history.enabledChannels.join(', ');

  const notes: Record<AlertCoverage, { tone: string; text: string }> = {
    monitored: {
      tone: neutral,
      text: `Ducks is watching this certificate and warns over ${channels}, checking every ${history.checkIntervalMinutes} minutes.`,
    },
    alertingDisabled: {
      tone: warn,
      text: 'Expiry monitoring is switched off, so no warnings are sent for any certificate. Nothing below was missed, because nothing is being watched.',
    },
    noChannelsConfigured: {
      tone: warn,
      text: 'Expiry monitoring is on, but no email recipient and no webhook is configured. Nothing is delivered and nothing is recorded, so an install in this state looks exactly like one where no certificate has needed a warning yet.',
    },
    revoked: {
      tone: neutral,
      text: 'This certificate is revoked, so Ducks no longer warns about it expiring. Any warnings sent before it was revoked are kept below.',
    },
    notIssued: {
      tone: neutral,
      text: 'This request never became a certificate, so there is nothing to warn about.',
    },
    alreadyExpired: {
      tone: neutral,
      text: 'This certificate has already expired. Ducks warns before expiry and does not keep nagging afterwards, so any warnings it did send are below.',
    },
    ownCertificate: {
      tone: neutral,
      text: 'This is the certificate Ducks serves its own web interface with. Automatic renewal owns it, and it speaks up only if a renewal fails, so no expiry warnings are scheduled here.',
    },
  };

  return notes[history.coverage] ?? { tone: neutral, text: '' };
}
