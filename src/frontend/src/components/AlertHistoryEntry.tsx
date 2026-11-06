import type { ReactNode } from 'react';
import { CheckCircle2, XCircle, AlertCircle, Clock, Minus } from 'lucide-react';
import type { AlertThresholdState, CertificateAlertThreshold } from '@/api/alerts';
import { formatDateTime } from '@/types';
import { describeChannelOutcome, type ChannelOutcome } from '@/lib/alerts';

/**
 * How one threshold reads. Every variant carries its own icon and its own words,
 * so the set stays distinguishable with no colour perception at all, the same
 * stance RenewalBadge takes.
 *
 * Only 'missing' is styled as a problem alongside 'failed'. A pending threshold
 * is the normal state of most of the ladder and must not read as an alarm, or
 * every healthy certificate looks broken.
 */
const outcomes: Record<
  AlertThresholdState,
  { label: string; badge: string; Icon: typeof CheckCircle2; iconClass: string }
> = {
  sent: {
    label: 'Sent',
    badge: 'bg-emerald-100 dark:bg-emerald-500/15 text-emerald-800 dark:text-emerald-300',
    Icon: CheckCircle2,
    iconClass: 'text-emerald-600',
  },
  failed: {
    label: 'Failed',
    badge: 'bg-red-100 dark:bg-red-500/15 text-red-800 dark:text-red-300',
    Icon: XCircle,
    iconClass: 'text-red-600',
  },
  missing: {
    label: 'Nothing recorded',
    badge: 'bg-amber-100 dark:bg-amber-500/15 text-amber-800 dark:text-amber-300',
    Icon: AlertCircle,
    iconClass: 'text-amber-600',
  },
  awaitingCheck: {
    label: 'Due, not checked yet',
    badge: 'bg-sunken-strong text-ink-soft',
    Icon: Clock,
    iconClass: 'text-faint',
  },
  pending: {
    label: 'Not due yet',
    badge: 'bg-sunken-strong text-ink-soft',
    Icon: Clock,
    iconClass: 'text-faint',
  },
  notApplicable: {
    label: 'Not scheduled',
    badge: 'bg-sunken-strong text-muted',
    Icon: Minus,
    // Fainter than `text-faint`, which the states above use. Expressed as an
    // opacity step rather than a lighter slate so the hierarchy survives the
    // theme flip: a literal slate-300 would render as the *brightest* icon in
    // the ladder on a dark page, inverting the meaning.
    iconClass: 'text-faint/60',
  },
};

/**
 * A failed row on which some channel still delivered (issue #206). Not a wire
 * state: the server reports 'failed', because a channel did fail. Amber rather
 * than red, so a webhook that broke beside an email that arrived does not read
 * as nobody being told.
 */
const partlySent = {
  label: 'Partly sent',
  badge: 'bg-amber-100 dark:bg-amber-500/15 text-amber-800 dark:text-amber-300',
  Icon: AlertCircle,
  iconClass: 'text-amber-600',
};

function outcomeFor(state: AlertThresholdState, partial: boolean) {
  if (partial && state === 'failed') return partlySent;
  return outcomes[state] ?? outcomes.notApplicable;
}

/** The outcome of one threshold, as a badge. Shared with the fleet wide list. */
export function AlertOutcomeBadge({
  state,
  partial = false,
}: {
  state: AlertThresholdState;
  /** True when a failed row still reached at least one channel. */
  partial?: boolean;
}) {
  const outcome = outcomeFor(state, partial);

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${outcome.badge}`}
    >
      {outcome.label}
    </span>
  );
}

/**
 * One rung of the alert ladder, rendered for both the per certificate block
 * (issue #160) and, via the certificate slot, a fleet wide list.
 *
 * Two wordings here are load bearing:
 *
 * A row says which channels delivered (issue #206), so an email that arrived
 * beside a webhook that 500'd reads as sent by email and failed by webhook, not
 * as nobody being told. A failed row written before that cannot say which
 * channel failed, so describeChannelOutcome keeps the old "at least one channel
 * failed" wording for it.
 *
 * And the expiry monitor's duplicate check does not filter on Success, so a
 * recorded failure permanently suppresses that threshold. A failed rung is a
 * hole that stays open, not a blip that the next pass sweeps up, and saying so
 * is the most useful sentence on the page.
 */
export function AlertHistoryEntry({
  entry,
  certificate,
}: {
  entry: CertificateAlertThreshold;
  /** Optional slot for a fleet wide list to name the certificate. */
  certificate?: ReactNode;
}) {
  const delivery =
    entry.state === 'sent' || entry.state === 'failed'
      ? describeChannelOutcome({
          channels: entry.channels,
          deliveredChannels: entry.deliveredChannels,
          success: entry.state === 'sent',
        })
      : null;
  const partial = delivery?.partial ?? false;
  const outcome = outcomeFor(entry.state, partial);
  const { Icon } = outcome;

  return (
    <li className="flex items-start gap-3 px-4 py-3">
      <Icon className={`h-4 w-4 mt-0.5 shrink-0 ${outcome.iconClass}`} aria-hidden="true" />

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-ink">
            {entry.thresholdDays} day warning
          </span>
          <AlertOutcomeBadge state={entry.state} partial={partial} />
          {certificate}
        </div>

        <p className="text-sm text-ink-mid mt-1">{timing(entry, delivery?.verb)}</p>

        {delivery && entry.channels && (
          <p className="text-sm text-ink-mid mt-1">{delivery.channels}</p>
        )}

        {entry.state === 'failed' && (
          <>
            {entry.errorMessage && (
              <p className="text-sm text-red-700 dark:text-red-300 mt-1 break-words whitespace-pre-line">
                {entry.errorMessage}
              </p>
            )}
            {delivery?.failure && (
              <p className="text-sm text-red-700 dark:text-red-300 mt-1">{delivery.failure}</p>
            )}
          </>
        )}

        {entry.state === 'missing' && (
          <p className="text-sm text-amber-800 dark:text-amber-300 mt-1">
            This warning came due and nothing was recorded, so nobody was told.
          </p>
        )}
      </div>
    </li>
  );
}

/**
 * How long after a threshold came due a send still counts as routine. The
 * monitor sweeps on an interval, so every alert lands somewhat after its
 * crossing and saying so every time is noise. Past a day the gap means
 * something: either the certificate was already inside the threshold when Ducks
 * first saw it, or the monitor was not running when it should have been.
 */
const NOTABLE_DELAY_MS = 24 * 60 * 60 * 1000;

/**
 * The one line about when.
 *
 * Only ever one labelled date, unless the send and the crossing are far enough
 * apart to be worth showing together. Two bare timestamps in a row read as a
 * rendering fault rather than as two different facts.
 */
function timing(entry: CertificateAlertThreshold, verb: ChannelOutcome['verb'] = 'Sent'): string {
  const due = formatDateTime(entry.dueAt);

  switch (entry.state) {
    case 'sent':
    case 'failed': {
      // Not "Attempted": the channel line below can carry that word, and the
      // two together read as a stutter. "Sent" when any channel delivered, so
      // a partial failure does not open with "Failed".
      if (!entry.sentAt) return `Came due ${due}.`;

      const late = new Date(entry.sentAt).getTime() - new Date(entry.dueAt).getTime();
      return late > NOTABLE_DELAY_MS
        ? `${verb} ${formatDateTime(entry.sentAt)}, for a warning that came due ${due}.`
        : `${verb} ${formatDateTime(entry.sentAt)}.`;
    }
    case 'missing':
      return `Came due ${due}.`;
    case 'awaitingCheck':
      return `Came due ${due}. The next check has not run yet.`;
    case 'pending':
      return `Due ${due}.`;
    default:
      return `Would have come due ${due}.`;
  }
}
