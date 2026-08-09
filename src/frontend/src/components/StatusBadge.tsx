import { Link } from 'react-router-dom';
import { Bot, Wrench } from 'lucide-react';
import type { CertStatus, ExpiryState } from '@/types';
import { getExpiryState } from '@/types';
import { useExpiryWarningDays } from '@/hooks/useExpiryWarningDays';

interface StatusBadgeProps {
  status: string;
}

const statusColors: Record<CertStatus, string> = {
  Issued: 'bg-emerald-100 dark:bg-emerald-500/15 text-emerald-800 dark:text-emerald-300',
  Revoked: 'bg-violet-100 dark:bg-violet-500/15 text-violet-800 dark:text-violet-300',
  Pending: 'bg-sunken-strong text-ink-strong',
  Denied: 'bg-red-100 dark:bg-red-500/15 text-red-800 dark:text-red-300',
  Failed: 'bg-red-100 dark:bg-red-500/15 text-red-800 dark:text-red-300',
};

const expiryColors: Record<ExpiryState, string> = {
  valid: '',
  'expiring-soon': 'bg-amber-100 dark:bg-amber-500/15 text-amber-800 dark:text-amber-300',
  expired: 'bg-red-100 dark:bg-red-500/15 text-red-800 dark:text-red-300',
};

export function StatusBadge({ status }: StatusBadgeProps) {
  const colorClass = statusColors[status as CertStatus] ?? 'bg-sunken-strong text-ink-strong';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
      {status}
    </span>
  );
}

export function ExpiryBadge({ notAfter }: { notAfter: string }) {
  const state = getExpiryState(notAfter, useExpiryWarningDays());

  if (state === 'valid') return null;

  const label = state === 'expired' ? 'Expired' : 'Expiring Soon';
  const colorClass = expiryColors[state];

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
      {label}
    </span>
  );
}

/**
 * Whether an ACME client is expected to renew this certificate, or whether
 * renewal is somebody's job to remember. One of those is handled and the other
 * is a future outage with a date on it, and the list otherwise shows them
 * identically.
 *
 * Callers guard on hasCertificate: a pending or failed request has no ACME
 * certificate row yet, so it would read as manual while it is nothing of the
 * sort.
 *
 * Each variant carries its own words and its own icon, so the pair stays
 * distinguishable with no colour perception at all. Bot against Wrench, rather
 * than a refresh arrow: every other RefreshCw in this app is a button you press
 * to reload something, and the certificate list header has one of those already,
 * so reusing it here would read as an action rather than a state.
 *
 * Manual is deliberately neutral rather than amber or red. Most rows on a
 * brownfield install are manual, and alarming all of them would drown the
 * ExpiryBadge signal that marks the certificates actually about to fail.
 */
export function RenewalBadge({ issuedByAcme }: { issuedByAcme: boolean }) {
  const { colorClass, Icon, label } = issuedByAcme
    ? { colorClass: 'bg-sky-100 dark:bg-sky-500/15 text-sky-800 dark:text-sky-300', Icon: Bot, label: 'ACME renewal' }
    : { colorClass: 'bg-sunken-strong text-ink-soft', Icon: Wrench, label: 'Manual renewal' };

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
      <Icon className="h-3 w-3" aria-hidden="true" />
      {label}
    </span>
  );
}

/**
 * A later certificate from the same template covers the same names, so this one
 * looks replaced (issue #154). Renders nothing when there is no successor, the
 * same shape as ExpiryBadge, so the call site stays a one liner.
 *
 * Reads "Replaced" and not "Superseded" on purpose. Revocation reason code 4 is
 * already labelled Superseded, and that one is a fact the CA asserts, while this
 * is a guess Ducks made from matching names. On a revoked and renewed
 * certificate both would be on screen at once, and identical wording would
 * present the guess with the authority of the fact.
 *
 * Quiet slate rather than a colour: an inference should not compete with the
 * status and expiry badges beside it, which are things the CA actually said. It
 * shares that palette with RenewalBadge's manual variant, which is tolerable
 * because the two sit in different columns and only this one is a link, but it
 * is the reason this badge stays wordy rather than leaning on colour to read.
 */
export function ReplacedBadge({ supersededById }: { supersededById?: number }) {
  if (supersededById == null) return null;

  return (
    <Link
      to={`/certificates/${supersededById}`}
      title="A later certificate from the same template covers the same names. Ducks matched these by name; the certification authority does not record renewals."
      className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-sunken-strong text-ink-soft hover:bg-track hover:text-ink"
    >
      Replaced
    </Link>
  );
}
