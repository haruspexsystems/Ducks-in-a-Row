import type { CertStatus, ExpiryState } from '@/types';
import { getExpiryState } from '@/types';

interface StatusBadgeProps {
  status: string;
}

const statusColors: Record<CertStatus, string> = {
  Issued: 'bg-emerald-100 text-emerald-800',
  Revoked: 'bg-violet-100 text-violet-800',
  Pending: 'bg-slate-100 text-slate-800',
  Denied: 'bg-red-100 text-red-800',
  Failed: 'bg-red-100 text-red-800',
};

const expiryColors: Record<ExpiryState, string> = {
  valid: '',
  'expiring-soon': 'bg-amber-100 text-amber-800',
  expired: 'bg-red-100 text-red-800',
};

export function StatusBadge({ status }: StatusBadgeProps) {
  const colorClass = statusColors[status as CertStatus] ?? 'bg-slate-100 text-slate-800';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
      {status}
    </span>
  );
}

export function ExpiryBadge({ notAfter }: { notAfter: string }) {
  const state = getExpiryState(notAfter);

  if (state === 'valid') return null;

  const label = state === 'expired' ? 'Expired' : 'Expiring Soon';
  const colorClass = expiryColors[state];

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${colorClass}`}>
      {label}
    </span>
  );
}
