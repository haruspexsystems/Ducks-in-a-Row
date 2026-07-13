import { useQuery } from '@tanstack/react-query';
import type {
  DashboardData,
  StatCard,
  ValidationMethod,
  ActivityItem,
  ActivityType,
  IconName,
  HealthStatus,
} from './types';
import type { CertificateStats } from '@/types';
import {
  fetchStats,
  fetchFleetHealth,
  fetchValidationMethods,
  fetchActivity,
  fetchRegistrations,
  type ActivityItemResponse,
  type ValidationMethodResponse,
} from '@/api/client';

// ── Query keys ──────────────────────────────────────────────────────
export const dashboardKeys = {
  all: ['dashboard'] as const,
  data: () => [...dashboardKeys.all, 'data'] as const,
};

// ── Presentation mapping ────────────────────────────────────────────
// The backend returns raw data payloads; icon, colour, and humanised time
// choices live here so the API stays free of view concerns.

const VALIDATION_META: Record<string, { label: string; color: string; note: string }> = {
  'http-01': { label: 'HTTP-01', color: '#6366F1', note: 'Most common' },
  'dns-01': { label: 'DNS-01', color: '#0EA5E9', note: 'Wildcards' },
  'tls-alpn-01': { label: 'TLS-ALPN-01', color: '#8B5CF6', note: 'Port 443' },
};

const ICON_BY_TYPE: Record<ActivityType, IconName> = {
  issued: 'plus',
  renewed: 'rotate',
  warning: 'alert',
  expired: 'clock',
  revoked: 'ban',
};

const STATUS_BY_TYPE: Record<ActivityType, HealthStatus> = {
  issued: 'success',
  renewed: 'success',
  warning: 'warning',
  expired: 'danger',
  revoked: 'danger',
};

/** Health-segment tones the widgets can render; an unknown tone maps to `pending`. */
const HEALTH_TONES = new Set<HealthStatus | 'pending'>(['success', 'warning', 'danger', 'pending']);
function normalizeTone(tone: string): HealthStatus | 'pending' {
  return HEALTH_TONES.has(tone as HealthStatus | 'pending') ? (tone as HealthStatus | 'pending') : 'pending';
}

/** Certificate-centric stat cards (full CA inventory, not just proxy traffic). */
function mapStats(s: CertificateStats): StatCard[] {
  return [
    { key: 'total',     label: 'Total Certificates', value: s.totalCertificates,  icon: 'layers', tone: 'total',     sub: 'All certificates in the CA database' },
    { key: 'issued',    label: 'Issued',             value: s.issuedCertificates, icon: 'check',  tone: 'success',   sub: 'Active, valid certificates' },
    { key: 'expiring',  label: 'Expiring Soon',      value: s.expiringSoon,       icon: 'alert',  tone: 'warning',   sub: 'Within 30 days' },
    { key: 'expired',   label: 'Expired',            value: s.expired,             icon: 'clock',  tone: 'danger',    sub: 'Past expiration' },
    { key: 'revoked',   label: 'Revoked',            value: s.revokedCertificates, icon: 'ban',    tone: 'revoked',   sub: 'Revoked by the CA' },
  ];
}

function mapValidation(items: ValidationMethodResponse[]): ValidationMethod[] {
  // Sort by count descending so the index 0 "MOST USED" badge and the bars
  // (scaled to the real max in the widget) agree, whatever order the API returns.
  return items
    .map((m) => {
      const meta = VALIDATION_META[m.type] ?? { label: m.type, color: '#94A3B8', note: '' };
      return { id: m.type, label: meta.label, count: m.count, color: meta.color, note: meta.note };
    })
    .sort((a, b) => b.count - a.count);
}

function relativeTime(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '';
  const minutes = Math.round((Date.now() - then) / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days === 1) return 'Yesterday';
  if (days < 7) return `${days}d ago`;
  return new Date(then).toLocaleDateString();
}

function mapActivity(items: ActivityItemResponse[]): ActivityItem[] {
  return items.map((i) => {
    const type = i.type as ActivityType;
    return {
      id: i.id,
      type,
      icon: ICON_BY_TYPE[type] ?? 'list',
      cn: i.cn,
      tmpl: i.tmpl,
      time: relativeTime(i.timestamp),
      ts: Date.parse(i.timestamp),
      status: STATUS_BY_TYPE[type] ?? 'success',
    };
  });
}

// ── Fetcher ─────────────────────────────────────────────────────────
async function fetchDashboard(): Promise<DashboardData> {
  const [stats, health, validation, activity, registrations] = await Promise.all([
    fetchStats(),
    fetchFleetHealth(),
    fetchValidationMethods(),
    fetchActivity(20),
    fetchRegistrations(30),
  ]);

  return {
    stats: mapStats(stats),
    health: {
      score: health.score,
      segments: health.segments.map((s) => ({
        key: s.key,
        label: s.label,
        count: s.count,
        tone: normalizeTone(s.tone),
      })),
    },
    registrations,
    validation: mapValidation(validation),
    activity: mapActivity(activity),
  };
}

// ── Hook ────────────────────────────────────────────────────────────
/** Loads the dashboard payload from the real API and maps it to view types. */
export function useDashboardData() {
  return useQuery({
    queryKey: dashboardKeys.data(),
    queryFn: fetchDashboard,
    staleTime: 30_000,
    // Poll so revocations and background syncs surface without a reload.
    // refetchIntervalInBackground defaults to false, so hidden tabs do not poll.
    refetchInterval: 60_000,
  });
}
