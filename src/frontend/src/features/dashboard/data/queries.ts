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
import { relativeTime, type CertificateStats } from '@/types';
import {
  fetchStats,
  fetchFleetHealth,
  fetchValidationMethods,
  fetchActivity,
  fetchRegistrations,
  type ActivityItemResponse,
  type ValidationMethodResponse,
} from '@/api/client';
import { fetchAlertConfig } from '@/api/alerts';
import { DEFAULT_EXPIRY_WARNING_DAYS } from '@/hooks/useExpiryWarningDays';

// ── Query keys ──────────────────────────────────────────────────────
export const dashboardKeys = {
  all: ['dashboard'] as const,
  data: () => [...dashboardKeys.all, 'data'] as const,
};

// ── Presentation mapping ────────────────────────────────────────────
// The backend returns raw data payloads; icon and colour choices live here
// so the API stays free of view concerns. The humanised time helper moved
// to the shared types module for the header sync context (issue #157).

// `color` is the 500 step (legible on white); `colorDark` is the 400 step of the
// same hue, which clears WCAG AA against the dark card where the 500 does not.
const VALIDATION_META: Record<string, { label: string; color: string; colorDark: string; note: string }> = {
  'http-01': { label: 'HTTP-01', color: '#6366F1', colorDark: '#818CF8', note: 'Most common' },
  'dns-01': { label: 'DNS-01', color: '#0EA5E9', colorDark: '#38BDF8', note: 'Wildcards' },
  'tls-alpn-01': { label: 'TLS-ALPN-01', color: '#8B5CF6', colorDark: '#A78BFA', note: 'Port 443' },
  'device-attest-01': { label: 'DEVICE-ATTEST-01', color: '#14B8A6', colorDark: '#2DD4BF', note: 'Apple devices' },
};

const ICON_BY_TYPE: Record<ActivityType, IconName> = {
  issued: 'plus',
  renewed: 'rotate',
  warning: 'alert',
  expired: 'clock',
  revoked: 'ban',
  rejected: 'ban',
};

const STATUS_BY_TYPE: Record<ActivityType, HealthStatus> = {
  issued: 'success',
  renewed: 'success',
  warning: 'warning',
  expired: 'danger',
  revoked: 'danger',
  // Amber, not red: a rejection is the domain policy working as designed.
  rejected: 'warning',
};

/** Health-segment tones the widgets can render; an unknown tone maps to `pending`. */
const HEALTH_TONES = new Set<HealthStatus | 'pending'>(['success', 'warning', 'danger', 'pending']);
function normalizeTone(tone: string): HealthStatus | 'pending' {
  return HEALTH_TONES.has(tone as HealthStatus | 'pending') ? (tone as HealthStatus | 'pending') : 'pending';
}

/**
 * Certificate-centric stat cards (full CA inventory, not just proxy traffic).
 * warningDays comes from the alert configuration so the "Expiring Soon" caption
 * describes the number above it (issue #152).
 */
function mapStats(s: CertificateStats, warningDays: number): StatCard[] {
  return [
    { key: 'total',     label: 'Total Certificates', value: s.totalCertificates,  icon: 'layers', tone: 'total',     sub: 'All certificates in the CA database' },
    { key: 'issued',    label: 'Issued',             value: s.issuedCertificates, icon: 'check',  tone: 'success',   sub: 'Active, valid certificates' },
    { key: 'expiring',  label: 'Expiring Soon',      value: s.expiringSoon,       icon: 'alert',  tone: 'warning',   sub: `Within ${warningDays} days` },
    { key: 'expired',   label: 'Expired',            value: s.expired,             icon: 'clock',  tone: 'danger',    sub: 'Past expiration' },
    { key: 'revoked',   label: 'Revoked',            value: s.revokedCertificates, icon: 'ban',    tone: 'revoked',   sub: 'Revoked by the CA' },
  ];
}

function mapValidation(items: ValidationMethodResponse[]): ValidationMethod[] {
  // Sort by count descending so the index 0 "MOST USED" badge and the bars
  // (scaled to the real max in the widget) agree, whatever order the API returns.
  return items
    .map((m) => {
      const meta = VALIDATION_META[m.type] ?? { label: m.type, color: '#94A3B8', colorDark: '#94A3B8', note: '' };
      return { id: m.type, label: meta.label, count: m.count, color: meta.color, colorDark: meta.colorDark, note: meta.note };
    })
    .sort((a, b) => b.count - a.count);
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
  const [stats, health, validation, activity, registrations, warningDays] = await Promise.all([
    fetchStats(),
    fetchFleetHealth(),
    fetchValidationMethods(),
    fetchActivity(20),
    fetchRegistrations(30),
    // The expiry window the backend applied to the counts above, so the card
    // captions and the deep links describe the same certificates the numbers do.
    //
    // Non-fatal on purpose. Promise.all rejects as a whole, and DashboardPage
    // replaces the entire page with an error notice when this query fails. The
    // other five calls carry the data the page is actually made of; this one
    // only sets a caption and a deep link bound, so a hiccup on the alert
    // configuration endpoint must not blank the stats, charts, and activity
    // feed that all arrived fine. It degrades to the same default
    // useExpiryWarningDays falls back to.
    fetchAlertConfig().then(
      (c) => c.expiryWarningDays,
      () => DEFAULT_EXPIRY_WARNING_DAYS
    ),
  ]);

  return {
    stats: mapStats(stats, warningDays),
    warningDays,
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
