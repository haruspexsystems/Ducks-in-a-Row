import type { StatusTone } from '../lib/colors';

// ── Domain types ────────────────────────────────────────────────────

export type IconName =
  | 'layers' | 'check' | 'alert' | 'ban' | 'list' | 'plus' | 'rotate' | 'clock';

export interface StatCard {
  key: string;
  label: string;
  value: number;
  icon: IconName;
  tone: StatusTone;
  sub: string;
}

export type HealthStatus = 'success' | 'warning' | 'danger';

export interface HealthSegment {
  key: string;
  label: string;
  count: number;
  /** semantic status tone (resolved to a color in the widget) */
  tone: HealthStatus | 'pending';
}

export interface FleetHealth {
  /** 0-100, or null when no certificate is scoreable yet (fresh install) */
  score: number | null;
  segments: HealthSegment[];
}

export type ActivityType = 'issued' | 'renewed' | 'expired' | 'revoked' | 'warning';

export interface ActivityItem {
  id: string;
  type: ActivityType;
  icon: IconName;
  /** common name / resource identifier */
  cn: string;
  /** template or context line */
  tmpl: string;
  time: string;
  /** sortable timestamp (ms since epoch) */
  ts: number;
  status: HealthStatus;
}

/** Daily registrations + renewals, last 30 days. */
export interface RegistrationSeries {
  registrations: number[];
  renewals: number[];
}

export interface ValidationMethod {
  id: string;
  label: string;
  count: number;
  color: string;
  note: string;
}

/** Everything the dashboard renders, as one fetchable payload. */
export interface DashboardData {
  stats: StatCard[];
  health: FleetHealth;
  registrations: RegistrationSeries;
  validation: ValidationMethod[];
  activity: ActivityItem[];
}
