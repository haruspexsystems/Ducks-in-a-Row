import type {
  CertificateDetail,
  CertificateQuery,
  CertificateStats,
  CertificateSummary,
  CertificateTemplate,
  PagedResult,
} from '@/types';

/**
 * CSRF guard header required by the backend on state-changing /api requests
 * (defense against CSRF riding on ambient Windows credentials). Sent on every
 * request — harmless on GET — so call sites stay simple. Windows Integrated
 * Authentication itself is negotiated by the browser at the transport layer;
 * no fetch configuration is needed for it.
 */
export const CSRF_HEADERS = { 'X-Certus-Csrf': '1' } as const;

/**
 * Single fetch helper for the JSON API. Merges the CSRF guard header with any
 * caller headers, and turns an empty or non-JSON body into an ApiError rather
 * than a raw SyntaxError so call sites only ever catch ApiError.
 */
export async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: { ...CSRF_HEADERS, ...(options?.headers ?? {}) },
  });
  if (!response.ok) {
    throw new ApiError(response.status, response.statusText, url);
  }
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(response.status, 'Malformed or empty JSON response', url);
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public url: string
  ) {
    super(`API error ${status}: ${statusText} (${url})`);
    this.name = 'ApiError';
  }
}

/** Build query string from CertificateQuery params. */
function buildQueryString(query: CertificateQuery): string {
  const params = new URLSearchParams();

  if (query.search) params.set('search', query.search);
  if (query.template) params.set('template', query.template);
  if (query.status) params.set('status', query.status);
  if (query.expiringBefore) params.set('expiringBefore', query.expiringBefore);
  if (query.expiringAfter) params.set('expiringAfter', query.expiringAfter);
  if (query.sortBy) params.set('sortBy', query.sortBy);
  if (query.sortDesc !== undefined) params.set('sortDesc', String(query.sortDesc));
  if (query.skip !== undefined) params.set('skip', String(query.skip));
  if (query.take !== undefined) params.set('take', String(query.take));

  const str = params.toString();
  return str ? `?${str}` : '';
}

/** Fetch paginated certificate list. */
export async function fetchCertificates(
  query: CertificateQuery = {}
): Promise<PagedResult<CertificateSummary>> {
  return fetchJson(`/api/certificates${buildQueryString(query)}`);
}

/** Fetch a single certificate by ID. */
export async function fetchCertificate(id: number): Promise<CertificateDetail> {
  return fetchJson(`/api/certificates/${id}`);
}

/** Fetch dashboard summary statistics. */
export async function fetchStats(): Promise<CertificateStats> {
  return fetchJson('/api/certificates/stats');
}

/** Fetch available ADCS templates. */
export async function fetchTemplates(): Promise<CertificateTemplate[]> {
  return fetchJson('/api/templates');
}

/** Outcome of an on demand inventory sync. */
export interface SyncResult {
  processed: number;
  created: number;
  updated: number;
  completedAtUtc: string;
}

/**
 * Pull the certificate inventory from the CA now. Used by the Refresh buttons
 * so the dashboard reflects the CA immediately instead of waiting for the
 * next background sync tick. Waits for the sync to finish.
 */
export async function triggerSync(): Promise<SyncResult> {
  return fetchJson('/api/certificates/sync', { method: 'POST' });
}

// ── Dashboard metrics (charts) ──────────────────────────────────────
// Raw shapes returned by /api/dashboard/*. The dashboard feature maps these
// onto its presentation types (see features/dashboard/data/queries.ts).

/** Fleet health score + segment breakdown. Score is null when no certificate is scoreable yet. */
export interface FleetHealthResponse {
  score: number | null;
  segments: { key: string; label: string; count: number; tone: string }[];
}

/** Successful validations for one challenge type. */
export interface ValidationMethodResponse {
  type: string;
  count: number;
}

/** A single synthesized activity-feed entry. */
export interface ActivityItemResponse {
  id: string;
  type: string;
  cn: string;
  tmpl: string;
  timestamp: string;
}

/** Daily issuance + renewal counts (renewals currently always zero). */
export interface RegistrationSeriesResponse {
  registrations: number[];
  renewals: number[];
}

/** Fetch fleet health (score + segments). */
export async function fetchFleetHealth(): Promise<FleetHealthResponse> {
  return fetchJson('/api/dashboard/health');
}

/** Fetch successful validations grouped by challenge type. */
export async function fetchValidationMethods(): Promise<ValidationMethodResponse[]> {
  return fetchJson('/api/dashboard/validation');
}

/** Fetch the recent activity feed. */
export async function fetchActivity(take = 20): Promise<ActivityItemResponse[]> {
  return fetchJson(`/api/dashboard/activity?take=${take}`);
}

/** Fetch daily issuance counts for the last N days. */
export async function fetchRegistrations(days = 30): Promise<RegistrationSeriesResponse> {
  return fetchJson(`/api/dashboard/registrations?days=${days}`);
}
