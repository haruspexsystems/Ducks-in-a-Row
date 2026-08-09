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
 * than a raw SyntaxError so call sites only ever catch ApiError. A non 2xx
 * problem+json body (RFC 7807) is parsed into the ApiError's problem fields,
 * so a caller can tell, for example, a CA that is unreachable from a CA that
 * denied view access (issue #157).
 */
export async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: { ...CSRF_HEADERS, ...(options?.headers ?? {}) },
  });
  if (!response.ok) throw await problemFrom(response, url);
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(response.status, 'Malformed or empty JSON response', url);
  }
}

/**
 * The same fetch for endpoints that answer with text rather than JSON, used by
 * the copy PEM button on the certificate detail page. Shares fetchJson's CSRF
 * header merge and its RFC 7807 error parsing, so a caller catches the one
 * ApiError type either way.
 *
 * A separate function rather than a flag on fetchJson because the two differ in
 * what they do with a successful body, and fetchJson treats a non JSON body as
 * an error by design.
 */
export async function fetchText(url: string, options?: RequestInit): Promise<string> {
  const response = await fetch(url, {
    ...options,
    headers: { ...CSRF_HEADERS, ...(options?.headers ?? {}) },
  });
  if (!response.ok) throw await problemFrom(response, url);
  return response.text();
}

/**
 * Turns a failed response into an ApiError, reading the RFC 7807 problem body
 * when there is one. Shared so the JSON and text helpers report failures
 * identically.
 */
async function problemFrom(response: Response, url: string): Promise<ApiError> {
  let problemType: string | undefined;
  let problemTitle: string | undefined;
  let problemDetail: string | undefined;
  try {
    const body: unknown = await response.json();
    if (body && typeof body === 'object') {
      const problem = body as Record<string, unknown>;
      if (typeof problem.type === 'string') problemType = problem.type;
      if (typeof problem.title === 'string') problemTitle = problem.title;
      if (typeof problem.detail === 'string') problemDetail = problem.detail;
    }
  } catch {
    // Non JSON error body: the status line is all there is.
  }
  return new ApiError(
    response.status, response.statusText, url, problemType, problemTitle, problemDetail);
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public url: string,
    /** RFC 7807 problem type URI, when the error body carried one. */
    public problemType?: string,
    /** RFC 7807 problem title, when the error body carried one. */
    public problemTitle?: string,
    /** RFC 7807 problem detail, when the error body carried one. */
    public problemDetail?: string
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
  if (query.state) params.set('state', query.state);
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

/** Outcome of a dashboard revocation (issue #159). */
export interface RevokeCertificateResult {
  outcome: 'revoked';
  /**
   * Whether the in request inventory resync succeeded. When false the CA has
   * revoked but the returned certificate may still read Issued until the next
   * background sync; the page says so instead of pretending.
   */
  resynced: boolean;
  /** The row as the resync read it back from the CA. */
  certificate: CertificateDetail;
}

/**
 * Revoke one certificate at the CA. The serial is echoed back so the server
 * refuses if the row underneath the dialog is not the certificate the admin
 * confirmed. Waits for the CA call and the follow up resync; failures arrive
 * as ApiError carrying the problem type (already revoked, target mismatch,
 * CA unavailable, and so on) for the dialog to word precisely.
 */
export async function revokeCertificate(
  id: number,
  reason: number,
  serialNumber: string
): Promise<RevokeCertificateResult> {
  return fetchJson(`/api/certificates/${id}/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason, serialNumber }),
  });
}

/** The connected CA and the outcome of the most recent inventory sync. */
export interface SyncStatus {
  /** CA display name from the connection string; null when unknown. */
  caName: string | null;
  caMode: 'real' | 'mock' | 'unconfigured';
  /** When the most recent attempt ran, success or failure; null before the first one. */
  lastAttemptAt: string | null;
  lastOutcome: 'success' | 'caUnavailable' | 'caAccessDenied' | 'failed' | null;
  /** The failure message of the last attempt, when it failed. */
  lastMessage: string | null;
  /** True when the most recent attempt failed. */
  failed: boolean;
  /** The most recent successful sync; null when none has succeeded yet. */
  lastSuccess: SyncResult | null;
}

/**
 * Fetch the sync status for the page headers (issue #157). A memory read on
 * the server with no CA round trip, so it is cheap to poll.
 */
export async function fetchSyncStatus(): Promise<SyncStatus> {
  return fetchJson('/api/certificates/sync-status');
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
