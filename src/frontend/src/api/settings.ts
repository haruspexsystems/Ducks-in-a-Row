import { ApiError, CSRF_HEADERS, fetchJson } from './client';
import type { SetupUnreachableUrlResponse } from './setup';

/**
 * The running application's release version, e.g. "0.10.0-beta.1", and the
 * commit it was built from (issue #112). commit is null when the build
 * carried no stamp, which is what a build from the release source snapshot
 * looks like. Treat it as an opaque string rather than a bare 40 character
 * sha: a build from a dirty working tree carries a ".dirty" suffix.
 */
export interface SystemInfo {
  version: string;
  commit?: string | null;
}

/** Fetch the running application version (admin only). */
export async function fetchSystemInfo(): Promise<SystemInfo> {
  return fetchJson('/api/settings/info');
}

/**
 * The external URL as each configuration layer sees it (issue #93).
 * effectiveUrl is the value in force in the running process; overlayUrl is
 * read fresh from settings.json, so a saved but not yet applied change shows
 * up as restartPending. effectiveSource names the winning layer — 'other'
 * means an environment variable or command line value outranks the overlay,
 * and saving from the dashboard will not take effect.
 */
export interface ExternalUrlSettings {
  effectiveUrl?: string | null;
  overlayUrl?: string | null;
  appSettingsUrl?: string | null;
  effectiveSource: 'overlay' | 'appsettings' | 'other' | 'none';
  restartPending: boolean;
}

/** Fetch the external URL layer report (admin only). */
export async function fetchExternalUrlSettings(): Promise<ExternalUrlSettings> {
  return fetchJson('/api/settings/external-url');
}

/** Successful update response. */
export interface ExternalUrlUpdateResult {
  externalUrl: string;
  /** True when the service scheduled its own restart to apply the change. */
  restartScheduled: boolean;
  message: string;
}

/**
 * An update either saves, or is refused with the probe outcome because the
 * URL did not answer and the request did not confirm it — the same contract
 * as setup completion, reusing its 422 body shape.
 */
export type ExternalUrlUpdateOutcome =
  | { kind: 'updated'; result: ExternalUrlUpdateResult }
  | { kind: 'unreachableUrl'; refusal: SetupUnreachableUrlResponse };

/**
 * Change the external URL. Plain fetch instead of fetchJson because the 422
 * refusal carries a body the settings page needs (fetchJson throws away non
 * 2xx bodies).
 */
export async function updateExternalUrl(
  url: string,
  confirmUnreachableExternalUrl = false,
): Promise<ExternalUrlUpdateOutcome> {
  const endpoint = '/api/settings/external-url';
  const response = await fetch(endpoint, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
    body: JSON.stringify({ url, confirmUnreachableExternalUrl }),
  });
  if (response.status === 422) {
    return {
      kind: 'unreachableUrl',
      refusal: (await response.json()) as SetupUnreachableUrlResponse,
    };
  }
  if (!response.ok) {
    // The server sends the actual reason as { error } (a validation message,
    // the setup lock, or an unreadable overlay); show that instead of the
    // bare status text when it is present.
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(response.status, body?.error ?? response.statusText, endpoint);
  }
  return { kind: 'updated', result: (await response.json()) as ExternalUrlUpdateResult };
}

/**
 * Wait for a saved external URL to become effective after the restart that
 * applies it. Polls the settings endpoint until effectiveUrl matches, which
 * only the restarted process can report — the setup status poll used by the
 * wizard is no witness here, because the old process already answers it with
 * setupCompleted true. Resolves false on timeout (manual restart needed).
 */
export async function waitForExternalUrlApplied(
  expectedUrl: string,
  timeoutMs = 90_000,
): Promise<boolean> {
  const startedAt = Date.now();
  // Give the service a moment to actually go down before the first probe,
  // so an answer from the old process does not count as "applied".
  await delay(4_000);

  let interval = 1_500;
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const settings = await fetchExternalUrlSettings();
      if (settings.effectiveUrl === expectedUrl) {
        return true;
      }
    } catch {
      // Connection refused while the service restarts — keep polling.
    }
    await delay(interval);
    interval = Math.min(interval * 1.5, 5_000);
  }
  return false;
}

/**
 * The allowed domain policy as stored in the wizard status file, plus the
 * machine's AD domain as a suggestion for the "Add my AD domain" button
 * (null when the server is not domain joined).
 */
export interface AllowedDomainsSettings {
  enabled: boolean;
  domains: string[];
  adDomain?: string | null;
}

/** Fetch the allowed domain policy (admin only). */
export async function fetchAllowedDomainsSettings(): Promise<AllowedDomainsSettings> {
  return fetchJson('/api/settings/allowed-domains');
}

/** One refused entry from a save, with the server's plain language reason. */
export interface InvalidDomainEntry {
  entry: string;
  reason: string;
}

/** Successful update response. */
export interface AllowedDomainsUpdateResult {
  enabled: boolean;
  /** The normalized list as stored (lowercase punycode, de-duplicated). */
  domains: string[];
  message: string;
}

/**
 * An update either saves, or is refused with per entry reasons. Unlike the
 * external URL there is no restart leg: the issuance policy hot reads the
 * file, so a save is in force for the next order.
 */
export type AllowedDomainsUpdateOutcome =
  | { kind: 'updated'; result: AllowedDomainsUpdateResult }
  | { kind: 'invalid'; error: string; invalidEntries: InvalidDomainEntry[] };

/**
 * Change the allowed domain policy. Plain fetch instead of fetchJson because
 * the 400 refusal carries the per entry reasons the settings card shows
 * (fetchJson throws away non 2xx bodies).
 */
export async function updateAllowedDomains(
  enabled: boolean,
  domains: string[],
): Promise<AllowedDomainsUpdateOutcome> {
  const endpoint = '/api/settings/allowed-domains';
  const response = await fetch(endpoint, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
    body: JSON.stringify({ enabled, domains }),
  });
  if (response.status === 400) {
    const body = (await response.json().catch(() => null)) as
      | { error?: string; invalidEntries?: InvalidDomainEntry[] }
      | null;
    return {
      kind: 'invalid',
      error: body?.error ?? 'The entries were not accepted.',
      invalidEntries: body?.invalidEntries ?? [],
    };
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(response.status, body?.error ?? response.statusText, endpoint);
  }
  return { kind: 'updated', result: (await response.json()) as AllowedDomainsUpdateResult };
}

/** The dashboard revocation scope modes, always under the TLS guardrail. */
export type RevocationScopeMode = 'ducks-managed' | 'custom' | 'all';

/**
 * The revocation scope as stored: the mode, the custom template list (kept
 * across mode switches), and the enabled ACME template set, which is what
 * ducks-managed covers on top of certificates Ducks itself issued.
 */
export interface RevocationScopeSettings {
  mode: RevocationScopeMode;
  customTemplates: string[];
  enabledTemplates: string[];
}

/** Fetch the revocation scope (admin only). */
export async function fetchRevocationScope(): Promise<RevocationScopeSettings> {
  return fetchJson('/api/settings/revocation-scope');
}

/** A template entry the API refused, with its reason. */
export interface InvalidTemplateEntry {
  entry: string;
  reason: string;
}

/**
 * An update either saves, or is refused with per entry reasons. No restart
 * leg: the eligibility gate hot reads the file, so a save is in force for
 * the next revocation attempt.
 */
export type RevocationScopeUpdateOutcome =
  | { kind: 'updated'; mode: RevocationScopeMode; customTemplates: string[]; message: string }
  | { kind: 'invalid'; error: string; invalidEntries: InvalidTemplateEntry[] };

/**
 * Change the revocation scope. Plain fetch instead of fetchJson because the
 * 400 refusal carries the per entry reasons the settings card shows
 * (fetchJson throws away non 2xx bodies).
 */
export async function updateRevocationScope(
  mode: RevocationScopeMode,
  customTemplates: string[],
): Promise<RevocationScopeUpdateOutcome> {
  const endpoint = '/api/settings/revocation-scope';
  const response = await fetch(endpoint, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
    body: JSON.stringify({ mode, customTemplates }),
  });
  if (response.status === 400) {
    const body = (await response.json().catch(() => null)) as
      | { error?: string; invalidEntries?: InvalidTemplateEntry[] }
      | null;
    return {
      kind: 'invalid',
      error: body?.error ?? 'The entries were not accepted.',
      invalidEntries: body?.invalidEntries ?? [],
    };
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(response.status, body?.error ?? response.statusText, endpoint);
  }
  const result = (await response.json()) as {
    mode: RevocationScopeMode;
    customTemplates: string[];
    message: string;
  };
  return { kind: 'updated', ...result };
}

/**
 * The webserver HTTPS certificate as the settings overlay records it.
 * configured false means no CA issued certificate was ever set up (the
 * service serves the self signed fallback). inStore false with configured
 * true means the overlay points at a thumbprint the store no longer holds.
 */
export interface HttpsCertificateInfo {
  configured: boolean;
  thumbprint?: string | null;
  inStore?: boolean;
  subject?: string | null;
  subjectNames?: string[] | null;
  notBefore?: string | null;
  notAfter?: string | null;
  /** The template recorded at enrollment; null on installs that predate it. */
  template?: string | null;
  /** The template a renewal would use (recorded, or first enabled). */
  renewTemplate?: string | null;
  /** True when the overlay thumbprint is not the one this process serves. */
  restartPending?: boolean;
  /** The thumbprint this process actually serves right now. */
  servedThumbprint?: string | null;
  /**
   * Expiry of the certificate still being served while a restart is pending.
   * This is what the notice escalates on: the renewed certificate is fine, the
   * one in use is the one running out.
   */
  servedNotAfter?: string | null;
  autoRenewal?: HttpsCertificateAutoRenewal;
}

/**
 * State of the background renewal (issue #105). It never restarts the service
 * itself, so a successful renewal shows up as restartPending until someone
 * applies it. `failed` singles out the outcomes worth acting on, as opposed to
 * the routine "nothing to do" passes that also record an attempt.
 */
export interface HttpsCertificateAutoRenewal {
  enabled: boolean;
  windowDays: number;
  lastAttemptAt?: string | null;
  lastOutcome?:
    | 'installed'
    | 'sanMismatch'
    | 'pending'
    | 'denied'
    | 'failed'
    | 'notApplicable'
    | null;
  lastMessage?: string | null;
  failed: boolean;
}

/** Fetch the webserver HTTPS certificate state (admin only). */
export async function fetchHttpsCertificate(): Promise<HttpsCertificateInfo> {
  return fetchJson('/api/settings/https-certificate');
}

/** Outcome of a renewal, mirroring the wizard's TLS provisioning result. */
export type RenewHttpsCertificateResult =
  | {
      outcome: 'installed';
      thumbprint: string;
      restartScheduled: boolean;
      currentHostCovered?: boolean | null;
    }
  | {
      outcome: 'sanMismatch';
      issuedNames?: string[] | null;
      requestId?: number | null;
      message?: string | null;
    }
  | {
      outcome: 'pending' | 'denied' | 'failed';
      message?: string | null;
      requestId?: number | null;
    };

/**
 * Renew the webserver certificate with the template recorded at setup. The
 * server re enrolls, applies the new thumbprint, and schedules the restart.
 */
export async function renewHttpsCertificate(): Promise<RenewHttpsCertificateResult> {
  const endpoint = '/api/settings/https-certificate/renew';
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
    body: '{}',
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as
      | { error?: string | boolean; message?: string }
      | null;
    const reason = body?.message ?? (typeof body?.error === 'string' ? body.error : null);
    throw new ApiError(response.status, reason ?? response.statusText, endpoint);
  }
  return (await response.json()) as RenewHttpsCertificateResult;
}

/** Outcome of applying a certificate the background renewal already enrolled. */
export interface ApplyHttpsCertificateResult {
  thumbprint: string;
  restartScheduled: boolean;
  message: string;
}

/**
 * Apply a certificate the background renewal enrolled: the overlay already
 * points at it, so this only schedules the restart that starts serving it.
 * Refused with 409 when nothing is pending.
 */
export async function applyHttpsCertificate(): Promise<ApplyHttpsCertificateResult> {
  const endpoint = '/api/settings/https-certificate/apply';
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
    body: '{}',
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(response.status, body?.error ?? response.statusText, endpoint);
  }
  return (await response.json()) as ApplyHttpsCertificateResult;
}

/**
 * Wait for a renewed certificate to be served after the restart that applies
 * it: polls until the settings endpoint reports the expected thumbprint with
 * no pending restart, which only the restarted process does. Resolves false
 * on timeout (manual restart needed).
 */
export async function waitForHttpsCertificateApplied(
  expectedThumbprint: string,
  timeoutMs = 90_000,
): Promise<boolean> {
  const startedAt = Date.now();
  // Give the service a moment to actually go down before the first probe,
  // so an answer from the old process does not count as "applied".
  await delay(4_000);

  let interval = 1_500;
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const info = await fetchHttpsCertificate();
      if (info.thumbprint === expectedThumbprint && info.restartPending === false) {
        return true;
      }
    } catch {
      // Connection refused while the service restarts — keep polling.
    }
    await delay(interval);
    interval = Math.min(interval * 1.5, 5_000);
  }
  return false;
}

/**
 * One certificate of the CA's signing chain, ordered issuing CA first,
 * root last. The download URLs are derived from the thumbprint:
 * /api/settings/ca-certificates/{thumbprint}/der and /pem, with the whole
 * chain at /api/settings/ca-certificates/chain/pem and /chain/p7b.
 */
export interface CaCertificateSummary {
  position: number;
  role: 'issuing' | 'intermediate' | 'root';
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  thumbprint: string;
}

/** Fetch the CA certificate chain metadata (admin only). */
export async function fetchCaCertificates(): Promise<CaCertificateSummary[]> {
  return fetchJson('/api/settings/ca-certificates');
}

/**
 * One place a CRL is published, and what was last read from it. A CA publishes
 * the same CRL to several locations, and the interesting case is when they
 * disagree: a root CRL renewed into the directory but never copied to the web
 * server leaves the web server serving one that expires.
 */
export interface CrlSourceStatus {
  source: string;
  crlNumber: string | null;
  thisUpdate: string | null;
  nextUpdate: string | null;
  nextPublish: string | null;
  signatureStatus: string | null;
  publishFlags: number | null;
  lastReadAt: string | null;
  lastCheckedAt: string;
  lastError: string | null;
}

/** Every CRL being watched for one CA key and kind. */
export interface CrlStatusGroup {
  scope: 'issuing' | 'parent';
  kind: 'base' | 'delta';
  issuerName: string;
  autoPublished: boolean;
  sources: CrlSourceStatus[];
}

export interface CrlStatusResponse {
  crls: CrlStatusGroup[];
  lastCheckedAt: string | null;
}

/** Fetch what the CRL monitor last saw (admin only). */
export async function fetchCrlStatus(): Promise<CrlStatusResponse> {
  return fetchJson('/api/settings/crl-status');
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
