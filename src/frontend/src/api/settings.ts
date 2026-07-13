import { ApiError, CSRF_HEADERS, fetchJson } from './client';
import type { SetupUnreachableUrlResponse } from './setup';

/** The running application's release version, e.g. "0.9.0-beta.1". */
export interface SystemInfo {
  version: string;
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

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
