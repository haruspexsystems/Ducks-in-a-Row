import { ApiError, CSRF_HEADERS, fetchJson } from './client';
import { isSetAside } from '@/lib/licence';

// ── Licence and paid module (issue #493) ─────────────────────────────
// The wire shapes of /api/settings/licence (LicenceController and LicenceViews
// in Certus.Core/Modules). Every date and day count here is the server's: the
// paid module computes them, and the browser shows them as given and never
// counts days of its own (licence design section 9.1).

/** Where the module host stands. Kept open to a string so a state added on the server still renders. */
export type ModuleState =
  | 'NotPresent'
  | 'Loaded'
  | 'Failed'
  | 'Unresponsive'
  | 'Quarantined'
  | 'Incompatible'
  | 'Refused';

/** The licence status the API answers (design section 13.3, Draft 2 note B4). */
export type LicenceStatus =
  | 'None'
  | 'StoredNotVerified'
  | 'NotYetValid'
  | 'Valid'
  | 'Expiring'
  | 'Grace'
  | 'Lapsed'
  | 'BindingMismatch'
  | 'Invalid';

/** A module's contract version beside the core's, each as major.minor. Only set for Incompatible. */
export interface ModuleContract {
  module: string;
  core: string;
}

export interface LicenceModule {
  state: ModuleState | (string & {});
  /** Why the module is in this state, in the host's own words; null while loaded. */
  reason: string | null;
  id: string | null;
  version: string | null;
  contract: ModuleContract | null;
}

export interface LicenceStored {
  active: boolean;
  previous: boolean;
  /** The licence folder is refused (design section 12.3), so it reads as holding nothing. */
  untrusted: boolean;
}

/**
 * A licence as the API answers it. The display fields are filled only when the
 * file passed the signature (isVerified); for None, StoredNotVerified and
 * Invalid they are empty, apart from the reason code and this server's forest.
 */
export interface LicenceDetails {
  status: LicenceStatus | (string & {});
  reasonCode: string | null;
  licenceId: string | null;
  tier: string | null;
  features: string[];
  maxCas: number | null;
  licenseeName: string | null;
  licenseeRef: string | null;
  validFrom: string | null;
  validUntil: string | null;
  warnFrom: string | null;
  graceUntil: string | null;
  /** Whole days to the next boundary, computed by the paid module. */
  daysRemaining: number | null;
  boundForests: string[];
  observedForest: string | null;
  clockAnomaly: boolean;
  unknownTier: boolean;
  isVerified: boolean;
}

export interface LicenceStatusResponse {
  module: LicenceModule;
  stored: LicenceStored;
  licence: LicenceDetails;
}

export interface LicenceCandidate {
  licence: LicenceDetails;
  /** The paid module judges this candidate worse than the licence installed now (design section 9.5). */
  worseThanInstalled: boolean;
}

export interface LicenceInspectResponse {
  module: LicenceModule;
  /** Null when no module is loaded to judge the file, or the module could not judge it. */
  candidate: LicenceCandidate | null;
}

export interface LicenceDowngrade {
  code: 'WouldDowngrade';
  error: string;
  module: LicenceModule;
  candidate: LicenceCandidate;
}

export type LicenceInstallOutcome =
  | { kind: 'installed'; status: LicenceStatusResponse }
  | { kind: 'wouldDowngrade'; refusal: LicenceDowngrade };

export interface RetryModuleResult {
  restartScheduled: boolean;
  message: string;
}

const ENDPOINT = '/api/settings/licence';
const LICENCE_MEDIA_TYPE = 'application/jose+json';

/** Fetch the module state, the stored files and the licence (admin only). */
export async function fetchLicence(): Promise<LicenceStatusResponse> {
  return fetchJson(ENDPOINT);
}

/**
 * Ask the paid module what it makes of a licence file, without installing it.
 * The body is sent byte for byte: a pasted text exactly as typed, a chosen file
 * exactly as read.
 */
export async function inspectLicence(licence: Blob): Promise<LicenceInspectResponse> {
  return send<LicenceInspectResponse>(`${ENDPOINT}/inspect`, 'POST', licence);
}

/**
 * Install a licence file. A candidate the paid module judges worse than the
 * installed licence is refused 409 WouldDowngrade unless confirm is set, and
 * that refusal carries the candidate for the card to show beside the current
 * one. Plain fetch rather than fetchJson, because fetchJson throws the body of
 * a refusal away.
 */
export async function installLicence(licence: Blob, confirm = false): Promise<LicenceInstallOutcome> {
  const url = confirm ? `${ENDPOINT}?confirm=true` : ENDPOINT;
  const response = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': LICENCE_MEDIA_TYPE, ...CSRF_HEADERS },
    body: licence,
  });

  if (response.status === 409) {
    // Two different 409s share the status: the downgrade, which names its
    // code, and a licence folder that cannot be trusted, which does not.
    const body = (await response.json().catch(() => null)) as Partial<LicenceDowngrade> | null;
    if (body?.code === 'WouldDowngrade' && body.candidate && body.module) {
      return { kind: 'wouldDowngrade', refusal: body as LicenceDowngrade };
    }
    throw new ApiError(response.status, body?.error ?? response.statusText, url);
  }

  if (!response.ok) throw await refusal(response, url);
  return { kind: 'installed', status: (await response.json()) as LicenceStatusResponse };
}

/** Remove the active licence, keeping it as the previous one. */
export async function removeLicence(): Promise<LicenceStatusResponse> {
  return send<LicenceStatusResponse>(ENDPOINT, 'DELETE');
}

/** Put the previous licence back, undoing the last replacement or removal. */
export async function restorePreviousLicence(): Promise<LicenceStatusResponse> {
  return send<LicenceStatusResponse>(`${ENDPOINT}/restore-previous`, 'POST');
}

/**
 * Clear a paid module that was set aside and restart the service, so the next
 * start tries it again. The dev host has no restarter and answers
 * restartScheduled false.
 */
export async function retryModule(): Promise<RetryModuleResult> {
  return send<RetryModuleResult>(`${ENDPOINT}/retry-module`, 'POST');
}

/**
 * Wait for the service to come back after a Retry restarted it, and answer the
 * licence status the new process reports, or null on timeout (the caller
 * refetches either way).
 *
 * The witness that the restart happened: a request that fails while the
 * service is down, or the answer a fresh process gives before its module host
 * has looked for a module, which is NotPresent with no reason. A set aside
 * module seen without either of those is still the old process speaking.
 */
export async function waitForModuleRestart(timeoutMs = 90_000): Promise<LicenceStatusResponse | null> {
  const startedAt = Date.now();
  // Give the service a moment to go down before the first probe.
  await delay(4_000);

  let sawRestart = false;
  let interval = 1_500;
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const status = await fetchLicence();
      const starting = status.module.state === 'NotPresent' && status.module.reason === null;
      if (starting) {
        sawRestart = true;
      } else if (sawRestart || !isSetAside(status.module.state) || Date.now() - startedAt > SET_ASIDE_AGAIN_AFTER) {
        // The last arm: a restart quick enough to finish inside the first
        // delay, whose new process set the module aside again, shows neither
        // witness. Past this long, a set aside answer is the new process's.
        return status;
      }
    } catch {
      // Connection refused while the service restarts: keep polling.
      sawRestart = true;
    }
    await delay(interval);
    interval = Math.min(interval * 1.5, 5_000);
  }
  return null;
}

/** A licence route call with an optional raw licence body; refusals carry the server's { error } text. */
async function send<T>(url: string, method: 'POST' | 'DELETE', licence?: Blob): Promise<T> {
  const response = await fetch(url, {
    method,
    headers: licence
      ? { 'Content-Type': LICENCE_MEDIA_TYPE, ...CSRF_HEADERS }
      : { ...CSRF_HEADERS },
    body: licence,
  });
  if (!response.ok) throw await refusal(response, url);
  return (await response.json()) as T;
}

/**
 * The licence API answers refusals as { error }, which fetchJson does not read.
 * The error carries it as its statusText, which is where errorText in
 * ./client looks for it.
 */
async function refusal(response: Response, url: string): Promise<ApiError> {
  const body = (await response.json().catch(() => null)) as { error?: string } | null;
  return new ApiError(response.status, body?.error ?? response.statusText, url);
}

/** How long after a Retry a set aside answer is taken as the restarted process's own. */
const SET_ASIDE_AGAIN_AFTER = 20_000;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
