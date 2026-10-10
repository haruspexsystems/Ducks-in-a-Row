import { ApiError, CSRF_HEADERS, fetchJson } from './client';

/**
 * Setup status response. Anonymous endpoint, reduced to the routing boolean
 * only — full configuration detail is admin-only on /api/setup/config.
 * The boolean reflects effective completeness: false when the wizard was
 * walked through but no CA is actually configured, so such installs route
 * back into the wizard.
 */
export interface SetupStatusResponse {
  setupCompleted: boolean;
}

/** The TLS certificate the settings overlay points at, if any. */
export interface ConfiguredTlsCertificate {
  thumbprint: string;
  /** False when the thumbprint is configured but not found in the store. */
  installed: boolean;
  names?: string[] | null;
  notAfter?: string | null;
}

/** Full setup configuration (admin-only). */
export interface SetupConfigResponse {
  setupCompleted: boolean;
  /** The raw wizard state: true when the wizard was finished at some point. */
  wizardCompleted: boolean;
  /** Effective CA mode: 'real', 'mock', or 'unconfigured'. */
  caMode: 'real' | 'mock' | 'unconfigured';
  completedAt?: string;
  caConnectionString?: string;
  enabledTemplates: string[];
  externalUrl?: string;
  /**
   * The URL the wizard seeds the Server URL field with when nothing was
   * saved before: the machine's DNS name plus the port the service listens
   * on, e.g. "https://certus.corp.example.com:5001".
   */
  suggestedExternalUrl?: string;
  /** The domain restriction recorded in the wizard file (draft or completed). */
  allowedDomainsEnabled?: boolean;
  allowedDomains?: string[];
  /** The machine's AD domain as an allowed domain suggestion; null in a workgroup. */
  suggestedAllowedDomain?: string | null;
  /**
   * The step id a saved draft should resume at ('url', 'review'). Null when
   * no draft recorded one or setup is complete.
   */
  wizardStep?: string | null;
  /** Set when the wizard's TLS enrollment already configured a certificate. */
  tlsCertificate?: ConfiguredTlsCertificate | null;
}

/** An enterprise CA discovered in Active Directory. */
export interface DiscoveredCa {
  hostName: string;
  caName: string;
  displayName: string;
  connectionString: string;
}

/**
 * Why a connectivity test failed, so the wizard can give the hint that fits
 * (issue #440). An access denial means a right is missing, which no firewall or
 * DNS check would fix.
 */
export type ConnectivityFailureKind =
  | 'accessDenied'
  | 'unavailable'
  | 'componentsMissing'
  | 'notAccessible'
  | 'other';

/** CA connectivity test result. */
export interface ConnectivityTestResult {
  success: boolean;
  caName?: string;
  caDnsName?: string;
  caDisplayName?: string;
  errorMessage?: string;
  failureKind?: ConnectivityFailureKind | null;
}

/**
 * ACME viability signals read from the template's AD object. Each member is
 * null when the attribute behind it could not be read; the checklist shows
 * "could not verify" for those. Advisory only — never blocks the wizard.
 */
export interface TemplateAcmeViability {
  /** CA manager approval: every ACME finalize would pend for a person. */
  requiresManagerApproval?: boolean | null;
  /** Enrollment agent signatures: ACME CSRs never carry them, so the CA denies. */
  requiresRaSignatures?: boolean | null;
  /** False means the CA builds the subject from AD and ignores requested names. */
  subjectSuppliedInRequest?: boolean | null;
  /** "RSA", an ECC algorithm name, or null when unknown. */
  keyAlgorithm?: string | null;
  minimalKeySize?: number | null;
}

/**
 * Why one of a template's published values does not read, or cannot be used, as
 * published. The class as the noun the checklist puts in its sentence, plus the
 * position and code point an operator can look up. Deliberately not the value
 * and not the character: a bidirectional override in a JSON body would reorder
 * the page reporting it, which is the fault this warning exists to report.
 *
 * Named for the display name it was written for, and since issue #292 it also
 * carries the template OID. The three members are right for both.
 */
export interface SetupTemplateNameWarning {
  /** "control", "line separator", or "formatting". */
  kind: string;
  position: number;
  codePoint: number;
}

/** Template from CA, as offered by the setup wizard. */
export interface SetupTemplate {
  name: string;
  displayName: string;
  oid: string;
  /** True when the template's EKU set contains Server Authentication. */
  hasServerAuthEku: boolean;
  /**
   * True when EKU could be read from AD for this template. False means EKU could
   * not be verified, and the wizard shows the template with an "unverified" notice.
   */
  ekuVerified: boolean;
  /** Null when the template's AD object could not be read at all. */
  viability?: TemplateAcmeViability | null;
  /**
   * Set when the AD display name carries a character the server refuses in a URL
   * path, so a client configured with the display name gets a 400 (issue #235).
   * The programmatic name is always clean here: a template whose programmatic
   * name carries one is not listed at all.
   */
  displayNameWarning?: SetupTemplateNameWarning | null;
  /**
   * Set when the template OID carries such a character (issue #292). Unlike the
   * display name warning nothing is refused: the template issues and is
   * addressed exactly as before. It is here because the wizard prints the OID
   * on every row, where an override in it reorders the line around it.
   */
  oidWarning?: SetupTemplateNameWarning | null;
}

/** Outcome of the server side reachability probe of the external URL. */
export interface UrlProbeResult {
  /** False when the probe was skipped (demo walkthrough with the mock CA). */
  attempted: boolean;
  reachable: boolean;
  /** The host and port the server dialed, for example "203.0.113.10:443". */
  dialedAuthority: string;
  failureKind?: 'connectionRefused' | 'timeout' | 'tlsError' | 'dnsFailure' | 'other' | null;
  failureDetail?: string | null;
  httpStatusCode?: number | null;
  certificateWarning?: string | null;
}

/** URL validation result. The probe rides along when async validation ran. */
export interface UrlValidationResult {
  valid: boolean;
  errorMessage?: string | null;
  warnings?: string[] | null;
  probe?: UrlProbeResult | null;
}

/** Setup completion result. */
export interface SetupCompleteResult {
  setupCompleted: boolean;
  completedAt: string;
  /** True when the service scheduled its own restart to apply the config. */
  restartScheduled: boolean;
  message: string;
}

/** Check if setup has been completed and is in effect. */
export async function fetchSetupStatus(): Promise<SetupStatusResponse> {
  return fetchJson('/api/setup/status');
}

/** Fetch the full setup configuration (requires admin authentication). */
export async function fetchSetupConfig(): Promise<SetupConfigResponse> {
  return fetchJson('/api/setup/config');
}

/** Discover the enterprise CAs published in AD (empty list → manual entry). */
export async function discoverCas(): Promise<DiscoveredCa[]> {
  return fetchJson('/api/setup/discover-cas');
}

/** Test connectivity to a candidate CA connection string. */
export async function testCaConnection(
  caConnectionString: string,
): Promise<ConnectivityTestResult> {
  return fetchJson('/api/setup/test-connection', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caConnectionString }),
  });
}

/**
 * The wizard's template listing: the templates worth offering, plus how many
 * published templates were hidden because they cannot issue a usable ACME
 * server certificate (no Server Authentication EKU, or the subject is built
 * from AD instead of the request).
 */
export interface SetupTemplatesResponse {
  templates: SetupTemplate[];
  excludedCount: number;
  /**
   * The subset of excludedCount hidden because the programmatic name itself
   * carries a control, line separator, or formatting character, so nothing can
   * be enrolled against the template on any path. Held apart because its fix is
   * a different one: a programmatic name is fixed when the template is created.
   */
  unusableNameCount: number;
}

/** List available templates from a candidate CA. */
export async function fetchSetupTemplates(
  caConnectionString: string,
): Promise<SetupTemplatesResponse> {
  return fetchJson('/api/setup/templates', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caConnectionString }),
  });
}

/**
 * Persist the wizard's current selections and step as a draft, so a page
 * reload or the cross origin continue link resumes the wizard where it was.
 * The caller decides whether a failure matters; drafting is best effort.
 */
export async function saveWizardDraft(draft: {
  caConnectionString?: string;
  enabledTemplates?: string[];
  externalUrl?: string;
  allowedDomainsEnabled?: boolean;
  allowedDomains?: string[];
  wizardStep?: string;
}): Promise<void> {
  await fetchJson('/api/setup/draft', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
    body: JSON.stringify(draft),
  });
}

/**
 * Validate an external URL. The template name, when given, points the
 * reachability probe at that template's ACME directory, the same URL the
 * wizard tells clients to use.
 */
export async function validateExternalUrl(
  url: string,
  templateName?: string,
): Promise<UrlValidationResult> {
  return fetchJson('/api/setup/validate-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, templateName }),
  });
}

/**
 * The 422 body when completion is refused pending URL confirmation. The
 * probe is optional because the body is an unvalidated cast: a 422 from an
 * intermediary rather than the setup controller may not carry it.
 */
export interface SetupUnreachableUrlResponse {
  reason: 'externalUrlUnreachable';
  message: string;
  probe?: UrlProbeResult | null;
}

/**
 * Completion either finishes, or is refused with the probe outcome because
 * the external URL did not answer and the request did not confirm it.
 */
export type SetupCompleteOutcome =
  | { kind: 'completed'; result: SetupCompleteResult }
  | { kind: 'unreachableUrl'; refusal: SetupUnreachableUrlResponse };

/**
 * Complete setup wizard. Plain fetch instead of fetchJson because the 422
 * refusal carries a body the wizard needs (fetchJson throws away non 2xx
 * bodies).
 */
export async function completeSetup(config: {
  caConnectionString?: string;
  enabledTemplates: string[];
  externalUrl: string;
  allowedDomainsEnabled?: boolean;
  allowedDomains?: string[];
  confirmUnreachableExternalUrl?: boolean;
}): Promise<SetupCompleteOutcome> {
  const url = '/api/setup/complete';
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
    body: JSON.stringify(config),
  });
  if (response.status === 422) {
    return { kind: 'unreachableUrl', refusal: (await response.json()) as SetupUnreachableUrlResponse };
  }
  if (!response.ok) {
    // The server sends the actual reason as { error } (a validation message
    // or the setup lock); show that instead of the bare status text.
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(response.status, body?.error ?? response.statusText, url);
  }
  return { kind: 'completed', result: (await response.json()) as SetupCompleteResult };
}

/**
 * Wait for the service to come back after the restart that applies setup,
 * polling the anonymous status endpoint with backoff. Resolves true when the
 * service answers with effective completeness, false on timeout.
 */
export async function waitForServiceRestart(timeoutMs = 90_000): Promise<boolean> {
  const startedAt = Date.now();
  // Give the service a moment to actually go down before the first probe,
  // so an answer from the old process does not count as "back up".
  await delay(4_000);

  let interval = 1_500;
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const status = await fetchSetupStatus();
      if (status.setupCompleted) {
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
 * Wait for the service to answer at all after the mid wizard restart that
 * applies the TLS certificate. Unlike waitForServiceRestart this does not
 * look at setupCompleted — setup is still in progress at that point — only
 * at whether the status endpoint responds again.
 */
export async function waitForServiceUp(timeoutMs = 90_000): Promise<boolean> {
  const startedAt = Date.now();
  // Same grace period as waitForServiceRestart: do not let an answer from
  // the old process count as "back up".
  await delay(4_000);

  let interval = 1_500;
  while (Date.now() - startedAt < timeoutMs) {
    try {
      await fetchSetupStatus();
      return true;
    } catch {
      // Connection refused while the service restarts — keep polling.
    }
    await delay(interval);
    interval = Math.min(interval * 1.5, 5_000);
  }
  return false;
}

/**
 * Outcome of enrolling a TLS certificate for the server itself.
 * "installed" means configured; the service restart is scheduled (or, when
 * restartScheduled is false, a manual restart applies it). "sanMismatch"
 * means the certificate is in the store but deliberately not configured: it
 * does not cover the external URL host, and the wizard asks for an explicit
 * decision (apply or discard). The failure outcomes carry the exact fix in
 * their message.
 */
export type TlsProvisionResult =
  | {
      outcome: 'installed';
      thumbprint: string;
      restartScheduled: boolean;
      /** Null when the browsing host could not be determined. */
      currentHostCovered?: boolean | null;
      /** Where to continue setup when the current origin will stop working. */
      continueUrl?: string | null;
    }
  | {
      outcome: 'sanMismatch';
      thumbprint: string;
      issuedNames: string[];
      requestId?: number | null;
    }
  | {
      outcome: 'pending' | 'denied' | 'failed';
      message?: string | null;
      requestId?: number | null;
    };

/**
 * Enroll a TLS certificate for the Ducks in a Row server from the candidate
 * CA using the selected template, and install it. Also the end to end test
 * of the template: ACME orders are submitted by the same account.
 */
export async function provisionTlsCertificate(
  caConnectionString: string,
  templateName: string,
  externalUrl: string,
): Promise<TlsProvisionResult> {
  return fetchJson('/api/setup/tls-certificate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caConnectionString, templateName, externalUrl }),
  });
}

/** Confirm the SAN mismatch outcome: configure and restart with the installed certificate. */
export async function applyTlsCertificate(
  caConnectionString: string,
  templateName: string,
  externalUrl: string,
  thumbprint: string,
): Promise<TlsProvisionResult> {
  return fetchJson('/api/setup/tls-certificate/apply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caConnectionString, templateName, externalUrl, thumbprint }),
  });
}

/** Decline the SAN mismatch outcome: remove the enrolled certificate from the store. */
export async function discardTlsCertificate(thumbprint: string): Promise<{ removed: boolean }> {
  return fetchJson('/api/setup/tls-certificate/discard', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ thumbprint }),
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
