import { ApiError, CSRF_HEADERS, fetchJson } from './client';

/** The canonical TLS mode names, matching SmtpTlsModes on the backend. */
export type SmtpTlsModeName = 'none' | 'starttls' | 'implicit';

/**
 * Email alerting, as much of it as the backend will say.
 *
 * A null AlertConfig.smtp means no SMTP block is configured at all, which is a
 * different state from a block that is present but incomplete.
 */
export interface AlertSmtpConfig {
  /**
   * Whether email would actually be attempted right now. Needs a host, at
   * least one recipient, and a sender address.
   */
  enabled: boolean;
  /**
   * Whether a relay host is set. Present so the card can tell "a relay is
   * configured but nobody is listed" apart from "recipients are listed but there
   * is no relay". Both report enabled false and need opposite advice.
   */
  hasHost: boolean;
  /**
   * The relay host, in the clear. Writable since issue #162, and a field an
   * administrator can set but cannot see is one they cannot safely edit. Not a
   * credential.
   */
  host: string;
  /** The relay port, in the clear like the host. */
  port: number;
  /**
   * The effective transport security mode: the explicit choice when one was
   * saved, otherwise what the legacy UseSsl and port derivation will do, so
   * the dropdown always shows what a send would use.
   */
  tlsMode: SmtpTlsModeName;
  /** The relay account name. An empty string means anonymous. */
  username: string;
  /**
   * Whether a sender address is set (issue #209). The code default makes this
   * true unless appsettings.json explicitly blanks Smtp:FromAddress, and the
   * mail cannot be built without one, so enabled is false whenever this is.
   */
  hasFromAddress: boolean;
  /** The sender address. Writable, and not a credential. */
  fromAddress: string;
  /** The sender display name. */
  fromName: string;
  recipients: string[];
  hasCredentials: boolean;
  /**
   * Whether a password is stored, from either source: the protected value
   * saved here or a plaintext one in the configuration file. Presence is all
   * the backend ever says about it; no password, in any form, is returned.
   */
  hasPassword: boolean;
}

/** Webhook alerting, presence only. The URL is never returned. */
export interface AlertWebhookConfig {
  enabled: boolean;
  hasSecret: boolean;
  /** How many custom headers are configured. The names are not returned. */
  headerCount: number;
}

/**
 * The sanitized alert configuration from GET /api/alerts/config.
 *
 * Presence only for anything sensitive: the SMTP password and the webhook URL
 * and its header names are withheld (the webhook URL routinely embeds a bearer
 * token, which is how most webhook relays authenticate, issue #161). The rest
 * of the SMTP transport is returned in the clear now that it is writable: a
 * field an administrator can set but cannot see is one they cannot safely
 * edit.
 */
export interface AlertConfig {
  enabled: boolean;
  checkIntervalMinutes: number;
  /** Every configured threshold, widest first, as the alerting engine sees them. */
  thresholdDays: number[];
  /**
   * The single "expiring soon" window the backend itself uses, in days: the
   * widest configured threshold (issue #152). Read this rather than deriving a
   * maximum from thresholdDays, so the dashboard cannot drift from the rule the
   * backend applies to its own counts.
   */
  expiryWarningDays: number;
  smtp: AlertSmtpConfig | null;
  webhook: AlertWebhookConfig | null;
  /**
   * The writable fields an administrator has saved from the dashboard, which the
   * settings overlay now owns (issue #162). Editing those keys in
   * appsettings.json has no effect, and the card has to say so.
   *
   * Field names, not configuration keys: 'enabled', 'checkIntervalMinutes',
   * 'thresholdDays', 'smtp.host', 'smtp.port', 'smtp.tlsMode',
   * 'smtp.username', 'smtp.password', 'smtp.fromAddress', 'smtp.fromName',
   * 'smtp.recipients'.
   */
  managedFields: string[];
  /**
   * Writable fields an environment variable or command line switch supplies.
   * Saving those cannot take effect while the override stands, so the card
   * disables them rather than pretending.
   */
  outrankedFields: string[];
  /** True when settings.json exists but could not be parsed. */
  overlayUnreadable: boolean;
  /**
   * True when the overlay holds a value this process is not running on, so a
   * restart is owed. Derived by the server on every read, not remembered by the
   * browser: a restart stays owed until it happens, which outlives the session
   * that saved.
   */
  restartPending: boolean;
}

/** The writable field names, matching AlertConfigView.Fields on the backend. */
export const ALERT_FIELDS = {
  enabled: 'enabled',
  checkIntervalMinutes: 'checkIntervalMinutes',
  thresholdDays: 'thresholdDays',
  smtpHost: 'smtp.host',
  smtpPort: 'smtp.port',
  smtpTlsMode: 'smtp.tlsMode',
  smtpUsername: 'smtp.username',
  smtpPassword: 'smtp.password',
  smtpFromAddress: 'smtp.fromAddress',
  smtpFromName: 'smtp.fromName',
  smtpRecipients: 'smtp.recipients',
} as const;

/** Fetch the alert configuration (admin only, like the rest of the dashboard API). */
export async function fetchAlertConfig(): Promise<AlertConfig> {
  return fetchJson('/api/alerts/config');
}

/**
 * The writable alert settings, as the card sends them.
 *
 * The webhook block has no field here at all, mirroring the request type on
 * the backend, which rejects it with a 400 rather than ignoring it. The SMTP
 * password is write only with three states: a non-empty `password` sets a new
 * one (protected before storage), `clearPassword` removes the stored one, and
 * neither keeps it. Nothing about the password ever comes back.
 *
 * A PUT replaces the whole writable set, so every field is sent on every save.
 */
export interface AlertConfigUpdate {
  enabled: boolean;
  checkIntervalMinutes: number;
  thresholdDays: number[];
  smtp: {
    host: string;
    port: number;
    tlsMode: SmtpTlsModeName;
    username: string;
    password?: string;
    clearPassword?: boolean;
    fromAddress: string;
    fromName: string;
    recipients: string[];
  };
}

/**
 * The outcome of a save. A union rather than a throw for the same reason
 * sendTestAlert is one: the refusal bodies carry text the card shows, and
 * fetchJson throws non 2xx bodies away.
 */
export type AlertConfigSaveOutcome =
  | {
      kind: 'saved';
      config: AlertConfig;
      /** Saved, but nothing will be delivered. Shown, never treated as failure. */
      warnings: string[];
      message: string;
    }
  | { kind: 'rejected'; problems: string[] }
  | { kind: 'overlayUnreadable'; error: string };

/**
 * Save the writable alert settings.
 *
 * Plain fetch rather than fetchJson, so the 400 and 409 bodies survive. That
 * means CSRF_HEADERS has to be spread by hand: fetchJson merges it for you and
 * plain fetch does not. Getting that wrong fails in production only, because the
 * CSRF middleware is not registered when authentication is disabled, which is how
 * the dev host and every integration test run.
 */
export async function saveAlertConfig(
  update: AlertConfigUpdate,
): Promise<AlertConfigSaveOutcome> {
  const endpoint = '/api/alerts/config';
  const response = await fetch(endpoint, {
    method: 'PUT',
    headers: { ...CSRF_HEADERS, 'Content-Type': 'application/json' },
    body: JSON.stringify(update),
  });

  if (response.status === 400) {
    return { kind: 'rejected', problems: await readProblems(response) };
  }

  if (response.status === 409) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    return {
      kind: 'overlayUnreadable',
      error:
        body?.error ??
        'The settings file could not be read, so nothing was changed. Check the service log.',
    };
  }

  if (!response.ok) {
    throw new ApiError(response.status, response.statusText, endpoint);
  }

  const result = (await response.json()) as {
    config: AlertConfig;
    warnings: string[];
    message: string;
  };
  return {
    kind: 'saved',
    config: result.config,
    warnings: result.warnings ?? [],
    message: result.message,
  };
}

/**
 * Pulls a readable list out of a 400, whichever shape it arrived in.
 *
 * Two shapes are possible and both matter. Validation the endpoint performs
 * itself answers with a `problems` array. A member the request type does not
 * allow, such as an SMTP password or a webhook URL, is rejected by the JSON
 * deserializer before the action runs, and ASP.NET turns that into an RFC 7807
 * ValidationProblemDetails keyed by JSON path instead.
 */
async function readProblems(response: Response): Promise<string[]> {
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body) return ['The settings could not be saved.'];

  if (Array.isArray(body.problems)) {
    return body.problems.filter((p): p is string => typeof p === 'string');
  }

  if (body.errors && typeof body.errors === 'object') {
    const flattened = Object.values(body.errors as Record<string, unknown>)
      .flatMap((value) => (Array.isArray(value) ? value : [value]))
      .filter((v): v is string => typeof v === 'string');
    if (flattened.length > 0) return flattened;
  }

  if (typeof body.title === 'string') return [body.title];
  return ['The settings could not be saved.'];
}

/** The outcome of asking the service to restart so a saved change comes into force. */
export interface AlertConfigApplyResult {
  /**
   * False on a host that cannot restart itself, which includes the dev host.
   * The operator is then told to restart by hand rather than told a restart is
   * under way.
   */
  restartScheduled: boolean;
  message: string;
}

/** Restart the service to apply saved alert settings. */
export async function applyAlertConfig(): Promise<AlertConfigApplyResult> {
  return fetchJson('/api/alerts/config/apply', { method: 'POST' });
}

/**
 * Wait for the restart applyAlertConfig scheduled to finish: polls until the
 * config endpoint reports no pending restart, which only the restarted process
 * does (the process that has not applied the overlay keeps reporting
 * restartPending true). Resolves false on timeout (manual restart needed).
 * Same shape as waitForHttpsCertificateApplied in settings.ts.
 */
export async function waitForAlertConfigApplied(timeoutMs = 90_000): Promise<boolean> {
  const startedAt = Date.now();
  // Give the service a moment to actually go down before the first probe,
  // so an answer from the old process does not count as "applied".
  await delay(4_000);

  let interval = 1_500;
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const config = await fetchAlertConfig();
      if (config.restartPending === false) {
        return true;
      }
    } catch {
      // Connection refused while the service restarts; keep polling.
    }
    await delay(interval);
    interval = Math.min(interval * 1.5, 5_000);
  }
  return false;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Why a certificate is, or is not, being alerted on. Certificate wide or install
 * wide, never per threshold. Mirrors AlertCoverage on the backend.
 */
export type AlertCoverage =
  | 'monitored'
  | 'alertingDisabled'
  | 'noChannelsConfigured'
  | 'revoked'
  | 'notIssued'
  | 'alreadyExpired'
  | 'ownCertificate';

/**
 * What happened at one threshold. Mirrors AlertThresholdState on the backend.
 * Only 'missing' is an alarm: it means the certificate crossed the threshold,
 * the monitor had time to act, and nothing was recorded.
 */
export type AlertThresholdState =
  | 'sent'
  | 'failed'
  | 'missing'
  | 'awaitingCheck'
  | 'pending'
  | 'notApplicable';

/** One rung of the alert ladder for a certificate. */
export interface CertificateAlertThreshold {
  thresholdDays: number;
  state: AlertThresholdState;
  /**
   * When the certificate crosses (or crossed) this threshold. Not the same as
   * sentAt: a certificate already inside several thresholds when it is first
   * synced fires all of them at once, long after they came due.
   */
  dueAt: string;
  /** Present only when a row exists. */
  sentAt?: string;
  /**
   * The channels that were *attempted*, not the ones that delivered. The row
   * aggregates the whole batch, so on a failure this does not say which channel
   * failed and nothing rendered from it may imply that it does.
   */
  channels?: string;
  /** The last failing channel's error, which is all the row carries. */
  errorMessage?: string;
}

/** The alert history for one certificate (issue #160). */
export interface CertificateAlertHistory {
  certificateId: number;
  coverage: AlertCoverage;
  checkIntervalMinutes: number;
  /** The channels that would be attempted right now. Empty means none is configured. */
  enabledChannels: string[];
  thresholds: CertificateAlertThreshold[];
}

/** Fetch the alert ladder for one certificate. 404s for an unknown certificate. */
export async function fetchCertificateAlertHistory(
  id: number,
): Promise<CertificateAlertHistory> {
  return fetchJson(`/api/alerts/certificate/${id}`);
}

/**
 * One recorded alert, fleet wide. This is a row that was written, so it is
 * always either a success or a failure: none of the forward looking ladder
 * states can appear here.
 */
export interface AlertHistoryItem {
  id: number;
  certificateId: number;
  subject: string;
  serialNumber: string;
  thresholdDays: number;
  sentAt: string;
  /** The channels that were attempted, comma separated, not the ones that delivered. */
  channels: string;
  success: boolean;
  /** The last failing channel's error, which is all the row carries. */
  errorMessage?: string;
}

/** A page of alert history, most recent first. */
export interface AlertHistoryResult {
  items: AlertHistoryItem[];
  totalCount: number;
  skip: number;
  take: number;
  hasMore: boolean;
}

/** Fetch a page of fleet wide alert history. The backend clamps take to 1..200. */
export async function fetchAlertHistory(
  skip = 0,
  take = 10,
): Promise<AlertHistoryResult> {
  return fetchJson(`/api/alerts/history?skip=${skip}&take=${take}`);
}

/** What one channel did with a test send. */
export interface AlertTestChannelResult {
  channel: string;
  success: boolean;
  /** Redacted server side: a notifier error can otherwise carry the webhook URL. */
  errorMessage?: string;
}

/**
 * The outcome of a test send. Both refusals carry a body worth showing, so this
 * is a union rather than a throw, the same shape as AllowedDomainsUpdateOutcome.
 */
export type AlertTestOutcome =
  | { kind: 'sent'; attemptedAt: string; results: AlertTestChannelResult[] }
  | { kind: 'noChannels'; error: string }
  | { kind: 'throttled'; error: string; retryAfterSeconds: number };

/**
 * The SMTP values a test send should prove instead of the running ones: the
 * form's current state. `password` is included only when one was typed this
 * session; omitted, the server authenticates with the stored password.
 */
export interface TestSmtpCandidate {
  host: string;
  port: number;
  tlsMode: SmtpTlsModeName;
  username: string;
  password?: string;
  fromAddress: string;
  fromName: string;
  recipients: string[];
}

/**
 * Send a test alert over every configured channel. With a candidate, the
 * email channel sends using those values instead of the running ones, which
 * is how a typed port, TLS mode or credential is proven without a restart;
 * the webhook channel is untouched either way.
 *
 * Plain fetch instead of fetchJson because the 409 and 429 refusals carry text
 * the card shows, and fetchJson throws non 2xx bodies away. That means
 * CSRF_HEADERS has to be spread by hand here: fetchJson merges it for you and
 * plain fetch does not. Getting that wrong fails in production only, because the
 * CSRF middleware is not registered when authentication is disabled, which is
 * how the dev host and every integration test run.
 */
export async function sendTestAlert(candidate?: TestSmtpCandidate): Promise<AlertTestOutcome> {
  const endpoint = '/api/alerts/test';
  const response = await fetch(
    endpoint,
    candidate
      ? {
          method: 'POST',
          headers: { ...CSRF_HEADERS, 'Content-Type': 'application/json' },
          body: JSON.stringify({ smtp: candidate }),
        }
      : {
          method: 'POST',
          headers: { ...CSRF_HEADERS },
        },
  );

  if (response.status === 409) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    return {
      kind: 'noChannels',
      error: body?.error ?? 'No alert channel is configured, so there is nothing to test.',
    };
  }

  if (response.status === 429) {
    const body = (await response.json().catch(() => null)) as
      | { error?: string; retryAfterSeconds?: number }
      | null;
    return {
      kind: 'throttled',
      error: body?.error ?? 'A test alert was sent very recently. Try again shortly.',
      retryAfterSeconds: body?.retryAfterSeconds ?? 60,
    };
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(response.status, body?.error ?? response.statusText, endpoint);
  }

  const result = (await response.json()) as {
    attemptedAt: string;
    results: AlertTestChannelResult[];
  };
  return { kind: 'sent', attemptedAt: result.attemptedAt, results: result.results };
}
