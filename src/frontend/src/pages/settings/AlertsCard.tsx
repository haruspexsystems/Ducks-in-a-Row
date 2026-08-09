import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  BellRing,
  CheckCircle2,
  Loader2,
  RotateCw,
  Send,
  XCircle,
} from 'lucide-react';
import {
  ALERT_FIELDS,
  applyAlertConfig,
  fetchAlertConfig,
  fetchAlertHistory,
  saveAlertConfig,
  sendTestAlert,
  waitForAlertConfigApplied,
  type AlertConfig,
  type AlertConfigUpdate,
  type AlertTestOutcome,
  type SmtpTlsModeName,
  type TestSmtpCandidate,
} from '@/api/alerts';
import { alertConfigKey } from '@/hooks/useExpiryWarningDays';
import { AlertOutcomeBadge } from '@/components/AlertHistoryEntry';
import { formatDateTime } from '@/types';

/** How many recorded alerts the card shows. The backend clamps take to 1..200. */
const HISTORY_PAGE_SIZE = 10;

/**
 * Dashboard card for expiry alerting (issues #161 and #162).
 *
 * The product shipped a complete alerting engine and no way to see it, so an
 * operator could not find out whether alerting was on, who was being told, or
 * whether sending had been failing. Issue #161 made it visible; issue #162 made
 * the operational parts of it writable, so adding a recipient or widening a
 * threshold no longer means editing a file on the server.
 *
 * Three things here are load bearing.
 *
 * A saved value is not an applied value. The settings overlay is registered with
 * reload switched off and every alert consumer snapshots its options when the
 * process starts, so nothing saved here reaches the running engine until a
 * restart. The form therefore keeps showing what was typed while the figures
 * elsewhere on the page keep showing what is running, and the banner says which
 * is which. Appearing to have changed monitoring when it has not is worse than
 * asking for a restart.
 *
 * The webhook block is absent, not disabled: it stays in appsettings.json and
 * the backend rejects it outright rather than ignoring it. The SMTP transport
 * is fully writable here, password included, but the password only ever
 * travels in one direction: a typed value is sent, protected server side, and
 * never returned in any form; the form starts empty every time and a presence
 * flag is all the backend says.
 *
 * The test send matters more than it looks. SMTP configuration fails quietly and
 * often, and an alerting system nobody has ever seen work is one nobody should
 * trust. When the form names a relay host, email tests the form's values rather
 * than the running ones, because SMTP changes apply only at a restart and a
 * transport nobody can prove before restarting is one nobody will dare change.
 * With the host blank there is nothing to candidate, so the classic test of the
 * running configuration runs, email included if the running values deliver.
 */
export function AlertsCard() {
  const queryClient = useQueryClient();

  const {
    data: config,
    isLoading,
    isError,
  } = useQuery({
    // The same key and staleTime as useExpiryWarningDays, so this card shares
    // the request every expiry affordance in the UI already makes.
    queryKey: alertConfigKey,
    queryFn: fetchAlertConfig,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });

  const { data: history, isError: historyError } = useQuery({
    queryKey: ['alerts', 'history', { skip: 0, take: HISTORY_PAGE_SIZE }],
    queryFn: () => fetchAlertHistory(0, HISTORY_PAGE_SIZE),
    staleTime: 30_000,
    retry: false,
  });

  const [form, setForm] = useState<AlertForm | null>(null);
  const [baseline, setBaseline] = useState<AlertForm | null>(null);
  const [saving, setSaving] = useState(false);
  const [problems, setProblems] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);
  const [restarting, setRestarting] = useState(false);
  const [restartMessage, setRestartMessage] = useState<string | null>(null);

  const [sending, setSending] = useState(false);
  const [outcome, setOutcome] = useState<AlertTestOutcome | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  // Seeded once, from whatever is in force when the card first loads. Not kept
  // in step with the query afterwards: after a save the server still reports the
  // running values, so re-seeding would throw away what the operator just saved
  // and show them the old numbers as though the save had not happened.
  useEffect(() => {
    if (config && form === null) {
      const initial = formFromConfig(config);
      setForm(initial);
      setBaseline(initial);
    }
  }, [config, form]);

  const dirty =
    form !== null && baseline !== null && JSON.stringify(form) !== JSON.stringify(baseline);

  const update = (change: Partial<AlertForm>) => {
    setForm((current) => (current === null ? current : { ...current, ...change }));
    setSavedMessage(null);
  };

  const outranked = (field: string) => config?.outrankedFields?.includes(field) ?? false;

  const handleSave = async () => {
    if (form === null) return;

    const parsed = parseForm(form);
    if (parsed.problems.length > 0) {
      setProblems(parsed.problems);
      setWarnings([]);
      setSavedMessage(null);
      return;
    }

    setSaving(true);
    setProblems([]);
    setWarnings([]);
    setSavedMessage(null);
    try {
      const result = await saveAlertConfig(parsed.update!);

      if (result.kind === 'rejected') {
        setProblems(result.problems);
        return;
      }

      if (result.kind === 'overlayUnreadable') {
        setProblems([result.error]);
        return;
      }

      setBaseline(form);
      setWarnings(result.warnings);
      setSavedMessage(result.message);
      setRestartMessage(null);

      // Seed rather than invalidate. The response carries the same in-force
      // values a refetch would return, plus the updated ownership report, so a
      // round trip would buy nothing; and an invalidate would race the effect
      // above into re-seeding the form from the values still running.
      queryClient.setQueryData(alertConfigKey, result.config);
    } catch (err) {
      setProblems([err instanceof Error ? err.message : 'The settings could not be saved.']);
    } finally {
      setSaving(false);
    }
  };

  const handleRestart = async () => {
    setRestarting(true);
    setRestartMessage(null);
    try {
      const result = await applyAlertConfig();
      if (!result.restartScheduled) {
        // A host that cannot restart itself (the dev host, a console run).
        // The server message says to restart by hand; the banner honestly
        // stays until that happens.
        setRestartMessage(result.message);
        return;
      }

      // The restart is under way. Wait for the restarted process, whose
      // in-force values match the overlay, then re-read the config so the
      // banner clears. Without the re-read the cached restartPending stays
      // true forever: the shared query's staleTime outlives any navigation,
      // so only a hard reload would ever clear the banner. Same shape as
      // ExternalUrlCard and HttpsCertificateNoticeBanner.
      setRestartMessage('Restarting the service…');
      const applied = await waitForAlertConfigApplied();
      // Unconditional, exactly like ExternalUrlCard and
      // HttpsCertificateNoticeBanner: on a timeout the service may still come
      // back a moment later, and a cache left stale then would keep every
      // surface sharing this key on the old values until a hard reload.
      await queryClient.invalidateQueries({ queryKey: alertConfigKey });
      if (applied) {
        setRestartMessage(null);
      } else {
        setRestartMessage(
          'The service did not come back in time. Restart it manually ' +
            '(Restart-Service DucksInARow), then reload this page.',
        );
      }
    } catch (err) {
      setRestartMessage(
        err instanceof Error ? err.message : 'The restart could not be requested.',
      );
    } finally {
      setRestarting(false);
    }
  };

  const handleTest = async () => {
    setSending(true);
    setOutcome(null);
    setTestError(null);
    try {
      // The email channel proves the values in the form, saved or not: SMTP
      // changes only apply at a restart, so testing the running values would
      // make a typed port, TLS mode or credential unprovable until after
      // restarting on it. With no relay host in the form there is nothing to
      // candidate and the classic body-less test of the running configuration
      // runs, email included when the running values deliver.
      let candidate: TestSmtpCandidate | undefined;
      if (form !== null && form.smtpHost.trim().length > 0) {
        const port = Number(form.smtpPort.trim());
        if (!Number.isInteger(port)) {
          setTestError('The SMTP port must be a whole number.');
          return;
        }
        candidate = {
          host: form.smtpHost.trim(),
          port,
          tlsMode: form.smtpTlsMode,
          username: form.smtpUsername.trim(),
          fromAddress: form.smtpFromAddress.trim(),
          fromName: form.smtpFromName.trim(),
          recipients: form.smtpRecipients
            .split('\n')
            .map((line) => line.trim())
            .filter(Boolean),
        };
        if (form.smtpPassword.length > 0) {
          candidate.password = form.smtpPassword;
        }
      }

      setOutcome(await sendTestAlert(candidate));
      // Deliberately no invalidateQueries here. A test send writes nothing, and
      // refetching the history would imply a row might appear.
    } catch (err) {
      setTestError(err instanceof Error ? err.message : 'The test could not be sent.');
    } finally {
      setSending(false);
    }
  };

  const emailEnabled = config?.smtp?.enabled ?? false;
  const webhookEnabled = config?.webhook?.enabled ?? false;
  const anyChannel = emailEnabled || webhookEnabled;

  return (
    <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
      <div className="flex items-center gap-2">
        <BellRing className="h-4 w-4 text-certus-600" />
        <h3 className="text-sm font-semibold text-ink">Alerts</h3>
      </div>
      <p className="text-sm text-muted">
        Ducks watches every issued certificate and warns you before it expires.
        Thresholds, recipients and the relay are set here and take effect when the
        service restarts.
      </p>

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-faint py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading the alert configuration…
        </div>
      ) : isError || !config || !form ? (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">
            The alert configuration could not be loaded, so this card cannot say
            whether alerting is working. Check the service log.
          </p>
        </div>
      ) : (
        <>
          {config.overlayUnreadable && (
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
              <p className="text-xs text-red-700 dark:text-red-300">
                The settings file in the data directory could not be read, so
                anything saved here before is not in force and nothing can be
                saved now. The values below come from{' '}
                <code className="font-mono">appsettings.json</code>. Check the
                service log for the file path and repair it by hand.
              </p>
            </div>
          )}

          {config.restartPending && (
            <div className="bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark:border-blue-500/30 rounded-lg p-3 space-y-2">
              <p className="text-xs text-blue-800 dark:text-blue-300">
                A saved change has not been applied yet. Expiry monitoring is still
                running on the settings it started with, and{' '}
                <strong className="font-semibold">
                  the fields below show those running settings, not what was saved
                </strong>
                , so editing them now would replace the change that is waiting.
                Restart the service to apply it.
              </p>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleRestart}
                  disabled={restarting}
                  className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium
                             text-blue-700 dark:text-blue-300 bg-surface border border-blue-300 rounded-lg
                             hover:bg-blue-50 dark:bg-blue-500/10 disabled:opacity-50 transition-colors"
                >
                  {restarting ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <>
                      <RotateCw className="h-3.5 w-3.5" />
                      Restart now
                    </>
                  )}
                </button>
                {restartMessage && (
                  <span className="text-xs text-blue-800 dark:text-blue-300">{restartMessage}</span>
                )}
              </div>
            </div>
          )}

          {!config.enabled && (
            <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
              <p className="text-xs text-amber-800 dark:text-amber-300">
                Expiry monitoring is switched off, so no certificate is being
                checked and no warning will be sent. Switch it on below and restart
                the service.
              </p>
            </div>
          )}

          {config.enabled && !anyChannel && (
            <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
              <p className="text-xs text-amber-800 dark:text-amber-300">{noChannelAdvice(config)}</p>
            </div>
          )}

          <div className="space-y-4 pt-2 border-t border-hairline-soft">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={form.enabled}
                disabled={outranked(ALERT_FIELDS.enabled)}
                onChange={(e) => update({ enabled: e.target.checked })}
                className="mt-0.5 h-4 w-4 rounded border-hairline-strong text-certus-600
                           focus:ring-certus-500 disabled:opacity-50"
              />
              <span className="text-sm font-medium text-ink">
                Watch certificates for expiry
                <span className="block text-xs font-normal text-muted mt-0.5">
                  When off, nothing is checked and no warning is sent, whatever
                  else is set here.
                </span>
              </span>
            </label>
            <OutrankedNote show={outranked(ALERT_FIELDS.enabled)} />

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field
                label="Check interval"
                hint="How often to look, in minutes. Between 1 and 1440."
              >
                <input
                  type="number"
                  min={1}
                  max={1440}
                  value={form.checkIntervalMinutes}
                  disabled={outranked(ALERT_FIELDS.checkIntervalMinutes)}
                  onChange={(e) => update({ checkIntervalMinutes: e.target.value })}
                  className={inputClass}
                />
                <OutrankedNote show={outranked(ALERT_FIELDS.checkIntervalMinutes)} />
              </Field>

              <Field
                label="Warning thresholds"
                hint="Days before expiry, separated by commas. A warning fires once at each."
              >
                <input
                  type="text"
                  value={form.thresholdDays}
                  onChange={(e) => update({ thresholdDays: e.target.value })}
                  placeholder="30, 14, 7, 1"
                  className={inputClass}
                />
              </Field>

              <Field
                label="SMTP relay host"
                hint="Host name or IP address on its own. Leave blank to switch email off."
              >
                <input
                  type="text"
                  value={form.smtpHost}
                  disabled={outranked(ALERT_FIELDS.smtpHost)}
                  onChange={(e) => update({ smtpHost: e.target.value })}
                  placeholder="smtp.example.com"
                  className={inputClass}
                />
                <OutrankedNote show={outranked(ALERT_FIELDS.smtpHost)} />
              </Field>

              <Field
                label="Port"
                hint="587 is the usual STARTTLS submission port; 465 is implicit TLS."
              >
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={form.smtpPort}
                  disabled={outranked(ALERT_FIELDS.smtpPort)}
                  onChange={(e) => update({ smtpPort: e.target.value })}
                  className={inputClass}
                />
                <OutrankedNote show={outranked(ALERT_FIELDS.smtpPort)} />
              </Field>

              <Field
                label="Transport security"
                hint="STARTTLS is required once negotiated, never opportunistic. None is only for a relay without TLS."
              >
                <select
                  value={form.smtpTlsMode}
                  disabled={outranked(ALERT_FIELDS.smtpTlsMode)}
                  onChange={(e) => update({ smtpTlsMode: e.target.value as SmtpTlsModeName })}
                  className={inputClass}
                >
                  <option value="starttls">STARTTLS (required)</option>
                  <option value="implicit">Implicit TLS</option>
                  <option value="none">None</option>
                </select>
                <OutrankedNote show={outranked(ALERT_FIELDS.smtpTlsMode)} />
              </Field>

              <Field
                label="Username"
                hint="Leave blank to contact the relay anonymously."
              >
                <input
                  type="text"
                  value={form.smtpUsername}
                  disabled={outranked(ALERT_FIELDS.smtpUsername)}
                  onChange={(e) => update({ smtpUsername: e.target.value })}
                  autoComplete="off"
                  className={inputClass}
                />
                <OutrankedNote show={outranked(ALERT_FIELDS.smtpUsername)} />
              </Field>

              <Field
                label="Password"
                hint={
                  config.smtp?.hasPassword
                    ? 'A password is stored. It is never shown; type to replace it.'
                    : 'Stored protected in the data directory, never shown again.'
                }
              >
                <input
                  type="password"
                  value={form.smtpPassword}
                  disabled={
                    outranked(ALERT_FIELDS.smtpPassword) || form.smtpClearPassword
                  }
                  onChange={(e) => update({ smtpPassword: e.target.value })}
                  placeholder={config.smtp?.hasPassword ? '(unchanged)' : '(not set)'}
                  autoComplete="new-password"
                  className={inputClass}
                />
                {config.smtp?.hasPassword && !outranked(ALERT_FIELDS.smtpPassword) && (
                  <label className="flex items-center gap-2 mt-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={form.smtpClearPassword}
                      onChange={(e) =>
                        update({ smtpClearPassword: e.target.checked, smtpPassword: '' })
                      }
                      className="h-3.5 w-3.5 rounded border-hairline-strong text-certus-600
                                 focus:ring-certus-500"
                    />
                    <span className="text-xs text-muted">Remove the saved password</span>
                  </label>
                )}
                <OutrankedNote show={outranked(ALERT_FIELDS.smtpPassword)} />
              </Field>

              <Field
                label="Sender name"
                hint="The display name alert mail is signed with."
              >
                <input
                  type="text"
                  value={form.smtpFromName}
                  disabled={outranked(ALERT_FIELDS.smtpFromName)}
                  onChange={(e) => update({ smtpFromName: e.target.value })}
                  placeholder="Ducks in a Row"
                  className={inputClass}
                />
                <OutrankedNote show={outranked(ALERT_FIELDS.smtpFromName)} />
              </Field>

              <Field label="Sender address" hint="The address alerts appear to come from.">
                <input
                  type="email"
                  value={form.smtpFromAddress}
                  disabled={outranked(ALERT_FIELDS.smtpFromAddress)}
                  onChange={(e) => update({ smtpFromAddress: e.target.value })}
                  placeholder="ducks@example.com"
                  className={inputClass}
                />
                <OutrankedNote show={outranked(ALERT_FIELDS.smtpFromAddress)} />
              </Field>
            </div>

            <Field
              label="Recipients"
              hint="One address per line. Everyone listed receives every expiry warning."
            >
              <textarea
                rows={3}
                value={form.smtpRecipients}
                onChange={(e) => update({ smtpRecipients: e.target.value })}
                placeholder="ops@example.com"
                className={`${inputClass} font-mono`}
              />
            </Field>

            {problems.length > 0 && (
              <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
                <ul className="text-xs text-red-700 dark:text-red-300 space-y-1">
                  {problems.map((problem) => (
                    <li key={problem}>{problem}</li>
                  ))}
                </ul>
              </div>
            )}

            {warnings.length > 0 && (
              <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
                <ul className="text-xs text-amber-800 dark:text-amber-300 space-y-1">
                  {warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex items-center justify-between gap-4">
              <p className="text-xs text-faint">
                The webhook stays in the{' '}
                <code className="font-mono">Certus:Alerts</code> section of{' '}
                <code className="font-mono">appsettings.json</code> and cannot be
                changed from here. Everything about the SMTP transport can.
              </p>
              <button
                onClick={handleSave}
                disabled={saving || !dirty || config.overlayUnreadable}
                className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                           bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50
                           whitespace-nowrap transition-colors"
              >
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
              </button>
            </div>

            {savedMessage && !config.restartPending && (
              <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-lg p-3 flex items-start gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5 shrink-0" />
                <p className="text-xs text-emerald-800 dark:text-emerald-300">{savedMessage}</p>
              </div>
            )}

            {config.managedFields.length > 0 && (
              <p className="text-xs text-faint">
                {describeManaged(config.managedFields)} now come from this page and
                are stored in the data directory. Editing those keys in{' '}
                <code className="font-mono">appsettings.json</code> no longer has
                any effect.
              </p>
            )}
          </div>

          <div className="pt-2 border-t border-hairline-soft">
            <dt className="text-sm font-medium text-muted">Webhook</dt>
            <dd className="text-sm text-ink mt-0.5">
              {config.webhook == null ? (
                <span className="text-muted">Not configured</span>
              ) : (
                <>
                  Configured
                  <span className="block text-xs text-muted mt-0.5">
                    {config.webhook.hasSecret
                      ? 'Payloads are signed with a shared secret.'
                      : 'No signing secret is set, so payloads are unsigned.'}
                    {config.webhook.headerCount > 0 &&
                      ` ${config.webhook.headerCount} custom header${
                        config.webhook.headerCount === 1 ? '' : 's'
                      }.`}
                  </span>
                </>
              )}
            </dd>
            <p className="text-xs text-faint mt-2">
              The webhook address is never shown here or returned to the browser,
              because it commonly carries an access token in the URL. The same goes
              for the SMTP password.
            </p>
          </div>

          <div className="pt-2 border-t border-hairline-soft space-y-3">
            <div className="flex items-center justify-between gap-4">
              <p className="text-sm text-muted">
                Send a test over every configured channel to confirm it arrives.
                It is clearly marked as a test and nothing is written to the alert
                history, so no record of it appears below. When a relay host is set
                above, email is tested with the values in the form, saved or not,
                so a typed relay, port or credential can be proven before a restart;
                with the host blank, the test uses the settings the service is
                running on. The webhook always uses the running settings.
              </p>
              <button
                onClick={handleTest}
                disabled={sending}
                className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium
                           text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                           hover:bg-certus-100 dark:bg-certus-500/15 disabled:opacity-50 whitespace-nowrap
                           transition-colors"
              >
                {sending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    <Send className="h-4 w-4" />
                    Send a test
                  </>
                )}
              </button>
            </div>

            {testError && (
              <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
                <p className="text-xs text-red-700 dark:text-red-300">{testError}</p>
              </div>
            )}

            {outcome && <TestOutcome outcome={outcome} monitoringEnabled={config.enabled} />}
          </div>

          <div className="pt-2 border-t border-hairline-soft space-y-2">
            <div className="flex items-baseline justify-between gap-4">
              <h4 className="text-sm font-semibold text-ink">Recent alerts</h4>
              {history != null && history.totalCount > history.items.length && (
                <span className="text-xs text-faint">
                  {history.items.length} most recent of {history.totalCount}
                </span>
              )}
            </div>

            {historyError ? (
              <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
                <p className="text-xs text-red-700 dark:text-red-300">
                  The alert history could not be loaded. This says nothing about
                  whether alerts were sent.
                </p>
              </div>
            ) : history == null ? (
              <div className="flex items-center gap-2 text-sm text-faint py-2">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading the alert history…
              </div>
            ) : history.items.length === 0 ? (
              <p className="text-sm text-muted py-2">
                No expiry warning has been sent yet. On a healthy install with
                nothing near expiry, that is the expected answer.
              </p>
            ) : (
              <ul className="divide-y divide-hairline-soft border border-hairline rounded-lg">
                {history.items.map((item) => (
                  <li key={item.id} className="px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        to={`/certificates/${item.certificateId}`}
                        className="text-sm font-medium text-certus-700 dark:text-certus-300 hover:underline break-all"
                      >
                        {item.subject}
                      </Link>
                      <AlertOutcomeBadge state={item.success ? 'sent' : 'failed'} />
                      <span className="text-xs text-muted">
                        {item.thresholdDays} day warning
                      </span>
                    </div>
                    <p className="text-sm text-ink-mid mt-1">
                      {item.success ? 'Sent' : 'Failed'} {formatDateTime(item.sentAt)}.{' '}
                      {/* "Attempted", not "delivered": the row records which
                          notifiers ran, not which of them the recipient heard from. */}
                      Attempted over {item.channels.split(',').filter(Boolean).join(', ')}.
                    </p>
                    {!item.success && (
                      <>
                        {item.errorMessage && (
                          <p className="text-sm text-red-700 dark:text-red-300 mt-1 break-words whitespace-pre-line">
                            {item.errorMessage}
                          </p>
                        )}
                        <p className="text-sm text-red-700 dark:text-red-300 mt-1">
                          At least one channel failed. Ducks does not retry a
                          threshold it has already recorded, so this warning will
                          not be sent again.
                        </p>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </div>
  );
}

const inputClass =
  'w-full px-3 py-2 border border-hairline-strong rounded-lg text-sm placeholder:text-faint ' +
  'focus:outline-none focus:ring-2 focus:ring-certus-500 focus:border-certus-500 ' +
  'disabled:bg-sunken disabled:text-faint';

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-sm font-medium text-muted mb-1">{label}</label>
      {children}
      <p className="text-xs text-faint mt-1">{hint}</p>
    </div>
  );
}

/**
 * Why a field is disabled. An environment variable or command line switch
 * outranks the settings file, so saving the field would store a value that never
 * comes into force; disabling it is more honest than accepting the edit.
 */
function OutrankedNote({ show }: { show: boolean }) {
  if (!show) return null;
  return (
    <p className="text-xs text-amber-700 dark:text-amber-300 mt-1">
      Set by an environment variable or command line argument, which outranks
      anything saved here. Remove that override to manage this from the dashboard.
    </p>
  );
}

/** The form's own shape: every field a string, so a part-typed value is legal. */
interface AlertForm {
  enabled: boolean;
  checkIntervalMinutes: string;
  thresholdDays: string;
  smtpHost: string;
  smtpPort: string;
  smtpTlsMode: SmtpTlsModeName;
  smtpUsername: string;
  /** Always starts empty: the saved password is never round tripped. */
  smtpPassword: string;
  smtpClearPassword: boolean;
  smtpFromAddress: string;
  smtpFromName: string;
  smtpRecipients: string;
}

function formFromConfig(config: AlertConfig): AlertForm {
  return {
    enabled: config.enabled,
    checkIntervalMinutes: String(config.checkIntervalMinutes),
    thresholdDays: config.thresholdDays.join(', '),
    smtpHost: config.smtp?.host ?? '',
    smtpPort: String(config.smtp?.port ?? 587),
    smtpTlsMode: config.smtp?.tlsMode ?? 'starttls',
    smtpUsername: config.smtp?.username ?? '',
    smtpPassword: '',
    smtpClearPassword: false,
    smtpFromAddress: config.smtp?.fromAddress ?? '',
    smtpFromName: config.smtp?.fromName ?? 'Ducks in a Row',
    smtpRecipients: (config.smtp?.recipients ?? []).join('\n'),
  };
}

/**
 * Turns the typed form into a request, or into the reasons it is not one yet.
 *
 * Only the checks the browser can make without guessing at backend rules: a
 * number that is not a number, a threshold list that is empty. Ranges, address
 * syntax and host shape are left to the server, so there is one set of rules
 * rather than two that can drift.
 */
function parseForm(form: AlertForm) {
  const problems: string[] = [];

  const interval = Number(form.checkIntervalMinutes.trim());
  if (!Number.isInteger(interval)) {
    problems.push('The check interval must be a whole number of minutes.');
  }

  const port = Number(form.smtpPort.trim());
  if (!Number.isInteger(port)) {
    problems.push('The SMTP port must be a whole number.');
  }

  const thresholdTokens = form.thresholdDays
    .split(/[,\s]+/)
    .map((token) => token.trim())
    .filter(Boolean);

  const thresholdDays = thresholdTokens.map(Number);
  const unparsable = thresholdTokens.filter((_, i) => !Number.isInteger(thresholdDays[i]));
  if (unparsable.length > 0) {
    problems.push(
      `Warning thresholds must be whole numbers of days. Not a number: ${unparsable.join(', ')}.`,
    );
  }

  if (thresholdTokens.length === 0) {
    problems.push(
      'Add at least one warning threshold, or switch expiry monitoring off. ' +
        'An empty list means no warning is ever sent.',
    );
  }

  if (problems.length > 0) return { problems, update: null };

  const update: AlertConfigUpdate = {
    enabled: form.enabled,
    checkIntervalMinutes: interval,
    thresholdDays,
    smtp: {
      host: form.smtpHost.trim(),
      port,
      tlsMode: form.smtpTlsMode,
      username: form.smtpUsername.trim(),
      fromAddress: form.smtpFromAddress.trim(),
      fromName: form.smtpFromName.trim(),
      recipients: form.smtpRecipients
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean),
    },
  };

  // The password travels only when something changes: a typed value sets it,
  // the checkbox clears it, and otherwise the stored one is left untouched.
  if (form.smtpClearPassword) {
    update.smtp.clearPassword = true;
  } else if (form.smtpPassword.length > 0) {
    update.smtp.password = form.smtpPassword;
  }

  return { problems, update };
}

/** "The thresholds and recipients", in the operator's words rather than field ids. */
function describeManaged(managedFields: string[]): string {
  const names: Record<string, string> = {
    [ALERT_FIELDS.enabled]: 'whether monitoring is on',
    [ALERT_FIELDS.checkIntervalMinutes]: 'the check interval',
    [ALERT_FIELDS.thresholdDays]: 'the thresholds',
    [ALERT_FIELDS.smtpHost]: 'the relay host',
    [ALERT_FIELDS.smtpPort]: 'the port',
    [ALERT_FIELDS.smtpTlsMode]: 'the transport security',
    [ALERT_FIELDS.smtpUsername]: 'the username',
    [ALERT_FIELDS.smtpPassword]: 'the password',
    [ALERT_FIELDS.smtpFromAddress]: 'the sender address',
    [ALERT_FIELDS.smtpFromName]: 'the sender name',
    [ALERT_FIELDS.smtpRecipients]: 'the recipients',
  };

  const described = managedFields.map((field) => names[field] ?? field);
  if (described.length === 1) return capitalize(described[0]);

  const last = described[described.length - 1];
  return capitalize(`${described.slice(0, -1).join(', ')} and ${last}`);
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

/**
 * What to say when monitoring is on and nothing can be sent. The four cases
 * need opposite advice, which is the reason the backend reports hasHost and
 * hasFromAddress separately from whether the channel is usable.
 */
function noChannelAdvice(config: AlertConfig): string {
  const smtp = config.smtp;
  const prefix =
    'Expiry monitoring is on, but nothing is configured to send over, so every warning goes nowhere. ';

  if (smtp != null && smtp.hasHost && smtp.recipients.length === 0) {
    return prefix + 'A relay is set but no recipient is listed. Add at least one below.';
  }

  if (smtp != null && !smtp.hasHost && smtp.recipients.length > 0) {
    return prefix + 'Recipients are listed but no relay host is set. Add one below.';
  }

  // Its own sentence rather than the shared prefix: in this state something
  // is configured to send over, it just cannot build a message (issue #209).
  if (smtp != null && smtp.hasHost && smtp.recipients.length > 0 && !smtp.hasFromAddress) {
    return (
      'Expiry monitoring is on and the relay and recipients are set, but no sender ' +
      'address is configured, so the mail cannot be built and every warning goes ' +
      'nowhere. Add a sender address below.'
    );
  }

  return (
    prefix +
    'Add a relay host with at least one recipient below, or configure a webhook under ' +
    'Certus:Alerts:Webhook in appsettings.json, then restart the service.'
  );
}

/**
 * The result of a test send.
 *
 * Two wordings here are load bearing.
 *
 * Monitoring being switched off does not stop a test from being delivered, so a
 * green panel could otherwise read as "alerting is working" on an install where
 * nothing is being watched. The success text is therefore scoped to delivery.
 *
 * And a webhook receiver that chokes on the test payload answers with an error
 * status, which proves delivery works and the handler does not. Reporting that
 * as a plain failure would send an operator off to fix a webhook that is fine,
 * so a rejection by the receiver is called out separately.
 */
function TestOutcome({
  outcome,
  monitoringEnabled,
}: {
  outcome: AlertTestOutcome;
  monitoringEnabled: boolean;
}) {
  if (outcome.kind === 'noChannels') {
    return (
      <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
        <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
        <p className="text-xs text-amber-800 dark:text-amber-300">{outcome.error}</p>
      </div>
    );
  }

  if (outcome.kind === 'throttled') {
    return (
      <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
        <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
        <p className="text-xs text-amber-800 dark:text-amber-300">
          {outcome.error} Try again in about {outcome.retryAfterSeconds} second
          {outcome.retryAfterSeconds === 1 ? '' : 's'}.
        </p>
      </div>
    );
  }

  const allDelivered = outcome.results.every((r) => r.success);
  const panel = allDelivered
    ? 'bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30'
    : 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30';

  return (
    <div className={`${panel} border rounded-lg p-3 space-y-2`}>
      <ul className="space-y-1.5">
        {outcome.results.map((result) => (
          <li key={result.channel} className="flex items-start gap-2">
            {result.success ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-600 mt-0.5 shrink-0" />
            ) : (
              <XCircle className="h-4 w-4 text-red-600 mt-0.5 shrink-0" />
            )}
            <div className="min-w-0">
              <p
                className={`text-xs font-medium ${
                  result.success ? 'text-emerald-800 dark:text-emerald-300' : 'text-red-700 dark:text-red-300'
                }`}
              >
                {result.channel === 'email' ? 'Email' : 'Webhook'}:{' '}
                {result.success ? 'delivered' : 'failed'}
              </p>
              {!result.success && result.errorMessage && (
                <p className="text-xs text-red-700 dark:text-red-300 mt-0.5 break-words whitespace-pre-line">
                  {result.errorMessage}
                </p>
              )}
              {!result.success && receiverRejected(result.errorMessage) && (
                <p className="text-xs text-red-700 dark:text-red-300 mt-0.5">
                  The endpoint was reached and answered with an error, so
                  delivery itself is working. Its handler rejected the test
                  payload, which carries no certificate list.
                </p>
              )}
            </div>
          </li>
        ))}
      </ul>

      {allDelivered && !monitoringEnabled && (
        <p className="text-xs text-emerald-800 dark:text-emerald-300">
          This proves delivery only. Expiry monitoring is still switched off, so
          no real warning is being sent.
        </p>
      )}
    </div>
  );
}

/**
 * Whether a webhook failure was the receiver answering badly rather than the
 * request never arriving. The notifier reports the two differently: a non 2xx
 * response becomes "Webhook returned {status}", and anything that stopped the
 * request reaching the endpoint surfaces as the exception message instead.
 */
function receiverRejected(errorMessage: string | undefined): boolean {
  return errorMessage?.startsWith('Webhook returned ') ?? false;
}
