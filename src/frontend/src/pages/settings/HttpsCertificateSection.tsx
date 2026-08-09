import { forwardRef, useImperativeHandle, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  BadgeCheck,
  Loader2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import {
  applyHttpsCertificate,
  fetchHttpsCertificate,
  renewHttpsCertificate,
  waitForHttpsCertificateApplied,
} from '@/api/settings';

type Phase =
  | 'view'
  | 'confirm'
  | 'renewing'
  | 'applying'
  | 'restarting'
  | 'done'
  | 'manual-restart'
  | 'move-origin';

export interface HttpsCertificateSectionHandle {
  /**
   * Step into the provision/renew confirmation and scroll the section into
   * view. The External URL card calls this from its certificate warning so the
   * operator can act on that warning in place, without a second provisioning
   * surface.
   */
  beginProvision: () => void;
}

/**
 * The webserver HTTPS certificate section inside the External URL card: shows
 * the certificate the settings overlay points at (expiry, names, thumbprint,
 * template) and offers one click enrollment. On a completed install this is the
 * only way to (re)provision it, because the wizard's enrollment is locked once
 * setup is complete (SEC-G1). Enrollment re enrolls with the template recorded
 * at setup (or the first enabled template when none was recorded), applies the
 * new thumbprint, and restarts the service, the same restart and poll flow the
 * URL save uses. The action, confirmation and restart panels are identical for
 * a first provision and a renewal; only the wording and the certificate detail
 * list differ.
 */
export const HttpsCertificateSection = forwardRef<HttpsCertificateSectionHandle>(
  function HttpsCertificateSection(_props, ref) {
    const queryClient = useQueryClient();
    const containerRef = useRef<HTMLDivElement>(null);

    const { data: cert, isLoading, isError } = useQuery({
      queryKey: ['settings', 'https-certificate'],
      queryFn: fetchHttpsCertificate,
      staleTime: 30_000,
      retry: false,
    });

    const [phase, setPhase] = useState<Phase>('view');
    const [message, setMessage] = useState<string | null>(null);

    useImperativeHandle(
      ref,
      () => ({
        beginProvision: () => {
          setMessage(null);
          // Only step into the confirmation when there is a template to enroll
          // from; otherwise just reveal the section, which explains why it
          // cannot enroll.
          if (cert?.renewTemplate) setPhase('confirm');
          containerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        },
      }),
      [cert?.renewTemplate],
    );

    const handleRenew = async () => {
      setPhase('renewing');
      setMessage(null);

      try {
        const result = await renewHttpsCertificate();

        if (result.outcome !== 'installed') {
          // sanMismatch / pending / denied / failed: the message carries the
          // exact fix; nothing was applied.
          setMessage(result.message ?? 'Certificate enrollment failed.');
          setPhase('view');
          return;
        }

        if (result.currentHostCovered === false) {
          // The new certificate does not cover the host this page is on, so
          // after the restart this origin stops answering TLS for this
          // browser. Polling from here would only time out; say where to go.
          setPhase('move-origin');
          return;
        }

        if (!result.restartScheduled) {
          setPhase('manual-restart');
          return;
        }

        setPhase('restarting');
        const applied = await waitForHttpsCertificateApplied(result.thumbprint);
        await queryClient.invalidateQueries({ queryKey: ['settings', 'https-certificate'] });
        setPhase(applied ? 'done' : 'manual-restart');
      } catch (err) {
        setMessage(err instanceof Error ? err.message : 'Certificate enrollment failed.');
        setPhase('view');
      }
    };

    /**
     * Apply a certificate the background renewal already enrolled: the overlay
     * points at it, so this only schedules the restart that serves it.
     */
    const handleApply = async () => {
      setPhase('applying');
      setMessage(null);

      try {
        const result = await applyHttpsCertificate();
        if (!result.restartScheduled) {
          setPhase('manual-restart');
          return;
        }

        setPhase('restarting');
        const applied = await waitForHttpsCertificateApplied(result.thumbprint);
        await queryClient.invalidateQueries({ queryKey: ['settings', 'https-certificate'] });
        setPhase(applied ? 'done' : 'manual-restart');
      } catch (err) {
        setMessage(err instanceof Error ? err.message : 'The certificate could not be applied.');
        setPhase('view');
      }
    };

    const notAfter = cert?.notAfter ? new Date(cert.notAfter) : null;
    const daysRemaining = notAfter
      ? Math.floor((notAfter.getTime() - Date.now()) / 86_400_000)
      : null;
    const expiryTone =
      daysRemaining === null ? 'text-ink'
      : daysRemaining < 0 ? 'text-red-700 dark:text-red-300 font-semibold'
      : daysRemaining <= 30 ? 'text-amber-700 dark:text-amber-300 font-semibold'
      : 'text-ink';

    const configured = cert?.configured ?? false;
    const actionLabel = configured ? 'Renew certificate' : 'Provision certificate';
    const confirmLabel = configured ? 'Renew and restart' : 'Provision and restart';
    const confirmHeading = configured
      ? 'Renew the webserver certificate now?'
      : 'Provision a webserver certificate now?';

    return (
      <div ref={containerRef} className="border-t border-hairline pt-4 space-y-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-certus-600" />
          <h3 className="text-sm font-semibold text-ink">HTTPS certificate</h3>
        </div>

        {isLoading && (
          <div className="flex items-center gap-2 text-sm text-faint py-1">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading certificate details…
          </div>
        )}

        {isError && (
          <p className="text-xs text-muted">
            The certificate details could not be loaded. Check the service log.
          </p>
        )}

        {!isLoading && !isError && cert && (
          <>
            {cert.configured ? (
              <>
                <dl className="text-sm space-y-1">
                  <div className="flex gap-2">
                    <dt className="text-muted min-w-[130px]">Expires:</dt>
                    <dd className={`text-xs pt-0.5 ${expiryTone}`}>
                      {notAfter ? notAfter.toLocaleDateString() : 'unknown'}
                      {daysRemaining !== null && (
                        <span className="ml-1">
                          {daysRemaining < 0
                            ? '(expired)'
                            : `(${daysRemaining} ${daysRemaining === 1 ? 'day' : 'days'} left)`}
                        </span>
                      )}
                    </dd>
                  </div>
                  {cert.subjectNames && cert.subjectNames.length > 0 && (
                    <div className="flex gap-2">
                      <dt className="text-muted min-w-[130px]">Names:</dt>
                      <dd className="text-ink font-mono text-xs pt-0.5">
                        {cert.subjectNames.join(', ')}
                      </dd>
                    </div>
                  )}
                  <div className="flex gap-2">
                    <dt className="text-muted min-w-[130px]">Thumbprint:</dt>
                    <dd className="text-ink font-mono text-xs pt-0.5 break-all">
                      {cert.thumbprint}
                    </dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="text-muted min-w-[130px]">Template:</dt>
                    <dd className="text-ink text-xs pt-0.5">
                      {cert.template ??
                        (cert.renewTemplate
                          ? `${cert.renewTemplate} (first enabled template; none was recorded at setup)`
                          : 'unknown')}
                    </dd>
                  </div>
                  {cert.autoRenewal && (
                    <div className="flex gap-2">
                      <dt className="text-muted min-w-[130px]">Automatic renewal:</dt>
                      <dd className="text-ink text-xs pt-0.5">
                        {cert.autoRenewal.enabled
                          ? `on, within ${cert.autoRenewal.windowDays} days of expiry`
                          : 'off'}
                        {cert.autoRenewal.lastAttemptAt && (
                          <span className="text-muted">
                            {' '}
                            (last checked{' '}
                            {new Date(cert.autoRenewal.lastAttemptAt).toLocaleString()})
                          </span>
                        )}
                      </dd>
                    </div>
                  )}
                </dl>

                {cert.autoRenewal?.failed && phase === 'view' && (
                  <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-amber-900 dark:text-amber-200">
                        Automatic renewal did not complete
                      </p>
                      <p className="text-xs text-amber-700 dark:text-amber-300 mt-0.5 whitespace-pre-line">
                        {cert.autoRenewal.lastMessage ??
                          'The service log has the detail. The current certificate is unchanged.'}
                      </p>
                    </div>
                  </div>
                )}

                {cert.inStore === false && (
                  <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
                    <ShieldAlert className="h-4 w-4 text-amber-600 mt-0.5" />
                    <p className="text-xs text-amber-800 dark:text-amber-300">
                      The configured certificate is no longer in the machine store; the
                      service falls back to its self signed certificate. Renewing enrolls
                      a fresh one.
                    </p>
                  </div>
                )}

                {cert.restartPending && phase === 'view' && (
                  <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 space-y-2">
                    <p className="text-xs text-amber-800 dark:text-amber-300">
                      A renewed certificate is installed and configured but not yet served. The
                      service keeps serving the previous certificate until it restarts.
                    </p>
                    <button
                      onClick={handleApply}
                      className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                                 text-amber-900 dark:text-amber-200 bg-amber-100 dark:bg-amber-500/15 border border-amber-300 rounded-lg
                                 hover:bg-amber-200 dark:bg-amber-500/25 transition-colors"
                    >
                      <RefreshCw className="h-3.5 w-3.5" />
                      Restart now to apply it
                    </button>
                  </div>
                )}
              </>
            ) : (
              <p className="text-xs text-muted">
                No CA issued HTTPS certificate is configured; the service serves its self
                signed fallback. Enroll one from the connected CA.
              </p>
            )}

            {phase === 'view' && cert.renewTemplate && (
              <button
                onClick={() => setPhase('confirm')}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                           text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                           hover:bg-certus-100 dark:bg-certus-500/15 transition-colors"
              >
                {configured ? (
                  <RefreshCw className="h-3.5 w-3.5" />
                ) : (
                  <ShieldCheck className="h-3.5 w-3.5" />
                )}
                {actionLabel}
              </button>
            )}

            {phase === 'view' && !cert.renewTemplate && (
              <p className="text-xs text-muted">
                No template is enabled to enroll a webserver certificate from. Enable one,
                then reload this page.
              </p>
            )}

            {phase === 'confirm' && (
              <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 space-y-2">
                <p className="text-xs font-semibold text-amber-900 dark:text-amber-200">{confirmHeading}</p>
                <p className="text-xs text-amber-800 dark:text-amber-300">
                  A new certificate is requested from the CA with the{' '}
                  <code className="font-mono">{cert.renewTemplate}</code> template. The
                  service then restarts briefly to serve it; this page and ACME clients
                  lose their connection for a few seconds.
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={handleRenew}
                    className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                               text-amber-900 dark:text-amber-200 bg-amber-100 dark:bg-amber-500/15 border border-amber-300 rounded-lg
                               hover:bg-amber-200 dark:bg-amber-500/25 transition-colors"
                  >
                    {confirmLabel}
                  </button>
                  <button
                    onClick={() => setPhase('view')}
                    className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-semibold
                               text-ink-soft bg-surface border border-hairline-strong rounded-lg
                               hover:bg-sunken transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {(phase === 'renewing' || phase === 'applying' || phase === 'restarting') && (
              <div className="bg-sunken border border-hairline rounded-lg p-3 flex items-start gap-2">
                <Loader2 className="h-4 w-4 text-certus-500 mt-0.5 animate-spin" />
                <div>
                  <p className="text-xs font-semibold text-ink">
                    {phase === 'renewing'
                      ? 'Requesting a certificate from the CA'
                      : phase === 'applying'
                        ? 'Scheduling the restart that applies the certificate'
                        : 'Certificate installed, the service is restarting'}
                  </p>
                  <p className="text-xs text-muted mt-0.5">
                    {phase === 'restarting'
                      ? 'This page reconnects automatically; it usually takes a few seconds.'
                      : 'This should only take a moment.'}
                  </p>
                </div>
              </div>
            )}

            {phase === 'done' && (
              <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-lg p-3 flex items-start gap-2">
                <BadgeCheck className="h-4 w-4 text-emerald-600 mt-0.5" />
                <p className="text-xs text-emerald-800 dark:text-emerald-300">
                  The service restarted and now serves the{' '}
                  {configured ? 'renewed' : 'new'} certificate.
                </p>
              </div>
            )}

            {phase === 'manual-restart' && (
              <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
                <div>
                  <p className="text-xs font-semibold text-amber-900 dark:text-amber-200">
                    Certificate {configured ? 'renewed' : 'installed'}, restart needed
                  </p>
                  <p className="text-xs text-amber-700 dark:text-amber-300 mt-0.5">
                    The new certificate is installed and configured, but the service
                    did not confirm the restart. Restart it manually (
                    <code className="font-mono">Restart-Service DucksInARow</code>
                    ), then reload this page.
                  </p>
                </div>
              </div>
            )}

            {phase === 'move-origin' && (
              <div className="bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg p-3 flex items-start gap-2">
                <ShieldAlert className="h-4 w-4 text-certus-600 mt-0.5" />
                <p className="text-xs text-certus-800 dark:text-certus-300">
                  The {configured ? 'renewed' : 'new'} certificate does not cover{' '}
                  <code className="font-mono">{window.location.hostname}</code>, so this
                  page loses its connection when the service restarts. Continue at the
                  external URL afterwards.
                </p>
              </div>
            )}

            {message && phase === 'view' && (
              <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                <p className="text-xs text-red-700 dark:text-red-300 whitespace-pre-line">{message}</p>
              </div>
            )}
          </>
        )}
      </div>
    );
  },
);
